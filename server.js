/**
 * Link Tracker Pro — Multi-tenant with User Authentication
 */

const express = require('express');
const Database = require('better-sqlite3');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { customAlphabet } = require('nanoid');
const fs = require('fs');
const path = require('path');

// ---------- Config ----------
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || '/var/data/tracker-v2.db';
const SITE_NAME = process.env.SITE_NAME || 'Link Tracker Pro';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const IS_PROD = process.env.NODE_ENV === 'production';

const DEFAULT_CR = Number(process.env.DEFAULT_CR || 0.008); // 0.8%
const DEFAULT_AOV = Number(process.env.DEFAULT_AOV || 45);  // $45

// ---------- Ensure DB folder ----------
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

// ---------- Init DB ----------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// Users table
db.prepare(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`).run();

// Add user_id to existing tables
db.prepare(`CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  slug TEXT NOT NULL,
  target TEXT NOT NULL,
  partner TEXT,
  campaign TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  cr REAL,
  aov REAL,
  UNIQUE(user_id, slug),
  FOREIGN KEY (user_id) REFERENCES users(id)
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS clicks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  slug TEXT,
  click_id TEXT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  ip_hash TEXT,
  ua TEXT,
  referer TEXT,
  utm_source TEXT,
  utm_medium TEXT,
  utm_campaign TEXT,
  user_session TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  user_session TEXT,
  url TEXT,
  referer TEXT,
  duration_ms INTEGER,
  data TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS pageviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  user_session TEXT,
  url TEXT,
  referer TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`).run();

// Sessions table
db.prepare(`CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token TEXT UNIQUE NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`).run();

// ---------- Helpers ----------
const nanoid = customAlphabet('0123456789abcdefghijklmnopqrstuvwxyz', 10);

function hashPassword(password) {
  return crypto.createHash('sha256').update(password + SESSION_SECRET).digest('hex');
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  // store as UNIX epoch seconds
  const expiresAt = Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60); // 30 days
  db.prepare('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)').run(
    userId,
    token,
    expiresAt
  );
  return token;
}

function getUserFromSession(token) {
  if (!token) return null;
  const session = db
    .prepare("SELECT user_id FROM sessions WHERE token = ? AND expires_at > strftime('%s','now')")
    .get(token);
  return session ? db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id) : null;
}

function requireAuth(req, res, next) {
  const user = getUserFromSession(req.cookies.session_token);
  if (!user) {
    return res.redirect('/login');
  }
  req.user = user;
  next();
}

function ipHash(req) {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0];
  const ua = req.headers['user-agent'] || '';
  const salt = new Date().toISOString().slice(0, 10);
  return crypto.createHash('sha256').update(ip + ua + salt).digest('hex').slice(0, 32);
}

function parseConversionRate(input) {
  if (!input) return DEFAULT_CR;
  const cleaned = input.toString().replace(/[^0-9.]/g, '');
  const num = parseFloat(cleaned);
  if (!num || isNaN(num)) return DEFAULT_CR;
  if (num > 1) return num / 100;
  if (num > 0.2) return num / 100;
  return num;
}

function parseMoney(input) {
  if (!input) return DEFAULT_AOV;
  const cleaned = input.toString().replace(/[^0-9.]/g, '');
  const num = parseFloat(cleaned);
  return num > 0 ? num : DEFAULT_AOV;
}

function slugify(text) {
  return (text || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function ensureUserActive(email) {
  const normalized = email.toLowerCase().trim();

  // add an 'active' column if it doesn't exist yet (safe to run repeatedly)
  try {
    db.prepare(`ALTER TABLE users ADD COLUMN active INTEGER DEFAULT 1`).run();
  } catch (_) { /* column already exists */ }

  // does the user already exist?
  const existing = db.prepare(`SELECT id FROM users WHERE email = ?`).get(normalized);
  if (existing) {
    // mark active (in case of re-activation after cancel/refund)
    db.prepare(`UPDATE users SET active = 1 WHERE id = ?`).run(existing.id);
    return { id: existing.id, created: false, tempPassword: null };
    }

  // create a new user with a temporary password
  const tempPassword = crypto.randomBytes(8).toString('hex'); // 16 chars
  const password_hash = hashPassword(tempPassword);
  const result = db
    .prepare(`INSERT INTO users (email, password_hash, active) VALUES (?, ?, 1)`)
    .run(normalized, password_hash);

  return { id: result.lastInsertRowid, created: true, tempPassword };
}

function toCSV(rows) {
  if (!rows.length) return '';
  const headers = Object.keys(rows[0]);
  const escape = (val) => `"${(val ?? '').toString().replace(/"/g, '""')}"`;
  return [headers.join(',')]
    .concat(rows.map((r) => headers.map((h) => escape(r[h])).join(',')))
    .join('\n');
}
// ---- Event logger (keep payload small) ----
function logEvent(userId, type, dataObj = null, req = null) {
  const data = dataObj ? JSON.stringify(dataObj).slice(0, 2000) : null;
  const user_session = req?.cookies?.sb_session || null;
  const url = req?.originalUrl || null;
  const referer = req?.headers?.referer || null;
  db.prepare(
    `INSERT INTO events (user_id, type, user_session, url, referer, duration_ms, data)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(userId, type, user_session, url, referer, null, data);
}

// ---------- App ----------
const app = express();
app.set('trust proxy', 1); // important behind Render/Proxies for secure cookies

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// lightweight session cookie
app.use((req, res, next) => {
  if (!req.cookies.sb_session) {
    res.cookie('sb_session', nanoid(), {
      httpOnly: false,     // readable by client JS if you want
      sameSite: 'Lax',
      secure: IS_PROD,     // only marked Secure in production (https)
      path: '/'
    });
  }
  next();
});

// ---------- Auth Routes ----------

// Registration page
app.get('/register', (req, res) => {
  res.send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Register — ${SITE_NAME}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root { --bg:#0b0f17; --card:#111827; --muted:#9ca3af; --fg:#e5e7eb; --fg-strong:#f9fafb; --accent:#4f46e5; --link:#38bdf8; }
  *{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,-apple-system;background:var(--bg);color:var(--fg);display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{background:var(--card);border:1px solid #1f2937;border-radius:14px;padding:40px;max-width:400px;width:100%;margin:20px}
  h1{font-size:32px;margin:0 0 24px;text-align:center}
  label{display:block;margin:16px 0 6px;font-weight:600}
  input{width:100%;padding:12px;border:1px solid #263041;border-radius:10px;background:#0b1220;color:var(--fg);font-size:16px}
  button{width:100%;background:var(--accent);color:#fff;border:none;border-radius:10px;padding:12px;margin-top:20px;cursor:pointer;font-weight:600;font-size:16px}
  button:hover{background:#4338ca}
  .link{text-align:center;margin-top:16px}
  a{color:var(--link);text-decoration:none} a:hover{text-decoration:underline}
  .error{background:#7f1d1d;border:1px solid #991b1b;color:#fecaca;padding:12px;border-radius:8px;margin-bottom:16px}
/* fix Create-a-short-link layout */
.form .row{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:14px;
  align-items:start;
}
.form .field{
  display:flex;
  flex-direction:column;
}
.form .field label{
  margin:10px 0 6px;
}
.form .field input{
  width:100%;
  box-sizing:border-box;
}
  </style>
</head>
<body>
<div class="card">
  <h1>${SITE_NAME}</h1>
  <h2 style="margin:0 0 24px;font-size:20px;text-align:center;color:var(--muted)">Create your account</h2>
  <form method="POST" action="/register">
    <label>Email</label>
    <input type="email" name="email" required autocomplete="email">
    <label>Password</label>
    <input type="password" name="password" required minlength="8" autocomplete="new-password">
    <label>Confirm Password</label>
    <input type="password" name="password_confirm" required minlength="8" autocomplete="new-password">
    <button type="submit">Create Account</button>
  </form>
  <div class="link">
    Already have an account? <a href="/login">Log in</a>
  </div>
</div>
</body>
</html>`);
});

// Paywall enforced: no direct sign-ups here
app.post('/register', (req, res) => {
  res.status(403).send('Signups are paywalled. Please purchase via our Gumroad link to receive access.');
});

// Login page
app.get('/login', (req, res) => {
  res.send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — ${SITE_NAME}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root { --bg:#0b0f17; --card:#111827; --muted:#9ca3af; --fg:#e5e7eb; --fg-strong:#f9fafb; --accent:#4f46e5; --link:#38bdf8; }
  *{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,-apple-system;background:var(--bg);color:var(--fg);display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{background:var(--card);border:1px solid #1f2937;border-radius:14px;padding:40px;max-width:400px;width:100%;margin:20px}
  h1{font-size:32px;margin:0 0 24px;text-align:center}
  label{display:block;margin:16px 0 6px;font-weight:600}
  input{width:100%;padding:12px;border:1px solid #263041;border-radius:10px;background:#0b1220;color:var(--fg);font-size:16px}
  button{width:100%;background:var(--accent);color:#fff;border:none;border-radius:10px;padding:12px;margin-top:20px;cursor:pointer;font-weight:600;font-size:16px}
  button:hover{background:#4338ca}
  .link{text-align:center;margin-top:16px}
  a{color:var(--link);text-decoration:none} a:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="card">
  <h1>${SITE_NAME}</h1>
  <h2 style="margin:0 0 24px;font-size:20px;text-align:center;color:var(--muted)">Welcome back</h2>
  <form method="POST" action="/login">
    <label>Email</label>
    <input type="email" name="email" required autocomplete="email">
    <label>Password</label>
    <input type="password" name="password" required autocomplete="current-password">
    <button type="submit">Log In</button>
  </form>
  <div class="link">
    Don’t have an account? <a href="${process.env.PAYWALL_URL || 'https://2561082560880.gumroad.com/l/almer'}" target="_blank">Sign up</a>
  </div>
</div>
</body>
</html>`);
});

// Login POST
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).send('Email and password required');
  }
  
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  
  if (!user || user.password_hash !== hashPassword(password)) {
    return res.status(401).send('Invalid email or password');
  }
  
  const token = createSession(user.id);
  res.cookie('session_token', token, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: IS_PROD,
    path: '/',
    maxAge: 30 * 24 * 60 * 60 * 1000
  });
  res.redirect('/');
});
// --- DEV: admin password reset endpoint (temporary) ---
const ADMIN_RESET_TOKEN = process.env.ADMIN_RESET_TOKEN || '';

app.post('/dev/reset-password', (req, res) => {
  // Disable if no token configured
  if (!ADMIN_RESET_TOKEN) return res.status(404).send('disabled');

  // Check admin header
  const headerToken = req.headers['x-admin-token'];
  if (!headerToken || headerToken !== ADMIN_RESET_TOKEN) {
    return res.status(403).send('forbidden');
  }

  const { email, newPassword } = req.body || {};
  if (!email || !newPassword) {
    return res.status(400).send('missing email or newPassword');
  }

  const user = db.prepare('SELECT id FROM users WHERE email = ?')
                 .get(email.toLowerCase().trim());
  if (!user) return res.status(404).send('user not found');

  const passwordHash = hashPassword(newPassword);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
    .run(passwordHash, user.id);

  // Invalidate existing sessions for safety
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);

  res.json({ ok: true, email: email.toLowerCase().trim() });
});
// --- end DEV reset endpoint ---

// Logout
app.get('/logout', (req, res) => {
  const token = req.cookies.session_token;
  if (token) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  }
  res.clearCookie('session_token', { path: '/' });
  res.redirect('/login');
});

// ---------- Create link ----------
app.post('/admin/links', requireAuth, (req, res) => {
  const { target, partner, campaign, cr, aov } = req.body;

  let targetUrl = (target || '').trim();
  if (targetUrl && !/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

  let baseSlug;
  if (partner && partner.trim()) {
    const partnerSlug = slugify(partner);
    const campaignSlug = campaign ? slugify(campaign) : '';
    baseSlug = campaignSlug ? `${partnerSlug}-${campaignSlug}` : partnerSlug;
  } else {
    baseSlug = campaign ? slugify(campaign) : `link-${nanoid()}`;
  }

  let finalSlug = baseSlug;
  let attempt = 0;
  while (db.prepare('SELECT id FROM links WHERE user_id = ? AND slug = ?').get(req.user.id, finalSlug)) {
    attempt++;
    finalSlug = `${baseSlug}-${nanoid().slice(0, 4)}`;
    if (attempt > 10) break;
  }

  const parsedCR = parseConversionRate(cr);
  const parsedAOV = parseMoney(aov);

  try {
db.prepare('INSERT INTO links (user_id, slug, target, partner, campaign, cr, aov) VALUES (?,?,?,?,?,?,?)')
  .run(req.user.id, finalSlug, targetUrl, partner || null, campaign || null, parsedCR, parsedAOV);

// Log event
logEvent(
  req.user.id,
  'create_link',
  { slug: finalSlug, target: targetUrl, partner, campaign, cr: parsedCR, aov: parsedAOV },
  req
);
res.redirect('/');
  } catch (e) {
    res.status(400).send('Error: ' + e.message);
  }
});

// ---------- Home ----------
app.get('/', requireAuth, (req, res) => {
  const links = db.prepare('SELECT * FROM links WHERE user_id = ? ORDER BY id DESC LIMIT 20').all(req.user.id);

  res.send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${SITE_NAME}: Tracking & Estimation Agent</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root { --bg:#0b0f17; --card:#111827; --muted:#9ca3af; --fg:#e5e7eb; --fg-strong:#f9fafb; --accent:#4f46e5; --link:#38bdf8; }
  *{box-sizing;border-box} body{margin:0;font-family:Inter,system-ui,-apple-system;background:var(--bg);color:var(--fg)}
  .wrap{max-width:1150px;margin:28px auto;padding:0 18px}
  .header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
  h1{font-size:36px;margin:0}
  .header-right{display:flex;gap:12px;align-items:center}
  .user-email{color:var(--muted);font-size:14px}
  .admin-btn, .logout-btn{background:#fff;color:#0b0f17;text-decoration:none;padding:10px 20px;border-radius:10px;font-weight:600;font-size:14px;display:inline-block;border:none;cursor:pointer}
  .admin-btn:hover, .logout-btn:hover{background:#e5e7eb}
  .logout-btn{background:#1f2937;color:var(--fg)}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:22px}
  .card{background:var(--card);border:1px solid #1f2937;border-radius:14px;padding:20px}
  label{display:block;margin:10px 0 6px}
  input{width:100%;padding:10px;border:1px solid #263041;border-radius:10px;background:#0b1220;color:var(--fg)}
  button{background:var(--accent);color:#fff;border:none;border-radius:10px;padding:10px 14px;margin-top:12px;cursor:pointer;font-weight:600}
  a{color:var(--link);text-decoration:none} a:hover{text-decoration:underline}
  table{width:100%;border-collapse:collapse;color:var(--fg)}
  th{color:var(--fg-strong);text-align:left;border-bottom:1px solid #1f2937;padding:10px 8px}
  td{color:var(--fg);border-bottom:1px solid #1f2937;padding:10px 8px}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>${SITE_NAME}: Tracking & Estimation Agent</h1>
    <div class="header-right">
      <span class="user-email">${req.user.email}</span>
      <a href="/admin" class="admin-btn">ADMIN DASHBOARD</a>
      <a href="/logout" class="logout-btn">Logout</a>
    </div>
  </div>
  <div class="grid">
    <div class="card">
      <h2>Create a short link</h2>
   <form action="/admin/links" method="POST" class="form">
  <label>Target URL</label>
  <input name="target" required>

  <div class="row">
    <div class="field">
      <label>Partner</label>
      <input name="partner" required>
    </div>
    <div class="field">
      <label>Campaign</label>
      <input name="campaign" required>
    </div>
  </div>

  <div class="row">
    <div class="field">
      <label>Conversion Rate</label>
      <input name="cr" placeholder="1%" required>
    </div>
    <div class="field">
      <label>Average Order Value</label>
      <input name="aov" placeholder="$45" required>
    </div>
  </div>

  <button type="submit">Create link</button>
</form>
    </div>

    <div class="card">
      <h2>Recent links</h2>
<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Slug</th>
        <th>Target</th>
        <th class="hide-sm">Partner</th>
        <th class="hide-sm">Campaign</th>
        <th class="hide-sm">CR</th>
        <th>AOV</th>
      </tr>
    </thead>
    <tbody>
      ${links.map(l => `
        <tr>
          <td><a href="/r/${l.slug}" target="_blank">/r/${l.slug}</a></td>
          <td style="max-width:360px;white-space:nowrap;text-overflow:ellipsis;overflow:hidden">${l.target}</td>
          <td class="hide-sm">${l.partner || ''}</td>
          <td class="hide-sm">${l.campaign || ''}</td>
          <td class="hide-sm">${(((l.cr ?? DEFAULT_CR) * 100).toFixed(2))}%</td>
          <td>$${l.aov ?? DEFAULT_AOV}</td>
        </tr>`).join('')}
    </tbody>
  </table>
</div>
</div>
</div>
</div>
</body>
</html>`);
});
// ---------- Redirect ----------
app.get('/r/:slug', (req, res) => {
  // Find link - try to match with any user since slugs should be unique across users for cleaner URLs
  const row = db.prepare('SELECT * FROM links WHERE slug = ? LIMIT 1').get(req.params.slug);
  if (!row) return res.status(404).send('Not found');

  const clickId = nanoid();
  db.prepare(
    `INSERT INTO clicks (user_id, slug, click_id, ip_hash, ua, referer, user_session)
     VALUES (?,?,?,?,?,?,?)`
  ).run(
    row.user_id,
    row.slug,
    clickId,
    ipHash(req),
    req.headers['user-agent'] || '',
    req.headers.referer || '',
    req.cookies.sb_session || ''
  );

  const url = new URL(row.target);
  if (row.partner) {
    url.searchParams.set('partner', row.partner.toUpperCase());
  }
  url.searchParams.set('sb_click', clickId);
  res.redirect(url.toString());
});

// --- Gumroad webhook: verify secret + log payload (step 1) ---
app.post('/webhooks/gumroad', (req, res) => {
  const provided =
    req.get('x-gumroad-secret') ||  // header option
    req.query.secret ||             // query option
    (req.body && (req.body.secret || req.body.webhook_secret)); // body option

  if (!process.env.GUMROAD_WEBHOOK_KEY) {
    console.error('GUMROAD_WEBHOOK_KEY not set');
    return res.status(500).send('server not configured');
  }

  if (!provided || provided !== process.env.GUMROAD_WEBHOOK_KEY) {
    return res.status(401).send('bad secret');
  }

  // Gumroad usually posts application/x-www-form-urlencoded
  console.log('✅ Gumroad webhook received:', req.body);
  return res.status(200).send('ok');
});

// ---------- Admin ----------
// ---------- Admin ----------
app.get('/admin', requireAuth, (req, res) => {
  const totals = db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM clicks WHERE user_id = ?) AS clicks,
      (SELECT COUNT(*) FROM pageviews WHERE user_id = ?) AS views,
      (SELECT ROUND(AVG(duration_ms),0) FROM events WHERE user_id = ? AND type='time_on_site') AS avg_ms
  `).get(req.user.id, req.user.id, req.user.id);

  const bySlug = db.prepare(`
    SELECT l.slug, l.partner, l.campaign,
           COUNT(c.id) AS clicks,
           COALESCE(l.cr, ?) AS cr,
           COALESCE(l.aov, ?) AS aov,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?) , 2) AS est_sales,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?) * COALESCE(l.aov, ?), 2) AS est_rev
    FROM links l
    LEFT JOIN clicks c ON c.slug = l.slug AND c.user_id = ?
    WHERE l.user_id = ?
    GROUP BY l.slug
    ORDER BY clicks DESC
  `).all(DEFAULT_CR, DEFAULT_AOV, DEFAULT_CR, DEFAULT_CR, DEFAULT_AOV, req.user.id, req.user.id);

  // NEW: total estimated revenue across all links
  const estTotal = bySlug.reduce((sum, r) => sum + (Number(r.est_rev) || 0), 0);

  res.send(`<!doctype html>
<html>
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${SITE_NAME}: Admin Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root { --bg:#0b0f17; --card:#111827; --muted:#9ca3af; --fg:#e5e7eb; --fg-strong:#f9fafb; --accent:#4f46e5; --link:#38bdf8; }
  *{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,-apple-system;background:var(--bg);color:var(--fg)}
  .wrap{max-width:1200px;margin:28px auto;padding:0 18px}
  .header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
  h1{font-size:36px;margin:0}
  .home-btn{background:#fff;color:#0b0f17;text-decoration:none;padding:10px 20px;border-radius:10px;font-weight:600;font-size:14px;display:inline-block}
  .home-btn:hover{background:#e5e7eb}
  .grid{display:grid;grid-template-columns:1fr 2fr;gap:22px}
  .card{background:var(--card);border:1px solid #1f2937;border-radius:14px;padding:20px}
  table{width:100%;border-collapse:collapse;color:var(--fg)}
  th{color:var(--fg-strong);text-align:left;border-bottom:1px solid #1f2937;padding:10px 8px}
  td{color:var(--fg);border-bottom:1px solid #1f2937;padding:10px 8px}
  a{color:var(--link);text-decoration:none} a:hover{text-decoration:underline}
  .btn{background:var(--accent);color:#fff;border:none;border-radius:10px;padding:10px 14px;cursor:pointer;font-weight:600}
/* === Mobile tweaks (≤ 720px) === */
@media (max-width: 720px) {
  .wrap { padding: 0 12px; }
  h1 { font-size: 24px; line-height: 1.2; }
  .header { flex-direction: column; gap: 10px; align-items: flex-start; }
  .admin-btn, .logout-btn { width: 100%; text-align: center; }
  .grid { grid-template-columns: 1fr; gap: 16px; }
  .card { padding: 16px; }
  label { margin: 8px 0 4px; }
  input { padding: 14px; font-size: 16px; } /* nicer touch target */

  /* Make tables scroll instead of squishing */
  .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
  table { min-width: 640px; } /* keeps columns readable; scrolls on phone */

  th, td { padding: 10px 12px; font-size: 14px; white-space: nowrap; }

  /* Hide non-essential columns on small screens */
  .hide-sm { display: none; }
}
  /* === Mobile tweaks (≤ 720px) for Admin === */
@media (max-width: 720px) {
  .wrap { padding: 0 12px; }
  h1 { font-size: 24px; line-height: 1.2; }
  .header { flex-direction: column; gap: 10px; align-items: flex-start; }
  .home-btn { width: 100%; text-align: center; }

  .grid { grid-template-columns: 1fr; gap: 16px; }
  .card { padding: 16px; }

  /* Scroll the big table */
  .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
  table { min-width: 720px; }
  th, td { padding: 10px 12px; font-size: 14px; white-space: nowrap; }

  /* Optionally hide lower-value columns on phones */
  .hide-sm { display: none; }
}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>${SITE_NAME}: Admin Dashboard</h1>
    <a href="/" class="home-btn">LINK TRACKER PRO</a>
  </div>
  <div class="grid">
    <div class="card">
      <h2>Summary</h2>
      <p>Total Views: ${totals.views || 0}</p>
      <p>Total Clicks: ${totals.clicks || 0}</p>
      <p>Avg Time: ${totals.avg_ms ? (totals.avg_ms/1000)+'s' : '—'}</p>
      <p><strong>Est Revenue: $${estTotal.toFixed(2)}</strong></p>
    </div>
    <div class="card">
   <h2>Per Link — Estimated Sales & Revenue</h2>
<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Slug</th>
        <th class="hide-sm">Partner</th>
        <th class="hide-sm">Campaign</th>
        <th>Clicks</th>
        <th class="hide-sm">CR</th>
        <th class="hide-sm">AOV</th>
        <th>Sales</th>
        <th>Revenue</th>
      </tr>
    </thead>
    <tbody>
      ${bySlug.map(r => `
        <tr>
          <td><code style="background:#1f2937;color:#93c5fd;padding:2px 6px;border-radius:6px">${r.slug}</code></td>
          <td class="hide-sm">${r.partner || ''}</td>
          <td class="hide-sm">${r.campaign || ''}</td>
          <td>${r.clicks}</td>
          <td class="hide-sm">${(r.cr * 100).toFixed(2)}%</td>
          <td class="hide-sm">$${r.aov.toFixed(2)}</td>
          <td>${r.est_sales}</td>
          <td>$${r.est_rev}</td>
        </tr>`).join('')}
    </tbody>
  </table>
</div>
</div>
</div>

  <div class="card" style="margin-top:24px;text-align:center">
    <h2>📊 Download Spreadsheets</h2>
    <a class="btn" href="/admin/export/clicks.csv" target="_blank" style="margin-right:8px">Clicks</a>
    <a class="btn" href="/admin/export/events.csv" target="_blank" style="margin-right:8px">Events</a>
    <a class="btn" href="/admin/export/estimates.csv" target="_blank">Estimates</a>
  </div>
</div>
</body>
</html>`);
});

// ---------- CSV Exports ----------
app.get('/admin/export/clicks.csv', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM clicks WHERE user_id = ? ORDER BY id DESC').all(req.user.id);
  res.setHeader('Content-Type', 'text/csv');
  res.send(toCSV(rows));
});

app.get('/admin/export/events.csv', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM events WHERE user_id = ? ORDER BY id DESC').all(req.user.id);
  res.setHeader('Content-Type', 'text/csv');
  res.send(toCSV(rows));
});

app.get('/admin/export/estimates.csv', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT l.slug, l.partner, l.campaign,
           COUNT(c.id) AS clicks,
           COALESCE(l.cr, ?) AS cr,
           COALESCE(l.aov, ?) AS aov,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?) , 2) AS est_sales,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?) * COALESCE(l.aov, ?), 2) AS est_rev
    FROM links l
    LEFT JOIN clicks c ON c.slug = l.slug AND c.user_id = ?
WHERE l.user_id = ?
GROUP BY l.slug
ORDER BY clicks DESC
`).all(DEFAULT_CR, DEFAULT_AOV, DEFAULT_CR, DEFAULT_CR, DEFAULT_AOV, req.user.id, req.user.id);
  res.setHeader('Content-Type', 'text/csv');
  res.send(toCSV(rows));
});

// ---------- Health ----------
app.get('/health', (req, res) => res.json({ ok: true }));

// other routes above…

// --- Gumroad webhook: provision user (step 2) ---
app.post('/webhooks/gumroad', (req, res) => {
  const provided =
    req.get('x-gumroad-secret') ||
    req.query.secret ||
    (req.body && (req.body.secret || req.body.webhook_secret));

  if (!process.env.GUMROAD_WEBHOOK_KEY) {
    console.error('GUMROAD_WEBHOOK_KEY not set');
    return res.status(500).send('server not configured');
  }
  if (!provided || provided !== process.env.GUMROAD_WEBHOOK_KEY) {
    return res.status(401).send('bad secret');
  }

  const email =
    (req.body &&
      (req.body.email ||
        req.body.purchaser_email ||
        req.body.buyer_email)) ||
    '';
  if (!email) {
    console.warn('Gumroad webhook missing email:', req.body);
    return res.status(400).send('missing email');
  }

  const result = ensureUserActive(email);

  console.log('✅ Gumroad provisioned:', {
    email,
    created: result.created,
    user_id: result.id
  });
  return res.status(200).json({
    ok: true,
    email,
    created: result.created,
    tempPassword: result.tempPassword
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});