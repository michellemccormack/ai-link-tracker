/**
 * Secret Boston — Simple Tracking & Estimation Agent
 * Node.js (Express) + SQLite (better-sqlite3)
 */

const express = require('express');
const Database = require('better-sqlite3');
const cookieParser = require('cookie-parser');
const basicAuth = require('basic-auth');
const crypto = require('crypto');
const { customAlphabet } = require('nanoid');

// ---------- Config ----------
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';
const DB_PATH = process.env.DB_PATH || './tracker.db';
const SITE_NAME = process.env.SITE_NAME || 'Secret Boston';

const DEFAULT_CR = Number(process.env.DEFAULT_CR || 0.008); // 0.8%
const DEFAULT_AOV = Number(process.env.DEFAULT_AOV || 45);   // $45

// ---------- Init DB ----------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.prepare(`CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE,
  target TEXT NOT NULL,
  partner TEXT,
  campaign TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  cr REAL,
  aov REAL
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS clicks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT,
  click_id TEXT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  ip_hash TEXT,
  ua TEXT,
  referer TEXT,
  utm_source TEXT,
  utm_medium TEXT,
  utm_campaign TEXT,
  user_session TEXT
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  user_session TEXT,
  url TEXT,
  referer TEXT,
  duration_ms INTEGER,
  data TEXT
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS pageviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  user_session TEXT,
  url TEXT,
  referer TEXT
)`).run();

// ---------- Helpers ----------
const nanoid = customAlphabet('0123456789abcdefghijklmnopqrstuvwxyz', 12);

function requireAdmin(req, res, next) {
  const user = basicAuth(req);
  if (!user || user.pass !== ADMIN_PASSWORD) {
    res.set('WWW-Authenticate', 'Basic realm="admin"');
    return res.status(401).send('Auth required');
  }
  next();
}

function ipHash(req) {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const ua = req.headers['user-agent'] || '';
  const salt = new Date().toISOString().slice(0,10); // rotate daily
  return crypto.createHash('sha256').update(ip + ua + salt).digest('hex').slice(0,32);
}

function html(head, body) {
  return `<!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${SITE_NAME} Tracker</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
      :root { --bg:#0b0f17; --fg:#e6edf3; --muted:#98a2b3; --card:#111827; --accent:#4f46e5; }
      *{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont;background:var(--bg);color:var(--fg)}
      .container{max-width:980px;margin:40px auto;padding:0 20px}
      .card{background:var(--card);border:1px solid #1f2937;border-radius:14px;padding:20px;margin-bottom:18px}
      h1{font-size:28px;margin:0 0 10px} h2{font-size:18px;margin:0 0 10px;color:var(--muted)}
      input,select,button,textarea{background:#0b1220;color:var(--fg);border:1px solid #263041;border-radius:10px;padding:10px}
      label{display:block;margin:8px 0 4px;color:#cbd5e1}
      table{width:100%;border-collapse:collapse}
      th,td{border-bottom:1px solid #1f2937;padding:10px;text-align:left}
      .btn{background:var(--accent);border:none;padding:10px 14px;border-radius:10px;font-weight:600;cursor:pointer}
      .grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
      .muted{color:var(--muted)}
      .tag{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #2b3444;color:#9aa4b2;font-size:12px;margin-left:8px}
      .pill{background:#151c2c;border:1px solid #283349;border-radius:999px;padding:6px 10px}
      code{background:#0e1422;border:1px solid #1f2937;padding:2px 6px;border-radius:6px}
      a { color:#38bdf8; text-decoration:none }
    </style>
    ${head||''}
  </head>
  <body>
    <div class="container">${body}</div>
  </body>
  </html>`;
}

// ---- Flexible parsers (accept %, $, words, etc.) ----
function parseConversionRate(input) {
  if (input == null || input === '') return DEFAULT_CR;
  let s = String(input).toLowerCase().replace(/percent/g,'').replace(/\s/g,'');
  s = s.replace(/[^0-9.+-]/g, ''); // remove % and other symbols, keep dot and sign
  if (s === '' || s === '.' || s === '-.' || s === '+.') return DEFAULT_CR;
  let x = Number(s);
  if (!isFinite(x)) return DEFAULT_CR;
  if (x > 1) return x / 100;     // 8 -> 8% -> 0.08
  if (x > 0.2) return x / 100;   // 0.8 -> 0.8% -> 0.008
  if (x <= 0) return DEFAULT_CR;
  return x;                      // already a fraction like 0.008 or 0.01
}

function parseMoney(input) {
  if (input == null || input === '') return DEFAULT_AOV;
  const s = String(input).replace(/[^0-9.]/g,''); // strip $ and commas
  const x = Number(s);
  return isFinite(x) && x > 0 ? x : DEFAULT_AOV;
}

// --- Slug helpers ---
function slugify(s) {
  if (!s) return '';
  return String(s)
    .toLowerCase()
    .trim()
    .replace(/&/g, 'and')
    .replace(/[^a-z0-9]+/g, '-')   // non-alphanum -> hyphen
    .replace(/^-+|-+$/g, '')       // trim hyphens
    .replace(/-{2,}/g, '-');       // collapse repeats
}

function ensureUniqueSlug(base) {
  let candidate = base || 'link';
  let n = 1;
  const exists = (slug) => !!db.prepare('SELECT 1 FROM links WHERE slug = ?').get(slug);
  while (exists(candidate)) {
    n += 1;
    candidate = `${base}-${n}`;
  }
  return candidate;
}

// ---------- App ----------
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Session cookie
app.use((req,res,next)=>{
  if (!req.cookies.sb_session) {
    res.cookie('sb_session', nanoid(), { httpOnly: false, sameSite: 'Lax' });
  }
  next();
});

// ---------- Landing page ----------
app.get('/', (req,res)=>{
  const links = db.prepare('SELECT slug,target,partner,campaign,cr,aov FROM links ORDER BY id DESC LIMIT 20').all();
  const body = `
  <div class="card">
    <h1>${SITE_NAME} — Tracking & Estimation Agent <span class="tag">MVP</span></h1>
  </div>
  <div class="grid">
    <div class="card">
      <h2>Create a short link</h2>
      <form method="POST" action="/admin/links">
        <label>Target URL (where to redirect)</label>
        <input name="target" required placeholder="https://todaytix.com/secretboston" style="width:100%" />
        <div class="grid">
          <div>
            <label>Partner</label>
            <input name="partner" placeholder="TodayTix" style="width:100%" />
          </div>
          <div>
            <label>Campaign</label>
            <input name="campaign" placeholder="October" style="width:100%" />
          </div>
        </div>
        <div class="grid">
          <div>
            <label>Enter Assumed Conversion Rate</label>
            <input name="cr" type="text" inputmode="decimal" placeholder="1%" style="width:100%" />
          </div>
          <div>
            <label>Assumed Average Order Value</label>
            <input name="aov" type="text" inputmode="decimal" placeholder="$45" style="width:100%" />
          </div>
        </div>
        <p><button class="btn" type="submit">Create link</button></p>
      </form>
      <p class="muted">Slug is auto-generated from Partner + Campaign (e.g., <code>todaytix-october</code>).</p>
    </div>

    <div class="card">
      <h2>Recent links</h2>
      <table>
        <thead><tr><th>Slug</th><th>Target</th><th>Partner</th><th>Campaign</th><th>Conversion Rate</th><th>Average Order Value</th></tr></thead>
        <tbody>
          ${links.map(l=>`<tr>
            <td><a href="/r/${l.slug}" target="_blank">/r/${l.slug}</a></td>
            <td class="muted" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${l.target}</td>
            <td>${l.partner||''}</td>
            <td>${l.campaign||''}</td>
            <td>${(((l.cr??DEFAULT_CR) * 100).toFixed(2))}%</td>
            <td>$${(l.aov??DEFAULT_AOV)}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
  </div>`;
  res.send(html('', body));
});

// ---------- Create link (slug auto from Partner + Campaign) ----------
app.post('/admin/links', (req,res)=>{
  const { slug, target, partner, campaign, cr, aov } = req.body;

  // Build slug from Partner + Campaign if not provided
  let finalSlug = (slug && slug.trim()) || '';
  if (!finalSlug) {
    const base = slugify(`${partner || 'link'}-${campaign || ''}`) || `link-${nanoid(6)}`;
    finalSlug = ensureUniqueSlug(base);
  }

  const parsedCR  = parseConversionRate(cr);
  const parsedAOV = parseMoney(aov);

  try {
    db.prepare('INSERT INTO links (slug,target,partner,campaign,cr,aov) VALUES (?,?,?,?,?,?)')
      .run(finalSlug, target.trim(), partner || null, campaign || null, parsedCR, parsedAOV);
    res.redirect('/');
  } catch (e) {
    res.status(400).send('Error creating link: ' + e.message);
  }
});

// ---------- Redirect + click logging ----------
app.get('/r/:slug', (req,res)=>{
  const row = db.prepare('SELECT * FROM links WHERE slug = ?').get(req.params.slug);
  if (!row) return res.status(404).send('Not found');
  const clickId = nanoid();
  const { utm_source, utm_medium, utm_campaign } = req.query;
  db.prepare(`INSERT INTO clicks (slug, click_id, ip_hash, ua, referer, utm_source, utm_medium, utm_campaign, user_session)
              VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(row.slug, clickId, ipHash(req), req.headers['user-agent']||'', req.headers.referer||'',
         utm_source||null, utm_medium||null, utm_campaign||null, req.cookies.sb_session||null);
  const url = new URL(row.target);
  url.searchParams.set('sb_click', clickId);
  if (utm_source) url.searchParams.set('utm_source', utm_source);
  if (utm_medium) url.searchParams.set('utm_medium', utm_medium);
  if (utm_campaign) url.searchParams.set('utm_campaign', utm_campaign);
  res.redirect(302, url.toString());
});

// ---------- Event ingest ----------
app.post('/api/event', (req,res)=>{
  try {
    const { type, user_session, url, referer, duration_ms, data } = req.body || {};
    if (!type) return res.status(400).json({ ok:false, error:'missing type' });
    const dataStr = data ? JSON.stringify(data).slice(0,2000) : null;
    db.prepare('INSERT INTO events (type,user_session,url,referer,duration_ms,data) VALUES (?,?,?,?,?,?)')
      .run(type, user_session||null, url||null, referer||null, duration_ms||null, dataStr);
    if (type==='pageview') {
      db.prepare('INSERT INTO pageviews (user_session,url,referer) VALUES (?,?,?)')
        .run(user_session||null, url||null, referer||null);
    }
    res.json({ ok:true });
  } catch (e) {
    res.status(500).json({ ok:false, error: e.message });
  }
});

// ---------- Admin dashboard ----------
app.get('/admin', requireAdmin, (req,res)=>{
  const totals = db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM clicks) AS clicks,
      (SELECT COUNT(*) FROM pageviews) AS views,
      (SELECT ROUND(AVG(duration_ms),0) FROM events WHERE type='time_on_site') AS avg_ms
  `).get();

  const bySlug = db.prepare(`
    SELECT l.slug, l.partner, l.campaign,
           COUNT(c.id) AS clicks,
           COALESCE(l.cr, ?) AS conversion_rate,
           COALESCE(l.aov, ?) AS average_order_value,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?) , 2) AS estimated_sales,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?) * COALESCE(l.aov, ?), 2) AS estimated_revenue
    FROM links l
    LEFT JOIN clicks c ON c.slug = l.slug
    GROUP BY l.slug
    ORDER BY clicks DESC
  `).all(DEFAULT_CR, DEFAULT_AOV, DEFAULT_CR, DEFAULT_CR, DEFAULT_AOV);

  const latestClicks = db.prepare(`SELECT slug, click_id, ts, utm_source, utm_medium, utm_campaign FROM clicks ORDER BY id DESC LIMIT 25`).all();
  const latestEvents = db.prepare(`SELECT type, ts, duration_ms, substr(url,1,60) AS url FROM events ORDER BY id DESC LIMIT 25`).all();

  const body = `
  <div class="card"><h1>Admin Dashboard</h1></div>
  <div class="grid">
    <div class="card">
      <h2>Summary</h2>
      <table>
        <tr><td>Total Views</td><td>${totals.views||0}</td></tr>
        <tr><td>Total Clicks</td><td>${totals.clicks||0}</td></tr>
        <tr><td>Avg Time on Site</td><td>${totals.avg_ms? (Math.round(totals.avg_ms/100)/10)+'s':'—'}</td></tr>
      </table>
    </div>
    <div class="card">
      <h2>Per Link — Estimated Sales & Revenue</h2>
      <table>
        <thead><tr><th>Slug</th><th>Partner</th><th>Campaign</th><th>Clicks</th><th>Conversion Rate</th><th>Average Order Value</th><th>Estimated Sales</th><th>Estimated Revenue</th></tr></thead>
        <tbody>
          ${bySlug.map(r=>`<tr>
            <td><code>${r.slug}</code></td>
            <td>${r.partner||''}</td>
            <td>${r.campaign||''}</td>
            <td>${r.clicks}</td>
            <td>${(Number(r.conversion_rate) * 100).toFixed(2)}%</td>
            <td>$${Number(r.average_order_value).toFixed(2)}</td>
            <td>${r.estimated_sales}</td>
            <td>$${r.estimated_revenue}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
  </div>`;
  res.send(html('', body));
});

// ---------- Health ----------
app.get('/health', (req,res)=>res.json({ ok:true }));

// ---------- Start ----------
app.listen(PORT, ()=>{
  console.log(`\n${SITE_NAME} Tracker running on http://localhost:${PORT}`);
  console.log(`Admin: http://localhost:${PORT}/admin  (password: ${ADMIN_PASSWORD})`);
});