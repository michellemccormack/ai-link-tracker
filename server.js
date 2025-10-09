/**
 * Link Tracker Pro — Tracking & Estimation Agent (Stable + Contrast Fix)
 */

const express = require('express');
const Database = require('better-sqlite3');
const cookieParser = require('cookie-parser');
const basicAuth = require('basic-auth');
const crypto = require('crypto');
const { customAlphabet } = require('nanoid');
const fs = require('fs');
const path = require('path');

// ---------- Config ----------
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';
const DB_PATH = process.env.DB_PATH || './tracker.db';
const SITE_NAME = process.env.SITE_NAME || 'Link Tracker Pro';

const DEFAULT_CR = Number(process.env.DEFAULT_CR || 0.008); // 0.8%
const DEFAULT_AOV = Number(process.env.DEFAULT_AOV || 45);  // $45

// ---------- Ensure DB folder ----------
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

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
const nanoid = customAlphabet('0123456789abcdefghijklmnopqrstuvwxyz', 10);

function requireAdmin(req, res, next) {
  const user = basicAuth(req);
  if (!user || user.pass !== ADMIN_PASSWORD) {
    res.set('WWW-Authenticate', 'Basic realm="admin"');
    return res.status(401).send('Auth required');
  }
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
  if (num > 1) return num / 100;     // 8  -> 8%
  if (num > 0.2) return num / 100;   // 0.8 -> 0.8%
  return num;                        // 0.008 etc
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

function toCSV(rows) {
  if (!rows.length) return '';
  const headers = Object.keys(rows[0]);
  const escape = (val) => `"${(val ?? '').toString().replace(/"/g, '""')}"`;
  return [headers.join(',')]
    .concat(rows.map((r) => headers.map((h) => escape(r[h])).join(',')))
    .join('\n');
}

// ---------- App ----------
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// lightweight session cookie
app.use((req, res, next) => {
  if (!req.cookies.sb_session) res.cookie('sb_session', nanoid(), { httpOnly: false, sameSite: 'Lax' });
  next();
});

// ---------- Create link ----------
app.post('/admin/links', (req, res) => {
  const { target, partner, campaign, cr, aov } = req.body;

  let targetUrl = (target || '').trim();
  if (targetUrl && !/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

  const baseSlug = slugify(`${partner || 'link'}-${campaign || ''}`) || `link-${nanoid()}`;
  const finalSlug = baseSlug;

  const parsedCR = parseConversionRate(cr);
  const parsedAOV = parseMoney(aov);

  try {
    db.prepare('INSERT INTO links (slug, target, partner, campaign, cr, aov) VALUES (?,?,?,?,?,?)')
      .run(finalSlug, targetUrl, partner || null, campaign || null, parsedCR, parsedAOV);
    res.redirect('/');
  } catch (e) {
    res.status(400).send('Error: ' + e.message);
  }
});

// ---------- Home ----------
app.get('/', (req, res) => {
  const links = db.prepare('SELECT * FROM links ORDER BY id DESC LIMIT 20').all();

  res.send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${SITE_NAME}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root { --bg:#0b0f17; --card:#111827; --muted:#9ca3af; --fg:#e5e7eb; --fg-strong:#f9fafb; --accent:#4f46e5; --link:#38bdf8; }
  *{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,-apple-system;background:var(--bg);color:var(--fg)}
  .wrap{max-width:1150px;margin:28px auto;padding:0 18px}
  h1{font-size:36px;margin:0 0 16px}
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
  <h1>${SITE_NAME}</h1>
  <div class="grid">
    <div class="card">
      <h2>Create a short link</h2>
      <form action="/admin/links" method="POST">
        <label>Target URL</label>
        <input name="target" required>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
          <div>
            <label>Partner</label>
            <input name="partner">
          </div>
          <div>
            <label>Campaign</label>
            <input name="campaign">
          </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
          <div>
            <label>Conversion Rate</label>
            <input name="cr" placeholder="1%">
          </div>
          <div>
            <label>Average Order Value</label>
            <input name="aov" placeholder="$45">
          </div>
        </div>
        <button type="submit">Create link</button>
      </form>
    </div>

    <div class="card">
      <h2>Recent links</h2>
      <table>
        <thead><tr><th>Slug</th><th>Target</th><th>Partner</th><th>Campaign</th><th>CR</th><th>AOV</th></tr></thead>
        <tbody>
          ${links.map(l => `
            <tr>
              <td><a href="/r/${l.slug}" target="_blank">/r/${l.slug}</a></td>
              <td style="max-width:360px;white-space:nowrap;text-overflow:ellipsis;overflow:hidden">${l.target}</td>
              <td>${l.partner || ''}</td>
              <td>${l.campaign || ''}</td>
              <td>${(((l.cr ?? DEFAULT_CR) * 100).toFixed(2))}%</td>
              <td>$${l.aov ?? DEFAULT_AOV}</td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>
  </div>
</div>
</body>
</html>`);
});

// ---------- Redirect ----------
app.get('/r/:slug', (req, res) => {
  const row = db.prepare('SELECT * FROM links WHERE slug = ?').get(req.params.slug);
  if (!row) return res.status(404).send('Not found');

  const clickId = nanoid();
  db.prepare(
    `INSERT INTO clicks (slug, click_id, ip_hash, ua, referer, user_session)
     VALUES (?,?,?,?,?,?)`
  ).run(
    row.slug,
    clickId,
    ipHash(req),
    req.headers['user-agent'] || '',
    req.headers.referer || '',
    req.cookies.sb_session || ''
  );

  const url = new URL(row.target);
  url.searchParams.set('sb_click', clickId);
  res.redirect(url.toString());
});

// ---------- Admin ----------
app.get('/admin', requireAdmin, (req, res) => {
  const totals = db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM clicks) AS clicks,
      (SELECT COUNT(*) FROM pageviews) AS views,
      (SELECT ROUND(AVG(duration_ms),0) FROM events WHERE type='time_on_site') AS avg_ms
  `).get();

  const bySlug = db.prepare(`
    SELECT l.slug, l.partner, l.campaign,
           COUNT(c.id) AS clicks,
           COALESCE(l.cr, ?) AS cr,
           COALESCE(l.aov, ?) AS aov,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?) , 2) AS est_sales,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?) * COALESCE(l.aov, ?), 2) AS est_rev
    FROM links l
    LEFT JOIN clicks c ON c.slug = l.slug
    GROUP BY l.slug
    ORDER BY clicks DESC
  `).all(DEFAULT_CR, DEFAULT_AOV, DEFAULT_CR, DEFAULT_CR, DEFAULT_AOV);

  res.send(`<!doctype html>
<html>
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — ${SITE_NAME}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root { --bg:#0b0f17; --card:#111827; --muted:#9ca3af; --fg:#e5e7eb; --fg-strong:#f9fafb; --accent:#4f46e5; --link:#38bdf8; }
  *{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,-apple-system;background:var(--bg);color:var(--fg)}
  .wrap{max-width:1200px;margin:28px auto;padding:0 18px}
  h1{font-size:36px;margin:0 0 16px}
  .grid{display:grid;grid-template-columns:1fr 2fr;gap:22px}
  .card{background:var(--card);border:1px solid #1f2937;border-radius:14px;padding:20px}
  table{width:100%;border-collapse:collapse;color:var(--fg)}
  th{color:var(--fg-strong);text-align:left;border-bottom:1px solid #1f2937;padding:10px 8px}
  td{color:var(--fg);border-bottom:1px solid #1f2937;padding:10px 8px}
  a{color:var(--link);text-decoration:none} a:hover{text-decoration:underline}
  .btn{background:var(--accent);color:#fff;border:none;border-radius:10px;padding:10px 14px;cursor:pointer;font-weight:600}
</style>
</head>
<body>
<div class="wrap">
  <h1>Admin Dashboard</h1>
  <div class="grid">
    <div class="card">
      <h2>Summary</h2>
      <p>Total Views: ${totals.views || 0}</p>
      <p>Total Clicks: ${totals.clicks || 0}</p>
      <p>Avg Time: ${totals.avg_ms ? (totals.avg_ms/1000)+'s' : '—'}</p>
    </div>
    <div class="card">
      <h2>Per Link — Estimated Sales & Revenue</h2>
      <table>
        <thead><tr><th>Slug</th><th>Partner</th><th>Campaign</th><th>Clicks</th><th>CR</th><th>AOV</th><th>Sales</th><th>Revenue</th></tr></thead>
        <tbody>
          ${bySlug.map(r => `
            <tr>
              <td><code style="background:#1f2937;color:#93c5fd;padding:2px 6px;border-radius:6px">${r.slug}</code></td>
              <td>${r.partner || ''}</td>
              <td>${r.campaign || ''}</td>
              <td>${r.clicks}</td>
              <td>${(r.cr * 100).toFixed(2)}%</td>
              <td>$${r.aov.toFixed(2)}</td>
              <td>${r.est_sales}</td>
              <td>$${r.est_rev}</td>
            </tr>`).join('')}
        </tbody>
      </table>
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
app.get('/admin/export/clicks.csv', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM clicks ORDER BY id DESC').all();
  res.setHeader('Content-Type', 'text/csv');
  res.send(toCSV(rows));
});

app.get('/admin/export/events.csv', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM events ORDER BY id DESC').all();
  res.setHeader('Content-Type', 'text/csv');
  res.send(toCSV(rows));
});

app.get('/admin/export/estimates.csv', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT l.slug, l.partner, l.campaign,
           COUNT(c.id) AS clicks,
           COALESCE(l.cr, ?) AS cr,
           COALESCE(l.aov, ?) AS aov,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?) , 2) AS est_sales,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?) * COALESCE(l.aov, ?), 2) AS est_rev
    FROM links l
    LEFT JOIN clicks c ON c.slug = l.slug
    GROUP BY l.slug
    ORDER BY clicks DESC
  `).all(DEFAULT_CR, DEFAULT_AOV, DEFAULT_CR, DEFAULT_CR, DEFAULT_AOV);
  res.setHeader('Content-Type', 'text/csv');
  res.send(toCSV(rows));
});

// ---------- Health ----------
app.get('/health', (req, res) => res.json({ ok: true }));

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});