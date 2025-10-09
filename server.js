/**
 * Link Tracker Pro — Simple Tracking & Estimation Agent
 * Stack: Node.js (Express) + SQLite (better-sqlite3)
 * Features:
 *  - Short links with redirect logging (/r/:slug)
 *  - Clean landing page to create links and see recent links
 *  - Admin dashboard with estimates + CSV exports
 *  - CR/AOV flexible input (1, 1%, .01, $45, 45, $45.00, etc.)
 */

const express = require('express');
const Database = require('better-sqlite3');
const cookieParser = require('cookie-parser');
const basicAuth = require('basic-auth');
const crypto = require('crypto');
const { customAlphabet } = require('nanoid');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';
const DB_PATH = process.env.DB_PATH || './tracker.db';
const SITE_NAME = process.env.SITE_NAME || 'Link Tracker Pro';
const DEFAULT_CR = Number(process.env.DEFAULT_CR || 0.008); // 0.8%
const DEFAULT_AOV = Number(process.env.DEFAULT_AOV || 45);  // $45

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
  const salt = new Date().toISOString().slice(0,10);
  return crypto.createHash('sha256').update(ip + ua + salt).digest('hex').slice(0,32);
}

function html(head, body) {
  return `<!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${SITE_NAME}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
      :root{--bg:#0b0f17;--fg:#e6edf3;--muted:#98a2b3;--card:#111827;--accent:#635bff;--line:#1f2937}
      *{box-sizing:border-box}
      body{margin:0;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont;background:var(--bg);color:var(--fg)}
      .container{max-width:1200px;margin:40px auto;padding:0 20px}
      .row{display:grid;grid-template-columns:1fr 1fr;gap:24px}
      .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px}
      h1{font-size:34px;margin:0 0 18px}
      h2{font-size:18px;margin:0 0 12px;color:var(--muted)}
      label{display:block;margin:10px 0 6px;color:#cbd5e1}
      input{width:100%;background:#0b1220;color:var(--fg);border:1px solid #263041;border-radius:10px;padding:12px}
      table{width:100%;border-collapse:collapse}
      th,td{border-bottom:1px solid var(--line);padding:12px;text-align:left}
      .btn{display:inline-block;background:var(--accent);color:white;border:none;padding:12px 16px;border-radius:10px;font-weight:600;cursor:pointer;text-decoration:none}
      .muted{color:var(--muted)}
      .pill{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #2b3444;color:#9aa4b2;font-size:12px}
      .grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
      .grid3{display:grid;grid-template-columns:1fr 1fr;gap:12px}
      code{background:#0e1422;border:1px solid #1f2937;padding:2px 6px;border-radius:6px}
      .footer-row{margin-top:16px; display:flex; gap:10px; flex-wrap:wrap}
    </style>
    ${head||''}
  </head>
  <body><div class="container">${body}</div></body>
  </html>`;
}

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.use((req,res,next)=>{
  if (!req.cookies.sb_session) {
    res.cookie('sb_session', nanoid(), { httpOnly: false, sameSite: 'Lax' });
  }
  next();
});

function parseCR(v){
  if (v == null || v === '') return null;
  if (typeof v === 'number') return v;
  const s = String(v).trim().toLowerCase().replace('%','');
  if (s.includes('.')) {
    const n = Number(s);
    if (!isNaN(n)) {
      return s.endsWith('%') ? n/100 : n; // already handled % removal
    }
  }
  const n = Number(s);
  if (isNaN(n)) return null;
  return n >= 1 ? n/100 : n; // "1" -> 1% -> 0.01
}
function parseAOV(v){
  if (v == null || v === '') return null;
  if (typeof v === 'number') return v;
  const s = String(v).trim().replace(/^\$/,'');
  const n = Number(s);
  return isNaN(n) ? null : n;
}

// ---------- Home (create link + recent links) ----------
app.get('/', (req,res)=>{
  const links = db.prepare('SELECT slug,target,partner,campaign,cr,aov FROM links ORDER BY id DESC LIMIT 20').all();
  const body = `
    <h1>${SITE_NAME}</h1>
    <div class="row">
      <div class="card">
        <h2>Create a short link</h2>
        <form method="POST" action="/admin/links">
          <label>Target URL</label>
          <input name="target" placeholder="https://example.com/page" required />
          <div class="grid2">
            <div>
              <label>Partner</label>
              <input name="partner" placeholder="todaytix / self" />
            </div>
            <div>
              <label>Campaign</label>
              <input name="campaign" placeholder="october / blog / calendar" />
            </div>
          </div>
          <div class="grid2" style="margin-top:6px">
            <div>
              <label>Conversion Rate</label>
              <input name="cr" placeholder="1% or 0.01" />
            </div>
            <div>
              <label>Average Order Value</label>
              <input name="aov" placeholder="$45 or 45" />
            </div>
          </div>
          <p style="margin-top:14px"><button class="btn" type="submit">Create link</button></p>
        </form>
        <p class="muted">Tip: CR accepts 1, 1%, .01. AOV accepts $45 or 45.</p>
      </div>

      <div class="card">
        <h2>Recent links</h2>
        <table>
          <thead>
            <tr><th>Slug</th><th>Target</th><th>Partner</th><th>Campaign</th><th>CR</th><th>AOV</th></tr>
          </thead>
          <tbody>
            ${links.map(l=>`<tr>
              <td><a class="pill" href="/r/${l.slug}" target="_blank">/r/${l.slug}</a></td>
              <td class="muted" style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${l.target}</td>
              <td>${l.partner||''}</td>
              <td>${l.campaign||''}</td>
              <td>${(l.cr ?? DEFAULT_CR)*100}%</td>
              <td>$${(l.aov ?? DEFAULT_AOV)}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
  res.send(html('', body));
});

// create link (public form)
app.post('/admin/links', (req,res)=>{
  try {
    const { target, partner, campaign, cr, aov } = req.body;
    if (!target) return res.status(400).send('Missing target URL');

    const cleanTarget = String(target).trim().startsWith('http')
      ? String(target).trim()
      : 'https://' + String(target).trim();

    const slug = `${(partner||'self').toLowerCase().replace(/\s+/g,'-')}-${(campaign||'link').toLowerCase().replace(/\s+/g,'-')}`;
    const safeSlug = slug.replace(/[^a-z0-9\-]/g,'').slice(0,40);

    const crVal = parseCR(cr);
    const aovVal = parseAOV(aov);

    db.prepare('INSERT OR REPLACE INTO links (slug,target,partner,campaign,cr,aov) VALUES (?,?,?,?,?,?)')
      .run(safeSlug, cleanTarget, partner||null, campaign||null, crVal, aovVal);

    res.redirect('/');
  } catch (e) {
    res.status(400).send('Error creating link: ' + e.message);
  }
});

// redirect + click log
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

// event ingest (optional; kept for forward-compat)
app.post('/api/event', (req,res)=>{
  try {
    const { type, user_session, url, referer, duration_ms, data } = req.body || {};
    if (!type) return res.status(400).json({ ok:false, error:'missing type' });
    const dataStr = data ? JSON.stringify(data).slice(0,2000) : null;
    db.prepare('INSERT INTO events (type,user_session,url,referer,duration_ms,data) VALUES (?,?,?,?,?,?)')
      .run(type, user_session||null, url||null, referer||null, duration_ms||null, dataStr);
    res.json({ ok:true });
  } catch (e) {
    res.status(500).json({ ok:false, error: e.message });
  }
});

// admin dashboard
app.get('/admin', requireAdmin, (req,res)=>{
  const totals = db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM clicks) AS clicks,
      (SELECT COUNT(*) FROM events WHERE type='pageview') AS views,
      (SELECT ROUND(AVG(duration_ms),0) FROM events WHERE type='time_on_site') AS avg_ms
  `).get();

  const bySlug = db.prepare(`
    SELECT l.slug, l.partner, l.campaign,
           COUNT(c.id) AS clicks,
           COALESCE(l.cr, ?) AS cr,
           COALESCE(l.aov, ?) AS aov,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?), 2) AS est_sales,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?) * COALESCE(l.aov, ?), 2) AS est_revenue
    FROM links l
    LEFT JOIN clicks c ON c.slug = l.slug
    GROUP BY l.slug
    ORDER BY clicks DESC
  `).all(DEFAULT_CR, DEFAULT_AOV, DEFAULT_CR, DEFAULT_CR, DEFAULT_AOV);

  const body = `
    <h1>Admin Dashboard</h1>
    <div class="row">
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
          <thead>
            <tr><th>Slug</th><th>Partner</th><th>Campaign</th><th>Clicks</th><th>CR</th><th>AOV</th><th>Est. Sales</th><th>Est. Revenue</th></tr>
          </thead>
          <tbody>
            ${bySlug.map(r=>`<tr>
              <td><span class="pill">${r.slug}</span></td>
              <td>${r.partner||''}</td>
              <td>${r.campaign||''}</td>
              <td>${r.clicks}</td>
              <td>${(Number(r.cr)*100).toFixed(2)}%</td>
              <td>$${Number(r.aov).toFixed(2)}</td>
              <td>${r.est_sales}</td>
              <td>$${r.est_revenue}</td>
            </tr>`).join('')}
          </tbody>
        </table>
        <div class="footer-row">
          <a class="btn" href="/admin/export/clicks.csv">Clicks CSV</a>
          <a class="btn" href="/admin/export/events.csv">Events CSV</a>
          <a class="btn" href="/admin/export/estimates.csv">Estimates CSV</a>
        </div>
      </div>
    </div>
  `;
  res.send(html('', body));
});

// CSV helpers
function toCSV(rows){
  if (!rows.length) return '';
  const headers = Object.keys(rows[0]);
  const esc = v => (v==null?'':String(v).replace(/"/g,'""'));
  const lines = [headers.join(',')].concat(rows.map(r=>headers.map(h=>`"${esc(r[h])}"`).join(',')));
  return lines.join('\n');
}

app.get('/admin/export/clicks.csv', requireAdmin, (req,res)=>{
  const rows = db.prepare('SELECT * FROM clicks ORDER BY id DESC').all();
  res.setHeader('Content-Type','text/csv');
  res.send(toCSV(rows));
});

app.get('/admin/export/events.csv', requireAdmin, (req,res)=>{
  const rows = db.prepare('SELECT * FROM events ORDER BY id DESC').all();
  res.setHeader('Content-Type','text/csv');
  res.send(toCSV(rows));
});

app.get('/admin/export/estimates.csv', requireAdmin, (req,res)=>{
  const rows = db.prepare(`
    SELECT l.slug, l.partner, l.campaign,
           COUNT(c.id) AS clicks,
           COALESCE(l.cr, ?) AS cr,
           COALESCE(l.aov, ?) AS aov,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?), 2) AS est_sales,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?) * COALESCE(l.aov, ?), 2) AS est_revenue
    FROM links l
    LEFT JOIN clicks c ON c.slug = l.slug
    GROUP BY l.slug
    ORDER BY clicks DESC
  `).all(DEFAULT_CR, DEFAULT_AOV, DEFAULT_CR, DEFAULT_CR, DEFAULT_AOV);
  res.setHeader('Content-Type','text/csv');
  res.send(toCSV(rows));
});

app.get('/health', (req,res)=>res.json({ ok:true, name: SITE_NAME }));

app.listen(PORT, ()=>{
  console.log(`\n${SITE_NAME} running on http://localhost:${PORT}`);
  console.log(`Admin: http://localhost:${PORT}/admin  (password: ${ADMIN_PASSWORD})`);
});