/**
 * Secret Boston — Tracking & Estimation Agent (Stable Build)
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
const SITE_NAME = process.env.SITE_NAME || 'Secret Boston';

const DEFAULT_CR = Number(process.env.DEFAULT_CR || 0.008);
const DEFAULT_AOV = Number(process.env.DEFAULT_AOV || 45);

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
  return text
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

app.use((req, res, next) => {
  if (!req.cookies.sb_session) res.cookie('sb_session', nanoid(), { httpOnly: false });
  next();
});

// ---------- Create link ----------
app.post('/admin/links', (req, res) => {
  const { target, partner, campaign, cr, aov } = req.body;

  let targetUrl = target.trim();
  if (targetUrl && !/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

  const baseSlug = slugify(`${partner || 'link'}-${campaign || ''}`);
  const slug = baseSlug || `link-${nanoid()}`;
  const finalSlug = slug;

  const parsedCR = parseConversionRate(cr);
  const parsedAOV = parseMoney(aov);

  try {
    db.prepare('INSERT INTO links (slug, target, partner, campaign, cr, aov) VALUES (?,?,?,?,?,?)')
      .run(finalSlug, targetUrl, partner, campaign, parsedCR, parsedAOV);
    res.redirect('/');
  } catch (e) {
    res.status(400).send('Error: ' + e.message);
  }
});

// ---------- Home ----------
app.get('/', (req, res) => {
  const links = db.prepare('SELECT * FROM links ORDER BY id DESC LIMIT 20').all();

  const body = `
  <div style="font-family:Inter,sans-serif;color:#fff;background:#0b0f17;padding:20px">
    <h1>Secret Boston — Tracking & Estimation Agent <span style="font-size:12px;color:#777">MVP</span></h1>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px">
      <form action="/admin/links" method="POST" style="background:#111827;padding:20px;border-radius:10px">
        <h2>Create a short link</h2>
        <label>Target URL</label><br>
        <input name="target" required style="width:100%;margin-bottom:10px"><br>
        <div style="display:flex;gap:10px">
          <div><label>Partner</label><br><input name="partner" style="width:100%"></div>
          <div><label>Campaign</label><br><input name="campaign" style="width:100%"></div>
        </div>
        <div style="display:flex;gap:10px;margin-top:10px">
          <div><label>Conversion Rate</label><br><input name="cr" placeholder="1%" style="width:100%"></div>
          <div><label>Average Order Value</label><br><input name="aov" placeholder="$45" style="width:100%"></div>
        </div>
        <button type="submit" style="margin-top:15px;background:#4f46e5;color:white;border:none;padding:8px 14px;border-radius:8px;cursor:pointer">Create link</button>
      </form>

      <div style="background:#111827;padding:20px;border-radius:10px">
        <h2>Recent links</h2>
        <table style="width:100%;border-collapse:collapse">
          <tr><th>Slug</th><th>Target</th><th>Partner</th><th>Campaign</th><th>CR</th><th>AOV</th></tr>
          ${links
            .map(
              (l) => `
            <tr>
              <td><a href="/r/${l.slug}" target="_blank" style="color:#38bdf8">/r/${l.slug}</a></td>
              <td>${l.target}</td>
              <td>${l.partner || ''}</td>
              <td>${l.campaign || ''}</td>
              <td>${((l.cr ?? DEFAULT_CR) * 100).toFixed(2)}%</td>
              <td>$${l.aov ?? DEFAULT_AOV}</td>
            </tr>`
            )
            .join('')}
        </table>
      </div>
    </div>
  </div>`;
  res.send(body);
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
  const totals = db
    .prepare(
      `SELECT
       (SELECT COUNT(*) FROM clicks) AS clicks,
       (SELECT COUNT(*) FROM pageviews) AS views,
       (SELECT ROUND(AVG(duration_ms),0) FROM events WHERE type='time_on_site') AS avg_ms`
    )
    .get();

  const bySlug = db
    .prepare(
      `SELECT l.slug, l.partner, l.campaign,
              COUNT(c.id) AS clicks,
              COALESCE(l.cr, ?) AS cr,
              COALESCE(l.aov, ?) AS aov,
              ROUND(COUNT(c.id) * COALESCE(l.cr, ?), 2) AS est_sales,
              ROUND(COUNT(c.id) * COALESCE(l.cr, ?) * COALESCE(l.aov, ?), 2) AS est_rev
       FROM links l
       LEFT JOIN clicks c ON c.slug = l.slug
       GROUP BY l.slug
       ORDER BY clicks DESC`
    )
    .all(DEFAULT_CR, DEFAULT_AOV, DEFAULT_CR, DEFAULT_CR, DEFAULT_AOV);

  const html = `
  <div style="font-family:Inter,sans-serif;color:#fff;background:#0b0f17;padding:20px">
    <h1>Admin Dashboard</h1>
    <div style="display:grid;grid-template-columns:1fr 2fr;gap:20px">
      <div style="background:#111827;padding:20px;border-radius:10px">
        <h2>Summary</h2>
        <p>Total Views: ${totals.views || 0}</p>
        <p>Total Clicks: ${totals.clicks || 0}</p>
        <p>Avg Time: ${totals.avg_ms ? totals.avg_ms / 1000 + 's' : '—'}</p>
      </div>
      <div style="background:#111827;padding:20px;border-radius:10px">
        <h2>Per Link — Estimated Sales & Revenue</h2>
        <table style="width:100%;border-collapse:collapse">
          <tr><th>Slug</th><th>Partner</th><th>Campaign</th><th>Clicks</th><th>CR</th><th>AOV</th><th>Sales</th><th>Revenue</th></tr>
          ${bySlug
            .map(
              (r) => `
              <tr>
                <td><code>${r.slug}</code></td>
                <td>${r.partner || ''}</td>
                <td>${r.campaign || ''}</td>
                <td>${r.clicks}</td>
                <td>${(r.cr * 100).toFixed(2)}%</td>
                <td>$${r.aov.toFixed(2)}</td>
                <td>${r.est_sales}</td>
                <td>$${r.est_rev}</td>
              </tr>`
            )
            .join('')}
        </table>
      </div>
    </div>
    <div style="background:#111827;margin-top:30px;padding:20px;border-radius:10px;text-align:center">
      <h2>📊 Download Spreadsheets</h2>
      <a href="/admin/export/clicks.csv" style="background:#4f46e5;color:white;padding:8px 12px;border-radius:8px;margin-right:8px">Clicks</a>
      <a href="/admin/export/events.csv" style="background:#4f46e5;color:white;padding:8px 12px;border-radius:8px;margin-right:8px">Events</a>
      <a href="/admin/export/estimates.csv" style="background:#4f46e5;color:white;padding:8px 12px;border-radius:8px">Estimates</a>
    </div>
  </div>`;
  res.send(html);
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
  const rows = db
    .prepare(
      `SELECT l.slug, l.partner, l.campaign,
              COUNT(c.id) AS clicks,
              COALESCE(l.cr, ?) AS cr,
              COALESCE(l.aov, ?) AS aov,
              ROUND(COUNT(c.id) * COALESCE(l.cr, ?), 2) AS est_sales,
              ROUND(COUNT(c.id) * COALESCE(l.cr, ?) * COALESCE(l.aov, ?), 2) AS est_rev
       FROM links l
       LEFT JOIN clicks c ON c.slug = l.slug
       GROUP BY l.slug
       ORDER BY clicks DESC`
    )
    .all(DEFAULT_CR, DEFAULT_AOV, DEFAULT_CR, DEFAULT_CR, DEFAULT_AOV);
  res.setHeader('Content-Type', 'text/csv');
  res.send(toCSV(rows));
});

// ---------- Health ----------
app.get('/health', (req, res) => res.json({ ok: true }));

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});