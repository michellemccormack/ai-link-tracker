// server.js
// Link Tracker Pro — full app (create links, redirect logging, admin dashboard, CSV exports)
// Stack: Node.js (Express) + better-sqlite3. ESM module (package.json should have:  "type": "module")

import express from "express";
import Database from "better-sqlite3";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const db = new Database(path.join(__dirname, "tracker.db"));

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// ---------- Constants ----------
const DEFAULT_CR = 0.008;   // 0.8% default if user leaves CR blank
const DEFAULT_AOV = 45;     // $45 default if user leaves AOV blank
const SITE_NAME = "Link Tracker Pro";

// ---------- DB Setup ----------
db.pragma("journal_mode = WAL");

db.prepare(`
CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE,
  target TEXT NOT NULL,
  partner TEXT,
  campaign TEXT,
  cr REAL,
  aov REAL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)` ).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS clicks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT,
  click_id TEXT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  ip_hash TEXT,
  ua TEXT,
  referer TEXT
)` ).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  user_session TEXT,
  url TEXT,
  referer TEXT,
  duration_ms INTEGER,
  data TEXT
)` ).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS pageviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  user_session TEXT,
  url TEXT,
  referer TEXT
)` ).run();

// ---------- Helpers ----------
function ipHash(req) {
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
  const ua = req.headers["user-agent"] || "";
  const salt = new Date().toISOString().slice(0, 10);
  return crypto.createHash("sha256").update(ip + ua + salt).digest("hex").slice(0, 32);
}

function toCSV(rows) {
  if (!rows || rows.length === 0) return "";
  const headers = Object.keys(rows[0]);
  const esc = (v) => (v == null ? "" : String(v).replace(/"/g, '""'));
  return [headers.join(",")]
    .concat(rows.map((r) => headers.map((h) => `"${esc(r[h])}"`).join(",")))
    ).join("\n");
}

// accept 1, 1%, .8%, 0.008, etc — quietly, without UI hints
function parseCR(x) {
  if (x == null || x === "") return DEFAULT_CR;
  const s = String(x).trim();
  if (s.endsWith("%")) {
    const n = parseFloat(s.replace("%", ""));
    if (!isFinite(n)) return DEFAULT_CR;
    return n / 100;
  }
  const n = parseFloat(s);
  if (!isFinite(n)) return DEFAULT_CR;
  // If user typed “1” meaning 1% (0.01), assume 0–1 means already decimal; >1 up to 100 means %.
  if (n > 1) return n / 100;
  return n;
}

// accept $45 or 45
function parseAOV(x) {
  if (x == null || x === "") return DEFAULT_AOV;
  const s = String(x).trim().replace(/^\$/, "");
  const n = parseFloat(s);
  return isFinite(n) ? n : DEFAULT_AOV;
}

function pageHTML(headInner, bodyInner) {
  return `
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${SITE_NAME}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root { --bg:#0b0f17; --fg:#e6edf3; --muted:#98a2b3; --card:#111827; --accent:#635bff; --line:#1f2937; }
  *{box-sizing:border-box}
  body{margin:0;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont;background:var(--bg);color:var(--fg)}
  .container{max-width:1200px;margin:40px auto;padding:0 24px}
  h1{font-size:36px;margin:0 0 22px;font-weight:800}
  h2{font-size:18px;margin:0 0 10px;font-weight:600;color:var(--fg)}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:22px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px}
  label{display:block;margin:12px 0 6px;color:#cbd5e1}
  input{width:100%;background:#0b1220;color:var(--fg);border:1px solid #263041;border-radius:10px;padding:10px}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  table{width:100%;border-collapse:collapse}
  th,td{border-bottom:1px solid var(--line);padding:10px;text-align:left;vertical-align:top}
  th{color:#cbd5e1;font-weight:600}
  .btn{background:var(--accent);border:none;padding:10px 14px;border-radius:10px;font-weight:700;cursor:pointer}
  .pill{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #2b3444;color:#9aa4b2;font-size:12px}
  .muted{color:var(--muted)}
  a.link{color:#7aa2ff;text-decoration:none}
  a.link:hover{text-decoration:underline}
  .spacer{height:8px}
  .exports{display:flex;gap:10px;flex-wrap:wrap}
  .xbtn{background:#23314a;border:1px solid #33435c;color:#d7e3ff;font-weight:700;border-radius:8px;padding:8px 12px;text-decoration:none}
  .xbtn:hover{background:#2a3a55}
</style>
${headInner || ""}
</head>
<body>
  <div class="container">
    ${bodyInner}
  </div>
</body>
</html>`;
}

// ---------- Routes: Home (Create + List) ----------
app.get("/", (req, res) => {
  const links = db.prepare(
    `SELECT slug,target,partner,campaign,cr,aov
     FROM links ORDER BY id DESC LIMIT 50`
  ).all();

  const body = `
    <h1>${SITE_NAME}</h1>

    <div class="row">
      <div class="card">
        <h2>Create a short link</h2>
        <form method="POST" action="/admin/links">
          <label>Target URL</label>
          <input name="target" />

          <div class="grid2">
            <div>
              <label>Partner</label>
              <input name="partner" />
            </div>
            <div>
              <label>Campaign</label>
              <input name="campaign" />
            </div>
          </div>

          <div class="grid2">
            <div>
              <label>Conversion Rate</label>
              <input name="cr" />
            </div>
            <div>
              <label>Average Order Value</label>
              <input name="aov" />
            </div>
          </div>

          <div class="spacer"></div>
          <button class="btn" type="submit">Create link</button>
        </form>
      </div>

      <div class="card">
        <h2>Recent links</h2>
        <table>
          <thead><tr>
            <th>Slug</th><th>Target</th><th>Partner</th><th>Campaign</th><th>CR</th><th>AOV</th>
          </tr></thead>
          <tbody>
            ${links.map(l => `
              <tr>
                <td><a class="link" href="/r/${l.slug}" target="_blank">/r/${l.slug}</a></td>
                <td class="muted" style="max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${l.target}</td>
                <td>${l.partner ?? ""}</td>
                <td>${l.campaign ?? ""}</td>
                <td>${(((l.cr ?? DEFAULT_CR) * 100).toFixed(2)).replace(/\.00$/,'')}%</td>
                <td>$${((l.aov ?? DEFAULT_AOV).toFixed(2)).replace(/\.00$/,'')}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;

  res.send(pageHTML("", body));
});

// ---------- Create Link ----------
app.post("/admin/links", (req, res) => {
  const { target, partner, campaign, cr, aov } = req.body || {};
  if (!target || !String(target).trim()) {
    return res.status(400).send("Target URL is required");
  }

  // slug auto: partner-campaign (lowercased, safe)
  const base = `${(partner || "self").toString().trim()}-${(campaign || Date.now()).toString().trim()}`.toLowerCase();
  const slug = base
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9-_]/g, "")
    .slice(0, 60) || `link-${Date.now()}`;

  const crVal = parseCR(cr);
  const aovVal = parseAOV(aov);

  try {
    db.prepare(
      `INSERT INTO links (slug,target,partner,campaign,cr,aov) VALUES (?,?,?,?,?,?)`
    ).run(slug, String(target).trim(), partner || null, campaign || null, crVal, aovVal);
    res.redirect("/");
  } catch (e) {
    if (/UNIQUE/i.test(String(e))) {
      return res.status(400).send("Slug already exists. Choose a different Partner/Campaign.");
    }
    res.status(500).send("Error creating link.");
  }
});

// ---------- Redirect + Click Log ----------
app.get("/r/:slug", (req, res) => {
  const link = db.prepare(`SELECT * FROM links WHERE slug = ?`).get(req.params.slug);
  if (!link) return res.status(404).send("Not found");

  const clickId = crypto.randomBytes(8).toString("hex");
  db.prepare(`
    INSERT INTO clicks (slug, click_id, ip_hash, ua, referer)
    VALUES (?,?,?,?,?)
  `).run(
    link.slug,
    clickId,
    ipHash(req),
    req.headers["user-agent"] || "",
    req.headers.referer || ""
  );

  // pass click id downstream if the partner ever echoes it in reports
  try {
    const url = new URL(link.target);
    url.searchParams.set("sb_click", clickId);
    return res.redirect(302, url.toString());
  } catch {
    // if target isn't a valid absolute URL, still redirect as-is
    return res.redirect(302, link.target);
  }
});

// ---------- Event ingest (kept for completeness; used by landing if you wire it) ----------
app.post("/api/event", (req, res) => {
  try {
    const { type, user_session, url, referer, duration_ms, data } = req.body || {};
    if (!type) return res.status(400).json({ ok: false, error: "missing type" });
    const dataStr = data ? JSON.stringify(data).slice(0, 2000) : null;
    db.prepare(
      `INSERT INTO events (type,user_session,url,referer,duration_ms,data)
       VALUES (?,?,?,?,?,?)`
    ).run(type, user_session || null, url || null, referer || null, duration_ms || null, dataStr);

    if (type === "pageview") {
      db.prepare(`INSERT INTO pageviews (user_session,url,referer) VALUES (?,?,?)`)
        .run(user_session || null, url || null, referer || null);
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: "event write failed" });
  }
});

// ---------- Admin Dashboard ----------
app.get("/admin", (req, res) => {
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
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?), 2) AS est_sales,
           ROUND(COUNT(c.id) * COALESCE(l.cr, ?) * COALESCE(l.aov, ?), 2) AS est_revenue
    FROM links l
    LEFT JOIN clicks c ON c.slug = l.slug
    GROUP BY l.slug
    ORDER BY clicks DESC, l.id DESC
  `).all(DEFAULT_CR, DEFAULT_AOV, DEFAULT_CR, DEFAULT_CR, DEFAULT_AOV);

  const latestClicks = db.prepare(`
    SELECT slug, click_id, ts, referer FROM clicks ORDER BY id DESC LIMIT 25
  `).all();

  const latestEvents = db.prepare(`
    SELECT type, ts, duration_ms, substr(url,1,80) AS url FROM events ORDER BY id DESC LIMIT 25
  `).all();

  const body = `
    <h1>Admin Dashboard</h1>

    <div class="row">
      <div class="card">
        <h2>Summary</h2>
        <table>
          <tr><td>Total Views</td><td>${totals.views || 0}</td></tr>
          <tr><td>Total Clicks</td><td>${totals.clicks || 0}</td></tr>
          <tr><td>Avg Time on Site</td><td>${totals.avg_ms ? (Math.round(totals.avg_ms/100)/10)+'s' : '—'}</td></tr>
        </table>
      </div>

      <div class="card">
        <h2>Per Link — Estimated Sales & Revenue</h2>
        <table>
          <thead>
            <tr>
              <th>Slug</th><th>Partner</th><th>Campaign</th><th>Clicks</th>
              <th>CR</th><th>AOV</th><th>Sales</th><th>Revenue</th>
            </tr>
          </thead>
          <tbody>
            ${bySlug.map(r => `
              <tr>
                <td><span class="pill">${r.slug}</span></td>
                <td>${r.partner || ""}</td>
                <td>${r.campaign || ""}</td>
                <td>${r.clicks}</td>
                <td>${(Number(r.cr) * 100).toFixed(2)}%</td>
                <td>$${Number(r.aov).toFixed(2).replace(/\.00$/,'')}</td>
                <td>${Number(r.est_sales).toFixed(2).replace(/\.00$/,'')}</td>
                <td>$${Number(r.est_revenue).toFixed(2).replace(/\.00$/,'')}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>

    <div class="spacer"></div>

    <div class="card">
      <h2>Download Spreadsheets</h2>
      <div class="exports">
        <a class="xbtn" href="/admin/export/clicks.csv">Clicks</a>
        <a class="xbtn" href="/admin/export/events.csv">Events</a>
        <a class="xbtn" href="/admin/export/estimates.csv">Estimates</a>
      </div>
    </div>

    <div class="spacer"></div>

    <div class="row">
      <div class="card">
        <h2>Latest Clicks</h2>
        <table>
          <thead><tr><th>Slug</th><th>Click ID</th><th>Time</th><th>Referer</th></tr></thead>
          <tbody>
            ${latestClicks.map(c => `
              <tr>
                <td>${c.slug}</td>
                <td class="muted">${c.click_id}</td>
                <td>${c.ts}</td>
                <td class="muted">${c.referer || "—"}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>

      <div class="card">
        <h2>Latest Events</h2>
        <table>
          <thead><tr><th>Type</th><th>Time</th><th>Duration</th><th>URL</th></tr></thead>
          <tbody>
            ${latestEvents.map(e => `
              <tr>
                <td>${e.type}</td>
                <td>${e.ts}</td>
                <td>${e.duration_ms ? (e.duration_ms+' ms') : '—'}</td>
                <td class="muted">${e.url || ""}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;

  res.send(pageHTML("", body));
});

// ---------- CSV Exports ----------
app.get("/admin/export/clicks.csv", (req, res) => {
  const rows = db.prepare(`SELECT * FROM clicks ORDER BY id DESC`).all();
  res.setHeader("Content-Type", "text/csv");
  res.send(toCSV(rows));
});

app.get("/admin/export/events.csv", (req, res) => {
  const rows = db.prepare(`SELECT * FROM events ORDER BY id DESC`).all();
  res.setHeader("Content-Type", "text/csv");
  res.send(toCSV(rows));
});

app.get("/admin/export/estimates.csv", (req, res) => {
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
    ORDER BY clicks DESC, l.id DESC
  `).all(DEFAULT_CR, DEFAULT_AOV, DEFAULT_CR, DEFAULT_CR, DEFAULT_AOV);
  res.setHeader("Content-Type", "text/csv");
  res.send(toCSV(rows));
});

// ---------- Health ----------
app.get("/health", (_req, res) => res.json({ ok: true, name: SITE_NAME }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ ${SITE_NAME} running on http://localhost:${PORT}`);
});