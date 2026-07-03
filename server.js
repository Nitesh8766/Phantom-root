const express = require("express");
const jwt = require("jsonwebtoken");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = "phantom_weak_key";
const PUBLIC_DIR = path.join(__dirname, "public");
const INDEX_FILE = path.join(PUBLIC_DIR, "index.html");
const SESSION_TTL_MS = 1000 * 60 * 60;
const SESSIONS = new Map();

const VERIFY_PATH = "/internal/services/runtime/authentication/legacy/builds/v2.4.18/container-node-04/secure-token-validation/runtime/session/verify";

function parseCookies(req) {
  const raw = req.headers.cookie || "";
  return raw.split(";").reduce((memo, entry) => {
    const [key, ...rest] = entry.trim().split("=");
    if (key) memo[key] = decodeURIComponent(rest.join("="));
    return memo;
  }, {});
}

function getSession(req) {
  const sessionId = parseCookies(req).phantom_session_id;
  if (!sessionId) return null;
  const session = SESSIONS.get(sessionId);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    SESSIONS.delete(sessionId);
    return null;
  }
  return session;
}

function setSession(res, sessionData) {
  const sessionId = crypto.randomBytes(16).toString("hex");
  SESSIONS.set(sessionId, {
    ...sessionData,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  res.cookie("phantom_session_id", sessionId, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_TTL_MS,
  });
  return sessionId;
}

function clearSession(res) {
  res.clearCookie("phantom_session_id", { path: "/" });
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.admin) {
    if (req.accepts("html")) {
      return res.status(403).send(`<!DOCTYPE html><html><head><meta charset="utf-8"/><title>Forbidden</title></head><body style="font-family:monospace;background:#000;color:#cc4444;padding:40px;">Forbidden. Authenticate through the legacy verification endpoint first.</body></html>`);
    }
    return res.status(403).json({ error: "Forbidden", message: "Admin session required." });
  }
  next();
}

function renderVerifyPage(error = null, fakeToken = null) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Phantom Root // Legacy Token Verification</title>
<style>
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:#040404; color:#cc4444; font-family:'Courier New', monospace; overflow:hidden; }
  body::before { content:""; position:fixed; inset:0; background:repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,68,68,0.04) 2px, rgba(255,68,68,0.04) 4px); pointer-events:none; }
  .panel { width:min(620px, calc(100vw - 32px)); padding:28px; border:1px solid rgba(204,68,68,0.35); background:rgba(0,0,0,0.95); box-shadow:0 0 40px rgba(204,68,68,0.15); }
  .path { font-size:10px; color:#6a0000; margin-bottom:16px; word-break:break-all; }
  h1 { font-size:22px; margin:0 0 6px; letter-spacing:0.2em; text-transform:uppercase; }
  .sub { font-size:10px; color:#4a0000; margin-bottom:18px; letter-spacing:0.22em; text-transform:uppercase; }
  label { display:block; font-size:10px; letter-spacing:0.18em; text-transform:uppercase; color:#7a0000; margin-bottom:8px; }
  textarea { width:100%; min-height:120px; padding:12px; background:#080808; border:1px solid rgba(204,68,68,0.25); color:#f7f7f7; font-family:'Courier New', monospace; resize:vertical; }
  textarea:focus { outline:none; border-color:#cc0000; box-shadow:0 0 14px rgba(204,68,68,0.18); }
  button { margin-top:16px; width:100%; padding:12px; border:1px solid #cc0000; background:#aa0000; color:#fff; font-family:'Courier New', monospace; letter-spacing:0.2em; text-transform:uppercase; cursor:pointer; }
  button:hover { background:#cc0000; }
  .error { margin-top:16px; padding:12px; border:1px solid rgba(255,68,68,0.25); background:rgba(255,68,68,0.08); color:#ff8c8c; font-size:11px; line-height:1.5; }
  .token { margin-top:16px; padding:12px; border:1px solid rgba(0,255,0,0.18); background:rgba(0,64,0,0.12); color:#9cff9c; font-size:11px; word-break:break-all; white-space:pre-wrap; }
</style>
</head>
<body>
  <div class="panel">
    <div class="path">${VERIFY_PATH}</div>
    <h1>Legacy Token Verification</h1>
    <div class="sub">Phantom Root Auth Runtime &mdash; Build v2.4.18</div>
    <form method="post" autocomplete="off">
      <label for="token">Session Token (JWT)</label>
      <textarea id="token" name="token" placeholder="Paste your JWT here..."></textarea>
      ${error ? `<div class="error">${error}</div>` : ""}
      ${fakeToken ? `<div class="token">${fakeToken}</div>` : ""}
      <button type="submit">Verify Token</button>
    </form>
  </div>
</body>
</html>`;
}

function renderAdminPage(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Phantom Root // ${title}</title>
<link rel="stylesheet" href="/admin.css"/>
</head>
<body>
<header class="admin-header">
  <div>
    <div class="admin-eyebrow">PhantomCorp Systems</div>
    <h1>Phantom Root</h1>
    <div class="admin-sub">${title}</div>
  </div>
  <div class="admin-user">
    <div>USER: <span class="admin-user__value">guest</span></div>
    <div>ROLE: <span class="admin-user__value admin-user__value--accent">ADMIN</span></div>
    <div class="admin-user__state">● authenticated</div>
  </div>
</header>
<nav class="admin-nav">
  <a href="/admin">Dashboard</a>
  <a href="/admin/users">Users</a>
  <a href="/admin/logs">Logs</a>
  <a href="/admin/archive">Archive</a>
  <a href="/admin/servers">Servers</a>
  <a href="/admin/monitoring">Monitoring</a>
  <a href="/admin/api-explorer">API Explorer</a>
</nav>
<main class="admin-main">${body}</main>
</body>
</html>`;
}

function renderDebugPage(data, active) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Phantom Root // Internal Debug</title>
<link rel="stylesheet" href="/admin.css"/>
<style>
  .debug-grid { display:grid; gap:16px; grid-template-columns:repeat(auto-fit, minmax(240px, 1fr)); }
  .debug-box { border:1px solid rgba(204,68,68,0.24); background:rgba(0,0,0,0.85); padding:18px; }
  .debug-box strong { color:#ff6666; display:block; margin-bottom:8px; }
</style>
</head>
<body>
<header class="admin-header">
  <div>
    <div class="admin-eyebrow">Internal Runtime</div>
    <h1>Phantom Root Debug</h1>
    <div class="admin-sub">${active ? "Debug interface active" : "Restricted access"}</div>
  </div>
</header>
<main class="admin-main">
  <div class="debug-grid">
    <div class="debug-box">
      <strong>Status</strong>
      <div>${data.status}</div>
    </div>
    <div class="debug-box">
      <strong>Node</strong>
      <div>${data.node}</div>
    </div>
    <div class="debug-box">
      <strong>Build</strong>
      <div>${data.build}</div>
    </div>
    <div class="debug-box">
      <strong>Runtime</strong>
      <div>${data.runtime}</div>
    </div>
  </div>
  <div class="debug-box" style="margin-top:16px;">
    <strong>Flag Material</strong>
    <div>Part 1: ${data.flag_part_1}</div>
    <div>Part 2: ${data.flag_part_2}</div>
    <div>${data.note}</div>
  </div>
  ${active ? `<div class="debug-box" style="margin-top:16px;"><strong>Warning</strong><div>${data.warning}</div></div>` : ""}
</main>
</body>
</html>`;
}

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
  req.session = getSession(req);
  next();
});
app.use(express.static(PUBLIC_DIR));

// ─── API ROUTES ─────────────────────────────────────────────────────────────

// Login — always rejects (SQL injection is sanitized, nothing works)
app.post("/api/auth/login", (req, res) => {
  const { username = "", password = "" } = req.body;
  const sqlPatterns = [/'\s*or\s*1\s*=\s*1/i, /--/, /union\s+select/i, /'\s*;\s*/];
  const isSqli = sqlPatterns.some((p) => p.test(username) || p.test(password));
  if (isSqli) {
    return res.status(400).json({ error: "Input validation failed.", message: "Request logged." });
  }
  return res.status(401).json({ error: "Authentication failed.", message: "Invalid credentials." });
});

// JWT Verify — checks for admin role
app.post("/api/auth/verify", (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: "No token provided." });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== "admin") {
      return res.status(403).json({ error: "Access denied.", message: "Insufficient privileges." });
    }
    setSession(res, { admin: true, user: decoded.user, role: decoded.role });
    return res.json({ success: true, user: decoded.user, role: decoded.role });
  } catch {
    return res.status(401).json({ error: "Invalid token.", message: "Token verification failed." });
  }
});

// IDOR — /api/user?id=X — no authorization check (intentional vulnerability)
const USERS = {
  1: { id: 1, username: "Administrator", role: "admin", email: "admin@phantomroot.internal", department: "Infrastructure Security", last_login: "2024-03-15T04:22:11Z", status: "active" },
  2: { id: 2, username: "guest", role: "user", email: "guest@phantomroot.internal", department: "External Access", last_login: "2024-03-15T09:44:02Z", status: "active" },
  3: { id: 3, username: "j.reeves", role: "user", email: "j.reeves@phantomroot.internal", department: "DevOps", last_login: "2024-03-14T18:03:45Z", status: "suspended" },
  4: { id: 4, username: "m.chen", role: "user", email: "m.chen@phantomroot.internal", department: "Security Operations", last_login: "2024-03-13T11:55:30Z", status: "active" },
  5: { id: 5, username: "nina.patel", role: "user", email: "nina.patel@phantomcorp.io", department: "Marketing" },
  6: { id: 6, username: "ghost.user", role: "user", email: "ghost@phantomcorp.io", department: "Unknown" },
  7: { id: 7, username: "alex.kim", role: "user", email: "alex.kim@phantomcorp.io", department: "Finance" },
  8: { id: 8, username: "backup.acc", role: "user", email: "backup@phantomcorp.io", department: "IT" },
  9: { id: 9, username: "r00t_admin", role: "SYSTEM_ADMIN", email: "root@phantomcorp.io", department: "CLASSIFIED", clearance: "LEVEL-5", flag_part_2: "r00t_m@s4er}", note: "Combine with Part 1: FLAG{ph#n40m_ + r00t_m@s4er}" },
  10: { id: 10, username: "audit.log", role: "user", email: "audit@phantomcorp.io", department: "Compliance" }
};

function renderUserPage(user, id, message = null) {
  const rows = Object.entries(user || {}).map(([key, value]) => {
    return `<div class="user-row"><span class="user-key">${key}</span><span class="user-val">${value}</span></div>`;
  }).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Phantom Root // User ${id}</title>
<style>
  body{margin:0;background:#000;color:#cc4444;font-family:'Courier New',monospace;min-height:100vh;overflow:hidden;}
  *{box-sizing:border-box;}
  .page-bg{position:fixed;inset:0;background:#060606;}
  .scanlines{position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(204,68,68,0.05) 2px,rgba(204,68,68,0.05) 4px);pointer-events:none;}
  .card{position:relative;z-index:2;margin:40px auto;max-width:760px;padding:28px 32px;background:rgba(0,0,0,0.9);border:1px solid rgba(204,68,68,0.25);box-shadow:0 0 40px rgba(204,68,68,0.12);}
  .title-row{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:20px;}
  .title-row h1{font-size:24px;margin:0;letter-spacing:0.18em;text-transform:uppercase;color:#ff6666;}
  .subtitle{font-size:11px;color:#7a0000;letter-spacing:0.22em;text-transform:uppercase;}
  .panel{border:1px solid rgba(204,68,68,0.16);background:rgba(255,255,255,0.02);padding:18px;margin-bottom:18px;}
  .panel h2{margin:0 0 12px;font-size:12px;color:#ff8c8c;text-transform:uppercase;letter-spacing:0.18em;}
  .user-row{display:flex;justify-content:space-between;gap:16px;padding:10px 0;border-bottom:1px solid rgba(204,68,68,0.08);}
  .user-row:last-child{border-bottom:none;}
  .user-key{color:#a63a3a;text-transform:uppercase;font-size:11px;letter-spacing:0.13em;}
  .user-val{color:#f7f7f7;text-align:right;word-break:break-word;font-size:12px;}
  .hint{font-size:11px;color:#7a0000;letter-spacing:0.16em;text-transform:uppercase;margin-top:16px;}
  .note{margin-top:16px;padding:14px;background:rgba(0,0,0,0.25);border:1px solid rgba(255,85,85,0.12);color:#ff8c8c;font-size:12px;line-height:1.5;}
  .footer{margin-top:18px;font-size:10px;color:#5a0000;text-align:center;letter-spacing:0.16em;}
  .error{padding:14px;border:1px solid rgba(255,85,85,0.22);background:rgba(255,85,85,0.08);color:#ff9999;margin-top:16px;}
  canvas{position:fixed;inset:0;z-index:0;}
</style>
</head>
<body>
<div class="page-bg"></div>
<canvas id="matrix"></canvas>
<div class="scanlines"></div>
<div class="card">
  <div class="title-row">
    <div>
      <h1>PHANTOM ROOT USER</h1>
      <div class="subtitle">IDOR RECON // USER RECORD</div>
    </div>
    <div class="subtitle">USER ID: ${id}</div>
  </div>
  <div class="panel">
    <h2>USER DATA</h2>
    ${user ? rows : '<div class="error">User id not found.</div>'}
  </div>
  ${message ? `<div class="error">${message}</div>` : ""}
  ${user && user.note ? `<div class="note">${user.note}</div>` : ""}
  <div class="hint">Tip: This page reveals the hidden user data across the CTF path.</div>
  <div class="footer">Phantom Corp — Internal Access Portal</div>
</div>
<script>
const canvas=document.getElementById('matrix');const ctx=canvas.getContext('2d');function resize(){canvas.width=window.innerWidth;canvas.height=window.innerHeight;}resize();window.addEventListener('resize',resize);const chars='01アイウエオカキクケコPHANTOMROOT!@#$%^&*';const drops=Array(Math.floor(window.innerWidth/18)).fill(1);setInterval(()=>{ctx.fillStyle='rgba(0,0,0,0.08)';ctx.fillRect(0,0,canvas.width,canvas.height);ctx.font='14px monospace';drops.forEach((y,i)=>{ctx.fillStyle=Math.random()>.88?'#ff4444':'#7a0000';ctx.fillText(chars[Math.floor(Math.random()*chars.length)],i*18,y*18);drops[i]=y*18>canvas.height&&Math.random()>.975?0:y+1;});},45);
</script>
</body>
</html>`;
}

app.get("/api/user", (req, res) => {
  const id = parseInt(req.query.id, 10);
  if (!req.query.id || Number.isNaN(id) || id < 1 || id > 10) {
    if (req.accepts("html")) {
      return res.status(400).send(renderUserPage(null, req.query.id || "unknown", "Invalid ID. Provide a value between 1 and 10."));
    }
    return res.status(400).json({ error: "Invalid ID. Provide a value between 1 and 10." });
  }

  const user = USERS[id];
  if (!user) {
    if (req.accepts("html")) {
      return res.status(404).send(renderUserPage(null, id, "User not found."));
    }
    return res.status(404).json({ error: "User not found." });
  }

  if (req.accepts("html")) {
    return res.send(renderUserPage(user, id));
  }
  return res.json(user);
});

app.get("/api/users", (req, res) => {
  const users = Object.values(USERS).map(({ id, username, status }) => ({ id, username, status }));
  return res.json({ count: users.length, users });
});

// Health check
app.get("/api/healthz", (req, res) => res.json({ status: "ok" }));

// Hidden JWT verification endpoint
app.get(VERIFY_PATH, (req, res) => {
  res.send(renderVerifyPage());
});

app.post(VERIFY_PATH, (req, res) => {
  const token = String(req.body?.token || "").trim();
  if (!token) {
    const fakeToken = jwt.sign({ user: "guest", role: "admin" }, JWT_SECRET, { expiresIn: "1h" });
    return res.status(200).send(renderVerifyPage("MISSING_TOKEN: No token provided. A fake JWT has been generated for testing purposes.", fakeToken));
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.user === "guest" && payload.role === "admin") {
      setSession(res, { admin: true, user: payload.user, role: payload.role });
      return res.redirect("/admin");
    }
    return res.status(200).send(renderVerifyPage(`TOKEN_PRIVILEGE_DENIED: Signature valid but role "${payload.role}" lacks admin privileges.`));
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(200).send(renderVerifyPage("TOKEN_EXPIRED: Session token has expired."));
    }
    if (error.name === "JsonWebTokenError") {
      return res.status(200).send(renderVerifyPage("SIGNATURE_INVALID: Token signature verification failed."));
    }
    return res.status(200).send(renderVerifyPage(`AUTH_FAILURE: ${error.message}`));
  }
});

// ─── ADMIN PAGES ───────────────────────────────────────────────────────────
app.get(["/admin", "/admin/"], requireAdmin, (req, res) => {
  res.send(renderAdminPage("Security Operations Center", `
    <div class="panel"><h2>Privileged Access Grant</h2><p>Welcome, ${req.session.user}. Authentication through the legacy runtime succeeded.</p><div class="flag-box"><div class="flag-label">Part 1 of 2</div><div class="flag-value">FLAG{ph#n40m_</div><div class="flag-note">The second half is hidden behind the user enumeration path.</div></div></div>
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-label">Active Sessions</div><div class="stat-value">247</div></div>
      <div class="stat-card"><div class="stat-label">Threat Level</div><div class="stat-value stat-value--warn">CRITICAL</div></div>
      <div class="stat-card"><div class="stat-label">System Status</div><div class="stat-value stat-value--muted">COMPROMISED</div></div>
    </div>`));
});

app.get(["/admin/users", "/admin/users/"], requireAdmin, (req, res) => {
  res.send(renderAdminPage("Users", `<div class="panel"><h2>Identity Inventory</h2><table class="data-table"><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Department</th></tr></thead><tbody>${Object.values(USERS).slice(0, 6).map((user) => `<tr><td>${user.username}</td><td>${user.role}</td><td>${user.status || "active"}</td><td>${user.department || "—"}</td></tr>`).join("")}</tbody></table></div>`));
});

app.get(["/admin/logs", "/admin/logs/"], requireAdmin, (req, res) => {
  res.send(renderAdminPage("Logs", `<div class="panel"><h2>Access Log</h2><ul class="log-list"><li>09:44:02 :: guest :: AUTH_OK</li><li>09:18:55 :: m.chen :: AUTH_OK</li><li>08:52:03 :: unknown :: AUTH_FAIL</li><li>08:22:11 :: j.reeves :: SUSPENDED</li></ul></div>`));
});

app.get(["/admin/archive", "/admin/archive/"], requireAdmin, (req, res) => {
  res.send(renderAdminPage("Archive", `<div class="panel"><h2>Restore Archive</h2><p>/dev-backup/backup.zip is available for inspection.</p><a class="inline-link" href="/dev-backup/backup.zip">Download backup archive</a></div>`));
});

app.get(["/admin/servers", "/admin/servers/"], requireAdmin, (req, res) => {
  res.send(renderAdminPage("Servers", `<div class="panel"><h2>Infrastructure Nodes</h2><table class="data-table"><thead><tr><th>Hostname</th><th>Role</th><th>Status</th><th>Uptime</th></tr></thead><tbody><tr><td>gl-prod-01</td><td>Primary Auth</td><td>ONLINE</td><td>47d 14h</td></tr><tr><td>gl-legacy-04</td><td>Legacy Runtime</td><td>DEGRADED</td><td>14d 07h</td></tr><tr><td>gl-log-01</td><td>Log Aggregator</td><td>ONLINE</td><td>31d 22h</td></tr></tbody></table></div>`));
});

app.get(["/admin/monitoring", "/admin/monitoring/"], requireAdmin, (req, res) => {
  res.send(renderAdminPage("Monitoring", `<div class="panel"><h2>Runtime Sensors</h2><div class="monitor-grid"><div class="metric">Cache <span>DEGRADED</span></div><div class="metric">DB <span>CONNECTED</span></div><div class="metric">Auth <span>BYPASSED</span></div></div></div>`));
});

app.get(["/admin/api-explorer", "/admin/api-explorer/"], requireAdmin, (req, res) => {
  res.send(renderAdminPage("API Explorer", `<div class="panel"><h2>Endpoint Catalog</h2><ul class="log-list"><li>GET /api/user?id=1</li><li>GET /api/users</li><li>POST /api/auth/verify</li><li>GET /internal/debug?mode=dev</li></ul></div>`));
});

// ─── USER PAGES ────────────────────────────────────────────────────────────
app.get(["/", "/index.html"], (req, res) => {
  res.sendFile(INDEX_FILE);
});

app.get("/login", (req, res) => {
  res.sendFile(INDEX_FILE);
});

app.get("/dev-backup", (req, res) => {
  res.status(403).send("Access denied.");
});

app.get("/dev-backup/backup.zip", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "dev-backup", "backup.zip"), { headers: { "Content-Disposition": "attachment; filename=backup.zip" } });
});

app.get("/user", (req, res) => {
  res.sendFile(INDEX_FILE);
});

app.get("/user/:id", (req, res) => {
  res.sendFile(INDEX_FILE);
});

app.get("/internal/debug", (req, res) => {
  const mode = req.query.mode;
  if (mode !== "dev") {
    if (req.accepts("html")) {
      return res.redirect(302, "/");
    }
    return res.status(403).json({ status: "RESTRICTED", message: "Access denied.", node: "container-node-04", build: "v2.4.18" });
  }

  const data = {
    status: "DEBUG_ACTIVE",
    node: "container-node-04",
    build: "v2.4.18",
    runtime: "legacy-node-runtime",
    flag_part_1: "FLAG{ph#n40m_",
    flag_part_2: "r00t_m@s4er}",
    note: "Concatenate flag_part_1 + flag_part_2 to obtain the flag.",
    warning: "This interface is scheduled for decommission. Do not use in production.",
  };

  if (req.accepts("html")) {
    return res.send(renderDebugPage(data, true));
  }
  return res.json(data);
});

app.get(["/internal", "/internal/", "/logs", "/logs/", "/archive", "/archive/"], (req, res) => {
  res.status(403).send("Forbidden.");
});

// ─── SPA FALLBACK ────────────────────────────────────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(INDEX_FILE);
});

app.listen(PORT, () => console.log(`[*] Phantom Root running on port ${PORT}`));
