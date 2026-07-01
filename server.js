const express = require("express");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = "phantom_weak_key";

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

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
    if (decoded.role !== "admin")
      return res.status(403).json({ error: "Access denied.", message: "Insufficient privileges." });
    return res.json({ success: true, user: decoded.user, role: decoded.role });
  } catch {
    return res.status(401).json({ error: "Invalid token.", message: "Token verification failed." });
  }
});

// IDOR — /api/user?id=X — no authorization check (intentional vulnerability)
const USERS = {
  1:  { id:1,  username:"john.doe",    email:"john.doe@phantomcorp.io",   role:"user",         department:"Engineering" },
  2:  { id:2,  username:"sarah.malik", email:"sarah.malik@phantomcorp.io",role:"user",         department:"Design" },
  3:  { id:3,  username:"dev.test01",  email:"devtest01@phantomcorp.io",  role:"user",         department:"QA" },
  4:  { id:4,  username:"james.r",     email:"james.r@phantomcorp.io",    role:"user",         department:"Operations" },
  5:  { id:5,  username:"nina.patel",  email:"nina.patel@phantomcorp.io", role:"user",         department:"Marketing" },
  6:  { id:6,  username:"ghost.user",  email:"ghost@phantomcorp.io",      role:"user",         department:"Unknown" },
  7:  { id:7,  username:"alex.kim",    email:"alex.kim@phantomcorp.io",   role:"user",         department:"Finance" },
  8:  { id:8,  username:"backup.acc",  email:"backup@phantomcorp.io",     role:"user",         department:"IT" },
  9:  { id:9,  username:"r00t_admin",  email:"root@phantomcorp.io",       role:"SYSTEM_ADMIN", department:"CLASSIFIED",
        clearance:"LEVEL-5", flag_part_2:"r00t_m@s4er}",
        note:"Combine with Part 1: FLAG{ph#n40m_ + r00t_m@s4er}" },
  10: { id:10, username:"audit.log",   email:"audit@phantomcorp.io",      role:"user",         department:"Compliance" },
};

app.get("/api/user", (req, res) => {
  const id = parseInt(req.query.id, 10);
  if (!req.query.id || isNaN(id) || id < 1 || id > 10)
    return res.status(400).json({ error: "Invalid ID. Provide a value between 1 and 10." });
  return res.json(USERS[id] || { error: "User not found." });
});

// Health check
app.get("/api/healthz", (req, res) => res.json({ status: "ok" }));

// ─── SPA FALLBACK ────────────────────────────────────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => console.log(`[*] Phantom Root running on port ${PORT}`));
