const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { OAuth2Client, GoogleAuth } = require("google-auth-library");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

const {
  GOOGLE_CLIENT_ID,
  SESSION_JWT_SECRET,
  BACKEND_BASE_URL,
  COOKIE_NAME = "mmg_renewal_generator_session",
} = process.env;

function mustEnv(name) {
  if (!process.env[name]) throw new Error(`Missing required env var: ${name}`);
}
["GOOGLE_CLIENT_ID", "SESSION_JWT_SECRET", "AUTHORISED_EMAILS_JSON", "BACKEND_BASE_URL"].forEach(mustEnv);

const oauthClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const auth = new GoogleAuth();

function getAuthorisedEmails() {
  try {
    const raw = process.env.AUTHORISED_EMAILS_JSON || "[]";
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr.map((e) => String(e).toLowerCase().trim()).filter(Boolean);
  } catch {
    return [];
  }
}

function isAuthorised(email) {
  return getAuthorisedEmails().includes(String(email || "").toLowerCase().trim());
}

function setSessionCookie(res, payload) {
  const token = jwt.sign(payload, SESSION_JWT_SECRET, { expiresIn: "12h" });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 12 * 60 * 60 * 1000,
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
  });
}

function readSession(req) {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) return null;
  try {
    return jwt.verify(token, SESSION_JWT_SECRET);
  } catch {
    return null;
  }
}

function acceptsHtml(req) {
  return String(req.headers.accept || "").includes("text/html");
}

function safeReturnTo(raw) {
  const s = String(raw || "/renewals");
  return s.startsWith("/") && !s.startsWith("//") ? s : "/renewals";
}

function requireAuth(req, res, next) {
  const session = readSession(req);
  if (!session?.email) {
    if (acceptsHtml(req)) return res.redirect(`/login?returnTo=${encodeURIComponent(req.originalUrl)}`);
    return res.status(401).json({ error: "Not authenticated" });
  }
  if (!isAuthorised(session.email)) {
    if (acceptsHtml(req)) return res.redirect(`/login?returnTo=${encodeURIComponent(req.originalUrl)}`);
    return res.status(403).json({ error: "Not authorised" });
  }
  req.user = session;
  next();
}

app.get("/health", (req, res) => res.json({ status: "ok" }));

app.get("/public-config.json", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json({ googleClientId: GOOGLE_CLIENT_ID });
});

app.get("/config.json", requireAuth, (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json({ backendBaseUrl: BACKEND_BASE_URL });
});

app.post("/auth/login", async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const credential = req.body?.credential;
    if (!credential) return res.status(400).json({ error: "Missing credential" });

    const ticket = await oauthClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = payload?.email;
    const emailVerified = payload?.email_verified === true;

    if (!email || !emailVerified) return res.status(403).json({ error: "Invalid Google identity" });
    if (!isAuthorised(email)) return res.status(403).json({ error: "Not authorised" });

    setSessionCookie(res, { email, name: payload?.name || null, picture: payload?.picture || null });
    return res.json({ ok: true, email });
  } catch (err) {
    console.error("auth/login failed:", err?.message || err);
    return res.status(500).json({ error: "Login failed" });
  }
});

app.get("/auth/me", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const session = readSession(req);
  if (!session?.email || !isAuthorised(session.email)) return res.json({ authenticated: false });
  return res.json({ authenticated: true, email: session.email, name: session.name || null });
});

app.post("/auth/logout", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.use("/api", requireAuth, async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const targetPath = req.originalUrl.replace(/^\/api/, "");
    const target = new URL(`${BACKEND_BASE_URL}${targetPath}`);
    const backendOrigin = new URL(BACKEND_BASE_URL).origin;
    const client = await auth.getIdTokenClient(backendOrigin);
    const idHeaders = await client.getRequestHeaders();

    const method = String(req.method).toUpperCase();
    const hasBody = !["GET", "HEAD"].includes(method);
    const body = hasBody ? { ...(req.body || {}) } : undefined;
    if (body && req.user?.email && body.requested_by === undefined) body.requested_by = req.user.email;

    const upstream = await fetch(target.toString(), {
      method,
      headers: {
        ...idHeaders,
        ...(hasBody ? { "Content-Type": "application/json" } : {}),
      },
      body: hasBody ? JSON.stringify(body) : undefined,
    });

    const ct = upstream.headers.get("content-type");
    if (ct) res.setHeader("content-type", ct);
    const text = await upstream.text();
    res.status(upstream.status).send(text);
  } catch (err) {
    console.error("Proxy error:", err?.message || err);
    res.status(500).json({ error: "Proxy failure" });
  }
});

const publicDir = path.join(__dirname, "public");

app.get("/login", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Return-To", safeReturnTo(req.query?.returnTo));
  res.sendFile(path.join(publicDir, "login.html"));
});

app.get(["/", "/renewals"], requireAuth, (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(publicDir, "renewals.html"));
});

app.get("/suppressions", requireAuth, (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(publicDir, "suppressions.html"));
});

app.use(express.static(publicDir, { index: false }));

const port = process.env.PORT || 8080;
app.listen(port, () => {
  const fp = crypto.createHash("sha256").update(process.env.AUTHORISED_EMAILS_JSON || "[]").digest("hex").slice(0, 12);
  console.log(`MMG Renewal Generator UI listening on ${port}. Allowlist fingerprint=${fp}`);
});
