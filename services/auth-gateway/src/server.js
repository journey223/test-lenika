// auth-gateway: a login page in front of one upstream app.
//
//   /auth/login    GET form, POST credentials -> signed session cookie
//   /auth/logout   clears the cookie
//   /auth/healthz  always 200, says whether the gateway is configured
//   everything else: signed in -> proxied to UPSTREAM_URL, otherwise login
//
// No dependencies: node:http, node:net and node:crypto only.

import http from "node:http";
import net from "node:net";
import { checkCredentials, createSession, parseCookies, parseUsers, readSession, safeNext } from "./auth.js";

const PORT = Number(process.env.PORT ?? 8080);
const UPSTREAM_URL = process.env.UPSTREAM_URL ?? "";
const SESSION_SECRET = process.env.SESSION_SECRET ?? "";
const USERS = parseUsers(process.env.AUTH_USERS);
const TTL_MS = Number(process.env.SESSION_TTL_HOURS ?? 12) * 3600_000;
const COOKIE_SECURE = process.env.COOKIE_SECURE !== "false";
const COOKIE = "ag_session";
const MAX_FAILS = 10;
const FAIL_WINDOW_MS = 15 * 60_000;

const problems = [];
let upstream = null;
try {
  upstream = new URL(UPSTREAM_URL);
  if (upstream.protocol !== "http:") problems.push("UPSTREAM_URL must be http://");
} catch {
  problems.push("UPSTREAM_URL is missing or not a URL");
}
if (SESSION_SECRET.length < 32) problems.push("SESSION_SECRET must be at least 32 characters");
if (USERS.size === 0) problems.push("AUTH_USERS has no users");
if (!(TTL_MS > 0)) problems.push("SESSION_TTL_HOURS must be a positive number");
const configured = problems.length === 0;

const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailer", "transfer-encoding", "upgrade",
]);

function clientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd) return fwd.split(",")[0].trim();
  return req.socket.remoteAddress ?? "unknown";
}

// In-memory login throttle per client IP.
const fails = new Map();
function throttled(ip, now = Date.now()) {
  const f = fails.get(ip);
  if (!f || f.until < now) return false;
  return f.count >= MAX_FAILS;
}
function recordFail(ip, now = Date.now()) {
  const f = fails.get(ip);
  if (!f || f.until < now) fails.set(ip, { count: 1, until: now + FAIL_WINDOW_MS });
  else f.count += 1;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, f] of fails) if (f.until < now) fails.delete(ip);
}, 60_000).unref();

function sessionOf(req) {
  return readSession(SESSION_SECRET, parseCookies(req.headers.cookie)[COOKIE]);
}

function cookie(value, maxAgeSec) {
  return [
    `${COOKIE}=${value}`, "Path=/", "HttpOnly", "SameSite=Lax", `Max-Age=${maxAgeSec}`,
    ...(COOKIE_SECURE ? ["Secure"] : []),
  ].join("; ");
}

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function loginPage(res, { next = "/", error = "", status = 200 } = {}) {
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "x-frame-options": "DENY",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
  });
  res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in</title>
<style>
body{font-family:system-ui,sans-serif;background:#f4f4f5;display:grid;place-items:center;min-height:100vh;margin:0}
form{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 1px 3px #0002;width:min(320px,90vw)}
h1{font-size:1.25rem;margin:0 0 1rem}label{display:block;font-size:.875rem;margin:.75rem 0 .25rem}
input{width:100%;box-sizing:border-box;padding:.6rem;border:1px solid #d4d4d8;border-radius:8px;font:inherit}
button{margin-top:1.25rem;width:100%;padding:.65rem;border:0;border-radius:8px;background:#18181b;color:#fff;font:inherit;cursor:pointer}
.err{color:#b91c1c;font-size:.875rem;margin:0 0 .5rem}
</style></head><body>
<form method="post" action="/auth/login">
<h1>Sign in</h1>${error ? `<p class="err">${esc(error)}</p>` : ""}
<input type="hidden" name="next" value="${esc(next)}">
<label for="u">Username</label><input id="u" name="username" autocomplete="username" required autofocus>
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form></body></html>`);
}

function readForm(req, limit = 8192) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > limit) { reject(new Error("too large")); req.destroy(); }
    });
    req.on("end", () => resolve(new URLSearchParams(body)));
    req.on("error", reject);
  });
}

// A cross-site POST to the login form carries a foreign Origin; refuse it.
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}

async function handleLogin(req, res, url) {
  if (req.method === "GET") return loginPage(res, { next: safeNext(url.searchParams.get("next")) });
  if (req.method !== "POST") { res.writeHead(405, { allow: "GET, POST" }); return res.end(); }
  if (!sameOrigin(req)) { res.writeHead(403); return res.end("cross-site login refused"); }

  const ip = clientIp(req);
  let form;
  try { form = await readForm(req); } catch { res.writeHead(413); return res.end(); }
  const next = safeNext(form.get("next"));
  if (throttled(ip)) return loginPage(res, { next, error: "Too many attempts. Try again in a few minutes.", status: 429 });

  const username = form.get("username") ?? "";
  if (!checkCredentials(USERS, username, form.get("password") ?? "")) {
    recordFail(ip);
    console.error(`auth-gateway: failed login for ${JSON.stringify(username.slice(0, 64))} from ${ip}`);
    return loginPage(res, { next, error: "Wrong username or password.", status: 401 });
  }
  fails.delete(ip);
  console.error(`auth-gateway: ${JSON.stringify(username)} signed in from ${ip}`);
  res.writeHead(303, {
    location: next,
    "set-cookie": cookie(createSession(SESSION_SECRET, username, TTL_MS), Math.floor(TTL_MS / 1000)),
    "cache-control": "no-store",
  });
  res.end();
}

function forwardHeaders(req, user) {
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (HOP_BY_HOP.has(k) || k === "x-auth-user") continue;
    headers[k] = v;
  }
  // Do not hand our session cookie to the app.
  if (headers.cookie) {
    const rest = String(headers.cookie).split(";").map((s) => s.trim()).filter((s) => s && !s.startsWith(`${COOKIE}=`));
    if (rest.length) headers.cookie = rest.join("; "); else delete headers.cookie;
  }
  const prior = req.headers["x-forwarded-for"];
  headers["x-forwarded-for"] = prior ? `${prior}, ${req.socket.remoteAddress}` : req.socket.remoteAddress;
  headers["x-forwarded-host"] = req.headers["x-forwarded-host"] ?? req.headers.host;
  headers["x-forwarded-proto"] = req.headers["x-forwarded-proto"] ?? (COOKIE_SECURE ? "https" : "http");
  headers["x-auth-user"] = user;
  headers.host = upstream.host;
  return headers;
}

function proxy(req, res, user) {
  const upstreamReq = http.request({
    host: upstream.hostname,
    port: upstream.port || 80,
    method: req.method,
    path: req.url,
    headers: forwardHeaders(req, user),
  }, (upRes) => {
    const headers = {};
    for (const [k, v] of Object.entries(upRes.headers)) if (!HOP_BY_HOP.has(k)) headers[k] = v;
    res.writeHead(upRes.statusCode ?? 502, upRes.statusMessage, headers);
    upRes.pipe(res);
  });
  upstreamReq.on("error", (err) => {
    console.error(`auth-gateway: upstream error: ${err.message}`);
    if (!res.headersSent) { res.writeHead(502, { "content-type": "text/plain" }); res.end("upstream unavailable"); }
    else res.destroy();
  });
  req.pipe(upstreamReq);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://gateway");
  if (url.pathname === "/auth/healthz") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ ok: true, configured, problems }));
  }
  if (!configured) {
    res.writeHead(503, { "content-type": "text/plain" });
    return res.end("auth-gateway is not configured; see /auth/healthz");
  }
  if (url.pathname === "/auth/login") return handleLogin(req, res, url);
  if (url.pathname === "/auth/logout") {
    res.writeHead(303, { location: "/auth/login", "set-cookie": cookie("", 0), "cache-control": "no-store" });
    return res.end();
  }

  const session = sessionOf(req);
  if (session) return proxy(req, res, session.u);

  const wantsHtml = (req.method === "GET" || req.method === "HEAD") && String(req.headers.accept ?? "").includes("text/html");
  if (wantsHtml) {
    res.writeHead(302, { location: `/auth/login?next=${encodeURIComponent(url.pathname + url.search)}`, "cache-control": "no-store" });
    return res.end();
  }
  res.writeHead(401, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify({ error: "unauthenticated" }));
});

// WebSocket and other upgrades: same session check, then a raw TCP pipe.
server.on("upgrade", (req, socket, head) => {
  const session = configured ? sessionOf(req) : null;
  if (!session) { socket.end("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n"); return; }
  const up = net.connect(Number(upstream.port || 80), upstream.hostname, () => {
    const headers = forwardHeaders(req, session.u);
    headers.connection = "Upgrade";
    headers.upgrade = req.headers.upgrade;
    const lines = [`${req.method} ${req.url} HTTP/1.1`];
    for (const [k, v] of Object.entries(headers)) for (const val of [v].flat()) lines.push(`${k}: ${val}`);
    up.write(lines.join("\r\n") + "\r\n\r\n");
    if (head?.length) up.write(head);
    up.pipe(socket).pipe(up);
  });
  up.on("error", () => socket.destroy());
  socket.on("error", () => up.destroy());
});

server.listen(PORT, () => {
  console.error(`auth-gateway: listening on :${PORT} -> ${UPSTREAM_URL || "(no upstream)"}, ${USERS.size} user(s)`);
  if (!configured) console.error(`auth-gateway: NOT CONFIGURED, refusing traffic: ${problems.join("; ")}`);
});
