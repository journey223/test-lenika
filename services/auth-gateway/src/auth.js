import { createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const SCRYPT_N = 16384;
const KEYLEN = 32;

export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, KEYLEN, { N: SCRYPT_N, r: 8, p: 1 });
  return `scrypt$${SCRYPT_N}$${salt.toString("base64url")}$${hash.toString("base64url")}`;
}

export function verifyPassword(password, stored) {
  const parts = String(stored).split("$");
  if (parts.length !== 4 || parts[0] !== "scrypt") return false;
  const N = Number(parts[1]);
  if (!Number.isInteger(N) || N < 2 || N > 1 << 20) return false;
  const salt = Buffer.from(parts[2], "base64url");
  const expected = Buffer.from(parts[3], "base64url");
  if (expected.length === 0) return false;
  const actual = scryptSync(password, salt, expected.length, { N, r: 8, p: 1, maxmem: 256 * N * 8 * 2 });
  return timingSafeEqual(actual, expected);
}

// "alice:scrypt$...,bob:scrypt$..." -> Map
export function parseUsers(raw) {
  const users = new Map();
  for (const entry of String(raw ?? "").split(",")) {
    const trimmed = entry.trim();
    const i = trimmed.indexOf(":");
    if (i <= 0) continue;
    users.set(trimmed.slice(0, i), trimmed.slice(i + 1));
  }
  return users;
}

// A hash to burn the same time on for unknown users, so timing does not reveal who exists.
const DUMMY_HASH = hashPassword(randomBytes(16).toString("hex"));

export function checkCredentials(users, username, password) {
  const stored = users.get(username);
  const ok = verifyPassword(password, stored ?? DUMMY_HASH);
  return Boolean(stored) && ok;
}

function sign(secret, data) {
  return createHmac("sha256", secret).update(data).digest("base64url");
}

export function createSession(secret, username, ttlMs, now = Date.now()) {
  const payload = Buffer.from(JSON.stringify({ u: username, exp: now + ttlMs })).toString("base64url");
  return `${payload}.${sign(secret, payload)}`;
}

export function readSession(secret, token, now = Date.now()) {
  if (typeof token !== "string") return null;
  const dot = token.indexOf(".");
  if (dot <= 0) return null;
  const payload = token.slice(0, dot);
  const given = Buffer.from(token.slice(dot + 1));
  const expected = Buffer.from(sign(secret, payload));
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (typeof data.u !== "string" || typeof data.exp !== "number" || data.exp <= now) return null;
    return data;
  } catch {
    return null;
  }
}

export function parseCookies(header) {
  const out = {};
  for (const part of String(header ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i <= 0) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

// Only same-site relative paths: "/x" yes, "//evil" or "/\evil" or "https://..." no.
export function safeNext(next) {
  if (typeof next !== "string" || !next.startsWith("/")) return "/";
  if (next.startsWith("//") || next.startsWith("/\\")) return "/";
  return next;
}
