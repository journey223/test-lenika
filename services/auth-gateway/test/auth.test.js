import test from "node:test";
import assert from "node:assert/strict";
import { checkCredentials, createSession, hashPassword, parseCookies, parseUsers, readSession, safeNext, verifyPassword } from "../src/auth.js";

const SECRET = "x".repeat(40);

test("password hash round-trips and rejects wrong passwords", () => {
  const h = hashPassword("hunter2");
  assert.ok(verifyPassword("hunter2", h));
  assert.ok(!verifyPassword("hunter3", h));
  assert.ok(!verifyPassword("hunter2", "garbage"));
});

test("users parse and credentials check", () => {
  const users = parseUsers(` alice:${hashPassword("a")} , bob:${hashPassword("b")},broken`);
  assert.deepEqual([...users.keys()], ["alice", "bob"]);
  assert.ok(checkCredentials(users, "alice", "a"));
  assert.ok(!checkCredentials(users, "alice", "b"));
  assert.ok(!checkCredentials(users, "mallory", "a"));
});

test("sessions verify, expire, and resist tampering", () => {
  const t = createSession(SECRET, "alice", 1000, 0);
  assert.equal(readSession(SECRET, t, 500).u, "alice");
  assert.equal(readSession(SECRET, t, 1000), null);
  assert.equal(readSession("y".repeat(40), t, 500), null);
  const forged = Buffer.from(JSON.stringify({ u: "admin", exp: 9e15 })).toString("base64url") + "." + t.split(".")[1];
  assert.equal(readSession(SECRET, forged, 500), null);
  assert.equal(readSession(SECRET, undefined), null);
});

test("cookies parse", () => {
  assert.deepEqual(parseCookies("a=1; b=x.y=z"), { a: "1", b: "x.y=z" });
});

test("next only allows local paths", () => {
  assert.equal(safeNext("/dash?x=1"), "/dash?x=1");
  for (const bad of ["//evil.com", "/\\evil.com", "https://evil.com", "", null]) assert.equal(safeNext(bad), "/");
});
