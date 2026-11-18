# auth-gateway

A login page in front of one app. Signed-in requests are proxied to `UPSTREAM_URL`
with an `X-Auth-User` header; everyone else gets the login form (browsers) or a 401 (APIs).
No dependencies — Node 18+ built-ins only.

| Path | |
|---|---|
| `/auth/login` | sign-in form; POST sets an HMAC-signed, HttpOnly session cookie |
| `/auth/logout` | clears the cookie |
| `/auth/healthz` | always 200; reports whether the gateway is configured |

## Configuration

See `.env.example`. Until `UPSTREAM_URL`, `AUTH_USERS` and `SESSION_SECRET` are valid the
gateway refuses all traffic (fails closed) and `/auth/healthz` lists what is missing.

Add a user: `npm run hash-password -- 'their password'`, then append `name:<hash>` to
`AUTH_USERS` (comma-separated) and restart the app.

Logins are throttled to 10 failures per IP per 15 minutes. Changing `SESSION_SECRET`
signs everyone out.

## Test

    npm test
