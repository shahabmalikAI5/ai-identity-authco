01 — Token stored hashed, queried raw
Better Auth stores opaque access tokens as SHA-256(base64url, no padding) in oauthAccessToken.token.
The resource verifier queried with the raw Authorization header token — always missed. Fix: hash it first.

02 — Mismatched DB connection config between auth.ts and introspect.ts
auth.ts resolved Neon hostname to IP via dig + set servername for SSL SNI; introspect.ts used hostname directly with bare ssl: { rejectUnauthorized: false }.
This caused silent connection failures swallowed by the catch block. Fix: mirror the same Pool config everywhere.

03 — Authorize-level scope rejection produces an error URL, not a consent URL
Better Auth 1.7 rejects invalid scopes BEFORE consent (redirect to /callback?error=invalid_scope).
The test script treated every authorize response URL as a consent URL, posted the error query as oauth_query, and got invalid_signature from the consent endpoint. Fix: detect error= in authorize response, handle as pass/deny.

04 — Cached consent skips the deny flow
After approving a (client, user, scopes) tuple, Better Auth auto-approves future requests for the same tuple.
AC-7 (deny test) reused scopes from AC-5 (approve test) — consent was cached, so no deny screen appeared. Fix: request a different scope combination for the deny test.

05 — Node.js doesn't load .env automatically for Express apps
The Notes app's AUTHCO_URL was undefined because Node needs dotenv (or similar) to load a .env file. Next.js and Vite auto-load it; a plain Express script does not. Fix: add import "dotenv/config" at the top of index.mjs.
