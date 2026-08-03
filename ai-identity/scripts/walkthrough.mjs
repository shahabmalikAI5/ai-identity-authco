import { createHash, randomBytes } from "node:crypto";
import { jwtVerify, createRemoteJWKSet } from "jose";

const BASE = "http://localhost:3000";
const JWKS = createRemoteJWKSet(new URL(BASE + "/api/auth/jwks"));
const CLIENT_ID = "test-client-02";
const CLIENT_SECRET = "test-secret-02-change-in-prod";
const REDIRECT_URI = "http://localhost:3000/callback";
const EMAIL = `spec02-walk-${Date.now()}@example.com`;
const PW = "TestPassword123!Secure";

function base64url(buf) { return buf.toString("base64url").replace(/=+$/, ""); }
function sha256(s) { return createHash("sha256").update(s).digest(); }
const codeVerifier = base64url(randomBytes(32));
const challenge = base64url(sha256(codeVerifier));

let cookies = "";
for (const step of ["sign-up", "sign-in"]) {
  const r = await fetch(`${BASE}/api/auth/${step}/email`, {
    method: "POST", headers: { "Content-Type": "application/json", "Origin": BASE },
    body: JSON.stringify({ email: EMAIL, password: PW, name: "Walkthrough" }),
    redirect: "manual"
  });
  cookies = r.headers.getSetCookie().map(c => c.split(";")[0]).join("; ") || cookies;
  await r.text();
}

const authz = await fetch(`${BASE}/api/auth/oauth2/authorize?${new URLSearchParams({
  client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
  response_type: "code", scope: "openid profile email",
  code_challenge: challenge, code_challenge_method: "S256",
})}`, {
  headers: { Cookie: cookies, "Sec-Fetch-Mode": "cors", "Origin": BASE }, redirect: "manual",
});
const consentUrl = new URL((await authz.json()).url, BASE);

const consent = await fetch(`${BASE}/api/auth/oauth2/consent`, {
  method: "POST",
  headers: { "Content-Type": "application/json", Cookie: cookies, "Sec-Fetch-Mode": "cors", "Origin": BASE },
  body: JSON.stringify({ accept: true, oauth_query: consentUrl.search.slice(1) }),
  redirect: "manual",
});
const code = (await consent.json()).url.match(/code=([^&]+)/)[1];

const tokenRes = await fetch(`${BASE}/api/auth/oauth2/token`, {
  method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Origin": BASE },
  body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier, client_id: CLIENT_ID, client_secret: CLIENT_SECRET }).toString(),
});
const { id_token } = await tokenRes.json();
console.log(id_token);
