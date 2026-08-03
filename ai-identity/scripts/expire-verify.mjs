import { jwtVerify, createRemoteJWKSet } from "jose";

const token = process.argv[2];
const payloadB64 = token.split(".")[1];
const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
const expDate = new Date(payload.exp * 1000);
const now = new Date();

const JWKS = createRemoteJWKSet(new URL("http://localhost:3000/api/auth/jwks"));

console.log("══════════════════════════════════════════════");
console.log("       TOKEN EXPIRY — CLOCK-SHIFT DEMO       ");
console.log("══════════════════════════════════════════════\n");

console.log(`Token issued at:   ${new Date(payload.iat * 1000).toISOString()}`);
console.log(`Token expires at:  ${expDate.toISOString()}`);
console.log(`Current real time: ${now.toISOString()}`);
console.log(`Time until expiry: ${Math.floor((expDate - now) / 1000 / 60)} minutes`);
console.log(`Lifetime:          ${Math.floor((payload.exp - payload.iat) / 60)} minutes\n`);

const ISSUER = "http://localhost:3000/api/auth";
const AUDIENCE = "test-client-02";

// ─── VERIFY 1: Real clock → PASS ───
console.log("──────────────────────────────────────────");
console.log("  VERIFY 1: Current real clock (now)");
console.log("──────────────────────────────────────────\n");

try {
  const r = await jwtVerify(token, JWKS, { issuer: ISSUER, audience: AUDIENCE });
  console.log(`✅ VERIFIED — signature, aud, iss all check out`);
  console.log(`   exp=${r.payload.exp} is still in the future. Token is alive.\n`);
} catch (e) {
  console.log(`❌ ${e.message}\n`);
}

// ─── VERIFY 2: Clock advanced past expiry → REJECT ───
console.log("──────────────────────────────────────────");
console.log("  VERIFY 2: Clock advanced past exp");
console.log("──────────────────────────────────────────\n");

const pastExpiry = new Date(expDate.getTime() + 60_000);

console.log(`  Real time:  ${now.toISOString()}`);
console.log(`  Faked time: ${pastExpiry.toISOString()}  ← moved clock past expiry`);
console.log(`  Token exp:  ${expDate.toISOString()}`);
console.log(`  Verdict:    clock > exp → token is dead\n`);

try {
  await jwtVerify(token, JWKS, {
    issuer: ISSUER,
    audience: AUDIENCE,
    currentDate: pastExpiry,
  });
  console.log(`✅ VERIFIED — should NEVER happen\n`);
} catch (e) {
  console.log(`❌ REJECTED — ${e.message}\n`);
  console.log(`  The verifier saw currentDate > exp and stopped.`);
  console.log(`  Signature still valid? Yes. Aud correct? Yes. Iss trusted? Yes.`);
  console.log(`  But the token's own exp says it's done. So it's done.\n`);
}

// ─── VERIFY 3: Back to real clock → PASS ───
console.log("──────────────────────────────────────────");
console.log("  VERIFY 3: Real clock — still valid     ");
console.log("──────────────────────────────────────────\n");

try {
  const r = await jwtVerify(token, JWKS, { issuer: ISSUER, audience: AUDIENCE });
  console.log(`✅ VERIFIED — on the real clock, the same token is fine.\n`);
} catch (e) {
  console.log(`❌ ${e.message}\n`);
}

console.log("══════════════════════════════════════════════");
console.log("                  TAKEAWAY                  ");
console.log("══════════════════════════════════════════════\n");
console.log("  Same token. Same JWKS. Same verifier. The only");
console.log("  difference is the clock.\n");
console.log("  Before exp → valid. After exp → dead.");
console.log("  No server-side lookup. No revocation list. The");
console.log("  expiry is IN the token and enforced by every");
console.log("  verifier, independently, offline.\n");
