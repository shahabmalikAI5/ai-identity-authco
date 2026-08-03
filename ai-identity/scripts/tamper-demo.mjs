import { jwtVerify, createRemoteJWKSet, decodeJwt } from "jose";

const BASE = "http://localhost:3000";
const JWKS = createRemoteJWKSet(new URL(BASE + "/api/auth/jwks"));

const token = process.argv[2];
if (!token) { console.error("Usage: node --experimental-import-meta-resolve scripts/tamper-demo.mjs <id_token>"); process.exit(1); }

const [headerB64, payloadB64, signatureB64] = token.split(".");
const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());

console.log("═══════════════════════════════════════");
console.log("        ID TOKEN — CLAIM BY CLAIM     ");
console.log("═══════════════════════════════════════\n");

console.log("aud:   \"test-client-02\"");
console.log("       ↑ Minted FOR \"test-client-02\". Any other app MUST reject this.\n");

console.log(`iss:   "${payload.iss}"`);
console.log("       ↑ Issued by AuthCo at localhost:3000. Verifiers check they trust this.\n");

console.log(`sub:   "${payload.sub}"`);
console.log("       ↑ The user (subject) this token identifies. A 32-char opaque ID.\n");

console.log(`exp:   ${payload.exp}  → ${new Date(payload.exp * 1000).toISOString()}`);
console.log("       ↑ Expiration time. After this, the token is dead. (~10h from iat).\n");

console.log(`iat:   ${payload.iat}  → ${new Date(payload.iat * 1000).toISOString()}`);
console.log("       ↑ Issued-at time. When this token was minted.\n");

console.log(`auth_time: ${payload.auth_time}  → ${new Date(payload.auth_time * 1000).toISOString()}`);
console.log("       ↑ When the password was entered. ~8s earlier than iat (consent + exchange delay).\n");

console.log(`acr:   "${payload.acr}"`);
console.log("       ↑ Authentication Context Reference. \"0\" = password-based.\n");

console.log(`at_hash: "${payload.at_hash}"`);
console.log("       ↑ Hash of the access_token. Binds id_token to its access_token,\n        preventing cross-token substitution attacks.\n");

// ─── DEMO 1: Correct aud → PASS ───
console.log("═══════════════════════════════════════");
console.log("   DEMO 1: Correct aud → VERIFIED     ");
console.log("═══════════════════════════════════════\n");

try {
  const r = await jwtVerify(token, JWKS, {
    issuer: "http://localhost:3000/api/auth",
    audience: "test-client-02",
  });
  console.log("✅ PASSED — aud=test-client-02 matches, iss matches, signature valid");
  console.log(`   sub=${r.payload.sub}\n`);
} catch (e) {
  console.log(`❌ Failed: ${e.message}\n`);
}

// ─── DEMO 2: Wrong aud expected → REJECT ───
console.log("═══════════════════════════════════════");
console.log("   DEMO 2: Wrong aud → REJECTED       ");
console.log("═══════════════════════════════════════\n");

console.log('   Verifier says "I expect aud=test-client-12"');
console.log('   Token says aud="test-client-02"');
console.log('   One character difference. Result:\n');

try {
  await jwtVerify(token, JWKS, {
    issuer: "http://localhost:3000/api/auth",
    audience: "test-client-12",
  });
  console.log("✅ PASSED — should NOT happen\n");
} catch (e) {
  console.log(`  ❌ REJECTED — ${e.message}`);
  console.log("     The token wasn't minted for this app. Denied.\n");
}

// ─── DEMO 3: Tamper aud in JWT → REJECT (signature breaks) ───
console.log("═══════════════════════════════════════");
console.log("   DEMO 3: Tamper token body → BROKEN ");
console.log("═══════════════════════════════════════\n");

const tamperedPayload = Buffer.from(JSON.stringify({ ...payload, aud: "test-client-12" })).toString("base64url");
const tamperedToken = `${headerB64}.${tamperedPayload}.${signatureB64}`;

console.log(`  Original base64: ${payloadB64.slice(0, 40)}...`);
console.log(`  Tampered base64: ${tamperedPayload.slice(0, 40)}...`);
console.log("                   ^^^ one char changes the whole encoding\n");
console.log("  The signature covers the original bytes. After your change,");
console.log("  the signature no longer matches. Watching the verifier:\n");

try {
  await jwtVerify(tamperedToken, JWKS);
  console.log("✅ PASSED — should NEVER happen\n");
} catch (e) {
  console.log(`  ❌ REJECTED — ${e.message}`);
  console.log("     You changed aud but couldn't re-sign. The math caught it.\n");
}

console.log("═══════════════════════════════════════");
console.log("              TAKEAWAY                ");
console.log("═══════════════════════════════════════\n");
console.log("  The JWKS gives the world your PUBLIC key (x). That's enough to");
console.log("  VERIFY the signature was made by your PRIVATE key (d).");
console.log("  But to CREATE a new signature, you'd need d — and d never leaves");
console.log("  your server. That's the asymmetry that makes this work.\n");
console.log("  Tamper the payload → signature mismatch. Use wrong audience →");
console.log("  verifier rejects. Only AuthCo holds d. Only AuthCo can mint tokens.\n");
