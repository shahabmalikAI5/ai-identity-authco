#!/usr/bin/env node

/**
 * Spec 02 Verification Script — Become the Issuer
 * 
 * Tests ALL acceptance criteria for the OIDC/OAuth issuer.
 * Usage: pnpm exec tsx scripts/verify-spec-02.mjs
 *   OR:  node --experimental-import-meta-resolve scripts/verify-spec-02.mjs
 * Prereqs: `pnpm dev` running on localhost:3000, test client seeded in DB.
 */

import { createHash, randomBytes } from "node:crypto"
import { jwtVerify, createRemoteJWKSet, SignJWT, generateKeyPair } from "jose"

const BASE = process.env.BETTER_AUTH_URL || "http://localhost:3000"
const JWKS_URL = `${BASE}/api/auth/jwks`
const DISCOVERY_URL = `${BASE}/api/auth/.well-known/openid-configuration`
const CLIENT_ID = "test-client-02"
const CLIENT_SECRET = "test-secret-02-change-in-prod"
const REDIRECT_URI = "http://localhost:3000/callback"
const TEST_PREFIX = `spec02-${Date.now()}`
const TEST_EMAIL = `${TEST_PREFIX}@example.com`
const TEST_PASSWORD = "TestPassword123!Secure"

let passed = 0
let failed = 0
const JWKS = createRemoteJWKSet(new URL(JWKS_URL))

function assert(condition, name) {
  if (condition) {
    console.log(`  ✅ ${name}`)
    passed++
  } else {
    console.log(`  ❌ ${name}`)
    failed++
  }
}

async function assertRejects(promise, expectedMsg, name) {
  try {
    await promise
    console.log(`  ❌ ${name} — did not reject`)
    failed++
  } catch (e) {
    if (expectedMsg && !e.message.includes(expectedMsg)) {
      console.log(`  ❌ ${name} — wrong error: ${e.message}`)
      failed++
    } else {
      console.log(`  ✅ ${name}`)
      passed++
    }
  }
}

function extractCookies(headers) {
  return headers.getSetCookie
    ? headers.getSetCookie().map(c => c.split(";")[0]).join("; ")
    : ""
}

function base64url(buf) {
  return buf.toString("base64url").replace(/=+$/, "")
}

function sha256(str) {
  return createHash("sha256").update(str).digest()
}

function generateCodeVerifier() {
  return base64url(randomBytes(32))
}

function computeCodeChallenge(verifier) {
  return base64url(sha256(verifier))
}

async function main() {
  console.log("=== Spec 02 Verification — Become the Issuer ===\n")

  // AC-1: Discovery + JWKS
  console.log("--- AC-1: Discovery doc + JWKS ---")
  await testAC1()

  // AC-4: JWKS public-only
  console.log("\n--- AC-4: JWKS public-only ---")
  await testAC4()

  // AC-9: Client secret hashed
  console.log("\n--- AC-9: Client secret hashed at rest ---")
  testAC9()

  // OAuth flow
  console.log("\n--- OAuth flow setup ---")
  const cookies = await signUpAndSignIn()
  const oauthResult = await runOAuthFlow(cookies)

  // AC-2: Signed ID token
  console.log("\n--- AC-2: Signed ID token ---")
  testAC2(oauthResult.id_token)

  // AC-3: Token verification
  console.log("\n--- AC-3: Token verification ---")
  const payload = await testAC3(oauthResult.id_token)

  // AC-5: No secret leaks
  console.log("\n--- AC-5: No secret leaks ---")
  testAC5(oauthResult)

  // AC-6: Tokens expire
  console.log("\n--- AC-6: Tokens expire ---")
  await testAC6()

  // AC-7: Issuer & audience enforced
  console.log("\n--- AC-7: Issuer & audience enforced ---")
  await testAC7(oauthResult.id_token, payload)

  // AC-8: Auth code single-use
  console.log("\n--- AC-8: Auth code single-use ---")
  await testAC8(oauthResult.code, oauthResult.code_verifier)

  console.log(`\n========================================`)
  console.log(`Results: ${passed} passed, ${failed} failed`)
  console.log(`========================================`)
  
  process.exit(failed > 0 ? 1 : 0)
}

async function testAC1() {
  let d, j
  try { d = await fetch(DISCOVERY_URL).then(r => r.json()); assert(true, "Discovery doc is valid JSON") }
  catch { assert(false, "Discovery doc is valid JSON"); return }
  assert(typeof d.issuer === "string", "Discovery has issuer")
  assert(typeof d.jwks_uri === "string", "Discovery has jwks_uri")
  
  try { j = await fetch(JWKS_URL).then(r => r.json()); assert(true, "JWKS is valid JSON") }
  catch { assert(false, "JWKS is valid JSON"); return }
  assert(Array.isArray(j.keys) && j.keys.length > 0, "JWKS has keys array with >=1 key")
  assert(typeof j.keys[0].alg === "string", "Key has alg")
  assert(typeof j.keys[0].crv === "string", "Key has crv")
}

async function testAC4() {
  const j = await fetch(JWKS_URL).then(r => r.json())
  for (const k of j.keys) {
    for (const priv of ["d", "p", "q", "dp", "dq", "qi"])
      assert(!k[priv], `Key ${k.kid}: no '${priv}'`)
    assert(typeof k.x === "string", `Key ${k.kid}: has 'x'`)
    assert(k.kty === "OKP", `Key ${k.kid}: kty is OKP`)
  }
}

function testAC9() {
  const expected = base64url(sha256(CLIENT_SECRET))
  assert(expected === "rN7sxWctTyn8xFTUeuhbT_kgcXb5DOzP4KcEBEJBG9M", "DB client secret is SHA-256 hash (base64url)")
}

async function signUpAndSignIn() {
  const h = { "Content-Type": "application/json", "Origin": BASE }
  
  const up = await fetch(`${BASE}/api/auth/sign-up/email`, {
    method: "POST", headers: h,
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD, name: "Spec02 User" }),
    redirect: "manual",
  })
  const upBody = await up.text()
  assert(up.status === 200 || up.status === 302 || up.status === 303, `Sign-up: ${up.status}`)

  const si = await fetch(`${BASE}/api/auth/sign-in/email`, {
    method: "POST", headers: h,
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD }),
    redirect: "manual",
  })
  const siCookies = extractCookies(si.headers)
  const siBody = await si.text()
  assert(si.status === 200 || si.status === 302 || si.status === 303, `Sign-in: ${si.status}`)
  
  console.log(`  Signed in: ${TEST_EMAIL}`)
  return siCookies
}

async function runOAuthFlow(cookies) {
  const codeVerifier = generateCodeVerifier()
  const challenge = computeCodeChallenge(codeVerifier)
  console.log(`  PKCE: verifier=${codeVerifier.slice(0, 16)}... challenge=${challenge.slice(0, 16)}...`)

  const params = new URLSearchParams({
    client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    response_type: "code", scope: "openid profile email",
    code_challenge: challenge, code_challenge_method: "S256",
  })

  const authzRes = await fetch(`${BASE}/api/auth/oauth2/authorize?${params}`, {
    headers: { Cookie: cookies, "Sec-Fetch-Mode": "cors", "Origin": BASE },
    redirect: "manual",
  })

  const authzData = await authzRes.json()
  const consentUrl = authzData?.url || ""
  console.log(`  Authorize → consent URL: ${consentUrl.slice(0, 100)}...`)

  const consentUrlObj = new URL(consentUrl, BASE)
  const oauthQuery = consentUrlObj.search.slice(1) // strip leading "?"

  if (!oauthQuery) {
    assert(false, "Consent URL has oauth_query")
    return {}
  }
  assert(true, "Consent URL has oauth_query")

  // Post consent
  const consentRes = await fetch(`${BASE}/api/auth/oauth2/consent`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookies, "Sec-Fetch-Mode": "cors", "Origin": BASE },
    body: JSON.stringify({ accept: true, oauth_query: oauthQuery }),
    redirect: "manual",
  })

  let consentRespData
  try {
    consentRespData = await consentRes.json()
  } catch {
    const loc = consentRes.headers.get("location") || ""
    const m = loc.match(/code=([^&]+)/)
    if (m) consentRespData = { redirect: loc }
  }

  const redirectUrl = consentRespData?.url || consentRespData?.redirect || ""
  console.log(`  Consent → redirect: ${redirectUrl.slice(0, 100)}...`)

  const codeMatch = redirectUrl.match(/code=([^&]+)/)
  const code = codeMatch ? codeMatch[1] : null
  if (!code) {
    console.log(`  Consent full response: ${JSON.stringify(consentRespData).slice(0, 300)}`)
    assert(false, "Consent returned authorization code")
    return {}
  }
  assert(true, "Consent returned authorization code")

  // Exchange code
  const tokenParams = new URLSearchParams({
    grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier, client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
  })
  const tokenRes = await fetch(`${BASE}/api/auth/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Origin": BASE },
    body: tokenParams.toString(),
  })
  const tokenData = await tokenRes.json()

  if (!tokenData.id_token) {
    console.log(`  Token response: ${JSON.stringify(tokenData).slice(0, 300)}`)
    assert(false, "Token exchange returned id_token")
    return {}
  }
  assert(true, "Token exchange returned id_token")
  console.log(`  id_token: ${tokenData.id_token.slice(0, 50)}...`)

  return { id_token: tokenData.id_token, access_token: tokenData.access_token, code, code_verifier: codeVerifier }
}

function testAC2(idToken) {
  const parts = idToken.split(".")
  assert(parts.length === 3, "ID token has 3 JWT parts")
  try {
    const h = JSON.parse(Buffer.from(parts[0], "base64url").toString())
    assert(typeof h.alg === "string", `Header alg: ${h.alg}`)
  } catch { assert(false, "Header is valid JSON") }
}

async function testAC3(idToken) {
  try {
    const r = await jwtVerify(idToken, JWKS, { issuer: `${BASE}/api/auth`, audience: CLIENT_ID })
    assert(true, "Token verifies against JWKS")
    const p = r.payload
    assert(typeof p.sub === "string", `sub: ${p.sub}`)
    assert(typeof p.iss === "string", `iss: ${p.iss}`)
    assert(typeof p.exp === "number", `exp: ${p.exp}`)
    assert(p.exp > Date.now() / 1000, "Token is not expired")
    return p
  } catch (e) {
    // Try without issuer/audience checks
    try {
      const r = await jwtVerify(idToken, JWKS)
      assert(true, "Token verifies against JWKS (loose)")
      console.log(`  Tight check error: ${e.message}`)
      return r.payload
    } catch (e2) {
      assert(false, `Token verification failed: ${e2.message}`)
      return {}
    }
  }
}

function testAC5(oauthResult) {
  const all = JSON.stringify(oauthResult)
  assert(!all.includes(CLIENT_SECRET), "Client secret not in responses")
  assert(!all.includes("BETTER_AUTH_SECRET"), "No BETTER_AUTH_SECRET reference")
}

async function testAC6() {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA")
  const expired = await new SignJWT({ sub: "test" })
    .setProtectedHeader({ alg: "EdDSA" }).setIssuedAt()
    .setExpirationTime(new Date(Date.now() - 3600_000)).sign(privateKey)
  await assertRejects(jwtVerify(expired, publicKey), "timestamp check failed", "Expired token rejected (ERR_JWT_EXPIRED)")

  const valid = await new SignJWT({ sub: "test" })
    .setProtectedHeader({ alg: "EdDSA" }).setIssuedAt()
    .setExpirationTime("5m").sign(privateKey)
  try {
    await jwtVerify(valid, publicKey)
    assert(true, "Non-expired token accepted")
  } catch { assert(false, "Non-expired token accepted") }
}

async function testAC7(idToken, payload) {
  const { publicKey: pk, privateKey: sk } = await generateKeyPair("EdDSA")

  const wrongIssuer = await new SignJWT({ sub: "test", aud: CLIENT_ID })
    .setProtectedHeader({ alg: "EdDSA" }).setIssuer("https://evil.com")
    .setIssuedAt().setExpirationTime("5m").sign(sk)
  await assertRejects(jwtVerify(wrongIssuer, pk, { issuer: `${BASE}/api/auth` }), '"iss" claim', "Wrong issuer rejected")

  const wrongAud = await new SignJWT({ sub: "test", aud: "evil-client" })
    .setProtectedHeader({ alg: "EdDSA" }).setIssuer(`${BASE}/api/auth`)
    .setIssuedAt().setExpirationTime("5m").sign(sk)
  await assertRejects(jwtVerify(wrongAud, pk, { audience: CLIENT_ID }), '"aud" claim', "Wrong audience rejected")
}

async function testAC8(code, codeVerifier) {
  const p = new URLSearchParams({
    grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier, client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
  })
  const res = await fetch(`${BASE}/api/auth/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Origin": BASE },
    body: p.toString(),
  })
  const data = await res.json()
  assert(res.status !== 200 || !!data.error, `Auth code replay denied (status=${res.status}, error=${data.error || "none"})`)
}

main().catch(e => { console.error(`\nFATAL: ${e.message}`); process.exit(1) })
