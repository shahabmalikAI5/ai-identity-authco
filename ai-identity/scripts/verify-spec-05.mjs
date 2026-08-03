#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto"
import { readFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import {
  jwtVerify, createRemoteJWKSet, SignJWT, importJWK, generateKeyPair,
} from "jose"
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js"
import { managedNonce, hexToBytes } from "@noble/ciphers/utils.js"

const BASE = "http://localhost:3000"
const JWKS_URL = `${BASE}/api/auth/jwks`
const RESOURCE_URL = process.env.RESOURCE_URL || "http://localhost:8000"
const RESOURCE_HTTP = "http://localhost:8000"
const TEST_PREFIX = `spec05-${Date.now()}`
const TEST_EMAIL = `${TEST_PREFIX}@example.com`
const TEST_PASSWORD = "TestPassword123!Secure"

let passed = 0
let failed = 0
const JWKS = createRemoteJWKSet(new URL(JWKS_URL))

function assert(condition, name) {
  if (condition) { console.log(`  \u2705 ${name}`); passed++ }
  else { console.log(`  \u274c ${name}`); failed++ }
}

async function assertRejected(res, name, wantStatus = 401) {
  try {
    const body = await res.json()
    if (res.status === wantStatus) {
      console.log(`  \u2705 ${name} (${res.status})`); passed++
    } else {
      console.log(`  \u274c ${name} — expected ${wantStatus}, got ${res.status}: ${JSON.stringify(body).slice(0, 120)}`); failed++
    }
  } catch (e) {
    console.log(`  \u274c ${name} — ${e.message}`); failed++
  }
}

function base64url(buf) { return Buffer.from(buf).toString("base64url").replace(/=+$/, "") }
function extractCookies(headers) {
  return headers.getSetCookie ? headers.getSetCookie().map(c => c.split(";")[0]).join("; ") : ""
}

async function readAuthCoPrivateJwk() {
  const env = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", ".env"), "utf-8")
  const secret = env.match(/BETTER_AUTH_SECRET=(.*)/)[1].trim()
  const dbUrl = env.match(/DATABASE_URL=(.*)/)[1].trim()
  const url = new URL(dbUrl)
  const hostname = url.hostname
  const { execSync } = await import("node:child_process")
  let ip = hostname
  try {
    const raw = execSync(`dig +short ${hostname} | tail -1`, { encoding: "utf8", timeout: 5000 }).trim()
    if (/^\d+\.\d+\.\d+\.\d+$/.test(raw)) ip = raw
  } catch {}
  const { default: pg } = await import("pg")
  const pool = new pg.Pool({
    host: ip,
    port: Number(url.port) || 5432,
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database: url.pathname.replace(/^\//, ""),
    ssl: { rejectUnauthorized: false, servername: hostname },
    connectionTimeoutMillis: 20000,
    max: 2,
  })
  try {
    const r = await pool.query('SELECT "privateKey" FROM "jwks" ORDER BY "createdAt" DESC LIMIT 1')
    const hex = JSON.parse(r.rows[0].privateKey)
    const keyBytes = createHash("sha256").update(secret).digest()
    const decrypted = new TextDecoder().decode(managedNonce(xchacha20poly1305)(keyBytes).decrypt(hexToBytes(hex)))
    return JSON.parse(decrypted)
  } finally {
    await pool.end()
  }
}

async function main() {
  console.log("=== Spec 05 Verification — Connect a Resource Server ===\n")

  // ---- Setup: session + token ----
  const siRes = await fetch(`${BASE}/api/auth/sign-up/email`, {
    method: "POST", headers: { "Content-Type": "application/json", Origin: BASE },
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD, name: "Spec05 User" }),
    redirect: "manual",
  })
  const siRes2 = await fetch(`${BASE}/api/auth/sign-in/email`, {
    method: "POST", headers: { "Content-Type": "application/json", Origin: BASE },
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD }),
    redirect: "manual",
  })
  const cookies = extractCookies(siRes2.headers)
  assert(siRes2.status === 200 || siRes2.status === 302, "Sign-in succeeds")

  const tokenRes = await fetch(`${BASE}/api/auth/token`, {
    headers: { Cookie: cookies, Origin: BASE },
  })
  const tokenData = await tokenRes.json()
  const token = tokenData.token || ""
  assert(!!token, "Got a JWT from GET /api/auth/token")

  let header = {}
  let payload = {}
  if (token) {
    header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString())
    payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString())
  }

  // ---- FR-1 / AC-6a: issuer emits RS256 ----
  console.log("\n--- FR-1: RS256 signing ---")
  assert(header.alg === "RS256", `Issuer signs with RS256 (got ${header.alg || "none"})`)
  assert(!!header.kid, "Token carries a kid")

  // ---- FR-2/3: aud/iss/exp claims ----
  console.log("\n--- FR-2/3: claims ---")
  assert(payload.aud === RESOURCE_URL, `aud is the resource URL (${payload.aud})`)
  assert(payload.iss === `${BASE}`, `iss is AuthCo (${payload.iss})`)
  assert(typeof payload.sub === "string" && payload.sub.length > 0, `sub is the user id (${payload.sub})`)
  assert(typeof payload.exp === "number", "Has finite exp")
  assert(typeof payload.iat === "number" && payload.iat < payload.exp, "iat < exp")

  // ---- AC-1: resource server accepts valid token and reads sub ----
  console.log("\n--- AC-1: valid token accepted ---")
  if (token) {
    const res = await fetch(`${RESOURCE_HTTP}/api/notes`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    const body = await res.json()
    if (res.status === 200 && body.sub === payload.sub) {
      assert(true, `Request succeeds and is attributed to sub=${payload.sub}`)
    } else {
      assert(false, `Expected 200 + sub=${payload.sub}, got ${res.status}: ${JSON.stringify(body).slice(0, 120)}`)
    }
  } else {
    assert(false, "No token available for AC-1")
  }

  // ---- AC-2: offline verification ----
  console.log("\n--- AC-2: offline verification (JWKS only) ---")
  const resDir = join(dirname(fileURLToPath(import.meta.url)), "..", "resource-server")
  const rsSource = readFileSync(join(resDir, "server.mjs"), "utf-8")
  assert(rsSource.includes("createRemoteJWKSet"), "Resource server uses createRemoteJWKSet")
  assert(!rsSource.includes("DATABASE_URL"), "Resource server has no DATABASE_URL")
  assert(!rsSource.includes("BETTER_AUTH_SECRET"), "Resource server has no BETTER_AUTH_SECRET")
  assert(!rsSource.includes("/api/auth/token"), "Resource server never calls AuthCo's token endpoint")
  assert(!rsSource.includes("/api/auth/oauth2/introspect"), "Resource server never calls introspection")

  // ---- AC-3: tampered token rejected ----
  console.log("\n--- AC-3: tampered token rejected ---")
  if (token) {
    const parts = token.split(".")
    const last = parts[2]
    const flipped = last[0] === "A" ? "B" : "A"
    const tampered = `${parts[0]}.${parts[1]}.${flipped}${last.slice(1)}`
    const res = await fetch(`${RESOURCE_HTTP}/api/notes`, {
      headers: { Authorization: `Bearer ${tampered}` },
    })
    await assertRejected(res, "Tampered signature rejected")
  } else {
    assert(false, "No token for AC-3")
  }

  // ---- AC-4: wrong audience rejected (AuthCo-signed) ----
  console.log("\n--- AC-4: wrong audience rejected (RFC 8707) ---")
  try {
    const authCoJwk = await readAuthCoPrivateJwk()
    const authCoPrivate = await importJWK(authCoJwk, "RS256")
    const wrongAudToken = await new SignJWT({ sub: payload.sub || "test-sub" })
      .setProtectedHeader({ alg: "RS256", kid: header.kid })
      .setIssuer(BASE)
      .setAudience("http://localhost:9999")
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(authCoPrivate)
    assert(true, "Minted an AuthCo-signed token for a different resource (aud=http://localhost:9999)")
    const res = await fetch(`${RESOURCE_HTTP}/api/notes`, {
      headers: { Authorization: `Bearer ${wrongAudToken}` },
    })
    await assertRejected(res, "Wrong-audience AuthCo-signed token rejected")
  } catch (e) {
    assert(false, `AC-4 setup failed: ${e.message}`)
  }

  // ---- AC-5: expired token rejected offline ----
  console.log("\n--- AC-5: expired token rejected offline ---")
  if (token) {
    const pastExp = new Date((payload.exp + 3600) * 1000)
    try {
      await jwtVerify(token, JWKS, { issuer: BASE, audience: RESOURCE_URL, currentDate: pastExp })
      assert(false, "Expired token accepted by jose (ERR_JWT_EXPIRED expected)")
    } catch (e) {
      assert(e.message.toLowerCase().includes("exp"), `jose rejects expired token offline (${e.code || e.message})`)
    }
    // Also prove the resource server itself rejects an expired AuthCo-signed token
    try {
      const authCoJwk = await readAuthCoPrivateJwk()
      const authCoPrivate = await importJWK(authCoJwk, "RS256")
      const expiredToken = await new SignJWT({ sub: "expired-user" })
        .setProtectedHeader({ alg: "RS256", kid: header.kid })
        .setIssuer(BASE)
        .setAudience(RESOURCE_URL)
        .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
        .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
        .sign(authCoPrivate)
      const res = await fetch(`${RESOURCE_HTTP}/api/notes`, {
        headers: { Authorization: `Bearer ${expiredToken}` },
      })
      await assertRejected(res, "Resource server rejects expired AuthCo-signed token (no callback)")
    } catch (e) {
      assert(false, `AC-5 resource-server check failed: ${e.message}`)
    }
  } else {
    assert(false, "No token for AC-5")
  }

  // ---- AC-6: algorithm matches; EdDSA rejected ----
  console.log("\n--- AC-6: algorithm enforcement (RS256 yes, EdDSA no) ---")
  const { publicKey: _pk, privateKey: edKey } = await generateKeyPair("EdDSA")
  const edToken = await new SignJWT({ sub: "eddsa-user" })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(BASE)
    .setAudience(RESOURCE_URL)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(edKey)
  const edRes = await fetch(`${RESOURCE_HTTP}/api/notes`, {
    headers: { Authorization: `Bearer ${edToken}` },
  })
  await assertRejected(edRes, "EdDSA token rejected by RS256-only verifier")

  // ---- AC-2 (reinforced): the JWT alg is declared RS256 at discovery ----
  console.log("\n--- Discovery metadata ---")
  const discRes = await fetch(`${BASE}/.well-known/openid-configuration`)
  const disc = await discRes.json()
  assert(discRes.status === 200, "GET /.well-known/openid-configuration works")
  assert(disc.issuer === BASE, "Discovery issuer is AuthCo")
  assert(disc.jwks_uri === JWKS_URL, "Discovery jwks_uri points at /api/auth/jwks")
  assert(Array.isArray(disc.id_token_signing_alg_values_supported) && disc.id_token_signing_alg_values_supported.includes("RS256"),
    "Discovery advertises RS256")

  console.log(`\n========================================`)
  console.log(`Results: ${passed} passed, ${failed} failed`)
  console.log(`========================================`)
  process.exit(failed > 0 ? 1 : 0)
}

main().catch(e => { console.error(`\nFATAL: ${e.message}`); process.exit(1) })
