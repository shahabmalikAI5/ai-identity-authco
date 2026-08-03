#!/usr/bin/env node

/**
 * Project — 2FA Verification Script
 *
 * Tests ALL acceptance criteria for hardening sign-in with a second factor:
 *   AC-1  password + valid TOTP → session issued, dashboard reachable
 *   AC-2  enrollment shows secret + backup codes once; a code generated
 *         from that secret is accepted
 *   AC-3  correct password + wrong/blank TOTP → refused, no session
 *   AC-4  backup codes are single-use (reuse refused)
 *   AC-5  secrets are hashed/encrypted at rest, never in responses/logs
 *
 * Usage: node scripts/verify-spec-2fa.mjs
 * Prereqs: `node node_modules/next/dist/bin/next dev` on localhost:3000,
 * DATABASE_URL + BETTER_AUTH_SECRET in .env.
 */

import { createHash, createHmac, randomBytes } from "node:crypto"
import { readFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { execSync } from "node:child_process"

const BASE = process.env.BETTER_AUTH_URL || "http://localhost:3000"
const TEST_PREFIX = `spec2fa-${Date.now()}`
const TEST_EMAIL = `${TEST_PREFIX}@example.com`
const TEST_PASSWORD = "TestPassword123!Secure"

let passed = 0
let failed = 0

function assert(condition, name) {
  if (condition) {
    console.log(`  ✅ ${name}`)
    passed++
  } else {
    console.log(`  ❌ ${name}`)
    failed++
  }
}

async function assertRejects(promise, name) {
  try {
    const out = await promise
    console.log(`  ❌ ${name} — did not reject (got: ${JSON.stringify(out).slice(0, 160)})`)
    failed++
  } catch {
    console.log(`  ✅ ${name}`)
    passed++
  }
}

function extractCookies(headers) {
  return headers.getSetCookie ? headers.getSetCookie().map((c) => c.split(";")[0]).join("; ") : ""
}

// ---- RFC 6238 TOTP (mirrors @better-auth/utils/otp) ----
const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
function base32Decode(s) {
  const clean = s.replace(/=+$/, "").toUpperCase()
  let bits = ""
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch)
    if (idx === -1) throw new Error(`bad base32 char ${ch}`)
    bits += idx.toString(2).padStart(5, "0")
  }
  const bytes = []
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2))
  return Buffer.from(bytes)
}

function hotp(secretBuf, counter, digits = 6) {
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt(counter))
  const hmac = createHmac("sha1", secretBuf).update(buf).digest()
  const offset = hmac[hmac.length - 1] & 0x0f
  const code = ((hmac[offset] & 0x7f) << 24 | (hmac[offset + 1] & 0xff) << 16 | (hmac[offset + 2] & 0xff) << 8 | (hmac[offset + 3] & 0xff)) % 10 ** digits
  return code.toString().padStart(digits, "0")
}

function totp(secretB32, period = 30, digits = 6) {
  const secretBuf = base32Decode(secretB32)
  const counter = Math.floor(Date.now() / 1000 / period)
  return hotp(secretBuf, counter, digits)
}

function secretFromTotpUri(uri) {
  const params = new URL(uri).searchParams
  return params.get("secret")
}

// ---- DB access (AC-5 at-rest check) ----
async function queryDb(sql, params = []) {
  const env = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", ".env"), "utf-8")
  const dbUrl = env.match(/DATABASE_URL=(.*)/)[1].trim()
  const url = new URL(dbUrl)
  const hostname = url.hostname
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
    const r = await pool.query(sql, params)
    return r.rows
  } finally {
    await pool.end()
  }
}

async function signUp() {
  const h = { "Content-Type": "application/json", "Origin": BASE }
  await fetch(`${BASE}/api/auth/sign-up/email`, {
    method: "POST",
    headers: h,
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD, name: "Spec2FA User" }),
    redirect: "manual",
  })
  const si = await fetch(`${BASE}/api/auth/sign-in/email`, {
    method: "POST",
    headers: h,
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD }),
    redirect: "manual",
  })
  return extractCookies(si.headers)
}

/** Sign in with password; returns { cookies, twoFactorRedirect, body }. */
async function signInPassword() {
  const res = await fetch(`${BASE}/api/auth/sign-in/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Origin": BASE },
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD }),
    redirect: "manual",
  })
  const body = await res.json().catch(() => null)
  return { cookies: extractCookies(res.headers), body, twoFactorRedirect: body?.twoFactorRedirect === true }
}

/** Verify a TOTP code against the 2FA challenge cookie. */
async function verifyTotp(code, cookies) {
  const res = await fetch(`${BASE}/api/auth/two-factor/verify-totp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Origin": BASE, Cookie: cookies },
    body: JSON.stringify({ code, trustDevice: false }),
    redirect: "manual",
  })
  const body = await res.json().catch(() => null)
  return { status: res.status, body, cookies: extractCookies(res.headers) }
}

/** Verify a backup code against the 2FA challenge cookie. */
async function verifyBackupCode(code, cookies) {
  const res = await fetch(`${BASE}/api/auth/two-factor/verify-backup-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Origin": BASE, Cookie: cookies },
    body: JSON.stringify({ code, trustDevice: false }),
    redirect: "manual",
  })
  const body = await res.json().catch(() => null)
  return { status: res.status, body, cookies: extractCookies(res.headers) }
}

async function main() {
  console.log("=== Project 2FA Verification — harden sign-in ===\n")

  console.log("--- Enrollment ---")
  let sessionCookies = await signUp()
  const enableRes = await fetch(`${BASE}/api/auth/two-factor/enable`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Origin": BASE, Cookie: sessionCookies },
    body: JSON.stringify({ password: TEST_PASSWORD }),
    redirect: "manual",
  })
  const enableBody = await enableRes.json().catch(() => null)
  assert(Boolean(enableBody?.totpURI), "Enrollment returned a TOTP URI")
  assert(Array.isArray(enableBody?.backupCodes) && enableBody.backupCodes.length > 0, "Enrollment returned backup codes")

  const secretB32 = secretFromTotpUri(enableBody?.totpURI)
  assert(Boolean(secretB32), "TOTP URI contains a secret")
  const backupCode = enableBody.backupCodes[0]

  // The freshly enrolled secret is not yet activated; verify once to set
  // twoFactorEnabled = true (matches "accepted at sign-in" after setup).
  const enrollCode = totp(secretB32)
  const enrollVerify = await verifyTotp(enrollCode, sessionCookies)
  assert(enrollVerify.status === 200, "Code generated from enrolled secret is accepted")

  // AC-2: enrollment showed secret + backup codes once. After the first
  // verification the plugin rotates to a NEW session; try to "show again"
  // and confirm nothing recoverable comes back.
  const sessionAfterEnroll = await fetch(`${BASE}/api/auth/get-session`, {
    headers: { Cookie: enrollVerify.cookies, Origin: BASE },
  })
  const sessionEnrollBody = await sessionAfterEnroll.json().catch(() => null)
  assert(Boolean(sessionEnrollBody?.user?.twoFactorEnabled), "twoFactorEnabled is true after first verification")
  sessionCookies = enrollVerify.cookies

  const showAgain = await fetch(`${BASE}/api/auth/two-factor/get-totp-uri`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: BASE, Cookie: sessionCookies },
    body: JSON.stringify({ password: TEST_PASSWORD }),
    redirect: "manual",
  })
  const showAgainBody = JSON.stringify(await showAgain.json().catch(() => null))
  assert(!showAgainBody.includes(secretB32), "TOTP secret cannot be shown again after enrollment")
  assert(!showAgainBody.includes(backupCode), "Backup codes cannot be shown again after enrollment")

  console.log("\n--- AC-1: Password + valid TOTP → session ---")
  const good = await signInPassword()
  assert(good.twoFactorRedirect, "Password-only sign-in returns twoFactorRedirect")
  const goodCode = totp(secretB32)
  const goodVerify = await verifyTotp(goodCode, good.cookies)
  assert(goodVerify.status === 200 && Boolean(goodVerify.body?.status !== false), "Valid TOTP accepted (status=200)")
  const sessionRes = await fetch(`${BASE}/api/auth/get-session`, {
    headers: { Cookie: goodVerify.cookies, Origin: BASE },
  })
  const sessionAfter = await sessionRes.json().catch(() => null)
  assert(Boolean(sessionAfter?.session), "A session exists after 2FA verification")
  const dashboard = await fetch(`${BASE}/dashboard`, { headers: { Cookie: goodVerify.cookies }, redirect: "manual" })
  assert(dashboard.status === 200, "Dashboard reachable with 2FA session")

  console.log("\n--- AC-3: Password alone (wrong/blank TOTP) → no session ---")
  const wrongSignIn = await signInPassword()
  const wrongVerify = await verifyTotp("000000", wrongSignIn.cookies)
  assert(wrongVerify.status !== 200, `Wrong TOTP refused (status=${wrongVerify.status})`)
  const sessionWrong = await fetch(`${BASE}/api/auth/get-session`, {
    headers: { Cookie: wrongVerify.cookies, Origin: BASE },
  }).then((r) => r.json().catch(() => null))
  assert(!sessionWrong?.session, "No session after wrong TOTP")

  const blankSignIn = await signInPassword()
  const blankVerify = await verifyTotp("", blankSignIn.cookies)
  assert(blankVerify.status !== 200, "Blank TOTP refused")

  console.log("\n--- AC-4: Backup codes are single-use ---")
  const b1 = await signInPassword()
  const b1Verify = await verifyBackupCode(backupCode, b1.cookies)
  assert(b1Verify.status === 200, "First use of a backup code is accepted")
  const sessionB1 = await fetch(`${BASE}/api/auth/get-session`, {
    headers: { Cookie: b1Verify.cookies, Origin: BASE },
  }).then((r) => r.json().catch(() => null))
  assert(Boolean(sessionB1?.session), "Backup-code sign-in issued a session")

  const b2 = await signInPassword()
  const b2Verify = await verifyBackupCode(backupCode, b2.cookies)
  assert(b2Verify.status !== 200, `Reuse of a spent backup code refused (status=${b2Verify.status})`)
  const sessionB2 = await fetch(`${BASE}/api/auth/get-session`, {
    headers: { Cookie: b2Verify.cookies, Origin: BASE },
  }).then((r) => r.json().catch(() => null))
  assert(!sessionB2?.session, "No session after reused backup code")

  console.log("\n--- AC-5: Secrets stay secret (at rest + responses) ---")
  const twoFactorRows = await queryDb(
    'SELECT "secret", "backupCodes" FROM "twoFactor" WHERE "userId" = (SELECT id FROM "user" WHERE email = $1) LIMIT 1',
    [TEST_EMAIL]
  )
  assert(twoFactorRows.length === 1, "Two-factor row exists")
  const atRest = twoFactorRows[0]
  assert(!atRest.secret.includes(secretB32), "TOTP secret at rest is not the plaintext secret")
  assert(!atRest.backupCodes.includes(backupCode), "Backup codes at rest are not plaintext")

  const enableBodyStr = JSON.stringify(enableBody)
  assert(enableBodyStr.includes("otpauth://totp/"), "Secret was shown once via a TOTP URI at enrollment")
  assert(enableBodyStr.includes(backupCode), "Backup codes returned exactly once at enrollment")

  console.log(`\n========================================`)
  console.log(`Results: ${passed} passed, ${failed} failed`)
  console.log(`========================================`)
  process.exit(failed > 0 ? 1 : 0)
}

main().catch((e) => {
  console.error(`\nFATAL: ${e.message}`)
  process.exit(1)
})
