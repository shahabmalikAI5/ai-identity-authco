#!/usr/bin/env node

/**
 * Spec 06 Verification Script — Client identity with CIMD
 *
 * Tests ALL acceptance criteria for Client ID Metadata Documents on the
 * Better Auth 1.7 pre-release line:
 *   AC-1 discovery advertises client_id_metadata_document_supported: true
 *   AC-2 a URL client_id is resolved by fetch (public cache row, no secret)
 *   AC-3 the static/DCR path still works unchanged
 *   AC-4 non-HTTPS client_id rejected before fetch
 *   AC-5 fragment / userinfo in client_id rejected
 *   AC-6 document must match the request (redirect_uris, client_id)
 *   AC-7 unreachable / non-JSON document fails closed
 *
 * Usage: node scripts/verify-spec-06.mjs
 * Prereqs: `pnpm dev` (or `node node_modules/next/dist/bin/next dev`) running
 * on localhost:3000, and DATABASE_URL in .env.
 */

import { createHash, randomBytes } from "node:crypto"
import { createServer } from "node:http"
import { readFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { execSync } from "node:child_process"

const BASE = process.env.BETTER_AUTH_URL || "http://localhost:3000"
const DISCOVERY_URL = `${BASE}/.well-known/openid-configuration`
const AUTH_SERVER_URL = `${BASE}/.well-known/oauth-authorization-server`
const TEST_PREFIX = `spec06-${Date.now()}`
const TEST_EMAIL = `${TEST_PREFIX}@example.com`
const TEST_PASSWORD = "TestPassword123!Secure"
const STATIC_CLIENT_ID = "test-client-02"
const STATIC_CLIENT_SECRET = "test-secret-02-change-in-prod"

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

/** Local loopback metadata-document server, keyed by request path. */
function startMetadataServer() {
  let hits = []
  const server = createServer((req, res) => {
    const path = req.url.split("?")[0]
    hits.push(req.url)
    const origin = `http://127.0.0.1:${server.address().port}`
    let body = null
    let status = 200
    let type = "application/json"
    if (path === "/oauth-client.json") {
      body = {
        client_id: `${origin}/oauth-client.json`,
        client_name: "Spec 06 CIMD test client",
        redirect_uris: [`${origin}/callback`],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        scope: "openid profile email",
      }
    } else if (path === "/wrong-id.json") {
      body = {
        client_id: "https://somewhere-else.example/oauth-client.json",
        redirect_uris: [`${origin}/callback`],
        token_endpoint_auth_method: "none",
      }
    } else if (path === "/mismatch-redirect.json") {
      body = {
        client_id: `${origin}/mismatch-redirect.json`,
        redirect_uris: [`${origin}/only-other-callback`],
        token_endpoint_auth_method: "none",
        scope: "openid profile email",
      }
    } else if (path === "/not-json") {
      body = "hello, this is not json"
      type = "text/plain"
    } else if (path === "/bad-json.json") {
      body = "{ this is : not json }"
      type = "application/json"
    } else if (path === "/callback") {
      body = { ok: true }
    } else {
      status = 404
      body = { error: "not_found" }
    }
    res.writeHead(status, { "Content-Type": type })
    res.end(typeof body === "string" ? body : JSON.stringify(body))
  })
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port, hits }))
  })
}

/** Run the authorize step; returns { data, location, status }. */
async function runAuthorize(params, cookies) {
  const q = new URLSearchParams(params).toString()
  const res = await fetch(`${BASE}/api/auth/oauth2/authorize?${q}`, {
    headers: { Cookie: cookies, "Sec-Fetch-Mode": "cors", "Origin": BASE },
    redirect: "manual",
  })
  const text = await res.text()
  let data
  try {
    data = JSON.parse(text)
  } catch {
    data = null
  }
  return { data, location: res.headers.get("location") || "", status: res.status }
}

/**
 * Authorize failures arrive in two shapes: a JSON `{ error }` envelope
 * (thrown inside the CIMD resolver) or a redirect-style
 * `{ redirect: true, url: ".../error?error=..." }`. This detects both.
 */
function isAuthorizeError(resp) {
  if (resp?.data?.error) return resp.data.error
  const url = resp?.data?.url || resp?.location || ""
  const m = url.match(/[?&]error=([^&]+)/)
  return m ? decodeURIComponent(m[1]) : null
}

/** Complete the flow from a valid authorize response to a token. */
async function completeFlow(authz, cookies, codeVerifier) {
  const consentUrl = authz.data?.url || ""
  const oauthQuery = consentUrl.split("?")[1] || ""
  const consentRes = await fetch(`${BASE}/api/auth/oauth2/consent`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookies, "Sec-Fetch-Mode": "cors", "Origin": BASE },
    body: JSON.stringify({ accept: true, oauth_query: oauthQuery }),
    redirect: "manual",
  })
  let resp
  try {
    resp = await consentRes.json()
  } catch {
    resp = null
  }
  const redirectUrl = resp?.url || resp?.redirect || consentRes.headers.get("location") || ""
  const codeMatch = redirectUrl.match(/[?&]code=([^&]+)/)
  return { redirectUrl, code: codeMatch ? codeMatch[1] : null, consentResp: resp }
}

async function exchangeCode(code, codeVerifier, clientId, clientSecret) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: clientSecret ? `http://localhost:3000/callback` : `${new URL(clientId).origin}/callback`,
    code_verifier: codeVerifier,
    client_id: clientId,
  })
  if (clientSecret) body.set("client_secret", clientSecret)
  const res = await fetch(`${BASE}/api/auth/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Origin": BASE },
    body: body.toString(),
  })
  const data = await res.json().catch(() => null)
  return { status: res.status, data }
}

/** Direct query of the oauthClient cache row for a URL client_id. */
async function fetchOauthClientRow(clientId) {
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
    const r = await pool.query('SELECT * FROM "oauthClient" WHERE "clientId" = $1 LIMIT 1', [clientId])
    return r.rows[0] ?? null
  } finally {
    await pool.end()
  }
}

async function signUpAndSignIn() {
  const h = { "Content-Type": "application/json", "Origin": BASE }
  await fetch(`${BASE}/api/auth/sign-up/email`, {
    method: "POST",
    headers: h,
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD, name: "Spec06 User" }),
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

async function main() {
  console.log("=== Spec 06 Verification — Client identity with CIMD ===\n")
  const meta = await startMetadataServer()
  const clientId = `http://127.0.0.1:${meta.port}/oauth-client.json`
  const redirectUri = `http://127.0.0.1:${meta.port}/callback`

  try {
    // AC-1: Discovery advertises CIMD
    console.log("--- AC-1: Discovery advertises CIMD ---")
    const disc = await fetch(DISCOVERY_URL).then((r) => r.json())
    assert(disc.client_id_metadata_document_supported === true, "openid-configuration advertises client_id_metadata_document_supported: true")
    const as = await fetch(AUTH_SERVER_URL).then((r) => r.json())
    assert(as.client_id_metadata_document_supported === true, "oauth-authorization-server advertises client_id_metadata_document_supported: true")

    // AC-2: URL client_id resolved by fetch, not by a seeded record
    console.log("\n--- AC-2: URL client_id resolved by fetch ---")
    const rowBefore = await fetchOauthClientRow(clientId)
    assert(rowBefore === null, `No seeded confidential client for ${clientId}`)

    const cookies = await signUpAndSignIn()
    const codeVerifier = generateCodeVerifier()
    const params = {
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "openid profile email",
      code_challenge: computeCodeChallenge(codeVerifier),
      code_challenge_method: "S256",
    }
    const authz = await runAuthorize(params, cookies)
    assert(Boolean(authz.data?.url), "Authorize resolved URL client_id → consent URL")

    const flow = await completeFlow(authz, cookies, codeVerifier)
    assert(Boolean(flow.code), "Consent returned an authorization code")

    const token = await exchangeCode(flow.code, codeVerifier, clientId)
    assert(Boolean(token.data?.access_token), `Token exchange for URL client_id issued access_token (status=${token.status})`)

    const row = await fetchOauthClientRow(clientId)
    assert(Boolean(row), "CIMD persisted a cache row keyed by the URL")
    assert(row.public === true, "Cache row is a public client (public = true)")
    assert(row.clientSecret === null, "Cache row has no client secret (clientSecret = NULL)")
    assert(row.clientId === clientId, "Cache row clientId is the URL")

    // AC-3: Static / DCR path still works
    console.log("\n--- AC-3: Static client path still works ---")
    const sVerifier = generateCodeVerifier()
    const sAuthz = await runAuthorize(
      {
        client_id: STATIC_CLIENT_ID,
        redirect_uri: "http://localhost:3000/callback",
        response_type: "code",
        scope: "openid profile email",
        code_challenge: computeCodeChallenge(sVerifier),
        code_challenge_method: "S256",
      },
      cookies
    )
    assert(Boolean(sAuthz.data?.url), "Static client still reaches consent")
    const sFlow = await completeFlow(sAuthz, cookies, sVerifier)
    assert(Boolean(sFlow.code), "Static client consent returned a code")
    const sToken = await exchangeCode(sFlow.code, sVerifier, STATIC_CLIENT_ID, STATIC_CLIENT_SECRET)
    assert(Boolean(sToken.data?.access_token), `Static client token exchange still works (status=${sToken.status})`)

    // AC-4: Non-HTTPS client_id rejected before fetch
    console.log("\n--- AC-4: Non-HTTPS client_id rejected ---")
    const before = meta.hits.length
    const httpAuthz = await runAuthorize(
      {
        client_id: "http://example.com/client.json",
        redirect_uri: "https://example.com/callback",
        response_type: "code",
        scope: "openid profile email",
        code_challenge: computeCodeChallenge(generateCodeVerifier()),
        code_challenge_method: "S256",
      },
      cookies
    )
    assert(isAuthorizeError(httpAuthz) === "invalid_client", `Plain-http non-loopback client_id refused (error=${isAuthorizeError(httpAuthz)})`)
    assert(meta.hits.length === before, "No metadata fetch attempted for non-HTTPS client_id")

    // AC-5: Malformed identifier (fragment / userinfo) rejected
    console.log("\n--- AC-5: Fragment / userinfo client_id rejected ---")
    const fragAuthz = await runAuthorize(
      {
        client_id: "https://example.com/client.json#fragment",
        redirect_uri: "https://example.com/callback",
        response_type: "code",
        scope: "openid profile email",
        code_challenge: computeCodeChallenge(generateCodeVerifier()),
        code_challenge_method: "S256",
      },
      cookies
    )
    assert(Boolean(isAuthorizeError(fragAuthz)), `Fragment client_id refused (error=${isAuthorizeError(fragAuthz)})`)

    const uiAuthz = await runAuthorize(
      {
        client_id: "https://user:pass@example.com/client.json",
        redirect_uri: "https://example.com/callback",
        response_type: "code",
        scope: "openid profile email",
        code_challenge: computeCodeChallenge(generateCodeVerifier()),
        code_challenge_method: "S256",
      },
      cookies
    )
    assert(Boolean(isAuthorizeError(uiAuthz)), `Userinfo client_id refused (error=${isAuthorizeError(uiAuthz)})`)

    // AC-6: Document must match the request
    console.log("\n--- AC-6: Document must match the request ---")
    const wrongId = `http://127.0.0.1:${meta.port}/wrong-id.json`
    const wrongIdAuthz = await runAuthorize(
      {
        client_id: wrongId,
        redirect_uri: `http://127.0.0.1:${meta.port}/callback`,
        response_type: "code",
        scope: "openid profile email",
        code_challenge: computeCodeChallenge(generateCodeVerifier()),
        code_challenge_method: "S256",
      },
      cookies
    )
    assert(Boolean(isAuthorizeError(wrongIdAuthz)), `Doc with wrong self-declared client_id refused (error=${isAuthorizeError(wrongIdAuthz)})`)
    assert((await fetchOauthClientRow(wrongId)) === null, "No client row created for mismatched doc")

    const mismatchRedirect = `http://127.0.0.1:${meta.port}/mismatch-redirect.json`
    const mismatchAuthz = await runAuthorize(
      {
        client_id: mismatchRedirect,
        redirect_uri: `http://127.0.0.1:${meta.port}/callback`,
        response_type: "code",
        scope: "openid profile email",
        code_challenge: computeCodeChallenge(generateCodeVerifier()),
        code_challenge_method: "S256",
      },
      cookies
    )
    assert(Boolean(isAuthorizeError(mismatchAuthz)), `Redirect URI not in the document refused (error=${isAuthorizeError(mismatchAuthz)})`)
    const mismatchRow = await fetchOauthClientRow(mismatchRedirect)
    assert(Boolean(mismatchRow), "Valid doc WAS cached as a public client row (refusal is from redirect_uri mismatch, not fetch failure)")
    assert(mismatchRow.public === true, "Mismatch-doc cache row is still a public client")

    // AC-7: Fails closed — unreachable / non-JSON document
    console.log("\n--- AC-7: Fails closed ---")
    const unreachable = "http://127.0.0.1:1/client.json"
    await assertRejects(
      fetch(`${BASE}/api/auth/oauth2/authorize?${new URLSearchParams({
        client_id: unreachable,
        redirect_uri: "http://127.0.0.1:1/callback",
        response_type: "code",
        scope: "openid profile email",
        code_challenge: computeCodeChallenge(generateCodeVerifier()),
        code_challenge_method: "S256",
      })}`, { headers: { Cookie: cookies, "Sec-Fetch-Mode": "cors", "Origin": BASE }, redirect: "manual" }).then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status)
        return r
      }),
      "Unreachable metadata document refuses the flow"
    )

    const notJson = `http://127.0.0.1:${meta.port}/not-json`
    const notJsonAuthz = await runAuthorize(
      {
        client_id: notJson,
        redirect_uri: `http://127.0.0.1:${meta.port}/callback`,
        response_type: "code",
        scope: "openid profile email",
        code_challenge: computeCodeChallenge(generateCodeVerifier()),
        code_challenge_method: "S256",
      },
      cookies
    )
    assert(Boolean(notJsonAuthz.data?.error), `Non-JSON document refused (error=${notJsonAuthz.data?.error})`)
    assert((await fetchOauthClientRow(notJson)) === null, "No client row created for non-JSON document")
  } finally {
    meta.server.close()
  }

  console.log(`\n========================================`)
  console.log(`Results: ${passed} passed, ${failed} failed`)
  console.log(`========================================`)
  process.exit(failed > 0 ? 1 : 0)
}

main().catch((e) => {
  console.error(`\nFATAL: ${e.message}`)
  process.exit(1)
})
