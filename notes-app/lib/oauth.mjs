import crypto from "node:crypto"

const CLIENT_ID = process.env.CLIENT_ID
const CLIENT_SECRET = process.env.CLIENT_SECRET
const AUTHCO_URL = process.env.AUTHCO_URL

export function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString("base64url")
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url")
  return { verifier, challenge }
}

export function authorizeURL({ challenge, state }) {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: "http://localhost:3001/callback",
    code_challenge: challenge,
    code_challenge_method: "S256",
    scope: "openid profile email",
    state: state || crypto.randomBytes(16).toString("hex"),
  })
  return `${AUTHCO_URL}/api/auth/oauth2/authorize?${params}`
}

export async function exchangeCode(code, verifier) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: "http://localhost:3001/callback",
    code_verifier: verifier,
  })
  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")
  const res = await fetch(`${AUTHCO_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`token exchange failed (${res.status}): ${text}`)
  }
  return res.json()
}

export async function revokeToken(token) {
  const body = new URLSearchParams({ token, token_type_hint: "access_token" })
  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")
  const res = await fetch(`${AUTHCO_URL}/api/auth/oauth2/revoke`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`revocation failed (${res.status}): ${text}`)
  }
  return true
}
