import { jwtVerify, createRemoteJWKSet } from "jose"

const AUTHCO_URL = process.env.AUTHCO_URL
const AUTHCO_JWKS_URL = process.env.AUTHCO_JWKS_URL
const CLIENT_ID = process.env.CLIENT_ID

let jwks = null

function getJWKS() {
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(AUTHCO_JWKS_URL))
  }
  return jwks
}

export async function verifyToken(idToken, options = {}) {
  const opts = {
    issuer: `${AUTHCO_URL}/api/auth`,
    audience: CLIENT_ID,
    ...options,
  }
  const { payload } = await jwtVerify(idToken, getJWKS(), opts)
  return {
    sub: payload.sub,
    aud: payload.aud,
    iss: payload.iss,
    exp: payload.exp,
    email: payload.email,
    name: payload.name,
    raw: payload,
  }
}
