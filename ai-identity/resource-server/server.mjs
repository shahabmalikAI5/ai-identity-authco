import http from "node:http"
import { createRemoteJWKSet, jwtVerify } from "jose"

const PORT = Number(process.env.PORT || 8000)
const JWKS_URL = process.env.AUTH_JWKS_URL || "http://localhost:3000/api/auth/jwks"
const ISSUER = process.env.AUTH_ISSUER || "http://localhost:3000"
const AUDIENCE = process.env.RESOURCE_URL || `http://localhost:${PORT}`

const JWKS = createRemoteJWKSet(new URL(JWKS_URL))

const NOTES = {
  welcome: "Welcome to the protected notes API.",
}

function send(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" })
  res.end(JSON.stringify(body))
}

async function verifyBearer(req) {
  const header = req.headers.authorization || ""
  if (!header.startsWith("Bearer ")) {
    return { error: { status: 401, code: "missing_token", detail: "Provide an Authorization: Bearer <token> header" } }
  }
  const token = header.slice(7)
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ["RS256"],
    })
    return { payload }
  } catch (e) {
    return { error: { status: 401, code: "invalid_token", detail: e.message } }
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`)

  if (req.method === "GET" && url.pathname === "/health") {
    return send(res, 200, { status: "ok" })
  }

  if (req.method === "GET" && url.pathname === "/api/notes") {
    const { payload, error } = await verifyBearer(req)
    if (error) return send(res, error.status, { error: error.code, detail: error.detail })
    return send(res, 200, {
      sub: payload.sub,
      notes: NOTES,
      message: `Serving notes to ${payload.sub}`,
    })
  }

  send(res, 404, { error: "not_found", detail: `No route for ${req.method} ${url.pathname}` })
})

server.listen(PORT, () => {
  console.log(`[resource-server] listening on http://localhost:${PORT}`)
  console.log(`[resource-server] jwks=${JWKS_URL} issuer=${ISSUER} audience=${AUDIENCE}`)
})
