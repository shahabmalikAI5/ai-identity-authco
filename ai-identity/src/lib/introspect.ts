import { Pool } from "pg"
import { createHash } from "crypto"
import { execSync } from "child_process"

const dbUrl = process.env.DATABASE_URL!
const url = new URL(dbUrl)
const hostname = url.hostname

let neonIP = hostname
try {
  const raw = execSync(`dig +short ${hostname} | tail -1`, {
    encoding: "utf8",
    timeout: 5000,
  }).trim()
  if (/^\d+\.\d+\.\d+\.\d+$/.test(raw)) {
    neonIP = raw
    console.log(`[introspect] Resolved ${hostname} -> ${neonIP}`)
  }
} catch {
  console.warn(`[introspect] DNS resolution failed, using hostname`)
}

const user = decodeURIComponent(url.username)
const password = decodeURIComponent(url.password)
const database = url.pathname.replace(/^\//, "")

const pool = new Pool({
  host: neonIP,
  port: Number(url.port) || 5432,
  user,
  password,
  database,
  ssl: { rejectUnauthorized: false, servername: hostname },
  connectionTimeoutMillis: 30000,
  max: 5,
})

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest().toString("base64url")
}

export async function verifyTokenScope(
  token: string,
  requiredScope: string
): Promise<{ authorized: boolean; status: number; scopes: string[] }> {
  if (!token || token.length < 10) {
    return { authorized: false, status: 401, scopes: [] }
  }

  try {
    const hashed = hashToken(token)
    const result = await pool.query(
      `SELECT "scopes", "expiresAt", "revoked"
       FROM "oauthAccessToken"
       WHERE "token" = $1`,
      [hashed]
    )

    if (result.rowCount === 0) {
      return { authorized: false, status: 401, scopes: [] }
    }

    const row = result.rows[0]
    if (row.revoked || new Date(row.expiresAt) < new Date()) {
      return { authorized: false, status: 401, scopes: [] }
    }

    const scopes: string[] = row.scopes ?? []
    if (scopes.includes(requiredScope)) {
      return { authorized: true, status: 200, scopes }
    }

    return { authorized: false, status: 403, scopes }
  } catch (e) {
    console.error("[introspect] verifyTokenScope error:", e instanceof Error ? e.message : String(e))
    return { authorized: false, status: 401, scopes: [] }
  }
}
