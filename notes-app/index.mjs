import "dotenv/config"
import express from "express"
import cookieParser from "cookie-parser"
import crypto from "node:crypto"
import { generatePKCE, authorizeURL, exchangeCode } from "./lib/oauth.mjs"
import { verifyToken } from "./lib/verify.mjs"

const app = express()
const PORT = process.env.PORT || 3001
const NOTES_SECRET = process.env.NOTES_SECRET

app.set("view engine", "ejs")
app.set("views", new URL("views", import.meta.url).pathname)
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser(NOTES_SECRET))

function signCookie(data) {
  const str = JSON.stringify(data)
  return Buffer.from(str).toString("base64url") + "." + hmac(str)
}

function unsignCookie(signed) {
  if (!signed || !signed.includes(".")) return null
  const [encoded, mac] = signed.split(".")
  const str = Buffer.from(encoded, "base64url").toString()
  if (hmac(str) !== mac) return null
  try { return JSON.parse(str) } catch { return null }
}

function hmac(str) {
  return crypto.createHmac("sha256", NOTES_SECRET).update(str).digest("base64url")
}

app.get("/", (req, res) => {
  const { verifier, challenge } = generatePKCE()
  const url = authorizeURL({ challenge })
  res.cookie("pkce_verifier", verifier, {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    maxAge: 5 * 60 * 1000,
  })
  res.render("home", { authorizeUrl: url })
})

app.get("/callback", async (req, res) => {
  const { code, error: errParam } = req.query
  if (errParam) {
    return res.render("callback", { message: `Auth error: ${errParam}`, redirect: "/" })
  }
  if (!code) {
    return res.render("callback", { message: "Missing authorization code", redirect: "/" })
  }
  const verifier = req.signedCookies?.pkce_verifier || req.cookies?.pkce_verifier
  if (!verifier) {
    return res.render("callback", { message: "Missing PKCE verifier (session expired?)", redirect: "/" })
  }
  try {
    const tokens = await exchangeCode(code, verifier)
    const user = await verifyToken(tokens.id_token)
    const session = signCookie({ sub: user.sub, name: user.name, email: user.email })
    res.cookie("notes_session", session, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 24 * 60 * 60 * 1000,
    })
    res.render("callback", { message: "Signed in!", redirect: "/dashboard" })
  } catch (err) {
    console.error("Callback error:", err)
    res.render("callback", { message: `Sign-in failed: ${err.message}`, redirect: "/" })
  }
})

app.get("/dashboard", (req, res) => {
  const session = unsignCookie(req.signedCookies?.notes_session || req.cookies?.notes_session)
  if (!session) {
    return res.redirect("/")
  }
  res.render("dashboard", { user: session })
})

app.post("/logout", (req, res) => {
  res.clearCookie("notes_session")
  res.redirect("/")
})

app.listen(PORT, () => {
  console.log(`Notes app running at http://localhost:${PORT}`)
})
