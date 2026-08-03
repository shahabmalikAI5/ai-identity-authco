import { betterAuth } from "better-auth"
import { Pool } from "pg"
import { nextCookies } from "better-auth/next-js"
import { jwt } from "better-auth/plugins/jwt"
import { twoFactor } from "better-auth/plugins/two-factor"
import { oauthProvider } from "@better-auth/oauth-provider"
import { cimd } from "@better-auth/cimd"
import { agentAuth } from "@better-auth/agent-auth"
import { execSync } from "child_process"
import { randomUUID } from "node:crypto"

const notes = new Map<
  string,
  { id: string; title: string; body: string; createdBy: string; createdByAgent: string; createdAt: string }
>()

const shares = new Map<
  string,
  { id: string; noteId: string; recipientDomain: string; sharedByAgent: string; createdAt: string }
>()

const signatures = new Map<
  string,
  { id: string; noteId: string; signedByAgent: string; signedBy: string; createdAt: string }
>()

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
    console.log(`[auth] Resolved ${hostname} → ${neonIP}`)
  } else {
    console.warn(`[auth] dig returned unexpected: "${raw}", using hostname`)
  }
} catch (e) {
  console.warn(`[auth] DNS resolution failed: ${e instanceof Error ? e.message : String(e)}. Using hostname.`)
}

const user = decodeURIComponent(url.username)
const password = decodeURIComponent(url.password)
const database = url.pathname.replace(/^\//, "")

export const auth = betterAuth({
  appName: "AuthCo",
  baseURL: process.env.BETTER_AUTH_URL || "http://localhost:3000",
  disabledPaths: ["/two-factor/get-totp-uri"],
  database: new Pool({
    host: neonIP,
    port: Number(url.port) || 5432,
    user,
    password,
    database,
    ssl:
      ["localhost", "127.0.0.1"].includes(hostname)
        ? undefined
        : { rejectUnauthorized: false, servername: hostname },
    connectionTimeoutMillis: 30000,
    max: 5,
  }),
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 12,
  },
  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID as string,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
      ...(process.env.GOOGLE_TEST_MODE === "true"
        ? {
            // Test seam (GOOGLE_TEST_MODE=true, acceptance harness only):
            // skip the live Google token/JWKS exchange and accept a locally
            // minted id_token, decoding its claims as the provider profile.
            // Inert in production: Better Auth uses Google's real verification.
            verifyIdToken: async (token: string) => {
              const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString())
              return payload !== null
            },
            getUserInfo: async ({ idToken }) => {
              const payload = JSON.parse(Buffer.from(String(idToken).split(".")[1], "base64url").toString())
              return {
                user: {
                  id: payload.sub,
                  name: payload.name,
                  email: payload.email,
                  image: payload.picture,
                  emailVerified: payload.email_verified === true,
                },
                data: payload,
              }
            },
          }
        : {}),
    },
  },
  plugins: [
    jwt({
      jwks: {
        keyPairConfig: {
          alg: "RS256",
          modulusLength: 2048,
        },
      },
      jwt: {
        issuer: process.env.BETTER_AUTH_URL,
        audience: process.env.RESOURCE_URL,
        expirationTime: "1h",
        getSubject: (session) => session.user.id,
        definePayload: ({ user }) => ({
          id: user.id,
          email: user.email,
          name: user.name,
        }),
      },
    }),
    oauthProvider({
      loginPage: "/sign-in",
      consentPage: "/consent",
      scopes: ["openid", "profile", "email", "offline_access", "notes.read", "notes.write"],
      silenceWarnings: {
        oauthAuthServerConfig: true,
        openidConfig: true,
      },
    }),
    cimd({ allowLoopback: true }),
    agentAuth({
      providerName: "AuthCo",
      providerDescription:
        "AuthCo note capabilities for AI agents. Read, create, and delete notes under an autonomous agent identity or on behalf of an approving human (delegated).",
      modes: ["delegated", "autonomous"],
      deviceAuthorizationPage: "/device/capabilities",
      // Step-up (proof of physical presence). Env-gated: on by explicit flag only
      // (specs/projects/step-up-approval). With it on, approving a capability whose
      // approvalStrength is "webauthn" requires a WebAuthn assertion; without a
      // registered passkey the approval is refused with webauthn_not_enrolled.
      // Off by default so the on-behalf-of approval flow (pending host + session
      // approval) keeps working unchanged.
      proofOfPresence:
        process.env.STEP_UP_PROOF_OF_PRESENCE === "true"
          ? { enabled: true, rpId: process.env.STEP_UP_RP_ID }
          : undefined,
      capabilities: [
        {
          name: "note.read",
          description: "List all notes the agent can see. Auto-granted (no human approval) via the host capability budget.",
          approvalStrength: "none",
          grantTTL: 3600,
          output: {
            type: "object",
            properties: {
              notes: {
                type: "array",
                items: { type: "object" },
              },
            },
          },
        },
        {
          name: "note.create",
          description: "Create a note. Requires title; body is optional.",
          grantTTL: 3600,
          input: {
            type: "object",
            properties: {
              title: { type: "string", minLength: 1 },
              body: { type: "string" },
            },
            required: ["title"],
          },
        },
        {
          name: "note.delete",
          description: "Delete a note by id. Not granted by default.",
          grantTTL: 3600,
          input: {
            type: "object",
            properties: {
              id: { type: "string" },
            },
            required: ["id"],
          },
        },
        {
          name: "note.share",
          description:
            "Share a note with a recipient. Requires an explicit allowed recipientDomain constraint; the constraint is enforced at execution time, so only in-scope domains ever get shared to.",
          approvalStrength: "session",
          requiredConstraints: ["recipientDomain"],
          grantTTL: 3600,
          input: {
            type: "object",
            properties: {
              noteId: { type: "string" },
              recipientDomain: { type: "string" },
            },
            required: ["noteId", "recipientDomain"],
          },
        },
        {
          name: "note.sign",
          description:
            "Sign a note (cryptographic receipt). A sensitive, single-use action: the grant is consumed on first successful execution.",
          approvalStrength: "session",
          grantTTL: 3600,
          input: {
            type: "object",
            properties: {
              noteId: { type: "string" },
            },
            required: ["noteId"],
          },
        },
        {
          name: "note.destroy",
          description:
            "Permanently destroy a note. Irreversible — requires proof of physical presence (WebAuthn) to approve; a normal logged-in session alone is refused. Single-use: consumed on execution.",
          approvalStrength: "webauthn",
          grantTTL: 3600,
          input: {
            type: "object",
            properties: {
              id: { type: "string" },
            },
            required: ["id"],
          },
        },
      ],
      allowDynamicHostRegistration: true,
      defaultHostCapabilities: ["note.read", "note.create"],
      resolveAutonomousUser: ({ hostName, agentId }) => ({
        id: `agent_${agentId}`,
        name: hostName ?? `agent_${agentId}`,
        email: `${agentId}@agents.authco.dev`,
        emailVerified: true,
      }),
      async onExecute({ capability, arguments: args, agentSession, revokeGrant }) {
        switch (capability) {
          case "note.read":
            return { notes: [...notes.values()] }
          case "note.create": {
            const id = randomUUID()
            notes.set(id, {
              id,
              title: String(args?.title ?? ""),
              body: String(args?.body ?? ""),
              createdBy: agentSession.user.id,
              createdByAgent: agentSession.agent.id,
              createdAt: new Date().toISOString(),
            })
            return { ok: true, id }
          }
          case "note.delete": {
            const removed = notes.delete(String(args?.id ?? ""))
            return { ok: removed }
          }
          case "note.share": {
            // The plugin already enforced grant.constraints against these args
            // before onExecute ran — an out-of-scope recipientDomain never reaches
            // this branch (and does not consume the grant). This is the business
            // side of the same contract.
            const id = randomUUID()
            shares.set(id, {
              id,
              noteId: String(args?.noteId ?? ""),
              recipientDomain: String(args?.recipientDomain ?? ""),
              sharedByAgent: agentSession.agent.id,
              createdAt: new Date().toISOString(),
            })
            return { ok: true, id }
          }
          case "note.sign": {
            const id = randomUUID()
            signatures.set(id, {
              id,
              noteId: String(args?.noteId ?? ""),
              signedByAgent: agentSession.agent.id,
              signedBy: agentSession.user.id,
              createdAt: new Date().toISOString(),
            })
            // Single-use: consume the grant that authorized this execution so the
            // next call must be re-approved.
            await revokeGrant()
            return { ok: true, id, noteId: String(args?.noteId ?? "") }
          }
          case "note.destroy": {
            const removed = notes.delete(String(args?.id ?? ""))
            await revokeGrant()
            return { ok: removed }
          }
          default:
            throw new Error(`Unsupported capability: ${capability}`)
        }
      },
    }),
    twoFactor({
      issuer: "AuthCo",
      backupCodeOptions: {
        storeBackupCodes: "encrypted",
      },
    }),
    nextCookies(),
  ],
})
