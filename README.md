# ai-identity-authco

A production-grade **AI identity provider** — human sign-in and agent access, end to end.

This repo is a monorepo of two apps built around one idea: **whose identity is this, and how does authority pass from a human to an agent?**

- `ai-identity/` — **AuthCo**, the identity server: email/password sign-in, an OIDC/OAuth issuer, scopes & consent, CIMD client discovery, 2FA, Google social login, and AI agent auth (autonomous + on-behalf-of + step-up approval).
- `notes-app/` — a separate client app that signs in **with AuthCo** via PKCE and verifies tokens offline against AuthCo's JWKS, holding zero of AuthCo's secrets.

## What it does

| Layer | Capability |
|-------|-----------|
| 🚪 Human sign-in | Email/password with one-way hashed passwords, server-side sessions, protected dashboard, 2FA with single-use backup codes, "Continue with Google" |
| 🏛️ Issuer | OIDC/OAuth server minting signed RS256 tokens and publishing JWKS |
| 🎫 Resource server | Offline JWKS validation, audience-bound, rejects `alg: none` / HS256 confusion / tampered audiences |
| 🤖 Agent identity | Autonomous agents with short-lived self-signed credentials (replay refused), on-behalf-of delegation gated by human approval, value-constraints, WebAuthn step-up for destructive actions |
| ✅ Governed | Every grant is least-privilege, time-boxed, revocable — revocation actually stops the next call |

## Stack

- **AuthCo:** Next.js 16 (App Router), TypeScript, Tailwind, shadcn/ui, Better Auth 1.7 (`better-auth`, `@better-auth/oauth-provider`, `@better-auth/cimd`, `@better-auth/agent-auth`), Neon Postgres
- **notes-app:** Express + PKCE OAuth client + offline JWT verifier (jose)
- **resource-server:** standalone RS256 verifier (jose), audience-bound offline validation

## Quick start

```bash
# 1. Provision a free Neon Postgres database, copy the connection string
cp ai-identity/.env.example ai-identity/.env
#    fill in DATABASE_URL and BETTER_AUTH_SECRET (openssl rand -base64 32)

# 2. Install + migrate
cd ai-identity && pnpm install
pnpm dlx @better-auth/cli@latest migrate

# 3. Run AuthCo (http://localhost:3000)
pnpm dev
```

Then run the client app and resource server per the prompts in `ai-identity/notes/02-how-to-use.md`.

## Security verification

Each capability ships with an acceptance harness in `ai-identity/scripts/` (`verify-spec-*.mjs`) covering the **adversarial** gates, not just the happy path — token tampering, audience forgery, expired-token rejection, scope overreach, replay, and revocation.

## Notes

Two Better Auth 1.7 gotchas handled in `ai-identity/AGENTS.md`: pin `kysely` to `0.28.17` (pnpm override) and serve OIDC discovery from the issuer root via `.well-known` route handlers.
