# How to use AuthCo

## 1. Get a database
Create a free Neon project at [neon.tech](https://console.neon.tech), copy the connection string.

## 2. Configure
```bash
cp .env.example .env
# Fill in:
#   DATABASE_URL=postgresql://user:pass@ep-xxx-pooler.us-west-2.aws.neon.tech/db?sslmode=require
#   BETTER_AUTH_SECRET=<run: openssl rand -base64 32>
```

## 3. Install and migrate
```bash
pnpm install
pnpm dlx @better-auth/cli@latest migrate   # creates user, session, account, verification tables
```

## 4. Start
```bash
pnpm dev
# Open http://localhost:3000
# Go to /sign-up → create account → auto-redirects to /dashboard
```

## 5. Verify
```bash
# Without session
curl localhost:3000/api/me                    # → 401 Unauthorized

# After signing in (replace token from browser cookie)
curl -b 'better-auth.session_token=YOURTOKEN' localhost:3000/api/me  # → 200 + user

# Weak password
curl -X POST localhost:3000/api/auth/sign-up/email \
  -H "Content-Type: application/json" -H "Origin: http://localhost:3000" \
  -d '{"name":"T","email":"x@y.com","password":"short"}'  # → Password too short
```
