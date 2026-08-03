"use client"

import { useSearchParams } from "next/navigation"
import { useState, Suspense, useMemo } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"

const SCOPE_LABELS: Record<string, string> = {
  openid: "Sign in with your identity",
  profile: "View your basic profile information",
  email: "View your email address",
  offline_access: "Remember your access (offline)",
  "notes.read": "Read your notes",
  "notes.write": "Create and modify your notes",
}

function ConsentForm() {
  const searchParams = useSearchParams()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const { oauthQuery, clientId, scopes } = useMemo(() => {
    const rawQuery = new URLSearchParams(window.location?.search ?? "")
    const oq = rawQuery.toString()
    const scopeStr = rawQuery.get("scope") || ""
    const scopes = scopeStr.split(" ").filter(Boolean)
    const clientId = rawQuery.get("client_id") || "Unknown client"
    return { oauthQuery: oq, clientId, scopes }
  }, [searchParams])

  if (!oauthQuery) {
    return (
      <div className="flex flex-1 items-center justify-center px-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Bad Request</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground">
              Missing authorization query. Please try again.
            </p>
          </CardContent>
        </Card>
      </div>
    )
  }

  async function handleConsent(accept: boolean) {
    setLoading(true)
    setError("")

    const res = await fetch("/api/auth/oauth2/consent", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ accept, oauth_query: oauthQuery }),
      credentials: "include",
    })

    const data = await res.json().catch(() => null)

    if (data?.url) {
      window.location.href = data.url
    } else if (!accept) {
      setError("Access denied. You can close this page.")
    } else {
      setError(data ? JSON.stringify(data) : "Consent failed")
    }

    setLoading(false)
  }

  return (
    <div className="flex flex-1 items-center justify-center px-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Authorize Application</CardTitle>
          <CardDescription>
            <span className="font-mono text-sm">{clientId}</span> is requesting access to:
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="mb-4 space-y-1">
            {scopes.map((scope) => (
              <li key={scope} className="text-sm flex items-start gap-2">
                <span className="text-muted-foreground mt-0.5">•</span>
                <span>{SCOPE_LABELS[scope] || scope}</span>
              </li>
            ))}
          </ul>
          {error && <p className="text-sm text-red-500 mb-4">{error}</p>}
          <div className="flex gap-2">
            <Button
              variant="outline"
              onClick={() => handleConsent(false)}
              disabled={loading}
              className="flex-1"
            >
              Deny
            </Button>
            <Button
              onClick={() => handleConsent(true)}
              disabled={loading}
              className="flex-1"
            >
              Allow
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

export default function ConsentPage() {
  return (
    <Suspense fallback={<div className="flex flex-1 items-center justify-center"><p>Loading...</p></div>}>
      <ConsentForm />
    </Suspense>
  )
}
