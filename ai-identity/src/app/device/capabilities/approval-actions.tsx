"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button, buttonVariants } from "@/components/ui/button"

const CAPABILITY_LABELS: Record<string, string> = {
  "note.read": "Read notes on your behalf (auto-granted)",
  "note.create": "Create notes on your behalf",
  "note.delete": "Delete notes on your behalf",
  "note.share": "Share a note (recipient domain restricted)",
  "note.sign": "Sign a note (single-use)",
  "note.destroy": "Permanently destroy a note (requires passkey)",
}

export function ApprovalActions({
  agentId,
  code,
  agentName,
  agentMode,
  capabilities,
}: {
  agentId: string
  code: string
  agentName: string | null
  agentMode: string | null
  capabilities: string[]
}) {
  const [loading, setLoading] = useState<"approve" | "deny" | null>(null)
  const [error, setError] = useState("")
  const [done, setDone] = useState(false)

  async function handle(action: "approve" | "deny") {
    setLoading(action)
    setError("")

    const res = await fetch("/api/auth/agent/approve-capability", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({
        agent_id: agentId,
        user_code: code,
        action,
      }),
    })

    const data = await res.json().catch(() => null)

    // The agent-auth plugin serializes refusals (e.g. webauthn_not_enrolled for
    // a capability that needs physical presence) as an HTTP 200 body with an
    // `error` field — so treat any error-bearing body as a refusal, not a success.
    if (res.ok && !data?.error) {
      setDone(true)
      setLoading(null)
      return
    }

    setError(data?.message ?? data?.error ?? `Request failed (${res.status})`)
    setLoading(null)
  }

  if (done) {
    return (
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Decision recorded</CardTitle>
          <CardDescription>The device has been notified and can continue.</CardDescription>
        </CardHeader>
        <CardContent>
          <a href="/dashboard" className={buttonVariants()}>
            Go to dashboard
          </a>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="w-full max-w-md">
      <CardHeader>
        <CardTitle>Authorize agent</CardTitle>
        <CardDescription>
          {agentName ? (
            <>
              <span className="font-mono text-sm">{agentName}</span>{" "}
              {agentMode ? `(${agentMode})` : ""} is asking to act on your behalf.
            </>
          ) : (
            "A device is asking to act on your behalf."
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {capabilities.length > 0 ? (
          <ul className="mb-4 space-y-1">
            {capabilities.map((cap) => (
              <li key={cap} className="text-sm flex items-start gap-2">
                <span className="text-muted-foreground mt-0.5">•</span>
                <span>{CAPABILITY_LABELS[cap] || cap}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground mb-4">
            No pending capabilities were found for this request. It may already be decided.
          </p>
        )}
        <p className="text-xs text-muted-foreground mb-4">
          Device code: <span className="font-mono">{code}</span>
        </p>
        {error && <p className="text-sm text-red-500 mb-4">{error}</p>}
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => handle("deny")}
            disabled={loading !== null}
            className="flex-1"
          >
            {loading === "deny" ? "Denying..." : "Deny"}
          </Button>
          <Button
            onClick={() => handle("approve")}
            disabled={loading !== null}
            className="flex-1"
          >
            {loading === "approve" ? "Approving..." : "Approve"}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
