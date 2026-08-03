"use client"

import { useState } from "react"
import Link from "next/link"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

type AgentRequest = {
  agent_id: string
  status: string
  granted?: boolean
  user_code?: string
  expires_in?: number
  verification_uri?: string
  verification_uri_complete?: string
}

const CAPABILITY_OPTIONS: { id: string; label: string; note: string; needsDomain?: boolean }[] = [
  { id: "note.read", label: "Read notes", note: "auto-grants — no human approval" },
  { id: "note.create", label: "Create notes", note: "needs your logged-in session" },
  {
    id: "note.share",
    label: "Share notes",
    note: "scoped to a recipient domain you name — enforced at execution",
    needsDomain: true,
  },
  { id: "note.sign", label: "Sign notes", note: "single-use — consumed on first success" },
  {
    id: "note.destroy",
    label: "Delete everything",
    note: "requires proof of physical presence (passkey) — a session alone is refused",
  },
]

export default function AgentConsolePage() {
  const [requesting, setRequesting] = useState(false)
  const [request, setRequest] = useState<AgentRequest | null>(null)
  const [error, setError] = useState("")
  const [selected, setSelected] = useState<Record<string, boolean>>({
    "note.read": true,
    "note.create": true,
    "note.share": true,
  })
  const [shareDomain, setShareDomain] = useState("acme.com")

  function toggle(id: string) {
    setSelected((prev) => ({ ...prev, [id]: !prev[id] }))
  }

  async function requestAccess() {
    setRequesting(true)
    setError("")
    setRequest(null)

    const capabilities: unknown[] = []
    const requestedNames: string[] = []
    if (selected["note.read"]) { capabilities.push("note.read"); requestedNames.push("note.read") }
    if (selected["note.create"]) { capabilities.push("note.create"); requestedNames.push("note.create") }
    if (selected["note.share"]) {
      const domain = shareDomain.trim().replace(/^@/, "")
      if (!domain) {
        setError("Enter a recipient domain for note.share (e.g. acme.com).")
        setRequesting(false)
        return
      }
      capabilities.push({ name: "note.share", constraints: { recipientDomain: { in: [domain] } } })
      requestedNames.push("note.share")
    }
    if (selected["note.sign"]) { capabilities.push("note.sign"); requestedNames.push("note.sign") }
    if (selected["note.destroy"]) { capabilities.push("note.destroy"); requestedNames.push("note.destroy") }

    try {
      const res = await fetch("/api/demo/agent-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ capabilities }),
      })
      const data = await res.json().catch(() => null)
      if (!res.ok || data?.error) {
        setError(data?.message ?? data?.error ?? `Request failed (${res.status})`)
        return
      }
      if (requestedNames.length > 0 && data.verification_uri_complete) {
        const url = new URL(data.verification_uri_complete, window.location.origin)
        url.searchParams.set("caps", requestedNames.join(","))
        data.verification_uri_complete = url.toString()
      }
      setRequest(data)
      // A request that is entirely within the device's pre-authorized budget
      // (e.g. only read/create) auto-grants — there is nothing to approve.
      if (!data.user_code) {
        setError(
          "All requested capabilities were pre-authorized by your device — the agent is already granted, no approval was needed. " +
            "Pick note.share / note.sign / note.destroy to see the approval gate."
        )
      }
    } catch {
      setError("Request failed — is the server running?")
    } finally {
      setRequesting(false)
    }
  }

  return (
    <div className="flex flex-1 items-center justify-center px-4 py-8">
      <div className="w-full max-w-md space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>Agent console</CardTitle>
            <CardDescription>
              This page plays the part of an AI assistant (the machine). Choose what it asks for,
              then request the right to act — it does not act until you approve elsewhere. The
              human-side approval page is the other tab.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              {CAPABILITY_OPTIONS.map((cap) => (
                <label key={cap.id} className="flex items-start gap-3 rounded-lg border p-3 cursor-pointer">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={!!selected[cap.id]}
                    onChange={() => toggle(cap.id)}
                  />
                  <span className="text-sm space-y-0.5">
                    <span className="block font-medium">{cap.label}</span>
                    <span className="block text-xs text-muted-foreground">{cap.note}</span>
                  </span>
                </label>
              ))}
              {selected["note.share"] && (
                <div className="pl-7 space-y-1.5">
                  <Label htmlFor="share-domain" className="text-xs">
                    Allow sharing only with this recipient domain:
                  </Label>
                  <Input
                    id="share-domain"
                    className="font-mono"
                    value={shareDomain}
                    onChange={(e) => setShareDomain(e.target.value)}
                    placeholder="acme.com"
                  />
                </div>
              )}
            </div>
            <Button onClick={requestAccess} disabled={requesting} className="w-full">
              {requesting ? "Requesting access..." : "Request the right to act for me"}
            </Button>
            {error && <p className="text-sm text-red-500">{error}</p>}
          </CardContent>
        </Card>

        {request && request.granted && (
          <Card className="border-dashed border-green-600/50">
            <CardHeader>
              <CardTitle>Granted — no approval needed</CardTitle>
              <CardDescription>
                Every requested capability was already pre-authorized by your device budget, so
                the assistant holds them immediately. Add a capability outside the budget
                (share / sign / destroy) to see the human approval gate.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p className="text-muted-foreground">agent_id</p>
              <p className="font-mono text-xs break-all">{request.agent_id}</p>
              <p className="text-muted-foreground">status</p>
              <p className="font-mono text-xs">{request.status}</p>
              <Link href="/dashboard" className="block text-center text-sm underline underline-offset-4 pt-2">
                See it on the dashboard
              </Link>
            </CardContent>
          </Card>
        )}

        {request && !request.granted && (
          <Card className="border-dashed">
            <CardHeader>
              <CardTitle>Request sent — waiting on the human</CardTitle>
              <CardDescription>
                The agent holds nothing until the human approves. Give them this code and link.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-lg border p-4 text-center">
                <p className="text-xs text-muted-foreground mb-1">Device code</p>
                <p className="font-mono text-3xl tracking-widest">{request.user_code}</p>
              </div>
              <div className="space-y-1 text-sm">
                <p className="text-muted-foreground">agent_id</p>
                <p className="font-mono text-xs break-all">{request.agent_id}</p>
              </div>
              <div className="space-y-1 text-sm">
                <p className="text-muted-foreground">status</p>
                <p className="font-mono text-xs">{request.status}</p>
              </div>
              <a href={request.verification_uri_complete} className={buttonVariants()}>
                Open the approval page
              </a>
              <p className="text-xs text-muted-foreground">
                Approval link (expires in {request.expires_in}s):
              </p>
              <p className="break-all font-mono text-xs text-muted-foreground">
                {request.verification_uri_complete}
              </p>
              <Link href="/" className="block text-center text-sm underline underline-offset-4">
                Back to home
              </Link>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
