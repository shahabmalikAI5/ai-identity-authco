"use client"

import { useState, useEffect, useCallback } from "react"
import { useRouter } from "next/navigation"
import { authClient } from "@/lib/auth-client"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

type ActiveAgent = {
  agent_id: string
  name: string
  status: string
  mode: string
  created_at: string
  last_used_at: string | null
  expires_at: string | null
  capabilities: string[]
}

function totpSecretFromUri(uri: string): string {
  try {
    const parsed = new URL(uri)
    return parsed.searchParams.get("secret") ?? ""
  } catch {
    return ""
  }
}

export default function DashboardPage() {
  const router = useRouter()
  const { data: session, isPending } = authClient.useSession()
  const [password, setPassword] = useState("")
  const [setup, setSetup] = useState<{ totpURI: string; backupCodes: string[] } | null>(null)
  const [activationCode, setActivationCode] = useState("")
  const [setupError, setSetupError] = useState("")
  const [enrolling, setEnrolling] = useState(false)
  const [activating, setActivating] = useState(false)

  const [agents, setAgents] = useState<ActiveAgent[]>([])
  const [agentsLoading, setAgentsLoading] = useState(true)
  const [revoking, setRevoking] = useState<string | null>(null)

  const loadAgents = useCallback(async () => {
    setAgentsLoading(true)
    try {
      const res = await fetch("/api/agent/list")
      const data = await res.json()
      setAgents(data.agents ?? [])
    } catch {
      setAgents([])
    } finally {
      setAgentsLoading(false)
    }
  }, [])

  useEffect(() => {
    if (session) loadAgents()
  }, [session, loadAgents])

  async function handleRevoke(agentId: string) {
    setRevoking(agentId)
    await fetch("/api/auth/agent/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ agent_id: agentId }),
    })
    setRevoking(null)
    await loadAgents()
  }

  async function handleSignOut() {
    await authClient.signOut({
      fetchOptions: {
        onSuccess: () => router.push("/sign-in"),
      },
    })
  }

  async function handleEnable2FA(e: React.FormEvent) {
    e.preventDefault()
    setSetupError("")
    setEnrolling(true)
    const { data, error } = await authClient.twoFactor.enable({
      password,
    })
    setEnrolling(false)
    if (error) {
      setSetupError(error.message ?? "Unable to enable 2FA")
      return
    }
    if (data?.method === "totp") {
      setSetup({ totpURI: data.totpURI ?? "", backupCodes: data.backupCodes ?? [] })
    }
  }

  async function handleActivate(e: React.FormEvent) {
    e.preventDefault()
    setSetupError("")
    setActivating(true)
    const { error } = await authClient.twoFactor.verifyTotp({
      code: activationCode,
      trustDevice: false,
    })
    setActivating(false)
    if (error) {
      setSetupError(error.message ?? "Invalid code")
      return
    }
    await authClient.getSession()
    setSetup(null)
    setActivationCode("")
  }

  if (isPending) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <p className="text-muted-foreground">Loading...</p>
      </div>
    )
  }

  if (!session) {
    router.push("/sign-in")
    return null
  }

  const twoFactorEnabled = Boolean(session.user.twoFactorEnabled)

  return (
    <div className="flex flex-1 items-center justify-center px-4 py-8">
      <div className="w-full max-w-md space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>Dashboard</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Name</p>
              <p className="font-medium">{session.user.name}</p>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Email</p>
              <p className="font-medium">{session.user.email}</p>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">User ID</p>
              <p className="font-mono text-sm">{session.user.id}</p>
            </div>
            <Button onClick={handleSignOut} variant="outline" className="w-full">
              Sign out
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Active agents</CardTitle>
          </CardHeader>
          <CardContent>
            {agentsLoading ? (
              <p className="text-sm text-muted-foreground">Loading...</p>
            ) : agents.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No agents are acting on your behalf. Approve one from the agent console to grant it
                access.
              </p>
            ) : (
              <ul className="space-y-3">
                {agents.map((a) => (
                  <li key={a.agent_id} className="rounded-lg border p-3 space-y-2">
                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-0.5">
                        <p className="font-medium">{a.name}</p>
                        <p className="font-mono text-xs text-muted-foreground break-all">{a.agent_id}</p>
                      </div>
                      <span
                        className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ${
                          a.status === "active"
                            ? "bg-emerald-500/10 text-emerald-600"
                            : "bg-zinc-500/10 text-zinc-500"
                        }`}
                      >
                        {a.status}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Capabilities: {a.capabilities.length ? a.capabilities.join(", ") : "(none)"}
                    </p>
                    {a.expires_at && (
                      <p className="text-xs text-muted-foreground">
                        Expires: {new Date(a.expires_at).toLocaleString()}
                      </p>
                    )}
                    <Button
                      variant="destructive"
                      size="sm"
                      className="w-full"
                      disabled={revoking === a.agent_id || a.status !== "active"}
                      onClick={() => handleRevoke(a.agent_id)}
                    >
                      {revoking === a.agent_id ? "Revoking..." : "Revoke access"}
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Two-factor authentication</CardTitle>
          </CardHeader>
          <CardContent>
            {twoFactorEnabled ? (
              <p className="text-sm text-emerald-600">Enabled. Your sign-in now requires a second factor.</p>
            ) : setup ? (
              <div className="space-y-4">
                <div className="space-y-1">
                  <p className="text-sm font-medium">Add this to your authenticator app</p>
                  <p className="break-all font-mono text-xs text-muted-foreground">{setup.totpURI}</p>
                  <p className="text-xs text-muted-foreground">
                    Secret: <span className="font-mono">{totpSecretFromUri(setup.totpURI)}</span>
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-sm font-medium">Backup codes — save these once</p>
                  <ul className="grid grid-cols-2 gap-1">
                    {setup.backupCodes.map((c) => (
                      <li key={c} className="font-mono text-xs">
                        {c}
                      </li>
                    ))}
                  </ul>
                </div>
                <form onSubmit={handleActivate} className="space-y-2 border-t pt-4">
                  <div className="space-y-2">
                    <Label htmlFor="activationCode">Enter a code from your authenticator app to activate</Label>
                    <Input
                      id="activationCode"
                      inputMode="numeric"
                      value={activationCode}
                      onChange={(e) => setActivationCode(e.target.value)}
                      required
                    />
                  </div>
                  {setupError && <p className="text-sm text-red-500">{setupError}</p>}
                  <Button type="submit" className="w-full" disabled={activating}>
                    {activating ? "Activating..." : "Activate 2FA"}
                  </Button>
                </form>
              </div>
            ) : (
              <form onSubmit={handleEnable2FA} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="password">Confirm your password</Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>
                {setupError && <p className="text-sm text-red-500">{setupError}</p>}
                <Button type="submit" className="w-full" disabled={enrolling}>
                  {enrolling ? "Enabling..." : "Enable 2FA"}
                </Button>
              </form>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
