"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { authClient } from "@/lib/auth-client"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export default function TwoFactorPage() {
  const router = useRouter()
  const [mode, setMode] = useState<"totp" | "backup">("totp")
  const [code, setCode] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)

    const fn =
      mode === "totp" ? authClient.twoFactor.verifyTotp : authClient.twoFactor.verifyBackupCode
    const { error: err } = await fn({
      code,
      trustDevice: false,
    })

    if (err) {
      setError(err.message ?? "Invalid code")
      setLoading(false)
      return
    }

    router.push("/dashboard")
  }

  return (
    <div className="flex flex-1 items-center justify-center px-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Two-factor authentication</CardTitle>
          <CardDescription>
            Enter a code from your authenticator app, or a backup code.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-4 flex gap-2">
            <Button
              type="button"
              variant={mode === "totp" ? "default" : "outline"}
              size="sm"
              onClick={() => setMode("totp")}
            >
              Authenticator app
            </Button>
            <Button
              type="button"
              variant={mode === "backup" ? "default" : "outline"}
              size="sm"
              onClick={() => setMode("backup")}
            >
              Backup code
            </Button>
          </div>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="code">{mode === "totp" ? "Six-digit code" : "Backup code"}</Label>
              <Input
                id="code"
                inputMode={mode === "totp" ? "numeric" : "text"}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                required
              />
            </div>
            {error && <p className="text-sm text-red-500">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? "Verifying..." : "Verify"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
