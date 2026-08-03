import { headers } from "next/headers"
import Link from "next/link"
import { auth } from "@/lib/auth"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { buttonVariants } from "@/components/ui/button"
import { ApprovalActions } from "./approval-actions"

export const metadata = {
  title: "Approve agent request",
}

type SearchParams = Promise<{ agent_id?: string; code?: string; caps?: string }>

type DeviceAgentInfo = {
  name: string | null
  mode: string | null
  agent_capability_grants: { capability: string; status?: string }[] | null
}

export default async function DeviceCapabilitiesPage({
  searchParams,
}: {
  searchParams: SearchParams
}) {
  const params = await searchParams
  const agentId = params.agent_id
  const code = params.code
  // The demo console forwards the requested capabilities here because a pending,
  // not-yet-claimed agent has no userId yet and getAgent only returns owned
  // agents — so the plugin can't list an unowned agent's pending grants. The
  // caps are display-only; the actual grants are decided server-side on approve.
  const capsFromQuery = params.caps
    ?.split(",")
    .map((c) => c.trim())
    .filter(Boolean)

  const session = await auth.api.getSession({
    headers: await headers(),
  })

  if (!session) {
    return (
      <div className="flex flex-1 items-center justify-center px-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Approve agent request</CardTitle>
            <CardDescription>
              A device is asking to act on your behalf. Review the capabilities before deciding.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground mb-4">
              You must be signed in to approve this request.
            </p>
            <Link href="/sign-in" className={buttonVariants()}>
              Sign in
            </Link>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (!agentId || !code) {
    return (
      <div className="flex flex-1 items-center justify-center px-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Bad request</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              This page is reached from the device authorization flow. No agent request was given.
            </p>
          </CardContent>
        </Card>
      </div>
    )
  }

  let agent: DeviceAgentInfo | null = null
  try {
    const result = await auth.api.getAgent({
      headers: await headers(),
      query: { agent_id: agentId },
    })
    agent = result as unknown as DeviceAgentInfo
  } catch {
    // Not found or not visible to this user.
  }

  const pendingCapabilities =
    capsFromQuery ??
    agent?.agent_capability_grants?.filter((g) => g.status === "pending").map((g) => g.capability) ??
    []

  return (
    <div className="flex flex-1 items-center justify-center px-4">
      <ApprovalActions
        agentId={agentId}
        code={code}
        agentName={agent?.name ?? null}
        agentMode={agent?.mode ?? null}
        capabilities={pendingCapabilities}
      />
    </div>
  )
}
