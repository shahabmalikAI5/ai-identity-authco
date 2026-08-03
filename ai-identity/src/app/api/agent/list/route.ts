import { NextResponse } from "next/server"
import { headers } from "next/headers"
import { auth } from "@/lib/auth"

export const dynamic = "force-dynamic"

type AgentGrant = { capability: string; status?: string }
type AgentListItem = {
  agent_id: string
  name: string
  status: string
  mode: string
  created_at: string
  last_used_at: string | null
  expires_at: string | null
  agent_capability_grants?: AgentGrant[] | null
}
type ListAgentsResponse = { agents?: AgentListItem[] }

export async function GET() {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const result = (await auth.api.listAgents({
    headers: await headers(),
    query: { mode: "delegated" },
  })) as unknown as ListAgentsResponse

  const agents = (result?.agents ?? []).map((a) => ({
    agent_id: a.agent_id,
    name: a.name,
    status: a.status,
    mode: a.mode,
    created_at: a.created_at,
    last_used_at: a.last_used_at,
    expires_at: a.expires_at,
    capabilities: (a.agent_capability_grants ?? [])
      .filter((g) => g.status === "active")
      .map((g) => g.capability),
  }))

  return NextResponse.json({ agents })
}
