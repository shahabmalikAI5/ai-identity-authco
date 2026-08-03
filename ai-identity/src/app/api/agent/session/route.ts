import { auth } from "@/lib/auth";
import { NextResponse } from "next/server";

export async function GET(request: Request) {
  let agentSession;
  try {
    agentSession = await auth.api.getAgentSession({
      headers: request.headers,
    });
  } catch (e) {
    const code =
      typeof e === "object" && e !== null && "body" in e
        ? (e as { body?: { error?: string } }).body?.error
        : "unauthorized";
    return NextResponse.json({ error: code ?? "unauthorized" }, { status: 401 });
  }
  if (!agentSession) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  return NextResponse.json({
    type: agentSession.type,
    user: { id: agentSession.user.id, name: agentSession.user.name },
    agent: {
      id: agentSession.agent.id,
      name: agentSession.agent.name,
      mode: agentSession.agent.mode,
      capabilityGrants: agentSession.agent.capabilityGrants,
    },
    host: agentSession.host,
  });
}
