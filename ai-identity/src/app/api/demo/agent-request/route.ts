import { NextResponse } from "next/server"
import { auth } from "@/lib/auth"
import { generateKeypair, signHostJWT } from "@auth/agent"

export const dynamic = "force-dynamic"

export async function POST(request: Request) {
  // The demo console lives in the human's browser, so it can act on their
  // session. We create a host OWNED by that human (active), then register the
  // agent on it. On an owned host the approval gate is keyed to each
  // capability's approvalStrength (session for note.share/note.sign, webauthn
  // for note.destroy) — a fresh unowned host would instead force WebAuthn for
  // every approval, which would blur the graded ladder this demo shows.
  const session = await auth.api.getSession({ headers: request.headers })
  if (!session) {
    return NextResponse.json(
      { error: "You must be signed in to demo the agent console. Open /sign-in first." },
      { status: 401 }
    )
  }
  const cookie = request.headers.get("cookie") ?? ""

  let capabilities: unknown[] = ["note.read", "note.create"]
  try {
    const body = await request.json().catch(() => null)
    if (body && Array.isArray(body.capabilities) && body.capabilities.length > 0) {
      capabilities = body.capabilities
    }
  } catch {
    // Malformed body -> fall back to the basic set below.
  }

  const baseURL = process.env.BETTER_AUTH_URL || "http://localhost:3000"
  const disco = await (await fetch(`${baseURL}/.well-known/agent-configuration`)).json()
  const issuer = disco.issuer

  const hostKp = await generateKeypair()
  const agentKp = await generateKeypair()

  const hostRes = await fetch(`${baseURL}/api/auth/host/create`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie, origin: baseURL },
    body: JSON.stringify({ name: "demo-agent-console", public_key: hostKp.publicKey }),
  })
  const hostBody = await hostRes.json().catch(() => null)
  if (!hostRes.ok || !hostBody?.hostId) {
    return NextResponse.json(
      { error: hostBody?.error ?? hostBody?.message ?? "Failed to create the demo device" },
      { status: hostRes.status }
    )
  }

  const hostJWT = await signHostJWT({
    hostKeypair: hostKp,
    agentPublicKey: agentKp.publicKey,
    hostName: "demo-agent-console",
    audience: issuer,
    expiresInSeconds: 60,
  })

  const reg = await fetch(`${baseURL}/api/auth/agent/register`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${hostJWT}`,
    },
    body: JSON.stringify({
      name: "demo-assistant",
      capabilities,
      mode: "delegated",
      preferred_method: "device_authorization",
      host_name: "demo-agent-console",
    }),
  })

  const body = await reg.json().catch(() => null)

  if (!reg.ok || !body?.agent_id) {
    return NextResponse.json(
      { error: body?.message ?? body?.error ?? "Agent request failed" },
      { status: reg.status }
    )
  }

  // All requested capabilities were pre-authorized by the device budget (e.g.
  // only read/create on this host): the agent auto-granted, no approval needed.
  if (!body?.approval?.user_code) {
    return NextResponse.json({
      agent_id: body.agent_id,
      status: body.status,
      granted: true,
    })
  }

  return NextResponse.json({
    agent_id: body.agent_id,
    status: body.status,
    user_code: body.approval.user_code,
    expires_in: body.approval.expires_in,
    verification_uri: body.approval.verification_uri,
    verification_uri_complete: body.approval.verification_uri_complete,
  })
}
