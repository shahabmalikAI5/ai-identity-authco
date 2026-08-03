// demo-delegated-request.mjs
// Live walkthrough: an agent requests delegated authority, then we STOP
// before the human approves — proving the agent has nothing until then.
//
// Usage: node scripts/demo-delegated-request.mjs

import { generateKeypair, signHostJWT, signAgentJWT } from "@auth/agent";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";
const AUTH_BASE = `${BASE}/api/auth`;
const EMAIL = `demo-request-${Date.now()}@example.com`;
const PASSWORD = "correct-horse-battery-staple-77";

function extractCookies(headers) {
  return headers.getSetCookie ? headers.getSetCookie().map((c) => c.split(";")[0]).join("; ") : "";
}

async function main() {
  console.log("\n=== The request happens FIRST. The authority comes AFTER approval. ===\n");

  const disco = await (await fetch(`${BASE}/.well-known/agent-configuration`)).json();
  const issuer = disco.issuer;
  const defaultLocation = disco.default_location;
  console.log(`[1] Provider discovered: ${disco.provider_name}`);
  console.log(`    modes: ${disco.modes.join(", ")}   (delegated = act for a person)`);
  console.log(`    execute endpoint: ${defaultLocation}\n`);

  // The human.
  await fetch(`${AUTH_BASE}/sign-up/email`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: BASE },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD, name: "Demo Human" }),
  });
  const si = await fetch(`${AUTH_BASE}/sign-in/email`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: BASE },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  const humanCookies = extractCookies(si.headers);
  console.log("[2] Human is signed in (they are the source of the authority)\n");

  // The agent requests the right to act FOR the human.
  const hostKp = await generateKeypair();
  const agentKp = await generateKeypair();
  const hostJWT = await signHostJWT({
    hostKeypair: hostKp,
    agentPublicKey: agentKp.publicKey,
    hostName: "demo-host",
    audience: issuer,
    expiresInSeconds: 60,
  });
  const reg = await fetch(`${AUTH_BASE}/agent/register`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${hostJWT}` },
    body: JSON.stringify({
      name: "demo-agent",
      capabilities: ["note.read", "note.create"],
      mode: "delegated",
      preferred_method: "device_authorization",
      host_name: "demo-host",
    }),
  });
  const regBody = await reg.json();
  const agentId = regBody.agent_id;
  console.log("[3] The agent asks to act on the human's behalf.");
  console.log(`    requests: ${regBody.agent_capability_grants.map((g) => `${g.capability} (${g.status})`).join(", ")}`);
  console.log(`    agent status: ${regBody.status}\n`);

  // STOP. No approval given.
  console.log("[4] The human does NOT approve. The request sits there, unfunded.\n");

  // Prove the agent has nothing: no band, no access.
  const jwt = await signAgentJWT({
    agentKeypair: agentKp,
    agentId,
    audience: defaultLocation,
    capabilities: ["note.read"],
    expiresInSeconds: 30,
  });
  const exec = await fetch(`${AUTH_BASE}/capability/execute`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${jwt}` },
    body: JSON.stringify({ capability: "note.read", arguments: {} }),
  });
  const execBody = await exec.json().catch(() => ({}));
  console.log(`[5] The agent tries to use it anyway:`);
  console.log(`    POST /capability/execute  ->  ${exec.status} ${execBody.error ?? ""}`);
  console.log(`    -> ${execBody.message}\n`);

  const sess = await fetch(`${AUTH_BASE}/agent/session`, {
    method: "GET",
    headers: { authorization: `Bearer ${jwt}` },
  });
  const sessBody = await sess.json().catch(() => null);
  const grants = sessBody?.agent?.capabilityGrants ?? [];
  const active = grants.filter((g) => g.status === "active");
  console.log("[6] What does the agent actually hold right now?");
  console.log(`    grants: ${grants.length === 0 ? "(none)" : grants.map((g) => `${g.capability}=${g.status}`).join(", ")}`);
  console.log(`    active grants: ${active.length === 0 ? "NONE" : active.map((g) => g.capability).join(", ")}`);
  console.log(`    delegated user: ${sessBody?.user ? sessBody.user.email : "(none — not bound to anyone)"}`);
  console.log(`    => no band, no access, no person bound to it.\n`);

  console.log("=== The agent requested. It holds nothing until the human approves. ===");
}

main().catch((err) => {
  console.error("Demo error:", err);
  process.exit(1);
});
