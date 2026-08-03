// demo-step-up-destroy.mjs
// Live demo: try to approve note.destroy ("delete everything") with ONLY a
// logged-in session, and watch the server demand physical presence instead.
// REQUIREMENT: server booted with STEP_UP_PROOF_OF_PRESENCE=true (the proof-of-
// presence WebAuthn gate is env-gated). note.destroy is approvalStrength "webauthn".
// Usage: node scripts/demo-step-up-destroy.mjs

import { generateKeypair, signHostJWT, signAgentJWT } from "@auth/agent";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";
const AUTH_BASE = `${BASE}/api/auth`;
const EMAIL = `destroy-demo-${Date.now()}@example.com`;
const PW = "correct-horse-battery-staple-77";
const cookies = (h) => (h.getSetCookie ? h.getSetCookie().map((c) => c.split(";")[0]).join("; ") : "");
const log = (label, body) => console.log(`${label} ${JSON.stringify(body, null, 2)}`);

const disco = await (await fetch(`${BASE}/.well-known/agent-configuration`)).json();
const issuer = disco.issuer;
const EXEC = disco.default_location;

console.log("=== Try to approve \"delete everything\" with just a logged-in session ===\n");

// What the server advertises for note.destroy
const caps = await (await fetch(`${AUTH_BASE}/capability/list`, { method: "GET" })).json();
const destroyDef = caps.capabilities.find((c) => c.name === "note.destroy");
console.log("note.destroy advertised approval_strength:", JSON.stringify(destroyDef?.approval_strength));

// Human signs in — a normal session, no passkey registered
await fetch(`${AUTH_BASE}/sign-up/email`, {
  method: "POST", headers: { "content-type": "application/json", origin: BASE },
  body: JSON.stringify({ email: EMAIL, password: PW, name: "Alice" }),
});
const si = await fetch(`${AUTH_BASE}/sign-in/email`, {
  method: "POST", headers: { "content-type": "application/json", origin: BASE },
  body: JSON.stringify({ email: EMAIL, password: PW }),
});
const humanCookies = cookies(si.headers);
console.log("\n1. human signed in — plain logged-in session, NO passkey registered\n");

// Agent registers wanting the destructive capability
const hostKp = await generateKeypair();
const agentKp = await generateKeypair();
const hostJWT = await signHostJWT({ hostKeypair: hostKp, agentPublicKey: agentKp.publicKey, hostName: "demo-destroyer", audience: issuer, expiresInSeconds: 60 });
const reg = await fetch(`${AUTH_BASE}/agent/register`, {
  method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${hostJWT}`, origin: BASE },
  body: JSON.stringify({ name: "cleanup-agent", capabilities: ["note.destroy"], mode: "delegated", preferred_method: "device_authorization", host_name: "demo-destroyer" }),
});
const regBody = await reg.json();
const agentId = regBody.agent_id;
const grant = regBody.agent_capability_grants.find((g) => g.capability === "note.destroy");
console.log("2. agent registered asking for note.destroy; grant status:", grant?.status, "(pending)\n");

// Human tries to approve with just the session + device code
const approve = await fetch(`${AUTH_BASE}/agent/approve-capability`, {
  method: "POST", headers: { "content-type": "application/json", cookie: humanCookies, origin: BASE },
  body: JSON.stringify({ agent_id: agentId, user_code: regBody.approval.user_code, action: "approve" }),
});
const approveBody = await approve.json();
console.log("3. human approves with ONLY the logged-in session:");
log("   server:", approveBody);

// Agent still cannot execute (grant never became active)
const jwt = await signAgentJWT({ agentKeypair: agentKp, agentId, audience: EXEC, capabilities: ["note.destroy"], expiresInSeconds: 30 });
const execRes = await fetch(`${AUTH_BASE}/capability/execute`, {
  method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${jwt}`, origin: BASE },
  body: JSON.stringify({ capability: "note.destroy", arguments: { id: "everything" } }),
});
console.log("4. the agent then tries to execute note.destroy:");
log("   result:", { status: execRes.status, ...(await execRes.json()) });

const statusJWT = await signHostJWT({ hostKeypair: hostKp, hostName: "status", audience: issuer, expiresInSeconds: 60 });
const st = await (await fetch(`${AUTH_BASE}/agent/status?agent_id=${agentId}`, { method: "GET", headers: { authorization: `Bearer ${statusJWT}` } })).json();
const stillPending = st.agent_capability_grants.find((g) => g.capability === "note.destroy");
console.log("5. grant after the attempt:", JSON.stringify({ status: stillPending.status }));
console.log("\nResult: the destructive grant stayed pending/ungranted — the server demanded physical presence.");
