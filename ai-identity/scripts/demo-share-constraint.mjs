// demo-share-constraint.mjs
// Live demo: give an agent the right to share notes, but only with @acme.com,
// then try @evil.com and watch the server refuse it mid-request.
// Boot: default (no STEP_UP_PROOF_OF_PRESENCE needed — note.share is a "session"
// capability). Uses a human-created host so the approval is a normal session.
// Usage: node scripts/demo-share-constraint.mjs

import { generateKeypair, signHostJWT, signAgentJWT } from "@auth/agent";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";
const AUTH_BASE = `${BASE}/api/auth`;
const EMAIL = `share-demo-${Date.now()}@example.com`;
const PW = "correct-horse-battery-staple-77";
const cookies = (h) => (h.getSetCookie ? h.getSetCookie().map((c) => c.split(";")[0]).join("; ") : "");

const log = (label, body) => console.log(`${label} ${JSON.stringify(body, null, 2)}`);

const disco = await (await fetch(`${BASE}/.well-known/agent-configuration`)).json();
const issuer = disco.issuer;
const EXEC = disco.default_location;

console.log("=== Give an agent note.share, constrained to @acme.com only ===\n");

// 1. Human signs up + in (the approver)
await fetch(`${AUTH_BASE}/sign-up/email`, {
  method: "POST", headers: { "content-type": "application/json", origin: BASE },
  body: JSON.stringify({ email: EMAIL, password: PW, name: "Alice" }),
});
const si = await fetch(`${AUTH_BASE}/sign-in/email`, {
  method: "POST", headers: { "content-type": "application/json", origin: BASE },
  body: JSON.stringify({ email: EMAIL, password: PW }),
});
const humanCookies = cookies(si.headers);
console.log("1. human signed in (approver)\n");

// 2. Human creates the device/host, then the agent registers note.share WITH a constraint
const hostKp = await generateKeypair();
await fetch(`${AUTH_BASE}/host/create`, {
  method: "POST", headers: { "content-type": "application/json", cookie: humanCookies, origin: BASE },
  body: JSON.stringify({ name: "demo-device", public_key: hostKp.publicKey }),
});
const agentKp = await generateKeypair();
const hostJWT = await signHostJWT({ hostKeypair: hostKp, agentPublicKey: agentKp.publicKey, hostName: "demo-device", audience: issuer, expiresInSeconds: 60 });
const reg = await fetch(`${AUTH_BASE}/agent/register`, {
  method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${hostJWT}`, origin: BASE },
  body: JSON.stringify({
    name: "note-sharer",
    capabilities: [{ name: "note.share", constraints: { recipientDomain: { in: ["acme.com"] } } }],
    mode: "delegated", preferred_method: "device_authorization", host_name: "demo-device",
  }),
});
const regBody = await reg.json();
const agentId = regBody.agent_id;
console.log("2. agent registered. Requested grant:");
log("   request:", JSON.stringify(regBody.agent_capability_grants.find((g) => g.capability === "note.share")));

// 3. Human approves (device code)
const approve = await fetch(`${AUTH_BASE}/agent/approve-capability`, {
  method: "POST", headers: { "content-type": "application/json", cookie: humanCookies, origin: BASE },
  body: JSON.stringify({ agent_id: agentId, user_code: regBody.approval.user_code, action: "approve" }),
});
const approveBody = await approve.json();
console.log("3. human approved via device code ->", approveBody.status, `(granted: [${approveBody.added?.join(", ")}])`);

// 4. Agent executes note.share in-bounds (@acme.com)
const exec = async (domain) => {
  const jwt = await signAgentJWT({ agentKeypair: agentKp, agentId, audience: EXEC, capabilities: ["note.share"], expiresInSeconds: 30 });
  const r = await fetch(`${AUTH_BASE}/capability/execute`, {
    method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${jwt}`, origin: BASE },
    body: JSON.stringify({ capability: "note.share", arguments: { noteId: "note-1", recipientDomain: domain } }),
  });
  return { status: r.status, body: await r.json() };
};

console.log("\n--- Agent tries: share with alice@acme.com (in-scope) ---");
const good = await exec("acme.com");
console.log(`HTTP ${good.status}`);
log("   response:", good.body);

console.log("\n--- Agent tries: share with bob@evil.com (out-of-scope) ---");
const bad = await exec("evil.com");
console.log(`HTTP ${bad.status}`);
log("   response:", bad.body);

// 5. Prove the refusal did NOT consume the grant: same grant still works in-bounds
console.log("\n--- Same grant, in-scope again (proves the refusal didn't consume it) ---");
const again = await exec("acme.com");
console.log(`HTTP ${again.status}`);
log("   response:", again.body);
