// demo-delegated-approved.mjs
// Live walkthrough: after the human approves, inspect the band — the granted
// authority — and see that it names BOTH the agent and the on-behalf-of user.
//
// Usage: node scripts/demo-delegated-approved.mjs

import { generateKeypair, signHostJWT, signAgentJWT } from "@auth/agent";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";
const AUTH_BASE = `${BASE}/api/auth`;
const EMAIL = `demo-approved-${Date.now()}@example.com`;
const PASSWORD = "correct-horse-battery-staple-77";

function extractCookies(headers) {
  return headers.getSetCookie ? headers.getSetCookie().map((c) => c.split(";")[0]).join("; ") : "";
}

async function main() {
  console.log("\n=== The approval mints the band. Let's look at what it names. ===\n");

  const disco = await (await fetch(`${BASE}/.well-known/agent-configuration`)).json();
  const issuer = disco.issuer;
  const defaultLocation = disco.default_location;

  // Human signs up + in.
  await fetch(`${AUTH_BASE}/sign-up/email`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: BASE },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD, name: "Alex Audit" }),
  });
  const si = await fetch(`${AUTH_BASE}/sign-in/email`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: BASE },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  const humanCookies = extractCookies(si.headers);

  // Agent registers in delegated mode -> pending + device approval.
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
      name: "note-writer-agent",
      capabilities: ["note.read", "note.create"],
      mode: "delegated",
      preferred_method: "device_authorization",
      host_name: "demo-host",
    }),
  });
  const regBody = await reg.json();
  const agentId = regBody.agent_id;
  const userCode = regBody.approval.user_code;

  // The human approves.
  const ap = await fetch(`${AUTH_BASE}/agent/approve-capability`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: BASE, cookie: humanCookies },
    body: JSON.stringify({ agent_id: agentId, user_code: userCode, action: "approve" }),
  });
  const apBody = await ap.json();
  console.log(`[1] Human approves the device code ${userCode}`);
  console.log(`    -> ${ap.status} ${apBody.status}, granted: ${apBody.added.join(", ")}\n`);

  // The band: what does the agent now hold, and who is it bound to?
  const sessJWT = await signAgentJWT({
    agentKeypair: agentKp,
    agentId,
    audience: issuer,
    capabilities: ["note.read", "note.create"],
    expiresInSeconds: 30,
  });
  const sess = await fetch(`${AUTH_BASE}/agent/session`, {
    method: "GET",
    headers: { authorization: `Bearer ${sessJWT}` },
  });
  const s = await sess.json();

  console.log("[2] The band — agent session after approval:\n");
  console.log("    AGENT (who acts):");
  console.log(`      id:   ${s.agent.id}`);
  console.log(`      name: ${s.agent.name}  (mode: ${s.agent.mode})`);
  console.log("      capabilityGrants:");
  for (const g of s.agent.capabilityGrants) {
    console.log(`        - ${g.capability}: status=${g.status} grantedBy=${g.grantedBy ? g.grantedBy.slice(0, 8) + "…" : "null"}`);
  }
  console.log("");
  console.log("    USER (on whose behalf):");
  console.log(`      id:    ${s.user.id}`);
  console.log(`      name:  ${s.user.name}`);
  console.log(`      email: ${s.user.email}\n`);

  const paired = s.agent?.id === agentId && s.user?.email === EMAIL;
  console.log(`    ==> The band names BOTH actors: the agent (${s.agent.id.slice(0, 8)}…) `);
  console.log(`        AND the human it acts for (${s.user.email}). ${paired ? "They are a pair." : ""}\n`);

  // Execute, then show the note's own attribution fields.
  const execJWT = await signAgentJWT({
    agentKeypair: agentKp,
    agentId,
    audience: defaultLocation,
    capabilities: ["note.create"],
    expiresInSeconds: 30,
  });
  await fetch(`${AUTH_BASE}/capability/execute`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${execJWT}` },
    body: JSON.stringify({ capability: "note.create", arguments: { title: "audit me", body: "made by the agent for Alex" } }),
  });
  const readJWT = await signAgentJWT({
    agentKeypair: agentKp,
    agentId,
    audience: defaultLocation,
    capabilities: ["note.read"],
    expiresInSeconds: 30,
  });
  const rb = await fetch(`${AUTH_BASE}/capability/execute`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${readJWT}` },
    body: JSON.stringify({ capability: "note.read", arguments: {} }),
  });
  const notes = (await rb.json())?.data?.notes ?? [];
  const mine = notes.filter((n) => n.title === "audit me");

  console.log("[3] The action it took, stamped with both halves:\n");
  for (const n of mine) {
    console.log(`    note.id:           ${n.id}`);
    console.log(`    title:             ${n.title}`);
    console.log(`    createdBy:         ${n.createdBy}   <- the human on whose behalf`);
    console.log(`    createdByAgent:    ${n.createdByAgent}   <- the agent that did it`);
    console.log(`    createdAt:         ${n.createdAt}`);
    console.log("");
  }

  console.log("=== The band binds agent + human + capability + clock. ===");
}

main().catch((err) => {
  console.error("Demo error:", err);
  process.exit(1);
});
