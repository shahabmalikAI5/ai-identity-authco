// verify-spec-agent.mjs
// Acceptance harness for specs/projects/agent-credential/spec.md
// Drives @better-auth/agent-auth (BETA) over HTTP against a running dev server.
//
// Flow: discover -> register agent under a dynamically-registered host (autonomous)
//       -> agent self-signs a short-lived JWT -> execute granted capability
//       -> prove least-privilege, expiry, replay, and revocation all bite.
//
// Usage: node scripts/verify-spec-agent.mjs  (BASE_URL=http://localhost:3000 default)

import {
  generateKeypair,
  signHostJWT,
  signAgentJWT,
} from "@auth/agent";
import { SignJWT } from "jose";
import { randomUUID } from "node:crypto";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";
const AUTH_BASE = `${BASE}/api/auth`;

let passed = 0;
let failed = 0;
const failures = [];

function check(name, cond, detail = "") {
  if (cond) {
    passed++;
    console.log(`  \x1b[32mPASS\x1b[0m ${name}`);
  } else {
    failed++;
    failures.push(name);
    console.log(`  \x1b[31mFAIL\x1b[0m ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

async function call(path, { method = "GET", body, token } = {}) {
  const res = await fetch(`${AUTH_BASE}${path}`, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try {
    json = await res.json();
  } catch {}
  return { status: res.status, json };
}

const signAgent = (agentKp, agentId, { capabilities, expiresInSeconds = 30 } = {}) =>
  signAgentJWT({
    agentKeypair: agentKp,
    agentId,
    audience: DEFAULT_LOCATION,
    capabilities,
    expiresInSeconds,
  });

let DEFAULT_LOCATION;

async function main() {
  console.log(`\n=== Agent credential acceptance (spec: projects/agent-credential) ===`);
  console.log(`Server: ${BASE}\n`);

  // ---- Discovery -----------------------------------------------------
  console.log("[1] Discovery (.well-known/agent-configuration)");
  const disco = await (await fetch(`${BASE}/.well-known/agent-configuration`)).json();
  check("autonomous mode advertised", disco.modes?.includes("autonomous"));
  check("default_location present", typeof disco.default_location === "string");
  check("register endpoint advertised", disco.endpoints?.register?.includes("/agent/register"));
  const issuer = disco.issuer;
  DEFAULT_LOCATION = disco.default_location;
  console.log(`     issuer=${issuer}\n     default_location=${DEFAULT_LOCATION}`);

  // ---- Register agent under a dynamically-registered host ------------
  console.log("[2] Agent registers under a host (autonomous)");
  const hostKp = await generateKeypair();
  const agentKp = await generateKeypair();
  const hostJWT = await signHostJWT({
    hostKeypair: hostKp,
    agentPublicKey: agentKp.publicKey,
    hostName: "demo-host",
    audience: issuer,
    expiresInSeconds: 60,
  });
  const reg = await call("/agent/register", {
    method: "POST",
    token: hostJWT,
    body: {
      name: "note-writer",
      capabilities: ["note.read", "note.create", "note.delete"],
      mode: "autonomous",
      host_name: "demo-host",
    },
  });
  check("register returns agent_id", reg.status === 200 && !!reg.json?.agent_id, `status=${reg.status}`);
  const agentId = reg.json?.agent_id;
  const hostId = reg.json?.host_id;
  check("register returns host_id", !!hostId);
  check("agent is active (autonomous, no approval)", reg.json?.status === "active", `status=${reg.json?.status}`);
  const grantedCaps = (reg.json?.agent_capability_grants ?? [])
    .filter((g) => g.status === "active")
    .map((g) => g.capability);
  check(
    "least privilege at issue: read+create granted, delete NOT granted",
    grantedCaps.includes("note.read") &&
      grantedCaps.includes("note.create") &&
      !grantedCaps.includes("note.delete"),
    `grants=[${grantedCaps.join(", ")}]`
  );
  console.log(`     agent_id=${agentId}\n     host_id=${hostId}\n     grants=[${grantedCaps.join(", ")}]`);

  // ---- Own credential (AC-1) + verification outside the work (FR-4) ----
  const sessionJWT = await signAgent(agentKp, agentId, { capabilities: ["note.read"] });
  const sess = await call("/agent/session", { method: "GET", token: sessionJWT });
  check("agent session resolves", sess.status === 200 && !!sess.json?.agent, `status=${sess.status}`);
  check(
    "AC-1 own credential: subject is the synthetic agent user, not a human",
    sess.json?.user?.id === `agent_${agentId}` && sess.json?.agent?.id === agentId,
    `user=${sess.json?.user?.id}`
  );

  const fr4JWT = await signAgent(agentKp, agentId, { capabilities: ["note.read"] });
  const fr4 = await fetch(`${BASE}/api/agent/session`, {
    headers: { authorization: `Bearer ${fr4JWT}` },
  });
  const fr4Body = await fr4.json().catch(() => null);
  check(
    "FR-4 session route resolves agent + host + grants (no action ran)",
    fr4.status === 200 && fr4Body?.agent?.id === agentId && !!fr4Body?.host,
    `status=${fr4.status}`
  );

  // ---- Self-signed short-lived credential, execute granted capability --
  console.log("[3] Self-signed short-lived JWT -> execute granted capability");
  const readJWT = await signAgent(agentKp, agentId, { capabilities: ["note.read"] });
  const expClaim = JSON.parse(Buffer.from(readJWT.split(".")[1], "base64url").toString());
  const ttlSec = expClaim.exp - expClaim.iat;
  check("AC-3 token is short-lived (exp-iat <= 30s)", ttlSec > 0 && ttlSec <= 30, `ttl=${ttlSec}s`);

  const exec = await call("/capability/execute", {
    method: "POST",
    token: readJWT,
    body: { capability: "note.read", arguments: {} },
  });
  check(
    "AC-2 granted capability executes",
    exec.status === 200 && Array.isArray(exec.json?.data?.notes),
    `status=${exec.status}`
  );

  // Create a note under the agent's identity, verify attribution.
  const createJWT = await signAgent(agentKp, agentId, { capabilities: ["note.create"] });
  const created = await call("/capability/execute", {
    method: "POST",
    token: createJWT,
    body: { capability: "note.create", arguments: { title: "agent note", body: "made by the agent" } },
  });
  const createdId = created.json?.data?.id;
  const readJWT2 = await signAgent(agentKp, agentId, { capabilities: ["note.read"] });
  const readAgain = await call("/capability/execute", {
    method: "POST",
    token: readJWT2,
    body: { capability: "note.read", arguments: {} },
  });
  const createdNote = readAgain.json?.data?.notes?.find((n) => n.id === createdId);
  check("note.create runs when granted", created.status === 200 && created.json?.data?.ok === true, `status=${created.status}`);
  check(
    "AC-1 actions attributable to the agent's own identity",
    createdNote?.createdBy === `agent_${agentId}`,
    `createdBy=${createdNote?.createdBy}`
  );

  // ---- Least privilege: refused, and cannot widen its own grant --------
  console.log("[4] Least privilege");
  const delJWT = await signAgent(agentKp, agentId, { capabilities: ["note.delete"] });
  const refused = await call("/capability/execute", {
    method: "POST",
    token: delJWT,
    body: { capability: "note.delete", arguments: { id: "x" } },
  });
  check("AC-2 never-granted capability refused", refused.status === 403, `status=${refused.status}`);
  check(
    "AC-2 refusal reason = capability_not_granted",
    refused.json?.error === "capability_not_granted",
    `error=${refused.json?.error}`
  );
  check(
    "AC-2 no way to widen own grant (JWT claims delete, still refused)",
    refused.status === 403
  );

  // ---- Expiry ----------------------------------------------------------
  console.log("[5] Expiry + replay");
  const expiredJWT = await new SignJWT({ capabilities: ["note.read"] })
    .setProtectedHeader({ alg: "EdDSA", typ: "agent+jwt" })
    .setSubject(agentId)
    .setAudience(DEFAULT_LOCATION)
    .setIssuedAt(Math.floor(Date.now() / 1000) - 120)
    .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
    .setJti(randomUUID())
    .sign(agentKp.privateKey);
  const expiredCall = await call("/capability/execute", {
    method: "POST",
    token: expiredJWT,
    body: { capability: "note.read", arguments: {} },
  });
  check("AC-3 expired token rejected", expiredCall.status === 401, `status=${expiredCall.status}`);

  // ---- Replay ----------------------------------------------------------
  const replay = await call("/capability/execute", {
    method: "POST",
    token: readJWT, // readJWT already consumed in [3] -> same jti
    body: { capability: "note.read", arguments: {} },
  });
  check("AC-3 replayed jti refused", replay.status === 401, `status=${replay.status}`);

  // ---- Grant revocation -------------------------------------------------
  console.log("[6] Revocation");
  const hostJWT2 = await signHostJWT({
    hostKeypair: hostKp,
    hostName: "demo-host",
    audience: issuer,
    expiresInSeconds: 60,
  });
  const revokeCap = await call("/agent/revoke-capability", {
    method: "POST",
    token: hostJWT2,
    body: { agent_id: agentId, capabilities: ["note.read"] },
  });
  check("grant revoked via host JWT", revokeCap.status === 200 && revokeCap.json?.revoked?.includes("note.read"), `status=${revokeCap.status}`);

  const readJWT3 = await signAgent(agentKp, agentId, { capabilities: ["note.read"] });
  const afterRevoke = await call("/capability/execute", {
    method: "POST",
    token: readJWT3,
    body: { capability: "note.read", arguments: {} },
  });
  check("AC-4 next call after grant revocation fails", afterRevoke.status === 403, `status=${afterRevoke.status}`);

  // ---- Agent revocation -------------------------------------------------
  const revokeAgent = await call("/agent/revoke", {
    method: "POST",
    token: hostJWT2,
    body: { agent_id: agentId },
  });
  check("agent revoked via host JWT", revokeAgent.status === 200 && revokeAgent.json?.status === "revoked", `status=${revokeAgent.status}`);

  const readJWT4 = await signAgent(agentKp, agentId, { capabilities: ["note.read"] });
  const afterAgentRevoke = await call("/capability/execute", {
    method: "POST",
    token: readJWT4,
    body: { capability: "note.read", arguments: {} },
  });
  check("AC-4 next call after agent revocation fails", afterAgentRevoke.status === 403, `status=${afterAgentRevoke.status}`);
  check(
    "AC-4 revocation reason = agent_revoked",
    afterAgentRevoke.json?.error === "agent_revoked",
    `error=${afterAgentRevoke.json?.error}`
  );

  // ---- Summary ----------------------------------------------------------
  console.log(`\n=== RESULT: ${passed} passed, ${failed} failed ===`);
  if (failed > 0) {
    console.log("Failures:");
    for (const f of failures) console.log(`  - ${f}`);
    process.exit(1);
  }
  console.log("All acceptance checks passed.");
  process.exit(0);
}

main().catch((err) => {
  console.error("Harness error:", err);
  process.exit(1);
});
