// verify-spec-on-behalf-of.mjs
// Acceptance harness for specs/projects/on-behalf-of/spec.md
// Drives @better-auth/agent-auth (BETA) delegated mode over HTTP against a
// running dev server.
//
// Flow: discover -> human signs in -> agent registers in DELEGATED mode
//       -> agent is pending (no-approval-no-grant) -> human approves via the
//       device code -> agent signs a short-lived scoped JWT and executes on
//       behalf of the human -> least-privilege, time-boxing, and human
//       revocation all bite.
//
// Each delegated agent gets its OWN host (one host = one device). A host that
// is claimed by a human auto-grants its other agents; a fresh host forces the
// approval gate.
//
// Usage: node scripts/verify-spec-on-behalf-of.mjs  (BASE_URL=http://localhost:3000 default)

import { generateKeypair, signHostJWT, signAgentJWT } from "@auth/agent";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";
const AUTH_BASE = `${BASE}/api/auth`;

const TEST_EMAIL = `delegated-${Date.now()}@example.com`;
const TEST_PASSWORD = "correct-horse-battery-staple-77";

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

function extractCookies(headers) {
  return headers.getSetCookie ? headers.getSetCookie().map((c) => c.split(";")[0]).join("; ") : "";
}

async function call(path, { method = "GET", body, token, cookies } = {}) {
  const res = await fetch(`${AUTH_BASE}${path}`, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(cookies ? { cookie: cookies } : {}),
      ...(body ? { origin: BASE } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try {
    json = await res.json();
  } catch {}
  return { status: res.status, json };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let DEFAULT_LOCATION;
let issuer;

async function registerDelegatedAgent(hostKp, agentKp, name, capabilities) {
  const hostJWT = await signHostJWT({
    hostKeypair: hostKp,
    agentPublicKey: agentKp.publicKey,
    hostName: `host-${name}`,
    audience: issuer,
    expiresInSeconds: 60,
  });
  const reg = await call("/agent/register", {
    method: "POST",
    token: hostJWT,
    body: {
      name,
      capabilities,
      mode: "delegated",
      preferred_method: "device_authorization",
      host_name: `host-${name}`,
    },
  });
  return {
    reg,
    agentId: reg.json?.agent_id,
    userCode: reg.json?.approval?.user_code,
    hostJWT,
  };
}

async function agentStatus(hostKp, agentId) {
  const jwt = await signHostJWT({
    hostKeypair: hostKp,
    hostName: `status-${agentId}`,
    audience: issuer,
    expiresInSeconds: 60,
  });
  return call(`/agent/status?agent_id=${agentId}`, { method: "GET", token: jwt });
}

async function main() {
  console.log(`\n=== On-behalf-of (delegated authority) acceptance (spec: projects/on-behalf-of) ===`);
  console.log(`Server: ${BASE}\n`);

  // ---- Discovery -----------------------------------------------------
  console.log("[1] Discovery (.well-known/agent-configuration)");
  const disco = await (await fetch(`${BASE}/.well-known/agent-configuration`)).json();
  check("FR-1 delegated mode advertised", disco.modes?.includes("delegated"));
  check("FR-4 device_authorization advertised", disco.approval_methods?.includes("device_authorization"));
  check("register endpoint advertised", disco.endpoints?.register?.includes("/agent/register"));
  issuer = disco.issuer;
  DEFAULT_LOCATION = disco.default_location;
  console.log(`     issuer=${issuer}\n     default_location=${DEFAULT_LOCATION}`);

  // ---- Human signs in ------------------------------------------------
  console.log("[2] Human signs in (the approver)");
  const su = await fetch(`${AUTH_BASE}/sign-up/email`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: BASE },
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD, name: "Delegated Human" }),
  });
  const suBody = await su.json().catch(() => null);
  check("human account created", su.status === 200 && !!suBody?.user?.id, `status=${su.status}`);
  const humanUserId = suBody?.user?.id;
  const si = await fetch(`${AUTH_BASE}/sign-in/email`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: BASE },
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD }),
  });
  const humanCookies = extractCookies(si.headers);
  check("human session established", si.status === 200 && humanCookies.length > 0, `status=${si.status}`);
  console.log(`     human_user_id=${humanUserId}`);

  // ---- Delegated agent registers -> pending + device approval --------
  console.log("[3] Agent registers in delegated mode (pending approval)");
  const hostKp = await generateKeypair();
  const agentKp = await generateKeypair();
  const { reg, agentId, userCode } = await registerDelegatedAgent(
    hostKp,
    agentKp,
    "on-behalf-note-writer",
    ["note.read", "note.create"]
  );
  check("register returns agent_id", reg.status === 200 && !!agentId, `status=${reg.status}`);
  check(
    "AC-1 agent is PENDING, not active (no approval yet)",
    reg.json?.status === "pending",
    `status=${reg.json?.status}`
  );
  const approval = reg.json?.approval;
  check(
    "FR-4 device-flow approval issued (user_code + verification_uri)",
    approval?.method === "device_authorization" &&
      typeof approval?.user_code === "string" &&
      typeof approval?.verification_uri_complete === "string",
    `method=${approval?.method}`
  );
  check("FR-3 approval is time-boxed (expires_in)", typeof approval?.expires_in === "number" && approval.expires_in > 0);
  console.log(`     agent_id=${agentId}\n     user_code=${userCode}\n     expires_in=${approval?.expires_in}s`);

  // ---- AC-1: no approval -> no grant ---------------------------------
  console.log("[4] No approval, no grant (AC-1)");
  const earlyJWT = await signAgentJWT({
    agentKeypair: agentKp,
    agentId,
    audience: DEFAULT_LOCATION,
    capabilities: ["note.read"],
    expiresInSeconds: 30,
  });
  const early = await call("/capability/execute", {
    method: "POST",
    token: earlyJWT,
    body: { capability: "note.read", arguments: {} },
  });
  check("AC-1 skipping approval yields nothing (403)", early.status === 403, `status=${early.status}`);
  const earlyStatus = await agentStatus(hostKp, agentId);
  check(
    "AC-1 agent still pending after skipped approval",
    earlyStatus.json?.status === "pending",
    `status=${earlyStatus.json?.status}`
  );

  // ---- Human approves via device code ---------------------------------
  console.log("[5] Human approves the device code");
  const approve = await call("/agent/approve-capability", {
    method: "POST",
    cookies: humanCookies,
    body: { agent_id: agentId, user_code: userCode, action: "approve" },
  });
  check("approve returns approved", approve.status === 200 && approve.json?.status === "approved", `status=${approve.status}`);
  check("note.read granted by approval", approve.json?.added?.includes("note.read"), `added=[${approve.json?.added?.join(", ")}]`);
  check("note.create granted by approval", approve.json?.added?.includes("note.create"), `added=[${approve.json?.added?.join(", ")}]`);

  const afterApproveStatus = await agentStatus(hostKp, agentId);
  check("AC-1 after approval agent is active", afterApproveStatus.json?.status === "active", `status=${afterApproveStatus.json?.status}`);

  // ---- AC-5: session shows agent + on-behalf-of user ------------------
  console.log("[6] Attribution: agent acting FOR the human (AC-5)");
  const sessJWT = await signAgentJWT({
    agentKeypair: agentKp,
    agentId,
    audience: issuer,
    capabilities: ["note.read"],
    expiresInSeconds: 30,
  });
  const sess = await call("/agent/session", { method: "GET", token: sessJWT });
  check("agent session resolves", sess.status === 200 && !!sess.json?.agent, `status=${sess.status}`);
  check(
    "AC-5 session shows BOTH the agent and the on-behalf-of human",
    sess.json?.agent?.id === agentId && sess.json?.user?.id === humanUserId,
    `agent=${sess.json?.agent?.id} user=${sess.json?.user?.id}`
  );
  check(
    "AC-5 not impersonation: the user is the approving human, not a synthetic user",
    sess.json?.user?.id === humanUserId,
    `user=${sess.json?.user?.id}`
  );

  // ---- AC-2: bounded authority ----------------------------------------
  console.log("[7] Least privilege (AC-2)");
  const readJWT = await signAgentJWT({
    agentKeypair: agentKp,
    agentId,
    audience: DEFAULT_LOCATION,
    capabilities: ["note.read"],
    expiresInSeconds: 30,
  });
  const exec = await call("/capability/execute", {
    method: "POST",
    token: readJWT,
    body: { capability: "note.read", arguments: {} },
  });
  check("AC-2 granted note.read executes on behalf of human", exec.status === 200 && Array.isArray(exec.json?.data?.notes), `status=${exec.status}`);

  const createJWT = await signAgentJWT({
    agentKeypair: agentKp,
    agentId,
    audience: DEFAULT_LOCATION,
    capabilities: ["note.create"],
    expiresInSeconds: 30,
  });
  const created = await call("/capability/execute", {
    method: "POST",
    token: createJWT,
    body: { capability: "note.create", arguments: { title: "on-behalf note", body: "written by the agent for the human" } },
  });
  const createdId = created.json?.data?.id;
  check("note.create runs when granted", created.status === 200 && created.json?.data?.ok === true, `status=${created.status}`);

  const readBackJWT = await signAgentJWT({
    agentKeypair: agentKp,
    agentId,
    audience: DEFAULT_LOCATION,
    capabilities: ["note.read"],
    expiresInSeconds: 30,
  });
  const readBack = await call("/capability/execute", {
    method: "POST",
    token: readBackJWT,
    body: { capability: "note.read", arguments: {} },
  });
  const note = readBack.json?.data?.notes?.find((n) => n.id === createdId);
  check(
    "AC-2 action attributed to the human on whose behalf it ran",
    note?.createdBy === humanUserId,
    `createdBy=${note?.createdBy}`
  );
  check(
    "AC-5 attribution includes the acting agent (createdByAgent)",
    note?.createdByAgent === agentId,
    `createdByAgent=${note?.createdByAgent}`
  );

  const delJWT = await signAgentJWT({
    agentKeypair: agentKp,
    agentId,
    audience: DEFAULT_LOCATION,
    capabilities: ["note.delete"],
    expiresInSeconds: 30,
  });
  const refused = await call("/capability/execute", {
    method: "POST",
    token: delJWT,
    body: { capability: "note.delete", arguments: { id: "x" } },
  });
  check("AC-2 never-approved note.delete refused", refused.status === 403, `status=${refused.status}`);
  check("AC-2 refusal reason = capability_not_granted", refused.json?.error === "capability_not_granted", `error=${refused.json?.error}`);

  // ---- AC-3: time-boxed grant ------------------------------------------
  console.log("[8] Time-boxed grant (AC-3)");
  // Use note.delete: it is NOT in the host's default budget (note.read/create),
  // so when its grant expires nothing re-grants it — the delegation truly ends.
  const hostKp2 = await generateKeypair();
  const agentKp2 = await generateKeypair();
  const r2 = await registerDelegatedAgent(hostKp2, agentKp2, "short-lived-writer", ["note.delete"]);
  const agentId2 = r2.agentId;
  const userCode2 = r2.userCode;
  const approve2 = await call("/agent/approve-capability", {
    method: "POST",
    cookies: humanCookies,
    body: { agent_id: agentId2, user_code: userCode2, action: "approve", ttl: 6 },
  });
  check("second agent approved with 6s grant ttl", approve2.status === 200 && approve2.json?.status === "approved", `status=${approve2.status}`);
  const shortJWT = await signAgentJWT({
    agentKeypair: agentKp2,
    agentId: agentId2,
    audience: DEFAULT_LOCATION,
    capabilities: ["note.delete"],
    expiresInSeconds: 30,
  });
  const okNow = await call("/capability/execute", {
    method: "POST",
    token: shortJWT,
    body: { capability: "note.delete", arguments: { id: "no-such-note" } },
  });
  check("AC-3 grant works while unexpired", okNow.status === 200, `status=${okNow.status}`);

  console.log("     waiting 8s for grant expiry...");
  await sleep(8000);
  const freshJWT = await signAgentJWT({
    agentKeypair: agentKp2,
    agentId: agentId2,
    audience: DEFAULT_LOCATION,
    capabilities: ["note.delete"],
    expiresInSeconds: 30,
  });
  const afterExpiry = await call("/capability/execute", {
    method: "POST",
    token: freshJWT,
    body: { capability: "note.delete", arguments: { id: "no-such-note" } },
  });
  check(
    "AC-3 past grant expiry the token is rejected",
    afterExpiry.status === 403,
    `status=${afterExpiry.status}`
  );

  // ---- AC-4: human can revoke ------------------------------------------
  console.log("[9] Human revokes the delegation (AC-4)");
  const revoke = await call("/agent/revoke", {
    method: "POST",
    cookies: humanCookies,
    body: { agent_id: agentId },
  });
  check("AC-4 human revokes via their own session", revoke.status === 200 && revoke.json?.status === "revoked", `status=${revoke.status}`);

  const revokedJWT = await signAgentJWT({
    agentKeypair: agentKp,
    agentId,
    audience: DEFAULT_LOCATION,
    capabilities: ["note.read"],
    expiresInSeconds: 30,
  });
  const afterRevoke = await call("/capability/execute", {
    method: "POST",
    token: revokedJWT,
    body: { capability: "note.read", arguments: {} },
  });
  check("AC-4 next call after human revocation fails", afterRevoke.status === 403, `status=${afterRevoke.status}`);
  check("AC-4 revocation reason = agent_revoked", afterRevoke.json?.error === "agent_revoked", `error=${afterRevoke.json?.error}`);

  // ---- AC-1 deny path (no approval => rejection) ------------------------
  console.log("[10] Deny path (AC-1)");
  const hostKp3 = await generateKeypair();
  const agentKp3 = await generateKeypair();
  const r3 = await registerDelegatedAgent(hostKp3, agentKp3, "denied-writer", ["note.read"]);
  const agentId3 = r3.agentId;
  const userCode3 = r3.userCode;
  const deny = await call("/agent/approve-capability", {
    method: "POST",
    cookies: humanCookies,
    body: { agent_id: agentId3, user_code: userCode3, action: "deny", reason: "I don't trust this agent" },
  });
  check("deny returns denied", deny.status === 200 && deny.json?.status === "denied", `status=${deny.status}`);
  const deniedJWT = await signAgentJWT({
    agentKeypair: agentKp3,
    agentId: agentId3,
    audience: DEFAULT_LOCATION,
    capabilities: ["note.read"],
    expiresInSeconds: 30,
  });
  const deniedExec = await call("/capability/execute", {
    method: "POST",
    token: deniedJWT,
    body: { capability: "note.read", arguments: {} },
  });
  check(
    "AC-1 denied agent cannot execute (no grant ever issued)",
    deniedExec.status === 403,
    `status=${deniedExec.status}`
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
