// verify-spec-step-up-approval.mjs
// Acceptance harness for specs/projects/step-up-approval/spec.md
// Drives @better-auth/agent-auth (BETA) over HTTP against a running dev server.
//
// The approval-strength ladder, exercised across two hosts:
//   Host A (autonomous, unowned)  — AUTO rung + least-privilege + no self-widen.
//     note.read (approvalStrength "none") auto-grants to an autonomous agent via
//     the host capability budget. No human anywhere. (This host is never
//     approved, so its autonomous agent is never claimed.)
//   Host B (created by the human) — SESSION rung + PHYSICAL rung.
//     note.share / note.sign (approvalStrength "session") are approved by a
//     logged-in human via the device flow. note.destroy ("webauthn") cannot be
//     approved by a session alone — refused with a physical-presence challenge.
// Plus: a value-constraint (recipientDomain) enforced at execution time, and a
// single-use grant (note.sign consumed by revokeGrant()).
//
// REQUIREMENT: boot the dev server with STEP_UP_PROOF_OF_PRESENCE=true, e.g.
//   STEP_UP_PROOF_OF_PRESENCE=true pnpm dev
// (default boot keeps proofOfPresence off so the on-behalf-of flow is unchanged)
//
// Usage: node scripts/verify-spec-step-up-approval.mjs  (BASE_URL=http://localhost:3000 default)

import { generateKeypair, signHostJWT, signAgentJWT } from "@auth/agent";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";
const AUTH_BASE = `${BASE}/api/auth`;

const TEST_EMAIL = `stepup-${Date.now()}@example.com`;
const TEST_PASSWORD = "correct-horse-battery-staple-77";

let passed = 0;
let failed = 0;
const failures = [];
let transientRetries = 0;

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

let DEFAULT_LOCATION;
let issuer;

async function registerAgent(hostKp, agentKp, name, capabilities, mode = "delegated") {
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
      mode,
      preferred_method: "device_authorization",
      host_name: `host-${name}`,
    },
  });
  return { reg, agentId: reg.json?.agent_id, userCode: reg.json?.approval?.user_code };
}

async function createHost(hostKp, name, cookies) {
  const res = await fetch(`${AUTH_BASE}/host/create`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: cookies, origin: BASE },
    body: JSON.stringify({ name, public_key: hostKp.publicKey }),
  });
  const json = await res.json().catch(() => null);
  return { status: res.status, json };
}

async function agentStatus(hostKp, agentId) {
  const jwt = await signHostJWT({ hostKeypair: hostKp, hostName: `status-${agentId}`, audience: issuer, expiresInSeconds: 60 });
  return call(`/agent/status?agent_id=${agentId}`, { method: "GET", token: jwt });
}

function agentJWT(agentKp, agentId, capabilities, audience = DEFAULT_LOCATION) {
  return signAgentJWT({ agentKeypair: agentKp, agentId, audience, capabilities, expiresInSeconds: 30 });
}

// Execute a capability as an agent, with a bounded retry for a known beta race:
// @better-auth/agent-auth intermittently fails a freshly signed agent JWT with a
// transient 401 invalid_jwt on the wire (fresh key, aud, and jti each attempt).
// A retry with a fresh JWT succeeds, and it never turns a deterministic refusal
// (403 constraint_violated / capability_not_granted) into a pass, because the
// grant state is identical between attempts.
async function execute(agentParams, capability, args) {
  const attempt = (jwt) => call("/capability/execute", {
    method: "POST",
    token: jwt,
    body: { capability, arguments: args ?? {} },
  });
  const jwt = await agentJWT(agentParams.agentKeypair, agentParams.agentId, agentParams.capabilities, agentParams.audience);
  const res = await attempt(jwt);
  if (res.status === 401 && res.json?.error === "invalid_jwt") {
    transientRetries++;
    const retry = await attempt(await agentJWT(agentParams.agentKeypair, agentParams.agentId, agentParams.capabilities, agentParams.audience));
    if (retry.status !== 401) return retry;
  }
  return res;
}

async function main() {
  console.log(`\n=== Step-up approval: capabilities, value-constraints, graded approval (spec: projects/step-up-approval) ===`);
  console.log(`Server: ${BASE} (must be booted with STEP_UP_PROOF_OF_PRESENCE=true)\n`);

  // ---- Discovery -----------------------------------------------------
  console.log("[1] Discovery + capability listing");
  const disco = await (await fetch(`${BASE}/.well-known/agent-configuration`)).json();
  check("delegated + autonomous modes advertised", disco.modes?.includes("delegated") && disco.modes?.includes("autonomous"));
  check("device_authorization advertised", disco.approval_methods?.includes("device_authorization"));
  issuer = disco.issuer;
  DEFAULT_LOCATION = disco.default_location;

  const caps = await call("/capability/list", { method: "GET" });
  const capNames = caps.json?.capabilities?.map((c) => c.name) ?? [];
  check("ladder capabilities advertised (read/share/sign/destroy)", ["note.read", "note.share", "note.sign", "note.destroy"].every((n) => capNames.includes(n)), `[${capNames.join(", ")}]`);
  const strengthOf = (n) => caps.json?.capabilities?.find((c) => c.name === n)?.approval_strength;
  check("FR-1 ladder advertised: read=none, share=session, destroy=webauthn", strengthOf("note.read") === "none" && strengthOf("note.share") === "session" && strengthOf("note.destroy") === "webauthn", `read=${strengthOf("note.read")} share=${strengthOf("note.share")} destroy=${strengthOf("note.destroy")}`);
  console.log(`     issuer=${issuer}\n     default_location=${DEFAULT_LOCATION}`);

  // ---- Human signs in ------------------------------------------------
  console.log("[2] Human signs in (the approver)");
  const su = await fetch(`${AUTH_BASE}/sign-up/email`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: BASE },
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD, name: "Step-up Human" }),
  });
  const suBody = await su.json().catch(() => null);
  check("human account created", su.status === 200 && !!suBody?.user?.id, `status=${su.status}`);
  const si = await fetch(`${AUTH_BASE}/sign-in/email`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: BASE },
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD }),
  });
  const humanCookies = extractCookies(si.headers);
  check("human session established", si.status === 200 && humanCookies.length > 0, `status=${si.status}`);

  // ---- Host A: AUTO rung + least privilege + no self-widen -----------
  console.log("[3] AUTO rung: note.read auto-grants, no human (AC-1)");
  const hostAKp = await generateKeypair();

  const agentKpAuto = await generateKeypair();
  const auto = await registerAgent(hostAKp, agentKpAuto, "auto-reader", ["note.read"], "autonomous");
  check("autonomous agent registered", auto.reg.status === 200 && !!auto.agentId, `status=${auto.reg.status}`);
  check("AC-1 note.read auto-grants WITHOUT approval (agent active, no pending)", auto.reg.json?.status === "active" && !auto.reg.json?.approval, `status=${auto.reg.json?.status} approval=${!!auto.reg.json?.approval}`);
  const autoGrantStatus = auto.reg.json?.agent_capability_grants?.find((g) => g.capability === "note.read")?.status;
  check("AC-1 note.read grant is active", autoGrantStatus === "active", `status=${autoGrantStatus}`);

  const read = await execute({ agentKeypair: agentKpAuto, agentId: auto.agentId, capabilities: ["note.read"] }, "note.read", {});
  check("AC-1 granted note.read executes", read.status === 200 && Array.isArray(read.json?.data?.notes), `status=${read.status}`);

  const notGrantedShare = await execute({ agentKeypair: agentKpAuto, agentId: auto.agentId, capabilities: ["note.share"] }, "note.share", { noteId: "n1", recipientDomain: "acme.com" });
  check("AC-1 not-granted note.share refused", notGrantedShare.status === 403 && notGrantedShare.json?.error === "capability_not_granted", `status=${notGrantedShare.status} error=${notGrantedShare.json?.error}`);

  const notGrantedDestroy = await execute({ agentKeypair: agentKpAuto, agentId: auto.agentId, capabilities: ["note.destroy"] }, "note.destroy", { id: "n1" });
  check("AC-1 not-granted note.destroy refused", notGrantedDestroy.status === 403, `status=${notGrantedDestroy.status}`);

  const forged = await execute({ agentKeypair: agentKpAuto, agentId: auto.agentId, capabilities: ["note.share", "note.sign"] }, "note.share", { noteId: "n1", recipientDomain: "acme.com" });
  check("AC-1 claiming an un-granted capability in the JWT still refused", forged.status === 403 && forged.json?.error === "capability_not_granted", `status=${forged.status} error=${forged.json?.error}`);

  // ---- FR-2 adversarial: requiredConstraints is enforced at request time ----
  console.log("[4] FR-2: requiredConstraints enforced at registration");
  const hostKpBad = await generateKeypair();
  const agentKpBad = await generateKeypair();
  const bare = await registerAgent(hostKpBad, agentKpBad, "no-constraint", ["note.share"]);
  check("FR-2 requesting note.share WITHOUT a constraint is rejected (400)", bare.reg.status === 400, `status=${bare.reg.status}`);
  check("FR-2 rejection is invalid_request", bare.reg.json?.error === "invalid_request", `error=${bare.reg.json?.error}`);

  // ---- Host B: human-owned, active — SESSION rung --------------------
  console.log("[5] Host B created by the human (active, owned)");
  const hostBKp = await generateKeypair();
  const hostB = await createHost(hostBKp, "stepup-device", humanCookies);
  check("human creates host B", hostB.status === 200 && !!hostB.json?.hostId, `status=${hostB.status}`);

  console.log("[6] SESSION rung: delegated agent requests note.share (constrained) + note.sign");
  const agentKpB = await generateKeypair();
  const b = await registerAgent(hostBKp, agentKpB, "stepup-delegated", [
    { name: "note.share", constraints: { recipientDomain: { in: ["acme.com"] } } },
    "note.sign",
  ]);
  check("delegated agent registered (pending)", b.reg.status === 200 && b.reg.json?.status === "pending", `status=${b.reg.status} agentStatus=${b.reg.json?.status}`);
  const bApproval = b.reg.json?.approval;
  check("device-flow approval issued (user_code)", typeof bApproval?.user_code === "string" && bApproval?.method === "device_authorization", `method=${bApproval?.method}`);

  const pre = await execute({ agentKeypair: agentKpB, agentId: b.agentId, capabilities: ["note.share"] }, "note.share", { noteId: "n1", recipientDomain: "acme.com" });
  check("before approval, note.share not granted", pre.status === 403, `status=${pre.status}`);

  const approveB = await call("/agent/approve-capability", {
    method: "POST",
    cookies: humanCookies,
    body: { agent_id: b.agentId, user_code: b.userCode, action: "approve" },
  });
  check("SESSION rung: normal logged-in session approves note.share + note.sign", approveB.status === 200 && approveB.json?.status === "approved", `status=${approveB.status}`);
  check("approval granted note.share", approveB.json?.added?.includes("note.share"), `added=[${approveB.json?.added?.join(", ")}]`);
  check("approval granted note.sign", approveB.json?.added?.includes("note.sign"));

  console.log("[7] AC-2/AC-3: value-constraint enforced at execution time");
  const inScope = await execute({ agentKeypair: agentKpB, agentId: b.agentId, capabilities: ["note.share"] }, "note.share", { noteId: "n1", recipientDomain: "acme.com" });
  check("AC-2 in-scope recipientDomain @acme.com executes", inScope.status === 200 && inScope.json?.data?.ok === true, `status=${inScope.status} error=${inScope.json?.error}`);

  const outScope = await execute({ agentKeypair: agentKpB, agentId: b.agentId, capabilities: ["note.share"] }, "note.share", { noteId: "n1", recipientDomain: "evil.com" });
  check("AC-3 out-of-scope recipientDomain @evil.com refused", outScope.status === 403 && outScope.json?.error === "constraint_violated", `status=${outScope.status} error=${outScope.json?.error}`);
  check("AC-3 refusal reports the violating field", Array.isArray(outScope.json?.violations) && outScope.json.violations.length > 0, `violations=${JSON.stringify(outScope.json?.violations)}`);

  const afterRefusal = await execute({ agentKeypair: agentKpB, agentId: b.agentId, capabilities: ["note.share"] }, "note.share", { noteId: "n1", recipientDomain: "acme.com" });
  check("AC-3 refusal did NOT consume the grant (in-scope still works)", afterRefusal.status === 200 && afterRefusal.json?.data?.ok === true, `status=${afterRefusal.status} error=${afterRefusal.json?.error}`);

  console.log("[8] AC-5: single-use sensitive grant (note.sign)");
  const sign1 = await execute({ agentKeypair: agentKpB, agentId: b.agentId, capabilities: ["note.sign"] }, "note.sign", { noteId: "n1" });
  check("AC-5 note.sign executes once", sign1.status === 200 && sign1.json?.data?.ok === true, `status=${sign1.status}`);
  const sign2 = await execute({ agentKeypair: agentKpB, agentId: b.agentId, capabilities: ["note.sign"] }, "note.sign", { noteId: "n1" });
  check("AC-5 second call fails as NOT-granted (stale grant rejected)", sign2.status === 403 && sign2.json?.error === "capability_not_granted", `status=${sign2.status} error=${sign2.json?.error} message=${sign2.json?.message}`);

  // ---- AC-4: physical-presence guardrail -------------------------------
  console.log("[9] PHYSICAL rung: note.destroy cannot be approved by a session (AC-4)");
  const agentKpC = await generateKeypair();
  const c = await registerAgent(hostBKp, agentKpC, "stepup-destroyer", ["note.destroy"]);
  check("destructive agent registered (pending)", c.reg.status === 200 && c.reg.json?.status === "pending", `status=${c.reg.status} agentStatus=${c.reg.json?.status}`);
  const cApproval = c.reg.json?.approval;
  check("destructive agent got a device approval request", typeof cApproval?.user_code === "string");

  const cApprove = await call("/agent/approve-capability", {
    method: "POST",
    cookies: humanCookies,
    body: { agent_id: c.agentId, user_code: c.userCode, action: "approve" },
  });
  // The plugin serializes this refusal as a 200 body with an error code on the
  // wire (a beta quirk of ctx.json in this build); the durable contract is that
  // the approval is REFUSED with a physical-presence challenge and NOT granted.
  check("AC-4 session-only approval of note.destroy is REFUSED with a physical-presence challenge", cApprove.json?.error === "webauthn_not_enrolled", `error=${cApprove.json?.error} status=${cApprove.status}`);
  check("AC-4 refusal message tells the human to register a passkey", typeof cApprove.json?.message === "string" && /passkey/i.test(cApprove.json.message), `message=${cApprove.json?.message}`);

  const cStatus = await agentStatus(hostBKp, c.agentId);
  check("AC-4 capability stays UNGRANTED (agent still pending)", cStatus.json?.status === "pending", `status=${cStatus.json?.status}`);
  const cGrant = cStatus.json?.agent_capability_grants?.find((g) => g.capability === "note.destroy");
  check("AC-4 note.destroy grant never became active", cGrant?.status !== "active", `grantStatus=${cGrant?.status}`);

  const cExec = await execute({ agentKeypair: agentKpC, agentId: c.agentId, capabilities: ["note.destroy"] }, "note.destroy", { id: "n1" });
  check("AC-4 agent still cannot execute note.destroy", cExec.status === 403, `status=${cExec.status} error=${cExec.json?.error}`);

  // ---- AC-1 adversarial: no way to widen one's own grant --------------
  console.log("[10] AC-1: an agent cannot widen its own grant");
  const agentKpWide = await generateKeypair();
  // Requests note.share WITH a proper constraint (valid form), plus the
  // destructive/single-use caps — none of which the autonomous budget grants.
  const wide = await registerAgent(hostAKp, agentKpWide, "wide-requestor", [
    "note.read",
    { name: "note.share", constraints: { recipientDomain: { in: ["acme.com"] } } },
    "note.destroy",
    "note.sign",
  ], "autonomous");
  check("AC-1 wide registration accepted (only budget caps granted)", wide.reg.status === 200 && !!wide.agentId, `status=${wide.reg.status} error=${wide.reg.json?.error}`);
  const wideGrantCaps = (wide.reg.json?.agent_capability_grants ?? [])
    .filter((g) => g.status === "active")
    .map((g) => g.capability);
  check("AC-1 out-of-budget requests (share/destroy/sign) were NOT auto-granted", !wideGrantCaps.includes("note.destroy") && !wideGrantCaps.includes("note.share") && !wideGrantCaps.includes("note.sign"), `active=[${wideGrantCaps.join(", ")}]`);
  const wideDestroy = await execute({ agentKeypair: agentKpWide, agentId: wide.agentId, capabilities: ["note.destroy"] }, "note.destroy", { id: "n1" });
  check("AC-1 widened note.destroy request still refused", wideDestroy.status === 403 && wideDestroy.json?.error === "capability_not_granted", `status=${wideDestroy.status} error=${wideDestroy.json?.error}`);

  // ---- Summary ----------------------------------------------------------
  console.log(`\n=== RESULT: ${passed} passed, ${failed} failed ===`);
  if (transientRetries > 0) {
    console.log(`(note: ${transientRetries} transient beta invalid_jwt 401s were retried with a fresh agent JWT and succeeded)`);
  }
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
