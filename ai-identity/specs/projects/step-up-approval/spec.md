# spec.md — Scope and gate an agent: capabilities, value-constraints, step-up

> **Half 2 — frontier.** Built on `@better-auth/agent-auth`, which is **beta, the standard is still moving**. A **verified worked example exists** (`worked-examples/ai-identity/` — `src/lib/auth.ts`, `agent-consumer/`, `agent-verify.sh`), so this is buildable, not theoretical. Treat the specific API as **one swappable instantiation** of the durable primitives (least-privilege capability, value-level constraint, graded human approval, single-use). When the standard settles, the primitives stay; only the calls change.

## Goal

The two mode specs (`agent-credential`, `on-behalf-of`) answer _whose_ authority an agent holds. This one answers _how tightly_ it is bounded and _how hard it is to widen_. Three primitives, each stricter than what plain OAuth scopes can express:

1. **Capabilities** — named actions, not blanket access. An agent holds only the capabilities it was granted.
2. **Value-level constraints** — a capability can be pinned to allowed _values_, not just turned on. "May share notes" is weaker than "may share notes only with `@acme.com`." OAuth scope strings cannot say that; a constraint can (`{ recipientDomain: { in: ["acme.com"] } }`), and it is checked at execution time.
3. **Graded approval (step-up)** — the strength of the human check scales with the blast radius. A read auto-grants; a share needs a logged-in human; an irreversible action needs **physical presence** (a passkey / WebAuthn), so an AI agent with a browser cannot approve its own destruction.

The durable point: authority is least-privilege by default, narrowed by value where it matters, and the human gate gets harder as the action gets more dangerous.

## Functional Requirements

- FR-1 Define at least three capabilities spanning the **approval-strength ladder**: one that auto-grants (no human), one that needs a normal logged-in session, and one destructive capability that requires physical-presence (WebAuthn) approval.
- FR-2 At least one capability carries a **required value-constraint** the agent must scope when it requests the capability (e.g. an allowed recipient domain, a maximum amount).
- FR-3 The constraint is **enforced at execution time**: a call whose argument violates the constraint is refused, and the refusal does not consume the grant.
- FR-4 The destructive capability **cannot be approved by a normal session** — approving it without a registered authenticator is refused with a step-up challenge, not granted.
- FR-5 A sensitive grant is **single-use** where appropriate: after one successful execution it is consumed and the next call must be re-approved.

## Acceptance Criteria

- [x] AC-1 **Least privilege:** an agent invokes a granted capability and is refused one it was not granted, with no way to widen its own grant.
- [x] AC-2 **Constraint holds in-bounds:** an in-scope value (recipient `@acme.com`) executes successfully.
- [x] AC-3 **Constraint bites out-of-bounds:** an out-of-scope value (recipient `@evil.com`) is refused with a constraint violation, and the grant survives (the rejected call did not consume it).
- [x] AC-4 **Step-up is enforced:** approving the destructive capability with only a logged-in session is refused with a physical-presence challenge; the capability stays ungranted and the agent still cannot execute it.
- [x] AC-5 **Single-use:** a sensitive grant works exactly once; the second call fails as not-granted rather than succeeding on a stale grant.

## Notes for the builder

- Read `.agents/skills/agent-identity-issuer/` and confirm the live surface against the Better Auth docs MCP — this is beta. The verified worked example shows one passing shape (capabilities with `approvalStrength: none|session|webauthn`, `requiredConstraints`, a `revokeGrant()` consume in the execute handler), but check the current API before you build.
- **Verified build notes (this repo, `@better-auth/agent-auth@0.6.2`):** the ladder lives on `capability.approvalStrength` (`none|session|webauthn`) with `capability.requiredConstraints` enforced at register/request time; value constraints use `eq|min|max|in|not_in` and are re-checked at execution time (a violation → `constraint_violated`, grant survives); single-use is a `revokeGrant()` call in `onExecute` that flips the grant to `consumed` (next call → `capability_not_granted`).
- **Proof-of-presence is env-gated:** the WebAuthn step-up gate requires `proofOfPresence: { enabled: true }`. This repo gates it behind `STEP_UP_PROOF_OF_PRESENCE=true` because, with it on, approving a pending agent on a *pending* host also demands WebAuthn for everything — which would break the on-behalf-of flow. Boot the server with the flag for this spec's harness; boot normally for the other specs. Two beta quirks the harness documents: the webauthn refusal is serialized as a 200 body with `error: webauthn_not_enrolled` (source says 403, wire says 200), and agent JWTs intermittently fail with a transient `401 invalid_jwt` (the harness retries once with a fresh JWT; grant state is unchanged so a deterministic refusal can't become a pass).
- Completing a WebAuthn approval needs a real or virtual authenticator. The **guardrail** (refusing a session-only approval for a destructive capability) is fully testable without one — that is what AC-4 checks. Note in your build where a real passkey would complete the step-up.
- Keep the acceptance criteria even if the calls move: least-privilege capability, value-constraint enforced at execution, graded approval with physical-presence step-up, single-use consume.
