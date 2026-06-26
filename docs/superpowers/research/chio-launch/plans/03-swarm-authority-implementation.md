# Swarm Authority Implementation Plan

Status: implementation plan
Depends on: `../architecture/03-swarm-authority-system.md`
Confidence: moderate.

## Objective

Make recursive delegation and multi-swarm coordination verifier-grade.

## Registry Acceptance

Swarm artifacts are authority artifacts, not log decoration. Any task graph, continuation token, witness chain, join receipt, route-plan receipt, or budget pool accepted by a verifier must be registered through `../indices/artifact-registry.md` and `../architecture/09-integration-contracts.md` before code treats it as supported.

## Implementation Slices

| Slice | Scope | Done when |
| --- | --- | --- |
| SWARM-0A | Register task graph, continuation token, witness chain, join receipt, route-plan receipt, revocation epoch, and budget pool schemas. | Registry, manifest, Rust allowlist, and unknown-schema negatives pass. |
| SWARM-0B | Validate task graph ids, parent links, edge predicates, route refs, and graph expiry. | Cycle, duplicate task id, missing parent, and stale graph negatives reject. |
| SWARM-0C | Emit per-child verifier report rows for task, route, witness, token, budget, and revocation evidence. | Reports answer each child authority question without aggregate-only verdicts. |
| SWARM-1A | Verify per-hop witness signatures against externally pinned witness keys. | Missing, stale, broadened, or untrusted witness rejects. |
| SWARM-1B | Enforce attenuation scope subset and egress constraints. | Child broader than parent and unsupported egress constraints reject. |
| SWARM-2A | Mint continuation tokens bound to graph, child task, parent receipt, route plan, budget lease, revocation epoch, and nonce. | Any binding mismatch rejects. |
| SWARM-2B | Persist single-use token consumption for side-effecting child work. | Reuse after side effect rejects in runtime admission. |
| SWARM-3A | Verify multi-parent join receipts before fan-in continuation. | Missing, duplicate, unexpected, or raw-parent fan-in rejects. |
| SWARM-4A | Verify signed route-plan receipts. | Route, registry snapshot, bridge id, and egress drift reject. |
| SWARM-4B | Require route plans for MCP dispatch. | Route-plan-less MCP child execution is denied. |
| SWARM-4C | Require route plans for A2A dispatch. | Route-plan-less A2A child execution is denied. |
| SWARM-4D | Require route plans for ACP-Client dispatch. | Route-plan-less ACP-Client child execution is denied. |
| SWARM-4E | Require route plans for HTTP and OpenAPI dispatch. | Route-plan-less HTTP or OpenAPI child execution is denied. |
| SWARM-4F | Require route plans for OpenAI provider dispatch. | Route-plan-less provider child execution is denied. |
| SWARM-4G | Require route plans for local nested dispatch. | Route-plan-less local child execution is denied. |

## Phase 0 - Spec And Types

Tasks:

1. Add protocol sections for swarm task graph, continuation token, delegation witness chain, join receipt, route-plan receipt, revocation epoch binding, and swarm budget pool.
2. Add schemas and canonical JSON rules.
3. Define graph validation rules.
4. Define side-effecting single-use semantics.

Tests:

- invalid cycle fails;
- duplicate task id fails;
- expired graph fails;
- unknown route-plan ref fails.

## Phase 1 - Per-Hop Witness Verification

Tasks:

1. Extend attenuation verification to require explicit per-hop witness material.
2. Add scope subset proof logic.
3. Add expiry and issuer chain checks.
4. Add verifier report entries for each hop.

Tests:

- two-hop attenuation valid fixture passes;
- child broader than parent fails;
- stale parent authority fails;
- wrong witness signer fails.

## Phase 2 - Continuation Tokens

Tasks:

1. Implement continuation token minting.
2. Bind child task, parent receipt, graph digest, route plan, budget allocation, revocation epoch, and nonce.
3. Add token consumption tracking for side-effecting tasks.
4. Add resumable mode for deferred tasks with fresh epoch check.

Tests:

- reused single-use token fails;
- deferred resume without fresh epoch check fails;
- token for different graph fails;
- token for different child task fails.

## Phase 3 - Join Receipts

Tasks:

1. Implement multi-parent join receipt generation.
2. Validate expected and actual parent receipt sets.
3. Bind join result to next task continuation.
4. Add proof room rendering for fan-in.

Tests:

- missing parent fails;
- duplicate parent fails;
- unexpected parent fails;
- next task using raw parent instead of join receipt fails.

## Phase 4 - Route-Plan Receipts

Tasks:

1. Promote existing route selection output into signed route-plan receipts.
2. Require route-plan receipt in MCP, A2A, ACP-Client, HTTP/OpenAPI, OpenAI, and local nested dispatch.
3. Bind registry snapshot and egress constraints.
4. Reject caller-supplied route metadata without a route-plan receipt.

Tests:

- selected route mismatch fails;
- registry snapshot mismatch fails;
- HTTP egress contract mismatch fails;
- bridge id mismatch fails.

## Phase 5 - Budget Pools And Revocation

Tasks:

1. Implement graph-level budget pool.
2. Add budget allocations and leases.
3. Add fan-out reservation and fan-in release.
4. Bind continuation token to revocation epoch root.

Tests:

- budget over-allocation fails;
- double spend fails;
- revoked leaf fails;
- revoked ancestor fails.

## Phase 6 - Launch Fixture

Tasks:

1. Build one recursive swarm fixture with at least three child tasks and one join.
2. Include one cross-protocol route.
3. Include one disclosure capsule and one commerce order ref if the swarm does commerce.
4. Add negative fixtures for all failure cases.

Exit criteria:

- "multi-swarm coordination" can be verified from a Transaction Passport;
- proof room graph shows parent, child, route, join, budget, and revocation evidence;
- stale or broadened authority fails closed.
