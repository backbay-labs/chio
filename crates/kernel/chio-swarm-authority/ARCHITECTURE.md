# chio-swarm-authority architecture

## Overview

`chio-swarm-authority` is a fail-closed verifier for recursive AI-agent swarm
delegation: given a signed bundle of task-graph, continuation, witness, join,
route-plan, budget, and revocation artifacts, it decides whether a specific
child task is authorized to run. It holds no runtime state and performs no
I/O; every fact it checks comes from the bundle itself or from the
caller-supplied trusted witness key set (`chio_core_types::crypto::PublicKey`).

It sits under `crates/kernel` because both of its consumers are
admission-adjacent rather than protocol-transport code: `chio-runtime-core`
calls `verify_swarm_authority_bundle` from a trusted pre-dispatch admission
hook, and `chio-proof-room` calls the same function from an untrusted-input,
post-hoc public proof path. Both call sites get identical acceptance criteria
because they call the same function against the same bundle shape, so the
workspace has one definition of delegation authority rather than two.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public module declarations and re-exports only; no logic. |
| `src/types.rs` | Wire types for every swarm artifact (task graph, continuation token, witness chain/hop, join receipt, route-plan receipt, budget pool/allocation, revocation epoch, terminal graph receipt, verifier report) and their schema (`CHIO_SWARM_*_SCHEMA`) and claim (`CLAIM_SWARM_*`) constants. |
| `src/error.rs` | `SwarmAuthorityError`: `Rejected` for fail-closed validation, `Canonical` for canonical-JSON/signing failure. |
| `src/verifier.rs` | `verify_swarm_authority_bundle` and the full validation pipeline (task-graph shape, route-plan/join/budget/revocation/terminal-receipt/continuation-token checks); the `mint_*`/`sign_*` fixture constructors and the budget fan-out/fan-in helpers. |
| `src/verifier/util.rs` | Shared field checks (`require_non_empty`, `require_sha256`, `require_unique_strings`, `require_same_graph`), the canonical signature-body builders (signature field stripped before hashing), and the `rejected()` error constructor. |
| `src/verifier/witness.rs` | Delegation witness chain and hop validation: edge coverage, scope/capability continuity between hops, attenuation-proof checks, `did:chio:<hex-pubkey>` issuer resolution, and witness-hop signature verification. |

## Verification flow

`verify_swarm_authority_bundle` runs a fixed pipeline; any failing step
returns `SwarmAuthorityError::Rejected` immediately and no partial report is
produced:

1. Reject if `trusted_witness_issuer_keys` is empty (fail-closed with no
   pinned keys, before any artifact is read).
2. Validate task-graph shape, then its signature (`validate_task_graph`,
   `verify_task_graph_signature`).
3. Require the bundle to carry at least one continuation token and one
   witness chain (`require_signed_swarm_delegation_evidence`).
4. Validate and index route-plan receipts, then join receipts, then the
   budget pool, then the revocation epoch, each individually
   signature-checked and issuer-pinned.
5. Validate terminal graph receipts against the task/route/join/budget
   indexes built above.
6. Validate continuation tokens against the task graph's canonical sha256,
   witness chains, routes, budget allocations, and the revocation epoch.
7. Validate witness chains cover every task-graph edge exactly once, with
   continuous scope hashes and capability digests hop to hop.
8. Assemble `SwarmAuthorityVerifierReport`: one `SwarmAuthorityHopReport` per
   continuation-bearing task node, plus the `CLAIM_SWARM_*` ids for the
   checks that ran.

## Invariants and failure modes

- Every signed artifact (task graph, route-plan receipt, join receipt,
  revocation epoch, terminal graph receipt, continuation token, witness hop)
  must verify against a key present in the caller-supplied
  `trusted_witness_issuer_keys`; an empty trust set rejects the bundle before
  any signature is checked.
- A continuation token carries exactly one parent context: `parent_task_id`
  (direct edge, requires a witness-chain binding) or `join_receipt_id`
  (fan-in), never both, never neither.
- A revoked subject (task-graph issuer, planner subject, or any witness-hop
  issuer) or a revoked task id present in the bundle rejects the whole
  bundle. Revocation is checked as a block-list against the bundle's current
  subjects and task ids on every call; there is no separate revoke-in-place
  path.
- Budget accounting uses `checked_add`/`checked_sub` throughout; a rollup
  that does not sum exactly to `max_units`, or that overflows, is rejected
  rather than clamped.
- Route-plan receipts must pin `selected_route`, `protocol_target`, and
  `egress_contract_id` to the same `bridge_id` prefix, and carry exactly one
  `egress_constraints` entry: `"deny-private-network"`.
- Terminal graph receipts are mandatory (an empty `terminal_receipts` list
  rejects). Their `completed_task_ids` / `join_receipt_ids` /
  `route_plan_receipt_ids` must equal the graph's full task/join/route sets
  exactly (set equality, not containment); `terminal_task_ids` only needs to
  reference known tasks.
- Witness chains must cover every task-graph edge exactly once: a missing or
  a duplicate chain for an edge both reject.
- The crate never reads `CHIO_SWARM_TRUSTED_WITNESS_KEYS` or any other
  environment variable; the name appears only in rejection text as the
  convention callers use to populate `trusted_witness_issuer_keys`.
- `mint_*` / `sign_*` / `reserve_swarm_budget_fanout` /
  `release_swarm_budget_fanin` are fixture and lifecycle helpers exercised by
  this crate's tests and downstream test suites; no production code path in
  this workspace calls them.

## Dependencies

`chio-core-types` supplies canonical JSON (`canonical_json_bytes`,
`sha256_hex`), Ed25519 (`Keypair`, `PublicKey`, `Signature`), and the
attenuation-proof primitives (`capability::attenuation::{AttenuationWitness,
validate_attenuation_proof}`) that witness hops are checked against; it is
not aliased. `serde`/`serde_json` (de)serialize every wire type and build
signature bodies. `thiserror` derives `SwarmAuthorityError`. Dev-only:
`chio-test-support` and `proptest` back the tests in
`tests/swarm_authority_stage0.rs`.
