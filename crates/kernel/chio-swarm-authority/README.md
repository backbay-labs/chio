# chio-swarm-authority

Fail-closed verifier for recursive AI-agent swarm delegation. It checks that a
signed bundle of task-graph, continuation-token, delegation-witness,
join-receipt, route-plan, budget, and revocation artifacts authorizes a
specific child task before that task runs, and returns a report the caller can
act on.

`chio-runtime-core` calls it from the runtime admission path and
`chio-proof-room` calls it from the public proof-verification path; both call
the same function, so a request is authorized under one shared definition or
rejected.

## Responsibilities

- Validate `SwarmTaskGraph` shape: exactly one root, edges reference known
  tasks with no duplicates, child depth = parent depth + 1, joins have at
  least two unique parents, the graph is acyclic, and it stays within
  `max_depth` / `max_fanout`.
- Verify Ed25519 signatures and pinned issuers on every signed artifact: task
  graph, route-plan receipts, join receipts, the revocation epoch, terminal
  graph receipts, continuation tokens, and delegation witness hops.
- Bind each continuation token to the task graph's canonical sha256, a
  witness chain (when it has a parent task), a route-plan receipt, an active
  budget allocation, and the current revocation epoch's id and root hash;
  reject duplicate nonces.
- Verify delegation witness chains cover every task-graph edge exactly once,
  that scope hashes and capability digests stay continuous hop to hop, and
  that each hop's attenuation proof narrows scope (via
  `chio_core_types::capability::attenuation`).
- Reconcile budget-pool accounting: allocation unit rollups against
  `max_units`, and terminal-receipt budget rollups against the live
  allocations, with `checked_add` / `checked_sub` throughout.
- Enforce revocation: a revoked subject (graph issuer, planner, or any
  witness issuer) or a revoked task id present in the bundle rejects the
  whole bundle.
- Provide `mint_*` / `sign_*` fixture constructors and
  `reserve_swarm_budget_fanout` / `release_swarm_budget_fanin` budget-lifecycle
  helpers used by this crate's tests and downstream test suites, not a
  runtime issuance path.

## Public API

- `verify_swarm_authority_bundle(bundle: &SwarmAuthorityBundle,
  trusted_witness_issuer_keys: &[PublicKey]) -> Result<SwarmAuthorityVerifierReport,
  SwarmAuthorityError>` - the single entry point.
- Bundle types: `SwarmAuthorityBundle`, `SwarmTaskGraph`, `SwarmGraphNode`,
  `SwarmGraphEdge`, `SwarmGraphJoin`, `SwarmContinuationToken`,
  `SwarmDelegationWitnessChain`, `SwarmDelegationWitnessHop`,
  `SwarmJoinReceipt`, `SwarmRoutePlanReceipt`, `SwarmBudgetPool`,
  `SwarmBudgetAllocation`, `SwarmRevocationEpoch`, `SwarmTerminalGraphReceipt`.
- Report types: `SwarmAuthorityVerifierReport`, `SwarmAuthorityHopReport`.
- Minting and signing: `mint_swarm_continuation_token`,
  `mint_swarm_join_receipt`, `sign_swarm_task_graph`,
  `sign_swarm_continuation_token`, `sign_swarm_join_receipt`,
  `sign_swarm_route_plan_receipt`, `sign_swarm_revocation_epoch`,
  `sign_swarm_terminal_graph_receipt`, `sign_swarm_delegation_witness_hop`.
- Budget lifecycle: `reserve_swarm_budget_fanout`, `release_swarm_budget_fanin`.
- Schema tags (`CHIO_SWARM_*_SCHEMA`) and verified-claim ids (`CLAIM_SWARM_*`)
  reported in `SwarmAuthorityVerifierReport::verified_claims`.
- `SwarmAuthorityError` - `Rejected(String)` for fail-closed validation,
  `Canonical(String)` for canonical-JSON/signing failure; `runtime_detail()`
  renders either as an operator-facing message.

## Usage

```rust
use chio_core_types::crypto::PublicKey;
use chio_swarm_authority::{verify_swarm_authority_bundle, SwarmAuthorityBundle};

fn admit(bundle: &SwarmAuthorityBundle, trusted_witness_issuer_keys: &[PublicKey]) -> bool {
    verify_swarm_authority_bundle(bundle, trusted_witness_issuer_keys).is_ok()
}
```

The crate never reads environment variables itself; callers source
`trusted_witness_issuer_keys`. Rejection messages name
`CHIO_SWARM_TRUSTED_WITNESS_KEYS` because that is the convention callers use
to populate the slice.

## Testing

`cargo test -p chio-swarm-authority`

## See also

- `chio-core-types` - canonical JSON, Ed25519 signing/verification, and the
  attenuation-proof primitives witness hops are checked against.
- `chio-runtime-core` - calls `verify_swarm_authority_bundle` from its
  admission hook before dispatching swarm child tasks.
- `chio-proof-room` - calls `verify_swarm_authority_bundle` on the public
  proof-verification path.
