# Agent 17 Runtime Security Debate

Status: adversarial architecture debate
Role: runtime enforcement and adversarial security architect
Confidence: high for gap diagnosis, moderate for exact crate placement
Source set: `INDEX.md`, `architecture/01-transaction-passport-system.md`, `architecture/03-swarm-authority-system.md`, `architecture/09-integration-contracts.md`, `plans/03-swarm-authority-implementation.md`, `plans/09-first-implementation-sprint.md`

## Position

The current launch package is strong as a verifier architecture, but it is still vulnerable to a launch overclaim: a signed Transaction Passport can prove what the proof assembler saw, while failing to prove that the live runtime could not have bypassed, replayed, downgraded, or laundered authority at execution time.

The strongest objection is simple: "verifier-grade evidence" is not the same thing as "runtime-enforced authority." The docs already require signed passports, evidence graphs, continuation tokens, route-plan receipts, join receipts, revocation epochs, and budget leases. That is necessary. It is not sufficient. Chio's launch claim depends on online enforcement gates that tool servers and kernels can verify before side effects happen, plus total receipt coverage for allow, deny, and infrastructure failure paths.

Agent 17 accepts the Transaction Passport as the root artifact. Agent 17 rejects any runtime-security claim until the passport can distinguish:

- an authorized mediated execution;
- an attempted execution denied before tool entry;
- an attempted execution denied by the tool server because the runtime lease is invalid;
- a failed execution whose denial receipt is present;
- an advisory observation that cannot authorize anything;
- an external projection that binds evidence but cannot widen Chio authority.

## Existing Strengths

The package already has several important security decisions:

- `INDEX.md` makes verifiable authority for every action a launch requirement.
- `architecture/01-transaction-passport-system.md` makes the passport a signed root over a typed evidence graph, not a directory manifest.
- `architecture/01-transaction-passport-system.md` treats silent omission as proof failure.
- `architecture/03-swarm-authority-system.md` defines continuation tokens, delegation witness chains, route-plan receipts, join receipts, budget pools, and revocation epoch binding.
- `architecture/09-integration-contracts.md` correctly says external protocols are projection subjects and cannot replace Chio authority.
- `architecture/09-integration-contracts.md` correctly says unknown predicates fail unless policy marks them advisory.
- `plans/03-swarm-authority-implementation.md` already contains stale epoch, reused token, route mismatch, bad parent, and double-spend negative tests.
- `plans/09-first-implementation-sprint.md` is appropriately small: schema registration, fail-closed unknown schema, digest validation, CLI verify, and one semantic policy digest mismatch.

Those are good foundations. The missing part is online runtime enforcement discipline.

## Security Verdict

The first sprint is acceptable only as a proof-root bootstrap. It should not be described as proving runtime enforcement. The first runtime-security slice must come immediately after the minimal Transaction Passport slice, unless launch copy avoids runtime-enforced authority claims entirely.

The launch package needs nine additional runtime capabilities:

1. tool-server-verifiable execution leases;
2. nonce defaults for every side-effect-capable call;
3. receipt totality for allow, deny, and infrastructure-failure paths;
4. hard separation of advisory evidence from authorization evidence;
5. revocation freshness checks with bounded staleness;
6. policy hot reload semantics that cannot widen in-flight authority;
7. sandbox attestation bound into route and lease decisions;
8. attack simulation as a first-class proof input;
9. chaos fixtures for runtime state loss, split brain, clock skew, and log failure.

## Feature Additions

| Capability | Required addition | Why current package is insufficient | First implementation home |
| --- | --- | --- | --- |
| Tool-server-verifiable execution leases | Add `chio.runtime.execution-lease.v1` as a signed or MAC-bound runtime artifact verified by the tool server before execution. | Budget leases constrain spend. They do not prove that the actual tool server received a kernel-issued execution grant for this request, route, sandbox, epoch, and policy digest. | `chio-runtime-core`, `chio-runtime`, `chio-kernel-core`, then CLI verifier consumption through `chio-control-plane`. |
| Nonce defaults | Make a nonce mandatory by default for all side-effect-capable dispatch, continuation token consumption, lease minting, and tool-server acknowledgement. | The swarm plan binds a nonce, but does not state that missing or empty nonce is a fail-closed default for side-effecting calls. Optional nonce semantics create replay gaps. | `chio-runtime-core` nonce ledger and `chio-kernel-core` dispatch validation. |
| Receipt totality | Add a receipt coverage invariant: every attempted governed dispatch produces exactly one terminal receipt status or a signed incident receipt that marks receipt production failure. | A passport can verify a successful receipt and still miss denied, abandoned, or bypassed attempts unless totality is a claim. | `chio-kernel-core`, receipt log code, `chio-control-plane` verifier. |
| Advisory versus authorization | Add verifier and Proof Room display rules that forbid `advisory-observation` evidence from satisfying `authorizes`, `executes`, or required authority claims. | Integration contracts classify advisory evidence, but do not yet make advisory laundering a named negative fixture across the Transaction Passport verifier. | `chio-control-plane` verifier and Proof Room report renderer. |
| Revocation freshness | Require every side-effecting call to bind a revocation epoch root plus freshness metadata: fetched-at, max-staleness, oracle identity, and monotonic sequence or inclusion proof. | `architecture/03` binds epoch roots, but stale cached roots can still authorize new work if freshness is not enforced online. | `chio-revocation-oracle`, `chio-runtime-core`, `chio-kernel-core`. |
| Policy hot reload | Define policy activation receipts and in-flight authority rules. A hot reload can narrow immediately, but cannot silently widen existing continuation tokens or leases. | Passport verifier policy digest proves what was checked later. It does not prove which policy was active at dispatch during reload races. | `chio-policy`, `chio-kernel-core`, `chio-runtime-core`. |
| Sandbox attestation | Add `chio.runtime.sandbox-attestation.v1` with tool image or binary digest, sandbox profile digest, guard bundle digest, egress profile, process instance id, and attestation signer. | Route-plan receipts bind protocol targets and egress constraints, but not the actual isolation state of the tool server that executed the request. | `chio-runtime-harness`, `chio-tee` or local harness first, then `chio-kernel-core`. |
| Attack simulation | Add adversarial scenario reports that are consumed as evidence, not kept as informal test logs. | Negative fixtures are listed, but there is no explicit attack simulation artifact that proves confused-deputy, replay, downgrade, and laundering attacks were run. | `chio-adversarial-suite`, `chio-runtime-harness`, fixture catalog. |
| Chaos fixtures | Add deterministic chaos runs for revocation outage, log outage, policy reload during dispatch, duplicate nonce race, tool restart, registry split brain, and clock skew. | Launch proof needs to show fail-closed behavior under partial failure, not only clean verifier rejection of malformed artifacts. | `chio-runtime-harness`, `tests/e2e`, `fixtures/chio-launch/runtime-security`. |

## Execution Lease Contract

`chio.runtime.execution-lease.v1` should be the online gate between kernel authorization and tool-server execution. It is not a budget lease and not a route-plan receipt. It is a short-lived execution authorization that the tool server can verify without trusting caller metadata.

Minimum fields:

- `schema`
- `lease_id`
- `issuer`
- `subject_agent`
- `tool_server_id`
- `tool_instance_id`
- `tool_manifest_digest`
- `sandbox_attestation_ref`
- `capability_digest`
- `request_digest`
- `response_policy_digest`
- `task_graph_digest`
- `child_task_id`
- `parent_receipt_ref`
- `join_receipt_ref`
- `route_plan_receipt_ref`
- `budget_lease_ref`
- `revocation_epoch_ref`
- `revocation_freshness_ref`
- `policy_digest`
- `nonce`
- `side_effect_class`
- `max_invocations`
- `issued_at`
- `expires_at`
- `signature`

Tool-server rule:

1. Reject missing lease for any governed side-effect-capable tool.
2. Reject lease with invalid signature or unsupported schema.
3. Reject lease whose tool id, tool manifest digest, sandbox attestation, route plan, request digest, nonce, policy digest, revocation epoch, or expiry does not match the current call.
4. Reject a lease after one side-effecting consumption unless policy explicitly marks it resumable and the resume path mints a fresh nonce.
5. Emit a signed tool-server acknowledgement that binds the lease id and terminal execution status.

Verifier rule:

1. A Transaction Passport authority claim fails if a governed side-effecting runtime receipt lacks a valid execution lease.
2. A tool-server acknowledgement is not authorization by itself. It proves that the tool server saw and accepted a kernel lease.
3. A kernel allow receipt without a tool-server lease acknowledgement is incomplete for side-effecting calls.
4. A tool-server acknowledgement without a kernel allow receipt is a bypass signal.

## Nonce Defaults

Nonce handling should be hostile by default:

- Side-effect-capable calls require a nonce.
- Empty nonce is invalid.
- Caller-supplied nonce is accepted only after canonicalization and binding to request digest, route-plan receipt, execution lease, revocation epoch, policy digest, and sandbox attestation.
- Kernel-minted nonce is preferred for local dispatch.
- Resumable continuation uses a new nonce for each side-effecting resume.
- Read-only calls can be nonce-optional only if the tool manifest marks the operation as no-side-effect and the policy agrees.
- Reused nonce under the same lease, request digest, or task id fails closed.
- Nonce ledger loss is a chaos failure, not a reason to accept the call.

This closes replay attacks where a valid continuation token or external projection is replayed into a new route, a stale policy, or a restarted tool server.

## Receipt Totality

The phrase "every action" is dangerous unless Chio can prove totality. Totality means every attempted governed dispatch is represented by a signed terminal decision.

Required terminal statuses:

- `allowed_executed`
- `allowed_tool_rejected`
- `denied_pre_dispatch`
- `denied_guard_request`
- `denied_guard_response`
- `denied_revocation_stale`
- `denied_policy_reload_conflict`
- `denied_missing_execution_lease`
- `denied_sandbox_attestation_mismatch`
- `failed_receipt_log_unavailable`
- `failed_tool_unreachable`
- `failed_timeout_before_tool_entry`
- `failed_timeout_after_tool_entry`

Verifier claim additions:

- `runtime.receipt_totality_complete`
- `runtime.no_unreceipted_governed_attempt`
- `runtime.denial_receipts_bound`
- `runtime.tool_server_ack_bound`

Evidence graph additions:

- Node class: `execution_lease`
- Node class: `tool_server_ack`
- Node class: `revocation_freshness_proof`
- Node class: `policy_activation_receipt`
- Node class: `sandbox_attestation`
- Node class: `attack_simulation_report`
- Node class: `chaos_run_report`
- Edge predicate: `leases`
- Edge predicate: `acknowledges`
- Edge predicate: `freshens`
- Edge predicate: `attests`
- Edge predicate: `denies`
- Edge predicate: `simulates`

Silent missing receipts must be verifier failure, not omission. Omission policy is valid for non-applicable evidence. It is not valid for attempted governed actions whose receipts disappeared.

## Advisory Is Not Authorization

The integration contracts already classify external claims as native external proof, Chio sidecar proof, digest-bound reference, advisory observation, or unsupported. Agent 17 would harden that into a launch invariant:

- `advisory-observation` can support explanation.
- `advisory-observation` cannot satisfy `authorizes`, `attenuates`, `executes`, `leases`, or `settles`.
- External protocol success cannot satisfy Chio authorization.
- Supply-chain proof cannot satisfy runtime authorization.
- Payment success cannot satisfy tool authorization.
- Trace presence cannot satisfy mediated allow.
- Tool-server acknowledgement cannot satisfy kernel authorization.

Add a required display invariant: the CLI verifier and Proof Room must label advisory evidence separately from authorization evidence. A fixture that contains only advisory evidence for a required authority claim must fail.

## Revocation Freshness

Revocation epoch binding is necessary but not enough. Runtime dispatch must prove the epoch was fresh enough for the operation.

Required fields for `chio.runtime.revocation-freshness-proof.v1`:

- `schema`
- `oracle_id`
- `epoch_id`
- `epoch_root`
- `sequence`
- `fetched_at`
- `max_staleness_ms`
- `subject_capability_digest`
- `ancestor_capability_digest`
- `revoked_leaf_result`
- `revoked_ancestor_result`
- `signature`

Runtime rules:

1. New side-effecting calls fail closed if freshness proof is older than policy permits.
2. Read-only calls can degrade under policy only if the receipt says the revocation source was stale.
3. A continuation token minted under one epoch cannot resume under an incompatible newer epoch.
4. Same epoch id with different root fails.
5. Revocation oracle unavailability is a denial or degraded read-only receipt, not an allow.

## Policy Hot Reload

Policy hot reload is a TOCTOU hazard. It needs explicit semantics before launch claims depend on live policy enforcement.

Required artifact:

`chio.policy.activation-receipt.v1`

Minimum fields:

- `schema`
- `policy_digest`
- `previous_policy_digest`
- `activation_epoch`
- `activated_at`
- `activation_mode`
- `narrowing_or_widening`
- `migration_rule`
- `issuer`
- `signature`

Runtime rules:

1. Every execution lease binds the active policy digest.
2. Every runtime receipt records the active policy digest.
3. Narrowing reloads can revoke or deny in-flight work immediately if policy says so.
4. Widening reloads cannot expand an existing continuation token, task graph, route plan, or execution lease.
5. Mixed old-policy and new-policy evidence in one side-effecting call fails unless a policy activation receipt explains the transition and the call was reminted under the new digest.

Negative fixture priority is high because policy reload races are exactly where after-the-fact verifier reports can lie by omission.

## Sandbox Attestation

Route-plan receipts say where a call should go. They do not prove what executed it. Tool isolation needs an attestation artifact that launch verifiers can inspect.

First slice should use deterministic local sandbox attestation, not production hardware attestation. The purpose is to make the contract real.

`chio.runtime.sandbox-attestation.v1` fields:

- `schema`
- `attestation_id`
- `tool_server_id`
- `tool_instance_id`
- `binary_digest`
- `container_image_digest`
- `tool_manifest_digest`
- `guard_bundle_digest`
- `sandbox_profile_digest`
- `egress_policy_digest`
- `filesystem_profile_digest`
- `network_profile_digest`
- `started_at`
- `expires_at`
- `attester`
- `signature`

Runtime rules:

1. Execution leases bind `sandbox_attestation_ref`.
2. Route-plan receipts bind the expected egress policy digest.
3. Tool-server acknowledgements bind the actual sandbox attestation id.
4. Verifier rejects route-plan egress constraints that do not match sandbox egress constraints.
5. Verifier rejects a tool acknowledgement from an unattested or mismatched tool instance.

## Attack Simulation

Attack simulation should be a launch artifact class, not a separate QA note. The proof room should show that adversarial cases were executed and rejected.

Add `chio.runtime.attack-simulation-report.v1` with:

- scenario id;
- attack class;
- fixture path;
- expected denial claim;
- actual verifier report digest;
- runtime receipt refs;
- chaos knobs if any;
- pass or fail status;
- simulator version digest.

Minimum attack classes:

- confused deputy through caller-supplied route metadata;
- replayed continuation token under a fresh request;
- stale revocation epoch accepted after revocation;
- policy hot reload widens in-flight authority;
- advisory evidence laundered as authorization;
- external payment success laundered as tool authorization;
- route-plan registry snapshot downgrade;
- tool-server bypass without kernel allow receipt;
- missing denial receipt after guard rejection;
- sandbox profile mismatch hidden by external projection.

## Chaos Fixtures

The first public runtime proof should include deterministic chaos fixtures. These are not load tests. They are security invariants under partial failure.

Required chaos cases:

| Fixture | Failure injected | Expected result |
| --- | --- | --- |
| `revocation-oracle-unavailable` | Revocation freshness source is unavailable before side effect. | Denial receipt or read-only degraded receipt, never side-effect allow. |
| `receipt-log-unavailable` | Append-only receipt log cannot commit terminal status. | Signed incident receipt if possible, verifier marks totality failed. |
| `policy-reload-during-dispatch` | Policy digest changes after lease mint and before tool ack. | Reject unless reminted or activation receipt proves a narrowing transition. |
| `duplicate-nonce-race` | Two concurrent calls consume the same nonce and lease. | Exactly one terminal side-effect status can succeed. |
| `tool-restart-lost-lease-cache` | Tool server restarts between lease mint and execution. | Tool verifies durable lease state or rejects. |
| `registry-split-brain` | Route-plan receipt uses one registry snapshot and verifier sees another. | Route-plan mismatch fails. |
| `clock-skew-expiry-bypass` | Tool server local clock is skewed around lease expiry. | Verifier rejects unless trusted time proof is bound. |
| `sandbox-profile-drift` | Tool starts under a different egress or filesystem profile than route plan required. | Tool ack and passport verification fail. |

## Affected Plans

### `architecture/01-transaction-passport-system.md`

Add runtime enforcement nodes and claims to the evidence graph. The passport should not merely prove a runtime receipt exists. It should prove the receipt is total, online-enforced, nonce-bound, lease-bound, revocation-fresh, policy-digest-bound, and sandbox-attested when the operation can have side effects.

New claim classes:

- `runtime.execution_lease_valid`
- `runtime.nonce_fresh`
- `runtime.receipt_totality_complete`
- `runtime.revocation_fresh_at_dispatch`
- `runtime.policy_activation_consistent`
- `runtime.sandbox_attestation_matched`
- `runtime.tool_server_ack_bound`
- `runtime.advisory_not_used_as_authorization`

### `architecture/03-swarm-authority-system.md`

Keep continuation tokens, witness chains, route-plan receipts, join receipts, budget pools, and revocation epochs. Add an execution lease as the last online authorization hop before tool entry.

Dispatch rule additions:

1. execution lease is present and valid for side-effect-capable child work;
2. nonce is present by default and fresh;
3. revocation freshness proof is within policy staleness;
4. active policy digest matches the lease and receipt;
5. sandbox attestation matches the route plan and tool manifest;
6. tool-server acknowledgement binds the lease id.

### `architecture/09-integration-contracts.md`

Add three contracts:

Contract 11 - Online Enforcement Precedes Proof

The Transaction Passport can report authority only for actions that passed online kernel and tool-server gates. After-the-fact evidence cannot upgrade an unleased tool call into authorized execution.

Contract 12 - Advisory Evidence Never Authorizes

Advisory observations, traces, external payment success, supply-chain attestations, and projection metadata cannot satisfy native Chio authority claims.

Contract 13 - Receipt Totality Is Required For "Every Action"

A verifier cannot accept "every action" coverage unless every attempted governed dispatch has a terminal receipt or a signed incident receipt explaining why totality failed.

### `plans/03-swarm-authority-implementation.md`

Split Phase 2 and Phase 5 more aggressively:

- Phase 2A: continuation token verifies child task, graph digest, parent receipt, route plan, revocation epoch, and nonce.
- Phase 2B: side-effecting token consumption writes nonce ledger and denial receipts.
- Phase 2C: execution lease minted from verified continuation token and verified by tool server.
- Phase 5A: revocation epoch binding.
- Phase 5B: revocation freshness proof with max-staleness policy.
- Phase 5C: budget leases and double-spend tests.
- Phase 5D: policy activation receipt and hot reload race tests.
- Phase 5E: sandbox attestation binding.

Do not bury revocation freshness, budget accounting, policy reload, and sandbox attestation in one implementation phase. They are independent failure domains.

### `plans/09-first-implementation-sprint.md`

Do not expand the first sprint until the minimal Transaction Passport verifies and rejects a policy digest mismatch. That sprint is the right bootstrap.

Add the next immediate sprint:

Runtime Security Slice 0 - prove one governed side-effecting tool call has an allow receipt, execution lease, nonce, revocation freshness proof, policy digest, tool-server acknowledgement, and sandbox attestation. Reject the same call when the execution lease is missing or the evidence graph uses an advisory observation as authorization.

This should be a second slice, not a rewrite of the first slice.

## First Executable Slice

Name: Runtime Security Slice 0

Objective: prove one governed side-effecting tool call cannot be verified from a Transaction Passport unless online enforcement evidence is present and internally consistent.

Suggested file scope:

- Create: `spec/schemas/chio-runtime/v1/execution-lease.schema.json`
- Create: `spec/schemas/chio-runtime/v1/tool-server-ack.schema.json`
- Create: `spec/schemas/chio-runtime/v1/revocation-freshness-proof.schema.json`
- Create: `spec/schemas/chio-runtime/v1/sandbox-attestation.schema.json`
- Create: `crates/chio-control-plane/tests/runtime_security_passport.rs`
- Modify: `crates/chio-control-plane/src/transaction_passport.rs`
- Create: `fixtures/chio-launch/runtime-security/valid-side-effecting-call/transaction-passport.json`
- Create: `fixtures/chio-launch/runtime-security/missing-execution-lease/transaction-passport.json`
- Create: `fixtures/chio-launch/runtime-security/advisory-used-as-authorization/transaction-passport.json`

First failing test:

```rust
use chio_test_support::prelude::*;

#[test]
fn side_effecting_runtime_claim_requires_execution_lease() {
    let bundle = load_runtime_security_fixture("missing-execution-lease")
        .test_expect("fixture loads");

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("missing execution lease must fail");

    assert!(error.to_string().contains("missing execution lease"));
}
```

Second failing test:

```rust
use chio_test_support::prelude::*;

#[test]
fn advisory_observation_cannot_authorize_runtime_execution() {
    let bundle = load_runtime_security_fixture("advisory-used-as-authorization")
        .test_expect("fixture loads");

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("advisory evidence must not authorize");

    assert!(error.to_string().contains("advisory evidence cannot authorize"));
}
```

Passing target:

```bash
cargo test -p chio-control-plane --test runtime_security_passport
```

Acceptance criteria:

- Valid side-effecting fixture verifies.
- Missing execution lease fails.
- Advisory evidence used as authorization fails.
- Reused nonce fixture fails if included in this slice.
- Verifier report names the failed runtime claim.
- Evidence graph points from failed claim to exact node and edge ids.

## Negative Fixtures

These fixtures should exist before launch copy claims runtime-enforced authority beyond the minimal single-call proof.

| Fixture path suffix | Attack | Expected rejection |
| --- | --- | --- |
| `runtime-security/missing-execution-lease` | Passport has runtime receipt but no tool-server-verifiable lease. | `runtime.execution_lease_valid` fails. |
| `runtime-security/expired-execution-lease` | Lease expires before tool entry. | Lease rejected and denial receipt required. |
| `runtime-security/lease-request-digest-mismatch` | Lease was minted for a different request body. | Tool-server ack invalid, passport fails. |
| `runtime-security/lease-route-mismatch` | Lease binds a different route-plan receipt. | Route and lease binding fails. |
| `runtime-security/reused-nonce-side-effect` | Same nonce consumed twice for side-effecting call. | Exactly one call can verify. |
| `runtime-security/empty-nonce-side-effect` | Side-effecting call omits nonce or uses empty nonce. | Nonce default rule fails. |
| `runtime-security/missing-denial-receipt` | Guard denial occurs but passport lacks terminal denial receipt. | Receipt totality fails. |
| `runtime-security/advisory-used-as-authorization` | Trace or review output is wired to `authorizes`. | Advisory laundering fails. |
| `runtime-security/stale-revocation-freshness` | Epoch root is valid but fetched outside max staleness. | Freshness claim fails. |
| `runtime-security/revocation-oracle-unavailable` | Runtime allows side effect while revocation source is unavailable. | Fail-closed violation. |
| `runtime-security/policy-hot-reload-widened-in-flight` | Policy reload widens authority for an existing token. | Policy activation consistency fails. |
| `runtime-security/policy-digest-receipt-mismatch` | Receipt records one policy digest and lease records another. | Runtime claim fails. |
| `runtime-security/sandbox-attestation-mismatch` | Tool ack comes from a different sandbox profile than route plan required. | Sandbox claim fails. |
| `runtime-security/tool-server-bypass-no-kernel-allow` | Tool server ack exists but kernel allow receipt is absent. | Bypass detected. |
| `runtime-security/receipt-log-unavailable` | Runtime proceeds after receipt log cannot commit. | Totality and incident receipt checks fail. |
| `runtime-security/registry-split-brain-route-plan` | Route-plan receipt uses stale registry snapshot. | Route-plan snapshot claim fails. |
| `runtime-security/clock-skew-expiry-bypass` | Tool server accepts a lease after expiry due to local clock skew. | Trusted time or expiry check fails. |

## Deferrals

Defer full production-grade versions of these items, but not their contract shape:

- Hardware TEE attestation can wait. Local deterministic sandbox attestation cannot wait.
- Byzantine revocation oracle consensus can wait. Bounded freshness proof cannot wait.
- Cluster-wide chaos automation can wait. Deterministic chaos fixtures cannot wait.
- Full external protocol coverage can wait. One local tool path plus one MCP or A2A path is enough for the first runtime-security proof.
- Full Proof Room visualization can wait. CLI verifier report fields for runtime-security failures cannot wait.
- Economic budget-pool sophistication can wait. Single-use execution lease and nonce replay rejection cannot wait.

## Debate Close

The launch architecture is directionally correct, but it is still too verifier-centric for a runtime-security claim. The Transaction Passport must become the public root over online enforcement, not a polished receipt scrapbook.

Agent 17's required bar:

1. Kernel authorizes.
2. Tool server verifies a lease.
3. Nonce is fresh by default.
4. Revocation is fresh at dispatch.
5. Policy digest cannot race through hot reload.
6. Sandbox state is attested.
7. Receipt coverage is total.
8. Advisory evidence never authorizes.
9. Attack and chaos fixtures prove fail-closed behavior.

Only then can Chio credibly claim runtime-enforced authority for autonomous commerce and recursive agent execution.
