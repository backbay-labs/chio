# AI Workflow Simulation Debate

Status: agent debate
Agent: 22
Role: AI-native workflow, simulation, and evaluation lead
Scope: `INDEX.md`, `architecture/00-system-map.md`, `architecture/03-swarm-authority-system.md`, `plans/03-swarm-authority-implementation.md`, `plans/07-proof-room-implementation.md`, `indices/proof-room-fixture-catalog.md`
Confidence: high that the current launch package underspecifies pre-execution AI workflow controls; moderate on exact crate boundaries; low on model/provider live-test stability without a pinned conformance corpus.

## Executive Verdict

The current launch package is strong on post-execution proof and weak on pre-execution control. It can explain why a completed action was valid or invalid, but it does not yet make the AI-native workflow itself inspectable before real authority, budget, settlement, or disclosure is consumed.

That is a material gap. A trust network for autonomous commerce cannot look like a receipt museum. It needs a planner-facing and reviewer-facing control plane that can:

1. simulate a proposed transaction before execution;
2. answer what changes if policy, model, provider, route, approval, budget, or revocation state changes;
3. rehearse recursive swarm plans without minting live authority;
4. generate benchmark and red-team traffic;
5. replay exact transcripts and verifier decisions deterministically;
6. compare model/provider behavior against Chio tool-use and receipt expectations;
7. stop at human approval gates with digest-bound intent.

The strongest counterargument is real: Chio should not dilute the Transaction Passport and Proof Room work by building a generic AI workflow IDE. The verifier and signed artifact spine must come first. But that counterargument only kills a polished GUI-first product. It does not kill a narrow read-only simulation layer. The first slice should be a CLI and fixture-backed preflight verifier that rejects an invalid swarm plan before a continuation token or tool call exists.

## Current Architecture Strength

The package already has the right proof skeleton:

- `architecture/00-system-map.md` makes the Transaction Passport the proof root.
- `architecture/03-swarm-authority-system.md` defines task graphs, continuation tokens, witness chains, join receipts, route-plan receipts, budget pools, and revocation epochs.
- `plans/03-swarm-authority-implementation.md` names graph, token, route, join, budget, and revocation failure cases.
- `plans/07-proof-room-implementation.md` correctly says the Proof Room consumes verifier output and must not invent proof semantics.
- `indices/proof-room-fixture-catalog.md` demands signed roots, sealed manifests, deterministic reports, and negative fixtures.

That is the correct direction. The missing layer is earlier in time: before dispatch, before token minting, before bridge routing, before settlement, before disclosure, and before a human approver clicks anything.

## Missing Layer

Add an AI Workflow Simulation and Evaluation layer between planned authority and live execution.

This layer must be read-only by default. It does not call live tools, does not debit budgets, does not publish receipts as final authority, and does not approve anything. It evaluates planned authority against the same verifier vocabulary that the Proof Room later renders.

Candidate artifact family:

- `chio.workflow.preflight-plan.v1`
- `chio.workflow.preflight-report.v1`
- `chio.workflow.what-if-delta.v1`
- `chio.workflow.rehearsal-run.v1`
- `chio.workflow.benchmark-scenario.v1`
- `chio.workflow.red-team-task.v1`
- `chio.workflow.replay-capsule.v1`
- `chio.workflow.synthetic-transaction-template.v1`
- `chio.workflow.model-provider-conformance.v1`
- `chio.workflow.approval-gate.v1`

These should not all be P0 implementation work. They are the vocabulary needed to keep AI-native workflow claims from leaking into vague product copy.

## Capability Debate

### 1. Preflight Simulation

Position: add P0.

Current problem: `chio.swarm.task-graph.v1` says what may execute, but the docs do not define a single preflight verdict over a proposed task graph, policy set, route candidates, approval requirements, budget pool, and revocation epoch before execution starts.

Required behavior:

- consume proposed Transaction Passport refs, swarm task graph, policy digests, trust roots, route-plan candidates, approval requirements, and budget envelope;
- run only pure validation and policy evaluation;
- emit `chio.workflow.preflight-report.v1`;
- reject a plan that would later fail graph, scope, route, budget, revocation, or approval checks;
- produce claim-level failure codes compatible with Proof Room reports;
- guarantee that preflight success is not a live execution proof.

The preflight report should answer:

- which tasks are authorized;
- which tasks need human approval;
- which route plans are admissible;
- which budgets are reserved only in simulation;
- which graph invariants are invalid;
- which artifacts are missing from the registry;
- which verifier claims are blocked.

Negative fixtures:

- preflight accepts a child task whose scope is broader than the parent;
- preflight accepts a route target without a route-plan receipt;
- preflight accepts a budget allocation that can never satisfy fan-out reservations;
- preflight marks an approval as satisfied without an approval artifact digest;
- preflight report is later treated as a live receipt.

### 2. What-If Verifier

Position: add P1 after the preflight report vocabulary is stable.

Current problem: the architecture can verify one artifact set, but it cannot explain the blast radius of changing a policy, provider, model, route, approval threshold, revocation epoch, privacy profile, or budget limit.

Required behavior:

- compare baseline and candidate artifact sets;
- emit `chio.workflow.what-if-delta.v1`;
- list claims whose verdict changes;
- distinguish stricter policy denials from evidence regressions;
- name the artifact digests that changed;
- preserve deterministic ordering in output JSON.

This is important because buyers and internal operators will not ask only "is this proof valid?" They will ask "what breaks if we switch provider, lower budget, rotate trust root, require approval, or remove this disclosure field?"

Negative fixtures:

- policy digest changes but the what-if report says no affected claims;
- revocation epoch changes and stale continuation tokens remain reported as valid;
- route-plan target changes while bridge and egress claims remain green;
- privacy profile becomes stricter while over-disclosure stays hidden;
- provider conformance profile changes without invalidating dependent benchmark results.

### 3. Agent Policy IDE

Position: defer polished IDE; add CLI-backed policy workbench first.

A graphical policy IDE is seductive and premature. It will become a parallel verifier unless it is forced to consume the same preflight and verifier reports as the CLI.

Required first shape:

- `chio workflow policy check <policy> --plan <preflight-plan> --json`;
- policy syntax and schema validation;
- policy digest preview;
- claim impact preview through what-if reports;
- approval gate preview;
- no custom UI verdict logic.

The Proof Room can later render the same output, but the first implementation should be CLI and fixture based.

Negative fixtures:

- IDE preview permits a policy that verifier load rejects;
- policy text changes but digest preview stays unchanged;
- approval condition shown in UI differs from report JSON;
- policy workbench hides fail-closed load errors.

### 4. Swarm Rehearsal

Position: add P0/P1 boundary. The first slice should reject invalid plans. The next slice can execute rehearsal-only steps against stubs.

Current problem: the swarm plan jumps from signed graph to live dispatch semantics. There is no rehearsal mode that proves a recursive plan can walk through tokens, joins, routes, budgets, approvals, and revocation without spending real authority.

Required behavior:

- consume `chio.workflow.preflight-plan.v1`;
- materialize rehearsal-only continuation tokens;
- mark every rehearsal artifact with `mode = rehearsal`;
- run against fixture-backed or simulated tool outputs;
- emit `chio.workflow.rehearsal-run.v1`;
- prevent rehearsal tokens and rehearsal receipts from satisfying live verifier claims.

The hard rule: a rehearsal can prove plan shape, not final authority. If the Proof Room renders a rehearsal next to a live proof, it must label the distinction from report data, not UI state.

Negative fixtures:

- rehearsal token accepted by live child dispatch;
- rehearsal receipt counted as live authority in a Transaction Passport;
- rehearsal tool output treated as an external provider transcript;
- route-plan rehearsal skips egress constraints that live dispatch requires;
- simulated approval later reused as live approval.

### 5. Benchmark Scenarios

Position: add P1. Do not wait for a full hosted benchmark suite.

The existing proof-room stages are launch fixtures. They are not yet benchmark scenarios. Benchmarks need stable scenario IDs, stable seeds, expected outcomes, model/provider profile requirements, and scoreable assertions.

Required scenario families:

- single-call authority benchmark;
- commerce order replay benchmark;
- recursive swarm authority benchmark;
- selective disclosure benchmark;
- external projection benchmark;
- human approval benchmark;
- red-team denial benchmark.

Benchmark results should be signed only as results over a pinned Chio version, corpus version, scenario seed, provider profile, and verifier policy. Anything else is marketing data, not conformance evidence.

Negative fixtures:

- benchmark result omits corpus version;
- benchmark run changes random seed but reports same scenario digest;
- benchmark passes with missing negative-control cases;
- benchmark uses hosted provider output without preserving transcript digest;
- benchmark claims conformance while the verifier rejected an artifact.

### 6. Red-Team Task Corpus

Position: add P0 as fixture taxonomy, P1 as generator-backed corpus.

This should not be prompt-safety theater. The corpus should attack Chio's actual claims: capability attenuation, route authority, order binding, approval binding, replay, disclosure, budget, provider conformance, and external projection.

Required task classes:

- broader child scope than parent;
- stale continuation token;
- route-plan mismatch;
- missing join parent;
- approval laundering across order IDs;
- quote replay;
- overspend through split subtasks;
- forged provider passport;
- model ignores required tool call;
- model fabricates tool result;
- provider streaming chunks reorder a tool-call argument;
- hidden prompt asks a child agent to bypass Chio;
- disclosure capsule reveals a forbidden field;
- external protocol digest mismatch;
- synthetic receipt with valid shape and invalid signature.

Negative fixtures are not optional here. The corpus is valuable only if every attack has an expected failure code and a minimal valid neighbor.

### 7. Deterministic Replay

Position: add P0 alignment with existing replay surfaces.

The repo already has replay CLI code and runtime proof parity concepts. The launch package should explicitly bind them to AI workflow simulation.

Important distinction: Chio cannot make an LLM deterministic. It can make recorded observations and verifier decisions deterministic. Replay must replay exact captured transcripts, tool calls, receipts, provider metadata, policy refs, and verifier inputs. It must not pretend that asking a hosted model the same question later is equivalent.

Required behavior:

- emit `chio.workflow.replay-capsule.v1`;
- include transcript digest, request digest, response digest, tool-call argument canonical digests, provider metadata, model identifier, adapter version, policy digest, and verifier report digest;
- support recorded-observation replay;
- support optional live rerun with a separate live-conformance verdict;
- fail if replay depends on wall-clock, random seed, provider default params, or unpinned policy.

Negative fixtures:

- replay passes after provider metadata is removed;
- replay passes with changed tool-call argument order that changes canonical digest;
- replay report hides post-tool request drift;
- replay accepts a transcript without request digests;
- live rerun result overwrites recorded replay verdict.

### 8. Synthetic Transaction Generator

Position: add P1 after Stage 0 and Stage 2 fixtures are stable.

The fixture catalog is hand-curated. That is necessary but insufficient. Chio needs a seed-bound generator that creates valid and invalid transaction passports, swarm graphs, event logs, approvals, budgets, disclosure capsules, and route plans.

Required behavior:

- deterministic seed produces stable bundle;
- generator names schema versions and corpus version;
- valid generator respects monotonic order state and graph constraints;
- invalid generator mutates exactly one invariant by default;
- generated negative fixtures include expected failure code;
- generated artifacts can be minimized for regression cases.

Negative fixtures:

- generator emits noncanonical JSON;
- generator creates two-invalid-invariant cases while claiming one expected failure;
- generated order event log is not replayable to terminal state;
- generated swarm graph has unstable node ordering;
- generated budget mutation masks route-plan failure.

### 9. Model/Provider Conformance

Position: add P1, with an explicit claim boundary.

Provider conformance must be observational and profile-scoped. It can say "this provider/model/profile produced Chio-compatible transcripts for this corpus under these params." It cannot say the provider is generally safe, deterministic, or cryptographically compliant.

Required dimensions:

- tool-call JSON canonicalization;
- parallel tool call handling;
- no-tool-call behavior when a tool is required;
- streaming chunk assembly;
- post-tool request capture;
- refusal and error mapping;
- max token and truncation behavior;
- provider metadata preservation;
- retry idempotency;
- adapter version compatibility.

The corpus should include both recorded transcripts and optional live tests. Public launch proof should not require live credentials by default.

Negative fixtures:

- streaming chunks assemble to a different tool-call digest;
- provider omits post-tool request and replay still passes;
- model returns natural language when a tool call is required;
- adapter normalizes away provider error metadata;
- retry creates duplicate side-effecting tool call;
- transcript claims a model id that provider metadata does not support.

### 10. Human-In-The-Loop Approvals

Position: add P0 for digest-bound approval gates.

The current docs mention mandate or approval, but they do not define an approval artifact strong enough for autonomous commerce. Human approval must bind to exact intent, order, route, policy, budget, expiry, approver authority, and execution mode.

Candidate artifact:

- `chio.workflow.approval-gate.v1`

Required fields:

- `approval_id`;
- `subject_transaction_ref`;
- `order_id` or governed intent digest;
- `policy_digest`;
- `route_plan_ref`, when route matters;
- `budget_limit`;
- `approval_text_digest`;
- `approver_subject`;
- `approver_authority_ref`;
- `created_at`;
- `expires_at`;
- `revocation_ref`;
- `mode`, with values such as `preflight`, `rehearsal`, or `live`;
- `signature`.

Required behavior:

- preflight reports required approvals before live dispatch;
- live execution rejects missing, expired, revoked, wrong-mode, or wrong-subject approval;
- approval text is display material, not the authority root;
- digest-bound intent is the authority root.

Negative fixtures:

- approval for order A reused for order B;
- approval for rehearsal used for live execution;
- expired approval accepted;
- approval text edited after signature;
- approver lacks authority for the policy threshold;
- route changes after approval without re-approval;
- approval covers budget 100 and execution spends 101.

## Recommended Additions

Add these concepts to the research package.

P0 additions:

1. Add an AI Workflow Simulation layer to `architecture/00-system-map.md`.
2. Add preflight semantics to `architecture/03-swarm-authority-system.md`.
3. Add `chio.workflow.preflight-plan.v1` and `chio.workflow.preflight-report.v1` as candidate signed or verifier-facing artifacts in `indices/artifact-registry.md`.
4. Add approval-gate semantics to commerce, swarm, and Proof Room docs.
5. Add cross-stage workflow negative fixtures to `indices/proof-room-fixture-catalog.md`.
6. Add a first execution slice for read-only preflight rejection of broader child scope.

P1 additions:

1. Add what-if delta reports.
2. Add rehearsal-only swarm runs.
3. Add deterministic replay capsule binding model/provider transcripts.
4. Add benchmark scenario IDs and corpus versioning.
5. Add red-team task corpus structure.
6. Add model/provider conformance profile reports.
7. Add synthetic transaction generator constraints.

P2 additions:

1. Add policy workbench UI.
2. Add Proof Room simulation and replay views.
3. Add hosted benchmark dashboards.
4. Add live provider conformance runners.

## Deferrals

Defer these deliberately:

- polished agent policy IDE until CLI reports and verifier report contracts are stable;
- live provider benchmark claims until recorded replay passes without credentials;
- synthetic generator publication until the hand-authored Stage 0 and Stage 2 fixture shapes are stable;
- Proof Room simulation UI until `chio.workflow.preflight-report.v1` exists;
- broad bridge rehearsal until local nested dispatch and one bridge have route-plan receipt enforcement;
- approval UI until approval artifacts have digest-bound CLI verification.

## Affected Docs

Directly affected:

- `architecture/00-system-map.md`: add AI Workflow Simulation and Evaluation as a pre-execution layer feeding Transaction Passport, verifier, and Proof Room.
- `architecture/03-swarm-authority-system.md`: define preflight versus rehearsal versus live mode, and require mode binding on continuation artifacts.
- `plans/03-swarm-authority-implementation.md`: add a Phase 0A for read-only preflight before token minting.
- `plans/07-proof-room-implementation.md`: add simulation/replay display as report consumers, not proof semantics.
- `indices/proof-room-fixture-catalog.md`: add workflow negative fixtures across all stages.

Second-order affected:

- `indices/artifact-registry.md`: reserve workflow artifact names only after owner review.
- `indices/verification-gates.md`: add gates for preflight, replay, model/provider profile, and approval binding.
- `indices/build-priority-matrix.md`: place preflight before full swarm authority.
- `indices/execution-slice-contract.md`: add workflow slice ownership and fixture rules.
- `plans/09-first-implementation-sprint.md`: add or sequence the first preflight slice after schema naming freeze.
- `architecture/09-integration-contracts.md`: bind workflow reports to Transaction Passport refs and verifier report claim IDs.

## First Slice

### WORKFLOW-PREFLIGHT-01: Reject Broader Child Scope Before Execution

Objective: a read-only preflight path rejects a proposed child task whose scope is broader than its parent before any continuation token is minted or any tool is invoked.

Why this slice first:

- it tests the highest-value swarm invariant;
- it requires no live provider;
- it does not need settlement, disclosure, or UI;
- it uses existing workflow and CLI surfaces;
- it creates a reusable report shape for later simulation work.

Proposed files:

- `crates/chio-workflow/src/preflight.rs`
- `crates/chio-workflow/src/lib.rs`
- `crates/chio-workflow/tests/preflight.rs`
- `crates/chio-cli/src/cli/types/workflow.rs`
- `crates/chio-cli/src/cli/types.rs`
- `crates/chio-cli/src/cli/dispatch/workflow.rs`
- `crates/chio-cli/src/cli/dispatch.rs`
- `fixtures/chio-launch/workflow/preflight-valid-scope-subset/plan.json`
- `fixtures/chio-launch/workflow/preflight-invalid-broader-child-scope/plan.json`
- `docs/superpowers/research/chio-launch/indices/proof-room-fixture-catalog.md`

Red step:

```bash
cargo test -p chio-workflow --test preflight broader_child_scope_fails_preflight
```

Expected initial failure: the test or module does not exist.

Green step:

Add a minimal preflight evaluator that reads a parent scope and child scope from a fixture-backed plan, checks subset relation, and emits a deterministic JSON report with:

- `schema = "chio.workflow.preflight-report.v1"`;
- `verdict = "rejected"`;
- `failure_code = "workflow.preflight.child_scope_not_subset"`;
- `claim_id`;
- `plan_digest`;
- `parent_scope_digest`;
- `child_scope_digest`.

CLI acceptance:

```bash
cargo test -p chio-cli workflow_preflight_rejects_broader_child_scope
```

Stop boundary:

- no live dispatch;
- no continuation token minting;
- no route-plan verification;
- no budget pool;
- no revocation epoch;
- no model/provider calls;
- no Proof Room UI.

## Negative Fixture Floor

Add this workflow negative fixture floor across the public catalog.

Preflight:

- `workflow/preflight-invalid-broader-child-scope`;
- `workflow/preflight-missing-approval-gate`;
- `workflow/preflight-route-plan-missing`;
- `workflow/preflight-budget-impossible`;
- `workflow/preflight-unknown-artifact-schema`.

What-if:

- `workflow/what-if-policy-digest-drift`;
- `workflow/what-if-revocation-epoch-stale`;
- `workflow/what-if-provider-profile-change`;
- `workflow/what-if-privacy-profile-tightened`;
- `workflow/what-if-budget-lowered-below-fanout`.

Rehearsal:

- `workflow/rehearsal-token-used-live`;
- `workflow/rehearsal-receipt-used-as-proof`;
- `workflow/rehearsal-route-egress-skipped`;
- `workflow/rehearsal-approval-used-live`;
- `workflow/rehearsal-tool-output-promoted`.

Replay:

- `workflow/replay-missing-provider-metadata`;
- `workflow/replay-post-tool-request-drift`;
- `workflow/replay-tool-args-canonical-digest-drift`;
- `workflow/replay-live-rerun-overwrites-recorded-verdict`;
- `workflow/replay-unpinned-policy`.

Provider conformance:

- `workflow/provider-streaming-chunk-reorder`;
- `workflow/provider-required-tool-no-call`;
- `workflow/provider-duplicate-side-effecting-retry`;
- `workflow/provider-natural-language-tool-result`;
- `workflow/provider-model-id-mismatch`.

Human approval:

- `workflow/approval-wrong-order`;
- `workflow/approval-wrong-mode`;
- `workflow/approval-expired`;
- `workflow/approval-text-edited`;
- `workflow/approval-budget-exceeded`;
- `workflow/approval-route-changed`.

## Proof Room Impact

The Proof Room should display workflow simulation only as verifier output.

It should not:

- calculate preflight verdicts in browser code;
- relabel rehearsal as proof;
- hide live versus recorded replay mode;
- let benchmark scores appear without corpus version and provider profile;
- display human approval text without its digest and signed approval artifact.

It should:

- show preflight failures before live execution artifacts;
- show what-if claim deltas;
- show rehearsal-only warnings from report JSON;
- show replay capsule mode as recorded or live;
- show model/provider conformance as profile-scoped;
- show approval gates as exact digest-bound constraints.

## Launch Copy Consequence

Without this layer, the homepage can defensibly claim post-execution verification, but not AI-native operational trust. "Autonomous commerce" implies that a buyer can evaluate a proposed autonomous transaction before it runs. "Multi-swarm coordination" implies that a recursive plan can be rehearsed and red-teamed before it spends authority. "Proof layer for the agent web" implies deterministic replay of agent transcripts and provider behavior, not only signed receipts after the fact.

The right launch position is therefore:

- P0: prove one governed action, one preflight rejection, and one recursive swarm negative case.
- P1: add replay capsules, rehearsal runs, approval gates, and benchmark scenarios.
- P2: render policy IDE and hosted evaluation experiences.

The project should resist GUI-first simulation. It should also resist proof-after-the-fact complacency. The narrow middle path is a verifier-grade preflight and replay layer that uses the same artifacts, failure codes, and fixture discipline as the Transaction Passport and Proof Room.
