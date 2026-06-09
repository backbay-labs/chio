# Execution Slicing And TDD Audit

Status: refinement audit
Scope: `docs/superpowers/research/chio-launch/plans`
Confidence: high for slicing defects, moderate for proposed file ownership where crate boundaries still need owner review.

## Executive Verdict

The plans are good architecture roadmaps, but most are not yet execution plans. They describe outcomes at phase scale: "implement verifier core", "add replay ledger", "require route-plan receipt in every bridge", "build static UI", "add projection library". Those are too large for agentic workers because they cross specs, schema registries, Rust crates, fixtures, CLI, UI, docs, and release gates in one task.

The launch pass needs a stricter execution contract: one slice names exact files, starts with a failing test or fixture, updates the schema and claim registries before any public claim is advertised, verifies with a concrete command, and leaves a deterministic artifact for the next slice.

## Agent-Ready Slice Contract

A task is agent-ready only if it includes all of this:

1. Exact files to create or modify, including tests and fixtures.
2. A red-first validation step: failing Rust test, schema test, CLI test, UI test, fixture replay, or lint.
3. A schema registry step when adding or accepting a signed artifact.
4. A claim registry step when adding or advertising a verifiable launch claim.
5. A proof manifest or theorem inventory step when the claim relies on formal, conformance, or signed-evidence backing.
6. A deterministic fixture, with at least one valid and one invalid case for any verifier behavior.
7. A command list that proves the slice passes.
8. An explicit stop boundary saying what the slice does not touch.

If a task cannot meet that shape, it is still design work.

## Cross-Plan Defects

### 1. Schema names are not frozen

The docs still drift between schema naming styles:

- `chio.transaction-passport.v1`, `chio.transaction.passport.v1`, and `chio.transaction_passport.v1`
- `chio.risk.comptroller-report.v1` and `chio.risk_comptroller_report.v1`
- `chio.agent-web-proof-envelope.v1` and `chio.agent_web_proof_envelope.v1`

This must be a P0 freeze before implementation. Otherwise agents will create incompatible schema files, registry rows, fixture fields, verifier constants, and CLI reports.

Recommended rule: use the architecture and artifact registry hyphenated IDs as canonical unless owner review overrides them:

- `chio.transaction-passport.v1`
- `chio.transaction.evidence-graph.v1`
- `chio.transaction.claim-set.v1`
- `chio.transaction.verifier-report.v1`
- `chio.commerce.order-context.v1`
- `chio.commerce.event-log.v1`
- `chio.swarm.task-graph.v1`
- `chio.bbs-projection.manifest.v2`
- `chio.web3-settlement-proof-bundle.v1`
- `chio.risk.comptroller-report.v1`
- `chio.agent-web-proof-envelope.v1`

### 2. Schema registry work is under-specified

The plans say "add schemas" or "register artifact names", but the repo has multiple registry surfaces. A schema slice must explicitly cover:

- `spec/schemas/registry.json`
- `spec/schemas/MANIFEST.sha256`
- `spec/schemas/VERSION`, if the schema-set version policy requires a bump
- `scripts/check-chio-schema-registry.sh`, if a new schema root such as `spec/schemas/chio-transaction/` is introduced
- `crates/chio-core-types/src/signed_artifact.rs`, if verifier code must accept the signed artifact schema ID
- `crates/chio-core-types/tests/signed_artifact_schema.rs`, for fail-closed unknown-schema behavior
- `spec/registries/claim-registry.v1.json`, when the artifact carries a public claim
- `spec/registries/proof-manifest.v1.json`, when the claim has named evidence
- `spec/registries/theorem-inventory.v1.json`, when the evidence references formal statements or assumptions

The current `09-first-implementation-sprint.md` is closer to executable, but still misses `spec/schemas/MANIFEST.sha256` and does not mention that `scripts/check-chio-schema-registry.sh` only checks selected roots. Creating `spec/schemas/chio-transaction/v1/` without extending that script leaves the new schema root outside the normal metadata gate.

### 3. Tests are listed after implementation instead of driving slices

Most plans have a "Tests" section, but the tasks do not say which test is written before which implementation. For agentic workers, every slice needs a first command expected to fail and a final command expected to pass.

Bad shape:

```text
Implement deterministic replay to materialized state.
Tests: quote amount drift fails.
```

Good shape:

```text
Add `crates/chio-commerce/tests/order_replay.rs::quote_amount_drift_rejected` using
`fixtures/chio-launch/commerce/invalid-quote-amount-drift/event-log.json`.
Run it and capture the failure. Then implement only the replay check needed to
make that test pass.
```

### 4. Exact file ownership is missing

Several plans leave ownership open with phrases like "or equivalent module", "existing schema layout", "add runtime path", "build static UI", and "add bridge-specific fixtures". Those are handoff blockers. Each task should name the crate and module.

For example, `chio proof verify` should not say "modify main.rs or existing CLI command module". It should name a narrow path such as:

- `crates/chio-cli/src/cli/types.rs`
- `crates/chio-cli/src/cli/types/proof.rs`
- `crates/chio-cli/src/cli/proof.rs`
- `crates/chio-cli/src/cli/dispatch.rs`
- `crates/chio-cli/tests/proof_verify.rs`

### 5. Fixtures arrive too late

The plans often put fixtures in launch qualification phases. That is backwards for verifier-grade work. Fixtures are not packaging polish; they are the executable specification. Every schema or verifier slice should create or update one valid fixture and one invalid fixture before expanding behavior.

Recommended fixture root:

- `fixtures/chio-launch/transaction/minimal-valid/`
- `fixtures/chio-launch/transaction/invalid-policy-digest-mismatch/`
- `fixtures/chio-launch/commerce/completed-valid/`
- `fixtures/chio-launch/commerce/invalid-quote-order-mismatch/`
- `fixtures/chio-launch/swarm/valid-three-child-one-join/`
- `fixtures/chio-launch/swarm/invalid-stale-continuation-token/`
- `fixtures/chio-launch/disclosure/invalid-excess-disclosure/`
- `fixtures/chio-launch/settlement/invalid-wrong-order-id/`
- `fixtures/chio-launch/risk/invalid-double-consumed-reserve/`
- `fixtures/chio-launch/envelope/mcp-invalid-external-digest/`

### 6. Negative cases are sometimes not semantically real

The first implementation sprint says the invalid policy hash fixture should prove "one real authority mismatch", but a non-hex digest shape is only a format error. A real authority or policy mismatch should compare two otherwise valid artifacts:

- passport references `verifier_policy_sha256 = A`
- bundle includes policy bytes whose canonical digest is `B`
- verifier rejects because `A != B`

Shape validation is useful, but it should not be sold as the launch authority mismatch.

### 7. Domain work is mixed with foundation work

The roadmap should prevent agents from starting commerce, swarm, disclosure, settlement, risk, and external envelopes before the transaction proof root and registry spine are stable. Otherwise every domain will invent its own reference shape and verifier report vocabulary.

Foundation artifacts that should land first:

- schema ID naming freeze
- signed-artifact registry update pattern
- claim ID naming pattern
- Transaction Passport reference shape
- evidence graph node and edge classes
- verifier report verdict vocabulary
- fixture directory contract
- CLI JSON report contract

## Plan-By-Plan Critique

### `00-roadmap.md`

The phase ordering is mostly right, but Phase 0 is too broad. "Register artifact names and versioning rules" should be split into one schema family per slice, plus one shared registry validation slice.

Missing execution details:

- exact schema IDs and file paths
- whether new schemas live under `spec/schemas/chio-transaction/v1/`, a shared launch root, or existing checked roots
- registry and manifest hash updates
- `KNOWN_SIGNED_ARTIFACT_SCHEMAS` acceptance rules
- claim registry rows for homepage claims
- unsupported-action exclusion artifact, schema, and verifier behavior

Recommended rewrite: make Phase 0 a sprint with a single registry owner and separate agents for transaction, commerce, swarm, disclosure, settlement, risk, proof room, and envelope schema stubs. Only the registry owner touches `spec/schemas/registry.json` and `spec/schemas/MANIFEST.sha256` after reviewing all schema IDs.

### `01-transaction-passport-implementation.md`

This is the most important plan and still too broad.

Problem tasks:

- "Build `chio-transaction` or equivalent module" is not executable. It leaves crate ownership undecided.
- "Bind one kernel receipt, capability proof, guard decision, policy hash, request digest, response digest, and trust root" combines seven verifier predicates.
- "Implement a passport assembler that can ingest receipts, capability proofs, policy docs, evidence exports, commerce order context, disclosure capsule, settlement proof bundle, and risk report" is a multi-sprint project.
- Proof Room adapter tasks should not start until the verifier report schema is stable.

Recommended split:

- TP-0A: freeze schema IDs and file paths.
- TP-0B: register schemas and update signed-artifact acceptance.
- TP-1A: verify only the passport root schema and digest field shapes.
- TP-1B: verify evidence graph root digest matches bundled graph bytes.
- TP-1C: verify exactly one receipt node binds request and response digests.
- TP-1D: verify policy hash mismatch fails using a real bundled policy.
- TP-1E: emit deterministic `chio.transaction.verifier-report.v1`.
- TP-1F: expose `chio proof verify` for the minimal fixture.

The assembler should be deferred until verifier fixtures are stable. Otherwise it can generate artifacts the verifier does not actually prove.

### `02-commerce-order-implementation.md`

The schema phase lists too many artifacts in one task. "Promote provider passport, reputation, federation, quote, mandate, budget, payment, fulfillment, settlement, dispute, and reconciliation into typed order events" is not a task; it is the whole commerce protocol.

Missing TDD slices:

- one event schema at a time
- one replay transition at a time
- one admission gate at a time
- one bridge projection at a time
- one negative fixture per invariant

Recommended first slices:

- COM-0A: schema and registry for `chio.commerce.order-context.v1` and `chio.commerce.event-log.v1`.
- COM-1A: replay empty-created-paid-completed valid path.
- COM-1B: reject quote event whose `order_id` differs from the event log root.
- COM-1C: reject payment evidence whose merchant differs from the accepted quote.
- COM-1D: reject settlement observer before settlement dispatch.
- COM-2A: bind commerce verifier report into the Transaction Passport evidence graph.

External bridges should be separate slices: AP2 only, x402 only, ACP-Commerce only, web3 settlement only.

### `03-swarm-authority-implementation.md`

The plan has good negative cases, but the execution surface is too wide.

Problem tasks:

- "Require route-plan receipt in MCP, A2A, ACP-Client, HTTP/OpenAPI, OpenAI, and local nested dispatch" touches at least six integration surfaces.
- "Implement continuation token minting" plus consumption tracking plus deferred resume is too much for one slice.
- Budget pools and revocation should not be implemented in one task because double spend, stale epoch, fan-out reservation, and fan-in release are different invariants.

Recommended split:

- SWARM-0A: schema and registry for task graph, continuation token, route-plan receipt, join receipt, and budget pool.
- SWARM-1A: per-hop witness verifier rejects child scope broader than parent.
- SWARM-2A: continuation token verifies child task, graph digest, parent receipt, and nonce.
- SWARM-2B: side-effecting token reuse fails with a local in-memory consumption registry.
- SWARM-2C: deferred resume requires fresh revocation epoch.
- SWARM-3A: join receipt rejects missing parent.
- SWARM-4A: local nested dispatch requires a route-plan receipt.
- SWARM-4B through SWARM-4G: one bridge per task, using `crates/chio-mcp-edge`, `crates/chio-a2a-edge`, `crates/chio-acp-edge`, `crates/chio-openapi-mcp-bridge`, and other specific bridge crates.

### `04-lineage-disclosure-implementation.md`

This is the closest to TDD because it starts by codifying current v1 behavior. The weakness is that the plan does not name files or split projection variants.

Missing exact files:

- `crates/chio-selective-disclosure/src/lib.rs`
- `crates/chio-selective-disclosure/src/encoding.rs`
- `crates/chio-selective-disclosure/tests/bbs_selective_disclosure.rs`
- `crates/chio-core-types/src/receipt/body.rs`
- `crates/chio-kernel/src/kernel/responses.rs`
- `crates/chio-kernel/src/receipt_support/signing.rs`
- schema and registry files for projection manifests, privacy profiles, capsules, signed lineage subgraphs, and leakage ledgers

Recommended split:

- DISC-0A: snapshot current receipt projection v1.
- DISC-0B: snapshot current workflow projection v1.
- DISC-0C: snapshot current step projection v1.
- DISC-1A: register `chio.bbs-projection.manifest.v2`.
- DISC-1B: manifest rejects unknown field.
- DISC-1C: stable message index ordering for receipt projection only.
- DISC-2A: required BBS runtime mode fails closed when key lookup fails.
- DISC-3A: privacy profile rejects one forbidden disclosed field.
- DISC-3B: hidden predicate over undeclared field fails.
- DISC-4A: signed lineage subgraph rejects missing required parent.
- DISC-5A: leakage ledger rejects disclosed field absent from ledger.

### `05-public-settlement-passport-implementation.md`

The plan is directionally right but too compact around verifier core. Verifying registry, escrow, bond, tx, block, finality, oracle, dispute, and identity binding sections is at least eight independent slices.

Missing details:

- exact source fixture paths under `examples/internet-of-agents-web3-network/app/tests/fixtures/good-bundle/`
- exact new proof bundle fixture path
- offline versus live-chain lookup fields in the schema
- deterministic report schema and downgrade vocabulary
- Transaction Passport edge class for settlement proof reports

Recommended split:

- SETTLE-0A: inventory IOA fixture files and select one canonical fixture path.
- SETTLE-0B: register `chio.web3-settlement-proof-bundle.v1` and `chio.public-settlement-verifier-report.v1`.
- SETTLE-1A: verifier rejects wrong order id.
- SETTLE-1B: verifier rejects wrong chain id.
- SETTLE-1C: verifier rejects tx and block mismatch.
- SETTLE-1D: verifier downgrades missing dispute posture.
- SETTLE-2A: promote only registry root evidence.
- SETTLE-2B: promote only escrow state evidence.
- SETTLE-2C: promote only bond state evidence.
- SETTLE-3A: bind settlement report into Transaction Passport.

### `06-risk-comptroller-implementation.md`

This plan is too large for first-pass execution. Risk, facility, coverage, claims, payouts, reserve release, reserve slash, market slash, actuarial evidence, and governance approval should not move as one system.

Problem tasks:

- "Implement report assembler over underwriting, appraisal, provider passport, reputation, federation, facility, bond, reserve, coverage, claim, payout, settlement, governance, and slashing refs" is not decomposed.
- "Define separate ledgers for claim payout, reserve release, reserve slash, and market slash" should be four schema slices plus one reconciliation slice.
- The actuarial evidence track should remain claim-gating until real backtest artifacts exist.

Recommended split:

- RISK-0A: freeze what launch can and cannot claim.
- RISK-0B: register `chio.risk.comptroller-report.v1`.
- RISK-1A: report verifier rejects missing reserve state.
- RISK-1B: report verifier rejects stale reputation snapshot.
- RISK-1C: coverage not bound to order id fails.
- FAC-1A: register `chio.risk.facility-state-report.v1`.
- FAC-1B: facility active without capital fails.
- LEDGER-1A: claim payout ledger schema.
- LEDGER-1B: reserve release ledger schema.
- LEDGER-1C: reserve slash ledger schema.
- LEDGER-1D: market slash ledger schema.
- LEDGER-2A: same reserve cannot be paid and released.

Autonomous pricing claims should stay blocked until a separate actuarial artifact and reserve adequacy verifier exist.

### `07-proof-room-implementation.md`

The Proof Room should be developed as a consumer of verifier report JSON, not as a parallel verifier. The plan risks building UI before the report contracts are stable.

Problem tasks:

- "Build static UI around verifier report JSON" is too broad.
- "Add overview, authority, graph, and failure tabs" should be one tab per slice.
- "Add commerce, swarm, disclosure, settlement, risk, and external envelope tabs" is six domain features.
- Release truth gate should be introduced as soon as public CLI or package claims exist, not after the full UI.

Recommended split:

- ROOM-0A: define `chio.proof-room.bundle.v1` and a one-fixture bundle shape.
- ROOM-1A: static loader renders verifier report verdict only.
- ROOM-1B: failure list renders failed claim IDs.
- ROOM-1C: artifact refs resolve to bundled JSON.
- ROOM-2A: authority tab only.
- ROOM-2B: graph tab only.
- ROOM-3A through ROOM-3F: one domain tab per task.
- ROOM-4A: release truth gate checks documented fixture paths.
- ROOM-4B: release truth gate checks documented CLI command from clean checkout.

Candidate exact UI files if reusing the current dashboard:

- `crates/chio-cli/dashboard/src/types.ts`
- `crates/chio-cli/dashboard/src/App.tsx`
- `crates/chio-cli/dashboard/src/App.test.tsx`
- `crates/chio-cli/dashboard/src/components/ProofRoomReport.tsx`
- `crates/chio-cli/dashboard/src/components/ProofRoomReport.test.tsx`

If Proof Room is a new static app instead, the plan must name that app path before implementation.

### `08-agent-web-proof-envelope-implementation.md`

This plan has the highest external-claim risk. It should be sliced more aggressively than the others.

Problem tasks:

- "Add taxonomy doc for MCP, A2A, ACP-Client, ACP-Commerce, AGNTCY-ACP, AG-UI, OpenAPI, AP2, x402, VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, and DSSE" is too broad and depends on live source review.
- "Implement protocol-specific projections" lists too many protocols for one phase.
- Standards review is Phase 5, but it needs to happen before taxonomy and copy lint finalize.

Recommended split:

- ENV-0A: create standards source file with source URLs, access dates, protocol names, and allowed copy.
- ENV-0B: copy lint rejects bare `ACP`.
- ENV-0C: copy lint rejects universal-protocol claims.
- ENV-1A: register `chio.agent-web-proof-envelope.v1`.
- ENV-1B: register `chio.agent-web.external-projection-manifest.v1`.
- ENV-1C: verifier rejects missing external subject digest.
- ENV-2A: MCP projection only.
- ENV-2B: A2A projection only.
- ENV-2C: ACP-Client projection only.
- ENV-2D: ACP-Commerce projection only.
- ENV-2E: AG-UI projection only.
- ENV-2F: OpenAPI projection only.
- ENV-2G: AP2 projection only.
- ENV-2H: x402 projection only.
- ENV-2I: VC/BBS/SD-JWT projection only if scope is narrowed further.
- ENV-2J: Sigstore/SLSA/in-toto/DSSE projection only if scope is narrowed further.

Each projection must produce one valid fixture, one digest-mismatch fixture, and one limitation report.

### `09-first-implementation-sprint.md`

This file is the closest to an execution plan and should be used as the model, but it needs hardening before handoff.

Required fixes:

- Add `spec/schemas/MANIFEST.sha256` to the file structure and completion gate.
- Add `scripts/check-chio-schema-registry.sh` update if `spec/schemas/chio-transaction/v1/` is a new checked schema root.
- Replace registry string containment tests with parsed JSON assertions over `schema`, `artifactKind`, `introducedBy`, and `schemaFile`.
- Decide between `schema` and `schema_id`. Existing signed-artifact registry language uses `schema`; do not introduce `schema_id` unless the protocol explicitly chooses that field.
- Name exact CLI files instead of "main.rs or existing CLI command module".
- Add `crates/chio-core-types/tests/signed_artifact_schema.rs` assertions for the new accepted schema IDs.
- Make the negative fixture a real policy digest mismatch, not only invalid hex shape.
- Avoid saying "authority mismatch" when the test is only digest format validation.
- Add `spec/registries/claim-registry.v1.json` and `spec/registries/proof-manifest.v1.json` rows for any launch claim surfaced by the verifier report.

## Recommended Sprint And Backlog Structure

### Sprint 0: Proof Surface Freeze

Goal: prevent schema, claim, fixture, and report fragmentation.

Backlog:

1. Freeze canonical schema IDs in `docs/superpowers/research/chio-launch/indices/artifact-registry.md`.
2. Add a schema-root decision note: existing checked root versus new `spec/schemas/chio-transaction/v1/` plus script update.
3. Add a launch fixture layout contract under `fixtures/chio-launch/README.md`.
4. Add a verifier report verdict vocabulary.
5. Add claim ID naming rules and first claim registry rows.
6. Add a registry gate command that checks schema registry, manifest hashes, and signed-artifact constants.

Parallelism: low. One registry owner should serialize changes to registry files.

### Sprint 1: Minimal Transaction Passport

Goal: one signed root over one governed action with one real negative case.

Backlog:

1. Register transaction schemas and signed-artifact IDs.
2. Implement minimal passport shape validation.
3. Implement evidence graph digest binding.
4. Implement policy digest binding with a real mismatch fixture.
5. Emit deterministic verifier report JSON.
6. Add `chio proof verify` for the minimal fixture.
7. Add one valid and one invalid minimal Proof Room bundle.

Parallelism: moderate after schema registration. CLI and verifier can split once report JSON is stable.

### Sprint 2: Proof Room Tier 0

Goal: reviewer can inspect the minimal Transaction Passport without domain tabs.

Backlog:

1. Define proof room bundle schema.
2. Load local bundle offline.
3. Render verifier verdict.
4. Render failed claim IDs and evidence refs.
5. Add release truth gate for fixture paths and CLI command.

Parallelism: moderate. UI consumes report JSON and should not mutate verifier logic.

### Sprint 3: Commerce Replay MVP

Goal: order replay verifies one complete commerce path and rejects one real binding mismatch.

Backlog:

1. Register commerce order context and event log schemas.
2. Implement replay for created, quoted, mandated, budgeted, paid, fulfilled, settled, completed.
3. Reject quote/order mismatch.
4. Reject payment/merchant mismatch.
5. Reject observer-before-dispatch.
6. Bind commerce report into Transaction Passport.

Parallelism: moderate. One event-family owner, one replay owner, one fixture owner.

### Sprint 4: Swarm Authority MVP

Goal: verify recursive delegation with one fan-out and one join.

Backlog:

1. Register task graph, continuation token, route-plan receipt, join receipt, and budget pool schemas.
2. Verify per-hop witness chain.
3. Verify continuation token freshness and graph binding.
4. Reject single-use token reuse.
5. Reject missing join parent.
6. Require route-plan receipt for local nested dispatch.
7. Add one bridge route-plan slice after local path passes.

Parallelism: moderate. Do not fan out bridge work until generic route-plan verifier passes.

### Sprint 5: Disclosure MVP

Goal: verifier profile rejects excess disclosure and accepts one valid capsule.

Backlog:

1. Snapshot v1 projection behavior.
2. Register BBS projection v2 manifest.
3. Add receipt projection v2 only.
4. Add required runtime mode fail-closed test.
5. Add privacy profile schema.
6. Reject forbidden field disclosure.
7. Add signed lineage subgraph minimal verifier.
8. Add leakage ledger coverage check.

Parallelism: moderate. Keep kernel runtime changes separate from schema and verifier changes.

### Sprint 6: Public Settlement Proof MVP

Goal: public settlement proof recomputes one offline-verifiable state and rejects wrong order binding.

Backlog:

1. Inventory IOA fixture paths and select canonical fixture.
2. Register settlement proof bundle and verifier report schemas.
3. Verify order binding.
4. Verify chain ID binding.
5. Verify tx/block binding.
6. Mark live lookup fields explicitly.
7. Bind settlement report into Transaction Passport.

Parallelism: moderate. Fixture promotion and verifier slices can split after the canonical fixture is selected.

### Sprint 7: Risk Comptroller MVP

Goal: risk context is verifiable without overclaiming insurance pricing.

Backlog:

1. Freeze launch risk and insurance copy limits.
2. Register risk comptroller report.
3. Verify reserve state is present.
4. Verify coverage binds to order ID.
5. Register facility state report.
6. Reject facility active without capital.
7. Add double-consumption detector for paid versus released reserve.
8. Bind risk report into Transaction Passport.

Parallelism: moderate. Keep actuarial evidence as a separate later sprint.

### Sprint 8: Agent Web Envelope MVP

Goal: one external protocol projection proves digest binding and limitation reporting.

Backlog:

1. Create standards source file before copy or projection work.
2. Add bare-ACP and universal-protocol copy lint.
3. Register envelope and projection manifest schemas.
4. Implement envelope verifier for external digest and Transaction Passport ref.
5. Implement MCP projection only.
6. Add one invalid digest fixture.
7. Add Proof Room envelope tab for limitation report.

Parallelism: low at first because naming and copy claims need one owner. Projection work can fan out after the MCP slice passes.

## Examples Of Rewritten Bite-Sized Tasks

### TP-SCHEMA-01: Register Transaction Passport Schema IDs

Objective: make verifier builds recognize the three minimal Transaction Passport artifact schemas.

Files:

- `spec/schemas/chio-transaction/v1/transaction-passport.schema.json`
- `spec/schemas/chio-transaction/v1/evidence-graph.schema.json`
- `spec/schemas/chio-transaction/v1/verifier-report.schema.json`
- `spec/schemas/registry.json`
- `spec/schemas/MANIFEST.sha256`
- `scripts/check-chio-schema-registry.sh`
- `crates/chio-core-types/src/signed_artifact.rs`
- `crates/chio-core-types/tests/signed_artifact_schema.rs`

Red step:

```bash
cargo test -p chio-core-types --test signed_artifact_schema transaction_passport_schemas_are_known
scripts/check-chio-schema-registry.sh
```

Expected first failure: schema IDs or files are absent.

Green step:

Add schemas, registry rows, manifest hashes, script root coverage, and Rust constants. Re-run the two commands.

Stop boundary: no verifier logic, no CLI command, no UI.

### TP-VERIFY-01: Reject Evidence Graph Digest Mismatch

Objective: a passport fails if its `evidence_graph_sha256` does not match bundled graph bytes.

Files:

- `crates/chio-control-plane/src/transaction_passport.rs`
- `crates/chio-control-plane/src/lib.rs`
- `crates/chio-control-plane/tests/transaction_passport.rs`
- `fixtures/chio-launch/transaction/minimal-valid/transaction-passport.json`
- `fixtures/chio-launch/transaction/minimal-valid/evidence-graph.json`
- `fixtures/chio-launch/transaction/invalid-evidence-graph-digest/transaction-passport.json`
- `fixtures/chio-launch/transaction/invalid-evidence-graph-digest/evidence-graph.json`

Red step:

```bash
cargo test -p chio-control-plane --test transaction_passport rejects_evidence_graph_digest_mismatch
```

Green step:

Use existing canonical JSON and SHA-256 helpers to hash the bundled graph and compare it with the passport reference.

Stop boundary: no receipt validation, no assembler, no CLI.

### CLI-PROOF-01: Add Minimal `chio proof verify`

Objective: expose the minimal verifier through CLI JSON output.

Files:

- `crates/chio-cli/src/cli/types.rs`
- `crates/chio-cli/src/cli/types/proof.rs`
- `crates/chio-cli/src/cli/proof.rs`
- `crates/chio-cli/src/cli/dispatch.rs`
- `crates/chio-cli/tests/proof_verify.rs`

Red step:

```bash
cargo test -p chio-cli --test proof_verify proof_verify_rejects_policy_digest_mismatch
```

Green step:

Implement only `chio proof verify <bundle-dir-or-passport-path>` and return deterministic JSON with schema, verdict, passport ID, failed claim IDs, and evidence refs.

Stop boundary: no `collect`, no `explain`, no Proof Room UI.

### COM-REPLAY-01: Reject Quote Bound To Wrong Order

Objective: the commerce replay ledger fails when a quote event is valid JSON but names a different order.

Files:

- `crates/chio-commerce/src/event.rs`
- `crates/chio-commerce/src/replay.rs`
- `crates/chio-commerce/tests/order_replay.rs`
- `fixtures/chio-launch/commerce/invalid-quote-order-mismatch/event-log.json`
- `fixtures/chio-launch/commerce/valid-completed/event-log.json`

Red step:

```bash
cargo test -p chio-commerce --test order_replay rejects_quote_order_mismatch
```

Green step:

Parse event log, materialize order ID from root, and reject any quote event whose bound order ID differs.

Stop boundary: no payment, settlement, provider admission, or external bridges.

### SWARM-TOKEN-01: Reject Reused Side-Effecting Continuation Token

Objective: side-effecting continuation tokens are single-use.

Files:

- `crates/chio-federation/src/continuation.rs`
- `crates/chio-federation/tests/continuation_token.rs`
- `fixtures/chio-launch/swarm/invalid-reused-token/task-graph.json`

Red step:

```bash
cargo test -p chio-federation --test continuation_token reused_side_effecting_token_fails
```

Green step:

Add token consumption tracking behind a small verifier trait and fail the second consumption for side-effecting tasks.

Stop boundary: no deferred resume, no budget pool, no bridge dispatch.

### DISC-PROFILE-01: Reject Excess Disclosure

Objective: a privacy profile rejects a cryptographically valid disclosure that reveals a forbidden field.

Files:

- `crates/chio-selective-disclosure/src/lib.rs`
- `crates/chio-selective-disclosure/tests/bbs_selective_disclosure.rs`
- `spec/schemas/chio-attest/v1/disclosure-privacy-profile.schema.json`
- `fixtures/chio-launch/disclosure/invalid-excess-disclosure/capsule.json`

Red step:

```bash
cargo test -p chio-selective-disclosure --test bbs_selective_disclosure rejects_forbidden_disclosed_field
```

Green step:

Add verifier profile evaluation after cryptographic verification and before returning a verified verdict.

Stop boundary: no kernel runtime mode change.

### SETTLE-BIND-01: Reject Settlement Proof For Wrong Order

Objective: settlement proof bundle fails when settlement evidence binds a different order than the Transaction Passport node.

Files:

- `crates/chio-settle/src/proof_bundle.rs`
- `crates/chio-settle/tests/public_settlement_proof.rs`
- `fixtures/chio-launch/settlement/invalid-wrong-order-id/proof-bundle.json`

Red step:

```bash
cargo test -p chio-settle --test public_settlement_proof rejects_wrong_order_id
```

Green step:

Parse proof bundle and compare every order ref against the expected order ID supplied by the passport verifier.

Stop boundary: no live chain lookup, no escrow/bond verifier.

### RISK-LEDGER-01: Reject Paid And Released Same Reserve

Objective: a reserve cannot be consumed by both claim payout and reserve release.

Files:

- `crates/chio-credit/src/risk_reports.rs`
- `crates/chio-credit/tests/risk_comptroller.rs`
- `fixtures/chio-launch/risk/invalid-double-consumed-reserve/risk-report.json`

Red step:

```bash
cargo test -p chio-credit --test risk_comptroller rejects_paid_and_released_same_reserve
```

Green step:

Add a reserve consumption index keyed by reserve ID and reject multiple terminal consumption events.

Stop boundary: no actuarial pricing, no governance approval path.

### ENV-MCP-01: Implement MCP Envelope Projection Only

Objective: an MCP external object can carry a detached Chio proof envelope reference with digest binding and limitation reporting.

Files:

- `crates/chio-mcp-edge/src/proof_envelope.rs`
- `crates/chio-mcp-edge/tests/proof_envelope.rs`
- `fixtures/chio-launch/envelope/mcp-valid/envelope.json`
- `fixtures/chio-launch/envelope/mcp-invalid-external-digest/envelope.json`

Red step:

```bash
cargo test -p chio-mcp-edge --test proof_envelope rejects_external_digest_mismatch
```

Green step:

Implement only MCP projection and generic digest verification. Mark unsupported MCP-native authority claims as limitations.

Stop boundary: no A2A, ACP, AG-UI, OpenAPI, AP2, x402, VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, or DSSE projection.

## Final Quality Bar

A launch plan is ready for agentic execution when an engineer can pick any backlog item, run the named failing test, edit only the named files, run the named passing command, and hand off an artifact that the next item can consume. Most current plans are one level too high. `09-first-implementation-sprint.md` is the right direction, but it still needs registry completeness, exact CLI files, real semantic negative fixtures, and claim/proof registry coverage before it should be copied as the worker template.
