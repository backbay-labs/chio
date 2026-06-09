# Execution Slice Contract

Status: second-pass implementation slicing contract
Confidence: high for sequencing and shared-file ownership, moderate for final crate placement.

## Purpose

The launch thesis is ambitious enough that parallel agents will be useful, but the shared registry files can become a collision point. This contract defines how to split work without fragmenting schema names, verifier claims, or crate ownership.

## Global Rule

Build launch proof as an integration layer over existing crates first. New crates are allowed only after owner review proves the existing crate homes cannot carry the abstraction.

Default homes:

| Surface | First implementation home | Do not create first |
| --- | --- | --- |
| Transaction Passport | `chio-attest-buyer-core`, `chio-control-plane`, `chio-lineage`, `chio-cli` | `chio-transaction` |
| Commerce order context | examples, `chio-market`, `chio-open-market`, `chio-credit`, `chio-settle`, `chio-control-plane` | `chio-commerce` |
| Swarm authority | `chio-runtime`, `chio-runtime-core`, `chio-federation`, `chio-pheromone`, `chio-reputation` | `chio-swarm` |
| Disclosure and lineage | `chio-selective-disclosure`, `chio-lineage`, `chio-credentials`, `chio-attest-buyer-core` | separate privacy product crate |
| Settlement proof | `chio-web3`, `chio-settle`, `chio-anchor`, `chio-link` | duplicate settlement passport crate |
| Risk comptroller | `chio-credit`, `chio-underwriting`, `chio-appraisal`, `chio-control-plane` | `chio-risk` or `chio-comptroller` |
| Proof Room | `chio-cli`, existing examples, static bundle viewer | proof semantics in UI |
| Agent Web envelope | protocol edge crates plus `chio-control-plane` | universal agent protocol crate |
| Runtime security | `chio-kernel-core`, `chio-runtime-core`, `chio-runtime`, `chio-control-plane`, `chio-cli` | after-the-fact-only proof surface |
| Workflow preflight | existing workflow, runtime, control-plane, and CLI surfaces first | polished policy IDE |
| Enterprise evidence | `chio-siem`, `chio-metering`, `chio-lineage`, `chio-control-plane`, disclosure and risk crates | compliance platform or IAM product |
| Trust-market context | `chio-market`, `chio-open-market`, `chio-credit`, `chio-underwriting`, `chio-reputation`, `chio-governance` | permissionless marketplace or liquidity pool |

## Shared File Ownership

Only the registry owner touches these files during a multi-agent implementation wave:

- `spec/schemas/registry.json`;
- `spec/schemas/MANIFEST.sha256`;
- `scripts/check-chio-schema-registry.sh`;
- `crates/chio-core-types/src/signed_artifact.rs`;
- `crates/chio-core-types/tests/signed_artifact_schema.rs`;
- `spec/registries/claim-registry.v1.json`;
- `spec/registries/proof-manifest.v1.json`.

Domain agents may draft schema files, fixtures, and tests in disjoint paths, then hand the registry delta to the owner. This prevents incompatible schema fields, duplicate IDs, and broken manifest hashes.

## Phase 0 Team Shape

| Role | Output | Write scope |
| --- | --- | --- |
| Registry owner | canonical schema rows, manifest hashes, signed-artifact constants, claim/proof rows | shared registry files only |
| Transaction slice | minimal passport schema, verifier, fixture, CLI proof verify test | transaction schema path, control-plane module, CLI proof dispatch, fixtures |
| Commerce slice | order event replay test and IOA fixture extraction plan | commerce fixtures and existing market/settle homes |
| Swarm slice | stale continuation negative fixture and verifier hook plan | runtime/federation fixture paths |
| Disclosure slice | excess-disclosure negative fixture and privacy profile schema draft | selective-disclosure and lineage fixture paths |
| Settlement slice | web3 proof bundle wrapper over existing settlement dispatch and receipt | web3/settle fixture paths |
| Risk slice | double-reserve-consumption negative fixture and facility-state schema draft | credit/control-plane fixture paths |
| Proof Room slice | CLI/UI report shape consuming verifier output | CLI proof command and static viewer paths |
| Standards slice | copy lint and source log refresh | docs lint and source log only |
| Runtime security slice | execution lease, nonce default, revocation freshness, sandbox attestation, tool-server ack, receipt totality | runtime/kernel/control-plane fixtures and verifier tests |
| DX launch slice | proof doctor, first-run evidence, docs command log, release truth | CLI proof dispatch, fixtures, docs quickstarts, release truth scripts |
| Payments slice | merchant payment lifecycle, mandate allowance, dispute recovery, fraud, currency, recurrence | commerce fixtures and existing market/settle/control-plane homes |
| Workflow preflight slice | read-only preflight report and broader-child-scope rejection | workflow/runtime fixtures and CLI workflow dispatch |
| Enterprise slice | data governance, evidence export, telemetry projection, approval case, control map | enterprise fixtures, SIEM/metering/control-plane/report paths |
| Trust-market slice | discovery snapshot, selection report, local scorecard, SLA, collateral, guarantee, jurisdiction | market/credit/reputation/governance fixture paths |

## First Sprint Stop Rule

The first sprint is not complete because schemas exist. It is complete only when one valid minimal Transaction Passport verifies and one invalid policy digest mismatch fails through `chio proof verify`.

Required first-sprint commands:

```bash
cargo test -p chio-core-types --test signed_artifact_schema transaction_passport_schemas_are_known
scripts/check-chio-schema-registry.sh
cargo test -p chio-control-plane --test transaction_passport
cargo test -p chio-cli --test proof_verify
```

The fixture must use `schema`, not `schema_id`, unless the protocol owner explicitly changes the repo convention.

## Follow-On Slice Order

After the first sprint passes, use this order unless an implementation owner finds a hard dependency:

1. Runtime Security Slice 0: side-effecting runtime claim requires execution lease, nonce, revocation freshness, sandbox attestation, policy digest, tool-server ack, and receipt totality.
2. DX Slice 0A: `chio proof doctor` verifies first-run evidence, valid and invalid fixtures, allow and denial receipts, docs command log, and release truth.
3. Commerce Payments Slice 0: payment lifecycle and mandate allowance ledger over one offline PSP-shaped fixture.
4. Workflow Preflight Slice 0: reject broader child scope before any continuation token or tool invocation exists.
5. Crypto Context Slice 0: disclosure verification binds key state, revocation snapshot, nonce, audience, holder binding, algorithm policy, and transparency state.
6. Enterprise Export Slice 0: data governance report, redacted evidence export bundle, telemetry projection, approval case, and control map rooted in one passport.
7. Agent Web Interop Slice 0: Standard Webhooks plus CloudEvents projection through existing Agent Web envelope IDs.
8. Trust-Market Slice 0: provider discovery, selection report, scorecard, SLA, collateral, guarantee, and jurisdiction receipt.

## Launch Claim Discipline

Each public claim needs:

1. claim id;
2. artifact carrying the claim;
3. verifier module or test;
4. positive fixture;
5. negative fixture;
6. omitted or unsupported state if not covered;
7. Proof Room display path;
8. copy phrase allowed only after the verifier passes.

No homepage phrase should be accepted because a demo transcript exists. The proof must be reproducible from signed roots, typed evidence, deterministic reports, and negative controls.

## Ambitious Feature Backlog

The most important missed or underbuilt features are:

1. receipt coverage matrix for the "every action" phrase;
2. deterministic Transaction Passport assembler over existing evidence exports;
3. claim registry delta for every homepage phrase;
4. runtime-spine recursive delegation fixture with stale continuation failure;
5. risk comptroller facility fixture with reserve, appeal, slash, payout, and settlement reconciliation;
6. Agent Web envelope for one MCP or A2A object plus unsupported-claim report;
7. copy lint tied to verifier coverage;
8. release truth gate for every public package, Docker, hosted demo, chain, and Sigstore/Rekor claim.
9. tool-server-verifiable execution lease for side-effecting calls;
10. `chio proof doctor` and first-run evidence bundle;
11. merchant payment lifecycle replay for PSP, refund, dispute, chargeback, fraud, currency, and recurring mandate state;
12. crypto verification context for key state, revocation, nonce, audience, holder binding, algorithm policy, and transparency state;
13. workflow preflight and replay capsules for AI-native planning;
14. enterprise evidence exports for telemetry, retention, legal hold, PII, residency, approval, controls, and incident review;
15. trust-market context for discovery, local scorecards, SLAs, collateral, guarantees, and adjudication jurisdiction;
16. webhook, CloudEvents, GraphQL, browser/RPA, SaaS connector, identity, Kubernetes, and OCI projection surfaces.
