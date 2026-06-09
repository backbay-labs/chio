# Agent J Codebase Alignment Audit

## Scope

This review compares the Chio launch research plans under `docs/superpowers/research/chio-launch/` to the actual workspace source, protocol specification, registries, examples, and CLI surfaces in this worktree. The focus is not product positioning. The focus is whether the proposed artifacts fit the codebase that exists today.

Confidence: high for crate, schema, registry, CLI, and example alignment. Moderate for final implementation slicing because several launch plan files are conceptual and not yet backed by code.

## Executive Verdict

The launch research direction is directionally compatible with Chio, but the current plans repeatedly treat the repo as if it needs greenfield "transaction", "commerce", "swarm", "risk", "proof room", and "agent web" crates. That is the wrong default. The workspace already has 100 plus crates and already contains most of the relevant substrate:

- `chio-attest-buyer-core`, `chio-attest-loopback`, `chio-control-plane`, `chio-lineage`, `chio-selective-disclosure`, `chio-credentials`, and `chio-cli` for proof packages, agent passports, verifier policy, evidence export, lineage, and disclosure.
- `chio-market`, `chio-open-market`, `chio-credit`, `chio-underwriting`, `chio-settle`, `chio-anchor`, `chio-web3`, and `chio-web3-bindings` for commerce, capital, risk, settlement, anchoring, and web3 contracts.
- `chio-runtime`, `chio-runtime-core`, `chio-federation`, `chio-federation-authority`, `chio-pheromone`, `chio-pheromone-relay`, `chio-pheromone-runtime`, and `chio-reputation` for runtime trust, treaty continuity, federation, routing, and reputation.
- `chio-mcp-*`, `chio-a2a-*`, `chio-acp-*`, `chio-ag-ui-proxy`, `chio-openapi`, and `chio-openapi-mcp-bridge` for protocol edges and external agent/web surfaces.

The plans should be edited around integration, schema registration, verifier behavior, examples, and proof-package composition. New crates should be created only after the existing crates cannot carry a specific stable abstraction.

The highest-risk mismatch is registry overstatement: Chio rejects unknown signed-artifact schemas fail-closed. Any launch artifact advertised as signed or verifiable has to pass through `spec/schemas/registry.json`, `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, and the claim/proof registries before the plan can call it supported. The plans mention many artifact families, but the current repo only registers a small core set. See `spec/PROTOCOL.md:155-160`, `spec/PROTOCOL.md:321-325`, `crates/chio-core-types/src/signed_artifact.rs:22-37`, `crates/chio-core-types/src/signed_artifact.rs:54-63`, and `spec/registries/README.md:3-6`.

## Existing Workspace Shape

The root workspace already declares the relevant integration homes:

- Core and kernel: `Cargo.toml:4-15`.
- Guards and policy: `Cargo.toml:18-27`.
- Protocol adapters and edges: `Cargo.toml:29-55`.
- Economics and settlement: `Cargo.toml:57-69`.
- Identity, federation, runtime, pheromone, reputation, and selective disclosure: `Cargo.toml:80-96`.
- Observability and lineage: `Cargo.toml:98-104`.
- Control plane and storage: `Cargo.toml:106-111`.
- Product surfaces including `chio-cli`: `Cargo.toml:120-125`.

I did not find workspace crates named `chio-transaction`, `chio-commerce`, `chio-swarm`, `chio-proof-room`, `chio-agent-web`, `chio-risk`, or `chio-comptroller`. That absence is not a gap by itself. It is mostly evidence that the launch artifacts should map into existing crates first.

## High-Risk Mismatches

### 1. The plans understate the signed-artifact registry gate

The protocol is explicit:

- Additive fields may appear, but unknown schema identifiers for schema-tagged artifacts must be rejected and fail-closed behavior is protocol-level, not optional implementation detail: `spec/PROTOCOL.md:155-160`.
- `spec/schemas/registry.json` is the signed-artifact compatibility registry, every accepted signed artifact schema ID must be listed there, verifier builds expose the same IDs through `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, and unknown signed-artifact schemas are rejected at load time and signature verification time: `spec/PROTOCOL.md:321-325`.
- Current `KNOWN_SIGNED_ARTIFACT_SCHEMAS` only includes core capability, receipt, lineage, session, oracle, and runtime attestation schemas: `crates/chio-core-types/src/signed_artifact.rs:22-37`.
- Unknown signed-artifact schema validation fails closed: `crates/chio-core-types/src/signed_artifact.rs:54-63`.
- The built-in registry entries are explicitly mirrored by `spec/schemas/registry.json`: `crates/chio-core-types/src/signed_artifact.rs:65-105`.

Recommended plan edit: add a Phase 0 registry gate before any artifact implementation. For every proposed launch schema, classify it as one of:

- A signed artifact accepted by core verifiers, requiring `spec/schemas/registry.json`, `crates/chio-core-types/src/signed_artifact.rs`, and schema fixture updates.
- A control-plane JSON export that is not accepted by signed-artifact verifiers.
- An example-only bundle shape that cannot be advertised as protocol-supported.

The plan should not say a launch artifact is "verifiable", "canonical", or "signed" unless it names the registry row and verifier path.

### 2. The claim and proof registries do not yet support the launch claims

The spec registries are not optional documentation. They are the repo's claim discipline:

- Any change introducing a signed artifact, verifiable claim, or theorem must update the relevant registry before the claim is advertised as supported: `spec/registries/README.md:3-6`.
- A registry change is complete only when the new artifact or behavior is in `claim-registry.v1.json`, the proof manifest ties it to theorems or conformance tests, and theorem entries are proven or explicitly assumed with a deferral target: `spec/registries/README.md:23-26`.

The current claim registry is still focused on core capability, receipt, attenuation, handshake, budget split, HTTP egress, anchor continuity, and receipt identity claims. It does not yet define transaction-passport, commerce-order, swarm-continuation, public-settlement, disclosure-capsule, risk-comptroller, or agent-web claims. The proof manifest follows that current scope.

Recommended plan edit: add a "claim registry delta" section for each launch pillar. Each pillar needs:

- Claim ID.
- Artifact that carries the claim.
- Status: proposed or enforced.
- Proof source: formal theorem, Kani harness, conformance test, signed assertion, or example-only evidence.
- Negative control expected to fail.

Without this, the launch plan overstates what the repo can honestly verify.

### 3. The formal proof boundary is much narrower than the plans imply

The current proof-facing boundary is explicitly limited. The protocol says the implementation-linked verified-core contract is defined in `formal/proof-manifest.toml`, with external assumptions in `formal/assumptions.toml` and theorem coverage in `formal/theorem-inventory.json`: `spec/PROTOCOL.md:653-658`.

The Rust symbols inside the current proof boundary are:

- `chio_kernel_core::capability_verify::{verify_capability, verify_capability_with_trusted}`.
- `chio_kernel_core::scope::{resolve_matching_grants, resolve_capability_grants}`.
- `chio_kernel_core::evaluate::evaluate`.
- `chio_kernel_core::receipts::sign_receipt`.

Those are listed in `spec/PROTOCOL.md:660-665`. The only shell entrypoints allowed to claim direct use of the pure core today are `ChioKernel::evaluate_portable_verdict` and `ChioKernel::build_and_sign_receipt`: `spec/PROTOCOL.md:667-671`.

Most important: anything outside that manifest is outside the current proof boundary. Cryptography, clocks, storage, transport, subprocess behavior, hosted registries, clustering, and external settlement rails are assumption-bound unless they receive their own manifest entry and proof lane: `spec/PROTOCOL.md:673-676`.

Recommended plan edit: replace broad statements that Chio "proves" settlement, commerce, swarm routing, web3, or risk behavior with narrower language:

- Core authorization and receipt signing are inside the verified-core boundary.
- Settlement, external standards, runtime routing, chain behavior, and capital/risk workflows are evidence-backed or assumption-bound until new proof rows exist.
- Launch proof packages can aggregate signed evidence, but aggregation is not the same as formal proof of the external system.

### 4. Transaction passport should be a composed proof package, not a new crate by default

The launch plans propose a transaction-passport artifact family. There is no `chio-transaction` crate, and adding one first would duplicate existing proof-package infrastructure.

Existing substrate:

- `ChioProofPackage` already packages claims, peer ladder bindings, vendor key bindings, tool receipts, workflow receipt, bilateral envelopes, capability leases, lease scope bindings, governance receipts, workflow intersection, and selective disclosure proof: `crates/chio-attest-buyer-core/src/proof_package.rs:17-36`.
- Its verifier explicitly rejects unsupported claims such as hidden range predicates, VC Data Integrity BBS interop, and zkVM support: `crates/chio-attest-buyer-core/src/proof_package.rs:51-72`.
- The CLI already has `Evidence`, `Passport`, `Attest`, `Settle`, and `Lineage` command families, but no `Proof` command family: `crates/chio-cli/src/cli/types.rs:337-359`, `crates/chio-cli/src/cli/types.rs:391-449`.
- Current `Passport` is Agent Passport and verifier-policy/OID4VP related, not a transaction passport. The command text says "Create, verify, and present Agent Passport bundles": `crates/chio-cli/src/cli/types.rs:355-359`.

Recommended plan edit:

- Rename "transaction passport" in the implementation plan to "transaction proof package" unless the product intentionally wants to reuse the passport term.
- Use `chio-attest-buyer-core` as the schema/type home for the package if it is an attestation package.
- Use `chio-control-plane` for evidence export and verifier policy integration.
- Add CLI subcommands under `Attest`, `Evidence`, or a deliberately new `Proof` namespace only after deciding how it composes with the existing `Passport`, `Attest`, `Settle`, and `Lineage` commands.
- Do not create `chio-transaction` until there is a stable domain model that cannot live in attest/control-plane/lineage/settle.

### 5. Commerce artifacts fit existing market, credit, settlement, and examples

The plan's commerce context and event-log artifacts overlap strongly with existing examples and crates.

Existing evidence:

- The workspace already has economics and settlement crates: `chio-credit`, `chio-market`, `chio-open-market`, `chio-settle`, `chio-underwriting`, `chio-web3`, and `chio-web3-bindings`: `Cargo.toml:57-69`.
- The `agent-commerce-network` example already frames a governed procurement flow with a buyer API, provider MCP, trust control, budgets, receipts, capabilities, and financial reports: `examples/agent-commerce-network/README.md:1-16`, `examples/agent-commerce-network/README.md:39-45`.
- The `internet-of-agents-web3-network` example already covers market broker selection, provider policy over passport/reputation/budget/runtime/federation, two-hop capability flow, settlement routing, denials, x402-style payment, cross-rail settlement, runtime trust, and adversarial denials: `examples/internet-of-agents-web3-network/README.md:24-52`.
- That example's artifact contract already writes a broad bundle with agents, behavior, adversarial, approvals, capabilities, receipts, budgets, contracts, disputes, evidence, federation, financial, identity, lineage, market, operations, payments, settlement, web3, manifest, review result, and summary: `examples/internet-of-agents-web3-network/README.md:150-193`.

Recommended plan edit:

- Treat launch commerce as a hardened extraction from `examples/internet-of-agents-web3-network` and `examples/agent-commerce-network`, not as a new `chio-commerce` crate.
- First stabilize bundle schemas, validators, and negative controls in examples.
- Then decide whether the durable types belong in `chio-market`, `chio-open-market`, `chio-credit`, `chio-settle`, or `chio-control-plane`.
- Avoid a new commerce crate unless it has clear ownership distinct from market, credit, settlement, and control-plane exports.

### 6. Swarm and trust-network artifacts overlap with runtime, federation, treaty, pheromone, and reputation

The swarm plan uses new artifact names for task graphs, continuation proofs, quorum/election evidence, and routing. The repo already has related trust-network machinery.

Existing substrate:

- `chio-runtime-core` admission inputs include runtime trust input, pheromone query, pheromone policy, pheromone weights, action class, and runtime profile/store checks: `crates/chio-runtime-core/src/admission.rs:8-20`.
- Runtime admission fails closed on schema, profile, and bundle mismatches: `crates/chio-runtime-core/src/admission.rs:22-64`.
- Runtime trust floor transition rejects rollback, same-version mismatch, previous-hash mismatch, and missing previous hash: `crates/chio-runtime-core/src/admission.rs:363-399`.
- Cross-boundary treaty evidence requires verifier-owned admission bundles and treaty scope: `crates/chio-runtime-core/src/admission_hook/treaty_evidence.rs:15-34`.
- The treaty hook loads and verifies cross-kernel continuation, receipt lineage bundle, bilateral invocation, and bilateral DSSE artifacts: `crates/chio-runtime-core/src/admission_hook/treaty_evidence.rs:84-170`.
- Bilateral DSSE verification checks strict Chio predicate, allow policy summary, treaty binding refs, lease refs, and governance refs: `crates/chio-runtime-core/src/admission_hook/dsse.rs:7-93`.
- Federation authority already has schemas for authority profile, issuance request, issuance bundle, revocation publication request, peer pins, and local signing keys: `crates/chio-federation-authority/src/lib.rs:41-47`.

Recommended plan edit:

- Map any "swarm continuation" proposal to existing runtime treaty continuation and receipt-lineage concepts before inventing `chio.swarm.*`.
- Use `chio-runtime-core` and `chio-runtime` for admission/trust semantics.
- Use `chio-federation` and `chio-federation-authority` for authority and lease material.
- Use `chio-pheromone*` for routing signals if the swarm concept is route discovery or trust signal propagation.
- Use `chio-reputation` for historical scoring. Do not duplicate reputation inside a new swarm schema.

### 7. Disclosure capsule v2 is constrained by current BBS v1 projection support

The selective-disclosure plan is plausible, but it should not imply that arbitrary BBS v2 disclosure capsules already exist.

Existing substrate:

- Current projection constants are `chio.bbs-projection.receipt.v1`, `chio.bbs-projection.workflow.v1`, and `chio.bbs-projection.step.v1`: `crates/chio-selective-disclosure/src/lib.rs:26-33`.
- `SelectiveDisclosureProof` is typed and currently carries schema, projection version, subject hash, ciphersuite, issuer keys, message count, disclosed indices, disclosed messages, nonce, and proof bytes: `crates/chio-selective-disclosure/src/lib.rs:106-121`.
- Receipt projection explicitly requires the receipt v1 BBS projection version and rejects a different projection version: `crates/chio-selective-disclosure/src/lib.rs:190-200`.
- The supported projection-version gate only accepts receipt/workflow/step v1: `crates/chio-selective-disclosure/src/lib.rs:492-502`.
- The proof package verifier rejects VC Data Integrity BBS interop today: `crates/chio-attest-buyer-core/src/proof_package.rs:62-65`.

Recommended plan edit:

- Treat launch disclosure as v1 extension work unless the plan includes a migration design for v2 projection identifiers, verifier compatibility, and schema registry updates.
- Do not advertise VC Data Integrity BBS or generic BBS v2 interop as current capability.
- Add explicit compatibility tests showing old v1 receipts still verify and new projections fail closed on old verifiers.

### 8. Web3 settlement proof bundle should wrap existing web3 and settle artifacts

The plans talk about public settlement and web3 proof bundles. The repo already has canonical web3 settlement contract types.

Existing substrate:

- `chio-web3` owns official web3 settlement, anchoring, trust-profile, chain config, oracle evidence, and settlement lifecycle contracts. It is the source of truth for on-chain artifact shapes, with generated bindings in `chio-web3-bindings`, execution in `chio-settle`, and anchoring in `chio-anchor`: `crates/chio-web3/ARCHITECTURE.md:3-6`.
- `chio-settle` owns settlement preparation, runtime controls, retry envelopes, cross-chain delivery reconciliation, and receipt projection: `crates/chio-settle/ARCHITECTURE.md:3-17`.
- Existing settlement schema constants include `chio.web3-settlement-dispatch.v1` and `chio.web3-settlement-execution-receipt.v1`: `crates/chio-web3/src/settlement.rs:18-23`.
- Dispatch artifacts already include trust profile, contract package, chain ID, capital instruction, optional bond, settlement path and amount, escrow, contracts, beneficiary, and support boundary: `crates/chio-web3/src/settlement.rs:49-72`.
- Execution receipt artifacts already include dispatch, observed execution, lifecycle state, settlement reference, anchor proof, oracle evidence, settled amount, reversal and failure fields: `crates/chio-web3/src/settlement.rs:74-98`.
- Validators enforce schema ID, non-empty fields, real dispatch support, custody boundary, Merkle anchor-proof requirement, capital-instruction schema, non-cancel action, web3 rail kind, amount matching, unreconciled state before execution, active bond, anchor proof validation, oracle evidence validation, and terminal/reconciled lifecycle states: `crates/chio-web3/src/settlement.rs:100-184`, `crates/chio-web3/src/settlement.rs:186-285`.

Recommended plan edit:

- Define any "public settlement proof bundle" as an envelope over `SignedWeb3SettlementDispatch`, `SignedWeb3SettlementExecutionReceipt`, anchor inclusion proof, oracle conversion evidence, and receipt lineage.
- Do not create duplicate settlement schema IDs outside `chio-web3`.
- Do not claim chain finality, payment finality, or FX correctness beyond the existing support boundaries and validators.

### 9. Risk comptroller should be built on credit and underwriting support boundaries

The risk plan maps to existing `chio-credit`, `chio-underwriting`, and control-plane service types, but the current code deliberately marks some attractive launch claims unsupported.

Existing substrate:

- Credit loss lifecycle supports delinquency, recovery, reserve release, reserve slash, and writeoff events: `crates/chio-credit/src/risk_reports.rs:19-46`.
- Credit loss lifecycle summaries include bond state, facility/capability/agent/tool references, delinquent/recovered/written-off/released/slashed amounts, reserve control source, execution state, appeal state, and event amount: `crates/chio-credit/src/risk_reports.rs:84-124`.
- Default credit loss support boundary says immutable lifecycle and bond lifecycle projection are authoritative, external claim adjudication is unsupported, automatic capital execution is unsupported, reserve control execution is supported, and appeal window is supported: `crates/chio-credit/src/risk_reports.rs:135-155`.
- Credit provider risk packages include support boundary, exposure, scorecard, facility report, compliance score, latest facility, runtime assurance, certification, loss history, and evidence refs: `crates/chio-credit/src/risk_reports.rs:651-672`.
- Default provider risk support boundary marks signed exposure, signed scorecard, facility policy, compliance score references, and external capital review as supported, but autonomous pricing and liability market are false: `crates/chio-credit/src/risk_reports.rs:612-633`.
- Trust-control service types already include runtime attestation appraisal, behavioral feeds, exposure ledger, credit scorecard, capital book, facility, bond, bonded execution, loss lifecycle, backtest, provider risk package, liability quote/pricing/coverage/claims/payouts/settlements, and underwriting endpoints: `crates/chio-control-plane/src/trust_control/service_types.rs:135-205`, `crates/chio-control-plane/src/trust_control/service_types.rs:1191-1330`.

Recommended plan edit:

- Rename "risk comptroller" implementation to "risk package and control-plane policy integration" unless there is a specific new state machine.
- Keep autonomous pricing, liability-market claims, and automatic capital execution out of launch claims unless support boundaries are changed and tested.
- Reuse `CreditProviderRiskPackage` and control-plane endpoints before adding `chio-risk` or `chio-comptroller`.

### 10. Proof Room should not be positioned as greenfield

The launch plans describe a Proof Room product surface. The repo already has a substantial example evidence console and review-result bundle.

Existing substrate:

- The internet-of-agents web3 example includes a Next.js evidence console and Playwright E2E option: `examples/internet-of-agents-web3-network/README.md:94-114`.
- Its artifact contract already includes a broad evidence bundle and fail-closed `review-result.json` checks over Chio artifacts, unmediated default path, denials, budget, reconciliation, RFQ, lineage, approval, payment, rail, dispute, runtime, observability, adversarial controls, and Base Sepolia evidence: `examples/internet-of-agents-web3-network/README.md:150-193`.
- The example states it proves x402 use without treating x402 as settlement source of truth, Chio-mediated authority, sidecars/edges, provider market trust/budget/runtime/federation/reputation, two-hop lineage, signed approval, settlement fallback, and denial cases: `examples/internet-of-agents-web3-network/README.md:195-210`.

Recommended plan edit:

- Define Proof Room as a hardened reader over existing evidence bundles first.
- Add canonical fixture generation and verifier summary output before building a separate product crate.
- If a product crate is later needed, make it consume `chio-control-plane`, `chio-lineage`, `chio-attest-buyer-core`, `chio-settle`, and `chio-web3` outputs instead of owning proof semantics.

### 11. Lineage and evidence graph plans must preserve evidence classes

The launch plans use "evidence graph" language. The repo already has a normative evidence-class model and a typed lineage graph. The plan must not flatten asserted, observed, and verified facts into one proof layer.

Existing substrate:

- Protocol evidence classes are `asserted`, `observed`, and `verified`: `spec/PROTOCOL.md:540-548`.
- Current release emits session anchors and request-lineage records for local continuity, with stronger receipt-lineage statements and continuation tokens when present. Absence of stronger forms must not be treated as verified upstream truth: `spec/PROTOCOL.md:550-563`.
- Reports and exports must preserve the evidence-class boundary and cannot silently upgrade caller input into proof: `spec/PROTOCOL.md:569-575`.
- `chio-lineage` mirrors those evidence classes and defines the schema source of truth for the lineage graph: `crates/chio-lineage/src/schema.rs:1-17`, `crates/chio-lineage/src/schema.rs:20-34`.
- Current lineage node kinds are only prompt, capability, guard verdict, tool call, and receipt. Current edge kinds are prompt/capability/guard/tool/receipt/request lineage and receipt lineage parent: `crates/chio-lineage/src/schema.rs:36-60`.
- The top-level lineage graph schema is versioned and includes nodes, edges, and truncation: `crates/chio-lineage/src/schema.rs:119-151`.

Recommended plan edit:

- If launch evidence graph requires commerce, settlement, risk, or external-protocol nodes, add an explicit lineage schema migration.
- Preserve `asserted`, `observed`, and `verified` in every graph, report, and UI.
- Do not present imported order metadata, payment provider callbacks, or external chain observations as verified Chio proof unless they are tied to signed artifacts and verifier checks.

### 12. Receipt semantics restrict what can be called authorization

Launch copy and proof-room display rules need to respect receipt kinds.

Existing substrate:

- Receipt fields include `receipt_kind`, `boundary_class`, `observation_outcome`, `decision`, `trust_level`, BBS projection version, key, algorithm, and signature: `spec/PROTOCOL.md:680-708`.
- Only `mediated_decision` plus `prevent` plus `Allow` may be displayed or exported as authorization. Trace and advisory records can be evidence, but are never authorization receipts: `spec/PROTOCOL.md:816-827`.

Recommended plan edit:

- Add a display invariant to Proof Room and transaction proof packages: never label `trace_observation` or `advisory_evaluation` as authorization.
- Separate "evidence that something happened" from "authorization that Chio allowed it".
- Add negative fixtures where a trace or advisory record is present but no mediated allow exists.

## Artifact Fit Matrix

| Proposed artifact or surface | Best existing home | Why | Plan edit |
| --- | --- | --- | --- |
| Transaction passport | `chio-attest-buyer-core`, `chio-attest-loopback`, `chio-control-plane`, `chio-lineage`, `chio-cli` | Existing proof packages already aggregate receipts, workflow, leases, governance, bilateral DSSE, and disclosure proof. | Rename to transaction proof package unless product intentionally reuses passport; avoid `chio-transaction` first. |
| Evidence graph | `chio-lineage`, `chio-control-plane`, `chio-store-sqlite` | Existing lineage graph already owns evidence classes and node/edge schema. | Add schema migration only for genuinely new node/edge kinds. |
| Verifier policy/report | `chio-control-plane` passport verifier/evidence export plus CLI `Evidence`, `Attest`, `Lineage` | Existing CLI has verifier-related surfaces but no `Proof` namespace. | Decide command namespace after avoiding overlap with Agent Passport. |
| Commerce order context | `chio-market`, `chio-open-market`, `chio-credit`, `chio-settle`, examples | Existing commerce examples and economics crates already model provider selection, budgets, RFQ, settlement, and reports. | Harden examples and extract stable schemas into existing crates. |
| Commerce event log | `chio-metering`, `chio-siem`, `chio-lineage`, `chio-control-plane` | Events, lineage, and SIEM already have ownership. | Avoid a parallel event-log crate until ownership is clearer. |
| Swarm task graph | `chio-runtime-core`, `chio-runtime`, `chio-pheromone*`, `chio-reputation` | Admission, treaty continuation, routing signals, and reputation already exist. | Map to runtime/trust-network terms first. |
| Continuation proof | `chio-runtime-core` treaty evidence, `chio-lineage`, `chio-federation` | Existing hooks verify continuation, lineage, bilateral invocation, and DSSE. | Reuse `call_chain_continuation` and receipt-lineage semantics. |
| Disclosure capsule | `chio-selective-disclosure`, `chio-attest-buyer-core` | Current BBS support is v1 receipt/workflow/step projection only. | Do v1-compatible extension or explicitly design v2 migration. |
| Public settlement proof | `chio-web3`, `chio-settle`, `chio-anchor`, `chio-control-plane` | Web3 dispatch and execution receipt schemas already exist and are validated. | Wrap existing artifacts; do not duplicate settlement schemas. |
| Risk comptroller | `chio-credit`, `chio-underwriting`, `chio-control-plane` | Existing risk packages and support boundaries are already typed. | Keep unsupported autonomous claims out unless code changes support flags and tests. |
| Agent web envelope | `chio-mcp-*`, `chio-a2a-*`, `chio-acp-*`, `chio-ag-ui-proxy`, `chio-openapi*`, `chio-cross-protocol` | Existing external protocol edges own compatibility. | Use adapters/edges first; avoid a generic `chio-agent-web` crate without a narrow contract. |
| Proof Room | `examples/internet-of-agents-web3-network`, `chio-control-plane`, `chio-lineage`, `chio-attest-buyer-core` | Existing evidence console and bundle contract are already close. | Productize the existing evidence reader before creating a new proof semantics layer. |

## New Crates That Look Unnecessary Now

The following proposed or implied crates should not be first-pass implementation targets:

- `chio-transaction`: use attest/control-plane/lineage/settle first.
- `chio-commerce`: use market/open-market/credit/settle/examples first.
- `chio-swarm`: use runtime/federation/pheromone/reputation first.
- `chio-proof-room`: use example console/control-plane reader first.
- `chio-risk` or `chio-comptroller`: use credit/underwriting/control-plane first.
- `chio-agent-web`: use MCP/A2A/ACP/AG-UI/OpenAPI edges first.

Creating any of these crates is defensible only after a short design note proves:

- The proposed crate owns a durable boundary not already owned by an existing crate.
- The artifact schemas cannot be naturally registered from the existing crate.
- The CLI and examples become simpler, not more fragmented.
- The verification path is clearer, not merely renamed.

## Required Plan Edits By Launch File Family

### Roadmap

Add a Phase 0 hard gate:

- Register artifact schemas or classify them as non-signed exports.
- Update `KNOWN_SIGNED_ARTIFACT_SCHEMAS` only for schemas core verifiers must accept.
- Add claim-registry and proof-manifest rows before claim wording is used.
- Add fail-closed unknown-schema tests.
- Add receipt-kind display tests for authorization wording.

### Architecture

For each artifact family, add "existing home" and "new type needed" fields. Default new type home should be an existing crate. New crate should be exceptional.

Replace generic "proof" language with four categories:

- Formal proof inside the verified-core boundary.
- Signed Chio artifact verification.
- Evidence aggregation over signed and observed inputs.
- Example or demo evidence.

### Source Map

The source map says it is not a fresh full-code audit. That caveat should remain, but the launch plan should now add the concrete codebase alignments above. In particular, it should stop treating "no canonical transaction passport" as meaning "new crate required." The accurate statement is: no transaction-specific proof package exists yet, but the repo has proof-package, lineage, disclosure, settlement, runtime, and verifier infrastructure that should be composed first.

### Verification Gates

Add gates for:

- Unknown signed-artifact schema rejection.
- Claim registry and proof manifest rows for every advertised claim.
- Old verifier failure on new schema families.
- Receipt-kind display correctness.
- Evidence class preservation.
- Settlement support-boundary preservation.
- Risk support-boundary preservation.
- Agent Passport versus transaction proof package naming separation.

## Suggested Implementation Slicing

1. Schema classification and registry plan.
   - Input: all proposed launch artifact names.
   - Output: signed artifact, non-signed export, or example-only classification.
   - Gate: unknown signed schema rejects fail closed.

2. Transaction proof package as composition.
   - Extend or wrap `chio.attest.proof-package.v1` only if compatible.
   - Otherwise define `chio.attest.transaction-proof-package.v1` in the attest crate.
   - Include receipts, workflow receipt, lineage graph, settlement artifacts, risk package refs, disclosure proof, and verifier report.

3. Evidence graph migration.
   - Start from `chio-lineage`.
   - Add only the node/edge kinds required by real launch fixtures.
   - Preserve evidence classes.

4. Commerce and settlement fixture hardening.
   - Promote the existing internet-of-agents evidence bundle to canonical launch fixture.
   - Ensure settlement bundle wraps `chio-web3` dispatch and execution receipt artifacts.
   - Keep x402/payment evidence distinct from Chio settlement authority.

5. Risk package integration.
   - Use `CreditProviderRiskPackage` and support boundaries.
   - Add verifier report sections for unsupported autonomous claims.
   - Do not silently flip support flags.

6. Proof Room reader.
   - Read the canonical fixture bundle.
   - Show schema status, verifier status, evidence classes, receipt kinds, settlement support boundaries, and risk support boundaries.
   - Fail closed on missing mediated allow receipts for authorization claims.

## Bottom Line

The launch work should be an integration and verification pass over existing Chio foundations, not a greenfield crate expansion. The repo already has the hard parts that matter for codebase alignment: signed-artifact registry gates, claim/proof registries, proof-package types, lineage evidence classes, disclosure projection constraints, web3 settlement schemas, risk support boundaries, runtime/federation/treaty machinery, and a substantial evidence-console example. The plan should lean into those constraints. The strongest launch story is not "we invented six new artifact families." It is "we composed Chio's existing receipt, lineage, runtime, settlement, risk, and disclosure machinery into a verifier-checked transaction proof package with fail-closed schema and claim discipline."
