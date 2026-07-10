# Chio Economic Layer: Developer Guide

**Audience:** Developers integrating Chio's metering, budgets, credit,
settlement, anchoring, reputation, or passport subsystems.

**Scope:** How to wire up the economic primitives, what each one produces,
and which CLI commands move the workflow forward. This guide is the
pragmatic companion to `docs/protocols/ECONOMIC-LAYER-OVERVIEW.md`, which
describes the model-level design.

---

## 1. Overview

Chio's economic layer turns the kernel's signed audit trail into a full
accounting system. The same receipt that proves a tool call happened also
carries the cost attribution, budget context, and settlement reference that
billing, risk, and insurance subsystems need. Nothing in the layer is
self-reported: every artifact downstream of a receipt is either derived
deterministically from signed evidence or signed itself.

The layer exists to answer five developer-facing questions:

1. **What did this agent spend?** `chio-metering` + receipt cost metadata.
2. **Can I prove it happened?** `chio-anchor` + checkpoints + chain proofs.
3. **Did the money move?** `chio-settle` over EVM, Solana, or CCIP.
4. **Can I trust this agent across organizations?** `chio-reputation` +
   `chio-credentials` passports.
5. **What is this agent's current trust tier?** An evaluated passport against
   a verifier policy.

Each question maps to a small set of signed artifacts and a small set of CLI
subcommands under the unified `chio` binary. You do not need to understand
the full stack to use any one piece: metering works without settlement,
reputation works without passports, passports work without on-chain anchoring.

Source-of-truth locations:

- Design overview: `docs/protocols/ECONOMIC-LAYER-OVERVIEW.md`
- Kernel-level economic primitives: `docs/AGENT_ECONOMY.md`
- Passport workflow: `docs/AGENT_PASSPORT_GUIDE.md`
- Reputation scoring: `docs/AGENT_REPUTATION.md`
- Settlement runbook: `docs/release/CHIO_SETTLE_RUNBOOK.md`
- Settlement profile: `docs/standards/CHIO_SETTLE_PROFILE.md`

---

## 2. Primitives

| Primitive | Crate | Artifact |
|-----------|-------|----------|
| Capability token | `chio-core` | `CapabilityToken` with `ToolGrant.max_total_cost` |
| Receipt | `chio-core` | `ChioReceipt` with `FinancialReceiptMetadata` and `CostMetadata` |
| Checkpoint | `chio-kernel` | `KernelCheckpoint` (Merkle-committed batch) |
| Anchor | `chio-anchor` | `Web3ChainAnchorRecord`, `AnchorProofBundle` |
| Settlement call | `chio-settle` | `PreparedEvmCall`, `PreparedSolanaSettlement` |
| Reputation score | `chio-reputation` | `LocalReputationScorecard` |
| Reputation credential | `chio-credentials` | Signed Verifiable Credential |
| Agent passport | `chio-credentials` | `AgentPassport` bundle |
| Exposure / credit / bond | `chio-credit` | Signed credit artifacts |
| Underwriting decision | `chio-underwriting` | `UnderwritingDecisionArtifact` |
| Liability coverage | `chio-market` | `LiabilityBoundCoverageArtifact` |

All artifacts use canonical JSON (RFC 8785) for signing. Every economic
decision traces back to one or more receipts you can verify independently.

---

## 3. Receipt as Evidence

The receipt is the foundation. Everything else in the economic layer is a
projection, derivation, or anchor of receipts.

### 3.1 Shape

Every allowed tool call produces an `ChioReceipt` signed by the kernel. When
the call is cost-bearing, the receipt carries `FinancialReceiptMetadata`
(see `crates/core/chio-core`) plus a `CostMetadata` block from
`chio-metering` (`crates/economy/chio-metering/src/lib.rs`). The financial fields
include:

- `cost_charged` / `cost_currency` -- the amount the kernel committed
- `budget_remaining` -- post-call residual on the capability token
- `settlement_status` -- `not_applicable` / `pending` / `settled` / `failed`
- `payment_reference` -- external payment rail handle (when present)
- `delegation_depth` and `root_budget_holder` -- cost-responsibility chain

### 3.2 Lineage

Receipts carry delegation depth and parent-capability references. To
reconstruct the responsibility chain for any receipt:

1. Read `root_budget_holder` from the receipt's financial metadata.
2. Walk the capability-lineage records (available via
   `chio-store-sqlite::SqliteReceiptStore` or evidence-export) by
   `parent_capability_id` until depth zero.
3. The resulting chain is the authoritative attribution path.

### 3.3 Compliance value

Because each receipt is individually signed and canonically serialized, a
receipt database backed by the Chio SQLite store enforces append-only
semantics through `BEFORE UPDATE` / `BEFORE DELETE` triggers on the receipt
and checkpoint tables; equivalent guarantees on other backends depend on
the operator wiring equivalent immutability controls. A compliance
reviewer can:

- Replay every signature offline with the issuer's public key.
- Sum `cost_charged` by `(capability, tool_server, period)` to produce an
  invoice without trusting any backend service.
- Export a verifiable package (see `chio evidence export`) that a partner can
  independently re-verify.

Query receipts (local mode requires an explicit read boundary; pass
`--tenant <id>` to scope to one tenant or `--admin-all` for a documented
cross-tenant operator read):

```
chio receipt list --tenant <tenant-id> --capability <cap-id> --tool-server <server-id> \
  --since <unix-ts> --until <unix-ts> --min-cost <minor-units>
```

See `crates/products/chio-cli/src/cli/types.rs:1883` for the full filter list.

---

## 4. Anchoring

Anchoring takes the kernel's rolling Merkle tree over receipts and commits
it to external substrates so that tampering with the local log becomes
detectable even if the kernel operator is compromised.

### 4.1 What gets anchored

The kernel produces a `KernelCheckpoint` (`crates/kernel/chio-kernel/src/checkpoint.rs`)
at operator-configured intervals. Each checkpoint commits to a batch of
receipts by Merkle root plus a range `[batch_start_seq, batch_end_seq]`.
The checkpoint body is canonical JSON and signed by the kernel.

`chio-anchor` publishes that Merkle root to one or more chains. A published
root becomes a `Web3ChainAnchorRecord`. Multiple records over the same
checkpoint accumulate into an `AnchorProofBundle` that proves the receipt
was committed to every lane that matters to the relying party.

### 4.2 Substrates

| Lane | Module | Purpose |
|------|--------|---------|
| EVM root registry | `crates/economy/chio-anchor/src/evm.rs` | Direct publish of the Merkle root to a ChioRootRegistry contract (`prepare_root_publication`, `confirm_root_publication`). |
| Bitcoin via OTS | `crates/economy/chio-anchor/src/bitcoin.rs` | Super-root aggregation timestamped via OpenTimestamps (`prepare_ots_submission`, `verify_ots_proof_for_submission`). |
| Solana memo | `crates/economy/chio-anchor/src/solana.rs` | Canonical memo publication (`prepare_solana_memo_publication`, `verify_solana_anchor`). |
| Chainlink Functions | `crates/economy/chio-anchor/src/functions.rs` | Off-chain attestation verification path with fallback assessment. |

The `AnchorServiceConfig` struct (`crates/economy/chio-anchor/src/lib.rs:98`)
composes the target set; the runtime can enforce lane-availability policies
through `ops::ensure_anchor_operation_allowed`.

### 4.3 Verification

Given a receipt, a checkpoint, and an `AnchorProofBundle`:

```rust
use chio_anchor::{verify_proof_bundle, AnchorProofBundle};

let report = verify_proof_bundle(&bundle, &checkpoint)?;
// report.lane_outcomes: one entry per lane (EVM / Bitcoin / Solana)
// report.overall: fail-closed aggregate
```

`verify_proof_bundle` is fail-closed: a single invalid lane rejects the
bundle. Use `verify_proof_bundle_with_discovery` when you want to evaluate
freshness against a published discovery artifact
(`crates/economy/chio-anchor/src/discovery.rs`).

### 4.4 Recipe: anchor a batch

1. Let checkpoints accumulate in the kernel receipt store.
2. For each checkpoint you want to anchor, call
   `prepare_root_publication` for each configured EVM target; submit the
   call with your operator key; then `confirm_root_publication` once
   finality is reached.
3. For Bitcoin coverage, call `prepare_ots_submission` over the set of EVM
   anchor records; submit via your OTS client; record the resulting
   attestation.
4. Persist the anchor records and build an `AnchorProofBundle` per
   checkpoint that covers every required lane.
5. Publish the bundle alongside the checkpoint for verifiers.

The `automation` module provides typed `AnchorAutomationJob` records that
drive scheduled publication without custom orchestration code.

---

## 5. Settlement

`chio-settle` turns approved capital instructions into real contract calls
and projects the on-chain state back into the receipt family. The module
layout lives in `crates/economy/chio-settle/src/lib.rs`.

### 5.1 When to settle on-chain

Not every receipt needs on-chain settlement. Use it when:

- Parties do not share a trusted custodian (escrow removes the need).
- Collateral is at stake (bond lock / release / impair).
- Amounts exceed the `SettlementAmountTier` threshold configured in
  `SettlementPolicyConfig`.
- A regulator or auditor requires tamper-evident settlement proof.

For small, high-frequency flows between trusted parties, off-chain
settlement via the kernel's `PaymentAdapter` (x402, ACP-Commerce, direct API) is
more appropriate. `chio-settle` provides adapters for those too, but the
actual transfer happens off-chain.

### 5.2 EVM path

Primary entry points (`crates/economy/chio-settle/src/evm`):

- `prepare_web3_escrow_dispatch` + `finalize_escrow_dispatch`
- `prepare_bond_lock` / `prepare_bond_release` / `prepare_bond_impair` /
  `prepare_bond_expiry`
- `prepare_dual_sign_release` -- operator + counterparty sign-off
- `prepare_merkle_release` -- batch settlement via Merkle proof
- `prepare_erc20_approval` + `scale_chio_amount_to_token_minor_units`
- `static_validate_call` (runs before every submission)
- `submit_call` + `confirm_transaction`

Each `prepare_*` function returns a `PreparedEvmCall` with gas estimation
and static validation completed. The workflow is always: prepare, validate,
submit, confirm, project.

### 5.3 Solana path

Ed25519-native surface (`crates/economy/chio-settle/src/solana.rs`):

- `prepare_solana_settlement` -- builds a settlement transaction using the
  Ed25519 program for signature verification.
- `verify_solana_binding_and_receipt` -- checks that a given Solana
  settlement matches the Chio receipt it claims to settle.
- `compare_commitments` -- produces a `CommitmentConsistencyReport`
  comparing Chio-side and Solana-side commitment state.

### 5.4 Cross-chain and HTTP rails

- CCIP cross-chain messaging: `crates/economy/chio-settle/src/ccip.rs`
  (`prepare_ccip_settlement_message`, `reconcile_ccip_delivery`).
- x402 HTTP 402 requirements: `build_x402_payment_requirements` in
  `crates/economy/chio-settle/src/payments.rs`.
- EIP-3009 meta-transactions: `prepare_transfer_with_authorization`.
- Circle nanopayments: `evaluate_circle_nanopayment`.
- ERC-4337 paymaster compatibility: `prepare_paymaster_compatibility`.

### 5.5 Settlement receipts

After confirmation, project the on-chain result back into the receipt
family:

```rust
use chio_settle::{inspect_finality_for_receipt, project_escrow_execution_receipt};

let finality = inspect_finality_for_receipt(&tx, &receipt_binding)?;
let exec_receipt = project_escrow_execution_receipt(&projection_input)?;
```

The projected execution receipt is a signed artifact that:

- References the originating capability and tool-call receipt.
- Carries the on-chain transaction hash and block reference.
- Gets stored alongside the original receipt so downstream consumers see a
  complete `receipt -> settlement -> finality` chain.

The `automation` module (`build_settlement_watchdog_job`,
`build_bond_watchdog_job`) schedules recurring checks for expiry,
state drift, and recovery opportunities.

### 5.6 Recipe: query settlement status

1. Pull the receipt(s) you care about with `chio receipt list`.
2. Read `financial.settlement_status` and `financial.payment_reference`.
3. For `pending` settlements backed by on-chain rails, call
   `inspect_finality_for_receipt` with the transaction reference.
4. For recovery classification (replaceable, superseded, reverted),
   call `classify_settlement_lane` + `SettlementRecoveryAction`.
5. The `ops::SettlementRuntimeReport` (schema in
   `docs/standards/CHIO_SETTLE_RUNTIME_REPORT_EXAMPLE.json`) is the
   operator-facing aggregate of every lane's current state.

Emergency controls (`SettlementEmergencyControls`,
`SettlementEmergencyMode`) allow a kill switch or circuit breaker to block
new settlements while existing ones drain.

---

## 6. Reputation

Reputation converts a receipt corpus into a portable signal of how an agent
has behaved. `chio-reputation` is intentionally pure and storage-agnostic
(`crates/trust/chio-reputation/src/lib.rs:1`): scoring never touches the network
and never mutates anything.

### 6.1 Local scoring

`compute_local_scorecard` (`crates/trust/chio-reputation/src/score.rs:3`) takes a
`LocalReputationCorpus` -- receipts, capability-lineage records, and
budget-usage rows -- and produces a `LocalReputationScorecard` with eight
weighted dimensions:

- Boundary pressure (deny ratio)
- Resource stewardship (budget fit)
- Least privilege (scope narrowness)
- History depth (corpus maturity)
- Specialization (tool focus)
- Delegation hygiene (child-grant discipline)
- Reliability (success ratio)
- Incident correlation (external signal coupling)

The output includes per-dimension scores, an effective overall score, and
explicit evidence references so a reviewer can trace every number back to
specific receipts.

### 6.2 Local vs. federated

"Local" means scored against your own receipt store. Federated scoring
relies on the passport workflow (next section): the subject's home
authority signs a reputation credential over their local corpus, and a
remote verifier evaluates the signed credential instead of re-running
scoring against raw receipts. This keeps raw behavior private while still
producing a verifiable trust signal.

### 6.3 Recipe: compute a reputation score

```
chio reputation local \
  --subject-public-key <hex> \
  --since <unix-ts> --until <unix-ts> \
  --policy <optional-policy-yaml>
```

See `crates/products/chio-cli/src/cli/types.rs:2727`. To compare live state against a
portable passport:

```
chio reputation compare \
  --subject-public-key <hex> \
  --passport passport.json \
  --verifier-policy policy.json
```

The compare path returns per-dimension deltas plus a drift summary. Use it
to detect staleness or federation-boundary discrepancies.

---

## 7. Passport

The agent passport is how an agent proves standing to a party outside its
home authority. It is a bundle of signed Verifiable Credentials keyed to
the subject's DID (see `crates/trust/chio-did/` for did:chio), synthesized from
local evidence (receipts, reputation, certifications, runtime assurance).

### 7.1 Bundle contents

An `AgentPassport` (`crates/trust/chio-credentials/src/...`) typically contains:

- A reputation credential over the subject's local scorecard.
- Attestation windows describing the covered evidence period.
- Optional enterprise-identity provenance.
- Optional lifecycle reference (`PassportLifecycleState`) for revocation
  checking.
- Zero or more additional credentials (certifications, runtime assurance).

Passports are selectively disclosable: `chio passport present` filters the
bundle down to what the relying party asked for without invalidating
signatures on the remaining credentials.

### 7.2 Evaluation vs. verification

- **Verify** (`chio passport verify`) -- signature checks on every embedded
  credential. No relying-party policy required.
- **Evaluate** (`chio passport evaluate --policy <file>`) -- applies a
  `PassportVerifierPolicy` (allow-lists, minimum scores, maximum age,
  required issuers) and produces a pass/fail resolution.

### 7.3 Trust-tier synthesis

Evaluation returns a `PassportLifecycleResolution` plus a derived trust
tier. The tier combines:

- Reputation score band
- Runtime assurance tier (from runtime-attestation credential if present)
- Certification state (from certification credential if present)
- Lifecycle state (active / revoked / suspended)

Relying parties translate the tier into their own admission decision; Chio
itself does not force a policy.

### 7.4 Challenge-bound presentations

For replay-safe flows, use the challenge protocol:

1. Verifier creates a challenge with `chio passport challenge create`.
2. Holder responds with `chio passport challenge respond`
   (`--holder-seed-file` signs the response with the subject key).
3. Holder submits to the verifier transport via `chio passport challenge submit`.
4. Verifier confirms with `chio passport challenge verify`, resolving the
   challenge from a local SQLite database or a trust-control service.

OID4VCI issuance and OID4VP request flows are wired under
`chio passport issuance ...` and `chio passport oid4vp ...` respectively.

### 7.5 Recipe: issue and present a passport

```
# Create a passport from local receipts and lineage
chio passport create \
  --subject-public-key <hex> \
  --output passport.json \
  --signing-seed-file ./authority.seed \
  --validity-days 30 \
  --since <unix-ts> --until <unix-ts>

# Verify signatures on every embedded credential
chio passport verify --input passport.json

# Evaluate against a relying-party policy
chio passport evaluate --input passport.json --policy verifier-policy.yaml

# Present a filtered bundle to a specific verifier
chio passport present \
  --input passport.json \
  --output presented.json \
  --issuer did:chio:... \
  --max-credentials 2
```

See `crates/products/chio-cli/src/cli/types.rs:2222` for the full option surface.

---

## 8. Credit, Insurance, and Marketplace Integration

The artifacts in this section live above the primitives above. You do not
need them for basic metering or settlement, but they are what binds the
economic layer into a marketplace.

### 8.1 Exposure and scorecard

`chio trust exposure-ledger ...` produces a `ExposureLedgerReport` (per-
currency settlement position). `chio trust credit-scorecard ...` produces a
`CreditScorecardReport` over the exposure ledger plus reputation
inspection. Both are signed and can be fed to underwriting or insurance
workflows.

### 8.2 Underwriting

Pipeline is: `chio trust underwriting-input` builds a signed
`UnderwritingPolicyInput`; `chio trust underwriting-decision` runs the pure
`evaluate_underwriting_policy_input` and emits an
`UnderwritingDecisionArtifact` with risk class, budget recommendation, and
premium quote. Appeals go through `chio trust underwriting-appeal`.

### 8.3 Facilities and bonds

`chio trust facility ...` issues bounded credit facilities; `chio trust bond
...` manages reserve locks; `chio trust loss ...` captures delinquency,
recovery, reserve-release, reserve-slash, and write-off events with strict
accounting invariants (see section 1.3 of the economic overview).

### 8.4 Capital execution

`chio trust capital-instruction ...` produces custody-neutral instructions;
`chio trust capital-allocation ...` emits simulation-first allocation
decisions; `chio trust capital-book ...` exports the live capital book
tying facilities, bonds, and losses to one source-of-funds view.

### 8.5 Liability marketplace

`chio trust liability-provider ...` manages provider registry entries;
`chio trust liability-market ...` drives quote, placement, and bound-
coverage workflows. The provider-risk package exported via
`chio trust provider-risk-package ...` is the signed evidence bundle sent
to underwriters.

---

## 9. Developer Recipes

### 9.1 Track every tool call cost

1. Configure the budget store (`--budget-db`) and receipt store
   (`--receipt-db`) when launching the kernel.
2. Issue capabilities with `ToolGrant.max_total_cost` set.
3. Ensure tool servers report cost per invocation (see
   `docs/TOOL_PRICING_GUIDE.md`).
4. Query cumulative cost (local mode requires `--tenant <id>` or
   `--admin-all`):

```
chio receipt list --tenant <tenant-id> --capability <cap-id> --min-cost 0
```

Pipe the JSON-Lines output into any analytics pipeline.

### 9.2 Export a billing record

Use `BillingExport` from `chio-metering` inside a Rust program, or drive it
via an evidence export:

```
chio evidence export \
  --output ./billing-2026-04 \
  --since <month-start> --until <month-end> \
  --capability <cap-id>
```

The exported directory is signature-checkable end-to-end with `chio evidence
verify --input ./billing-2026-04`.

### 9.3 Anchor a batch

See section 4.4 above. The short version:

```
# 1. Let the kernel produce a checkpoint covering the batch you care about.
# 2. Publish the Merkle root to EVM:
#    (programmatic; no dedicated CLI subcommand yet)
cargo run -p chio-anchor --example publish_root -- \
  --checkpoint checkpoint.json --target evm-target.json
# 3. Attach a Bitcoin OTS anchor:
cargo run -p chio-anchor --example attach_bitcoin_anchor -- \
  --records evm-records.json --ots-proof proof.ots
# 4. Verify the resulting bundle:
cargo run -p chio-anchor --example verify_bundle -- \
  --bundle bundle.json --checkpoint checkpoint.json
```

The public API is stable; the CLI surface is currently
programmatic-first. Direct access is via `chio_anchor::prepare_root_publication`
and friends in any Rust or SDK caller.

### 9.4 Query settlement status

See section 5.6.

### 9.5 Compute and share a reputation score

```
# Local score
chio reputation local --subject-public-key <hex>

# Signed reputation credential embedded in a passport
chio passport create \
  --subject-public-key <hex> \
  --output passport.json \
  --signing-seed-file authority.seed

# Share passport; verifier evaluates:
chio passport evaluate --input passport.json --policy policy.yaml
```

### 9.6 Issue federated delegation after a portable presentation

```
# Verifier side: issue one local capability after validating a presentation
chio trust federated-issue \
  --presentation-response response.json \
  --challenge challenge.json \
  --capability-policy policy.yaml \
  --delegation-policy signed-delegation-policy.json
```

See `crates/products/chio-cli/src/cli/types.rs:667` for the full option set.

---

## 10. CLI Reference

The economic layer surfaces through the `chio` CLI binary and programmatic
access via the Rust crates for code paths that are not yet wrapped.

### 10.1 `chio` core economic subcommands

| Subcommand | Purpose | Source |
|-----------|---------|--------|
| `chio receipt list` | Filter and page receipts, including by cost range. | `crates/products/chio-cli/src/cli/types.rs:1883` |
| `chio evidence export` | Create a verifiable offline evidence package. | `crates/products/chio-cli/src/cli/types.rs:1920` |
| `chio evidence verify` | Verify an exported evidence package. | `crates/products/chio-cli/src/cli/types.rs:1948` |
| `chio evidence import` | Import a bilateral package for later federation. | `crates/products/chio-cli/src/cli/types.rs:1954` |
| `chio evidence federation-policy create` | Sign a bilateral receipt-sharing policy. | `crates/products/chio-cli/src/cli/types.rs:1967` |
| `chio certify check` / `verify` / `registry ...` | Conformance certifications feeding trust tiers. | `crates/products/chio-cli/src/cli/types.rs:2007` |
| `chio passport create / verify / evaluate / present` | Passport bundle lifecycle. | `crates/products/chio-cli/src/cli/types.rs:2222` |
| `chio passport policy ...` | Signed verifier-policy artifacts. | `crates/products/chio-cli/src/cli/types.rs:2300` |
| `chio passport challenge create / respond / submit / verify` | Challenge-bound presentations. | `crates/products/chio-cli/src/cli/types.rs:2331` |
| `chio passport status ...` | Publish, resolve, and revoke lifecycle state. | `crates/products/chio-cli/src/cli/types.rs:2312` |
| `chio passport issuance ...` | OID4VCI-style pre-authorized issuance flows. | `crates/products/chio-cli/src/cli/types.rs:2318` |
| `chio passport oid4vp ...` | OID4VP request and verification flow. | `crates/products/chio-cli/src/cli/types.rs:2324` |
| `chio reputation local` | Compute a local scorecard. | `crates/products/chio-cli/src/cli/types.rs:2727` |
| `chio reputation compare` | Compare local corpus against a passport. | `crates/products/chio-cli/src/cli/types.rs:2744` |
| `chio cert generate / verify / inspect` | ACP-Client session compliance certificates. | `crates/products/chio-cli/src/cli/types.rs:2767` |

### 10.2 `chio trust` economic export subcommands

| Subcommand | Produces | Source |
|-----------|----------|--------|
| `chio trust behavioral-feed ...` | Signed insurer-facing behavioral feed. | `crates/products/chio-cli/src/cli/types.rs:962` |
| `chio trust exposure-ledger ...` | Signed `ExposureLedgerReport`. | `crates/products/chio-cli/src/cli/types.rs:990` |
| `chio trust credit-scorecard ...` | Signed `CreditScorecardReport`. | `crates/products/chio-cli/src/cli/types.rs:1021` |
| `chio trust capital-book ...` | Signed live capital book. | `crates/products/chio-cli/src/cli/types.rs:1052` |
| `chio trust capital-instruction ...` | Custody-neutral instruction artifact. | `crates/products/chio-cli/src/cli/types.rs:588` |
| `chio trust capital-allocation ...` | Simulation-first allocation decision. | `crates/products/chio-cli/src/cli/types.rs:594` |
| `chio trust facility ...` | Credit facility artifacts. | `crates/products/chio-cli/src/cli/types.rs:600` |
| `chio trust bond ...` | Credit bond artifacts. | `crates/products/chio-cli/src/cli/types.rs:606` |
| `chio trust loss ...` | Loss-lifecycle artifacts. | `crates/products/chio-cli/src/cli/types.rs:612` |
| `chio trust credit-backtest ...` | Deterministic backtests over evidence. | `crates/products/chio-cli/src/cli/types.rs:618` |
| `chio trust provider-risk-package ...` | Signed insurer-facing risk bundle. | `crates/products/chio-cli/src/cli/types.rs:624` |
| `chio trust liability-provider ...` | Provider registry lifecycle. | `crates/products/chio-cli/src/cli/types.rs:630` |
| `chio trust liability-market ...` | Quote / placement / bound-coverage flow. | `crates/products/chio-cli/src/cli/types.rs:636` |
| `chio trust underwriting-input ...` | Signed `UnderwritingPolicyInput`. | `crates/products/chio-cli/src/cli/types.rs:642` |
| `chio trust underwriting-decision ...` | Evaluated `UnderwritingDecisionArtifact`. | `crates/products/chio-cli/src/cli/types.rs:648` |
| `chio trust underwriting-appeal ...` | Appeal lifecycle. | `crates/products/chio-cli/src/cli/types.rs:654` |
| `chio trust appraisal ...` | Signed runtime-attestation appraisal report. | `crates/products/chio-cli/src/cli/types.rs:558` |
| `chio trust authorization-context ...` | Derived external authorization context. | `crates/products/chio-cli/src/cli/types.rs:552` |
| `chio trust evidence-share ...` | Shared evidence references. | `crates/products/chio-cli/src/cli/types.rs:546` |
| `chio trust provider ...` | Enterprise federation provider records. | `crates/products/chio-cli/src/cli/types.rs:534` |
| `chio trust federation-policy ...` | Permissionless admission policies. | `crates/products/chio-cli/src/cli/types.rs:540` |
| `chio trust revoke` / `status` | Capability revocation lifecycle. | `crates/products/chio-cli/src/cli/types.rs:660` |
| `chio trust federated-issue` | Issue after verifying portable presentation. | `crates/products/chio-cli/src/cli/types.rs:667` |
| `chio trust federated-delegation-policy-create` | Signed federated delegation policy. | `crates/products/chio-cli/src/cli/types.rs:694` |
| `chio trust serve` | Shared trust-control HTTP service. | `crates/products/chio-cli/src/cli/types.rs:467` |

### 10.3 Anchor and settle surfaces

Anchoring and settlement currently expose programmatic APIs rather than
first-class `chio` subcommands. The relevant entry points:

- `chio-anchor::prepare_root_publication` (EVM) -- `crates/economy/chio-anchor/src/evm.rs`
- `chio-anchor::prepare_ots_submission` (Bitcoin) -- `crates/economy/chio-anchor/src/bitcoin.rs`
- `chio-anchor::prepare_solana_memo_publication` -- `crates/economy/chio-anchor/src/solana.rs`
- `chio-anchor::verify_proof_bundle` -- `crates/economy/chio-anchor/src/bundle.rs`
- `chio-settle::prepare_web3_escrow_dispatch` and bond functions --
  `crates/economy/chio-settle/src/evm`
- `chio-settle::prepare_solana_settlement` -- `crates/economy/chio-settle/src/solana.rs`
- `chio-settle::prepare_ccip_settlement_message` -- `crates/economy/chio-settle/src/ccip.rs`
- `chio-settle::build_x402_payment_requirements` -- `crates/economy/chio-settle/src/payments.rs`

The settlement runtime report schema is published at
`docs/standards/CHIO_SETTLE_RUNTIME_REPORT_EXAMPLE.json`; the settle profile
is at `docs/standards/CHIO_SETTLE_PROFILE.md`.

---

## 11. Further Reading

- `docs/protocols/ECONOMIC-LAYER-OVERVIEW.md` -- model and stack composition.
- `docs/AGENT_ECONOMY.md` -- kernel-level economic extensions.
- `docs/AGENT_PASSPORT_GUIDE.md` -- passport design and verifier integration.
- `docs/AGENT_REPUTATION.md` -- reputation scoring details.
- `docs/TOOL_PRICING_GUIDE.md` -- how tool servers report cost.
- `docs/MONETARY_BUDGETS_GUIDE.md` -- denominated budget policies.
- `docs/ECONOMIC_INTEROP_GUIDE.md` -- interoperability with external systems.
- `docs/release/CHIO_SETTLE_RUNBOOK.md` -- operator runbook for settlement.

When this guide and any referenced source disagree, the source is
authoritative; file an issue so the guide can be updated.
