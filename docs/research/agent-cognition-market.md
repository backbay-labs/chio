# Agent-to-Agent Cognition Market on Chio: Design-Research Memo

- Status: research spike (not a roadmap commitment)
- Date: 2026-07-20
- Branch: `research/cognition-market` (companion ADR: `docs/adr/ADR-0017-cognition-market-finding-artifacts.md`, spec-shaped test: `crates/economy/chio-open-market/tests/cognition_market_flow.rs`)
- Question answered: can Chio's existing primitives support a market where autonomous agents trade solved cognition (especially negative results), and what exactly is the gap between "supported today", "small extension", and "open research"?
- Evidence discipline: every codebase claim cites a real path as of this branch (forked from `feat/roadmap-execution` at `55ec2c4c41`). Anything not backed by code or a cited doc is marked `[speculative]`. Confidence is stated per section.

---

## 1. Executive summary

Chio already implements five of the six primitives a cognition market needs, in production-shaped code: trusted-path metering and budgets, bonded participation with adjudicated slashing, escrow with predeclared non-discretionary terminal states, signed execution receipts with Merkle checkpointing and multi-chain anchoring, and a listing/bid/accept marketplace whose buyers are already autonomous agents identified by public keys. What is missing is narrow and specific:

1. **There is no information-good type.** The only tradeable good today is a scoped tool-invocation right (`CapabilityToken` / `ToolGrant`, `crates/core/chio-core-types/src/capability/scope.rs:63`), plus liability coverage. No commit-reveal, no data-goods, no content-addressed goods trading exists anywhere in the workspace (confirmed by repo-wide search; see 5.Q1, 5.Q3).
2. **The reveal-vs-payment binding is one wiring step away, not a new subsystem.** The kernel already binds a payload digest (`content_hash`) into every signed receipt, already supports prepaid/hold-capture settlement with refund-on-abort, and the on-chain escrow already releases against Merkle-proven receipt evidence (`contracts/src/ChioEscrow.sol` via `releaseWithProofDetailed`, per ADR-0015). Modeling "reveal the finding" as a governed tool call makes delivery-versus-payment fall out of existing machinery.
3. **Proof-without-disclosure is real but narrow.** Chio can today prove, without revealing content: that a mediated computation ran, what it cost, the digest of what it produced, what runtime tier executed it, and selectively disclosed fields of the signed receipt (BBS projections, `crates/trust/chio-selective-disclosure/src/lib.rs:248`). The hidden-predicate vocabulary is a registry containing exactly one predicate (`amount_lte_100`, `crates/trust/chio-disclosure-lineage/src/verifier.rs:55`). Rich ZK predicates over experimental data are open research and this memo does not pretend otherwise.
4. **Pricing a negative result is an open research problem; eliciting a bounded bid is not.** Chio's metering gives the buyer the one counterfactual it can actually estimate: the metered cost of re-deriving the result itself (`metered_billing.quote`, `spec/PROTOCOL.md:514`). The proposed elicitation interface caps bids by that estimate; it does not claim to compute true value.
5. **Swarm-scale clearing should be hierarchical, and the hierarchy already exists.** The current market path is strictly one bid against one listing, synchronously (`crates/economy/chio-open-market/src/bidding.rs:308`). The swarm-authority layer already does budget fan-out/fan-in with signed depth and fan-out ceilings (`crates/kernel/chio-swarm-authority/src/types.rs:44,247`), which is the right decomposition substrate for per-pool purchasing agents. Flat auctions are neither present nor proposed.

**Recommendation (section 8): pursue the coding-agent instance first.** A "verified fix" is a finding whose claim predicate ("these tests pass at this commit") is checkable by deterministic re-execution inside the machinery Chio already meters and attests. The R&D negative-result instance shares every interface but pushes the two genuinely open problems (verifying nulls, pricing dead ends) to their hardest form; it should be the second instantiation, not the first.

Filter note, held throughout: the market described here is agent-principal on the buy side today (bidders are agent subjects, `bidding.rs:101`) and operator-principal on the sell side (listings are operator-signed, `crates/economy/chio-listing/src/discovery.rs:48`). Making sellers agent-principals is a policy change (who may sign a listing and post a bond), not a type change; the place where human institutions genuinely persist is adjudication (roster-anchored, ADR-0015 follow-up B), and section 6.3 treats that honestly rather than assuming it away.

---

## 2. Method and evidence base

- Read: `AGENTS.md`, `README.md`, `docs/README.md`, `docs/start-here/VISION.md`, `spec/PROTOCOL.md` (sections 5.2-5.5, 6.1-6.5, 14), `docs/guides/ECONOMIC-LAYER.md`, `docs/adr/README.md`, `docs/adr/ADR-0015-predeclared-escrow-circuit-breakers.md`, `docs/formal/CURRENT_STATE.md`, `docs/reference/CLAIM_REGISTRY.md` (head), `docs/reference/AGENT_ECONOMY.md` (structure).
- Direct source reads: `chio-disclosure-lineage` (full types + verifier core), `chio-selective-disclosure` (projection surface), `chio-swarm-authority/src/types.rs`, `chio-open-market/src/bidding.rs`, `chio-listing` and `chio-open-market` module docs, `chio-attest-buyer{,-core}` module docs, `contracts/src/` listing, spot-checks of every line-level claim relied on below (`chio-kernel/src/kernel/validation.rs:990`, `chio-open-market/src/evaluation.rs:356`, `chio-kernel/src/memory_provenance.rs:63`, `chio-revocation-oracle/src/api.rs:116`).
- Six scoped sub-explorations (settlement, bonding, metering/budgets, verification/attestation, memory/provenance, market/pricing) with verbatim-signature reporting; their load-bearing citations were independently spot-checked before inclusion.
- Known correction made during research: the crate map in `AGENTS.md` omits several economy/trust crates that turned out to be load-bearing for this question (`chio-listing`, `chio-open-market`, `chio-autonomy`, `chio-selective-disclosure`, `chio-attest-buyer{,-core}`, `chio-revocation-oracle`, `chio-trust-market-context`). The Solidity value-movement contracts are in-repo at `contracts/src/` (deployment is external).

Confidence legend used below: **high** (read the code or two independent confirmations), **moderate** (one careful read, not exercised), **low** (inferred from docs), **unknown**.

---

## 3. Primitive -> module map

The brief's six-primitive taxonomy maps onto the code as follows. Where the code disagrees with the taxonomy, the code wins and the row says so.

| # | Brief primitive | What Chio actually has | Where (representative paths) | Fit |
|---|---|---|---|---|
| 1 | Formal verification | Provable bounds on the action space: Lean-mechanized P1-P10 (83 theorems: attenuation, revocation cut, fail-closed evaluation, receipt sign/verify + immutability, Merkle-log membership) linked to a pure Rust core via Aeneas extraction, plus Creusot/Kani lanes and model-checked Apalache/TLC invariants (receipt-before-allow, revocation-cut completeness, cancel atomicity, delegation depth). Execution attestation is separate: signed receipts + checkpoints + anchors, real TEE quote verification (TDX / SEV-SNP / Nitro), and TEE-tier appraisal. Naming trap: the `chio-tee` crate is a replay-capture sidecar, not enclave code; quote crypto lives in `chio-attest-verify` (feature `tee-quotes`) | `formal/` (see `docs/formal/CURRENT_STATE.md`, `formal/theorem-inventory.json`, `formal/apalache/`), `spec/PROTOCOL.md:598-681`, `crates/kernel/chio-kernel-core/src/formal_aeneas.rs`, `crates/core/chio-core-types/src/receipt/body.rs:34`, `crates/trust/chio-attest-verify/src/quote.rs:162`, `crates/economy/chio-appraisal/src/appraisal.rs:711`, `crates/trust/chio-tee/src/lib.rs:1` | Strong on action-space bounds; execution attestation is assumption-bounded (kernel-observed, not world-observed) |
| 2 | Programmable economic sovereignty | Budget envelopes the agent cannot exceed, enforced in the trusted kernel path pre-dispatch: grant-level caps, atomic hold ledger with exposed/realized split, sibling-sum delegation splits, swarm budget pools with signed ceilings | `crates/core/chio-core-types/src/capability/scope.rs:63-81`, `crates/kernel/chio-kernel/src/budget_store.rs:347`, `crates/kernel/chio-kernel/src/kernel/validation.rs:990`, `crates/kernel/chio-kernel-core/src/budget_split.rs:84`, `crates/kernel/chio-swarm-authority/src/types.rs:247` | Direct match |
| 3 | Metering | Consumption accounting in currency minor units + invocation counts (kernel-authoritative) and richer advisory dimensions (compute-ms, bytes, tokens); quotes before execution; cost stamped into signed receipts. No accounting of value produced anywhere (consumption only) | `crates/economy/chio-metering/src/cost.rs:16,69`, `crates/kernel/chio-kernel/src/budget_store.rs:16`, `crates/core/chio-core-types/src/receipt/economics.rs:33`, `spec/PROTOCOL.md:514` (quote block) | Direct match; "produced value" is deliberately absent, consistent with elicit-not-measure |
| 4 | Memory governance | Governed memory writes with hash-chained provenance tied to capability + receipt; opt-in ingestion guards (store allowlists, deny patterns, embedding anomaly, prompt injection); execution-lineage DAG queryable in reverse; sparse-Merkle revocation oracle with epoch roots and non-inclusion proofs. No data tombstones, no automatic retraction propagation | `crates/kernel/chio-kernel/src/memory_provenance.rs:63`, `crates/guards/chio-guards/src/memory_governance.rs:108`, `crates/guards/chio-data-guards/src/vector_guard.rs:317`, `crates/observability/chio-lineage/src/query.rs:56`, `crates/trust/chio-revocation-oracle/src/api.rs:116` | Partial: provenance-in and blast-radius exist; retraction-out does not |
| 5 | Bonding | Posted, slashable bonds with adjudicated forfeiture: marketplace bond classes with `slashable` flags, penalty state machine gated on an enforced governance Sanction case, on-chain bond vault impairment with exact-sum beneficiary distribution, appeal/reverse path, anti-discretion posture fixed by ADR | `crates/economy/chio-open-market/src/fee_schedule.rs:56`, `src/penalty.rs:21-53`, `src/evaluation.rs:356-451`, `crates/economy/chio-credit/src/lib.rs:722,753`, `crates/economy/chio-settle/src/evm/prepare.rs:989-1020,1325`, `contracts/src/ChioBondVault.sol`, `crates/trust/chio-governance/src/generic.rs:17`, `docs/adr/ADR-0015-predeclared-escrow-circuit-breakers.md` | Direct match |
| 6 | Settlement / clearing | Single-leg escrow (lock / partial release / release / refund) with receipt-Merkle-gated and dual-signature release and deadline refund; kernel two-phase holds (`MustPrepay` / `HoldCapture` / `AllowThenSettle`) with refund-on-abort; payment adapters (x402, ACP, EIP-3009, CCIP, Solana); checkpoint anchoring. No atomic two-good swap, no order book, no price discovery | `contracts/src/ChioEscrow.sol`, `crates/economy/chio-settle/src/lib.rs:40-91`, `src/observe.rs:18-55`, `crates/kernel/chio-kernel/src/payment.rs:152-184`, `crates/kernel/chio-kernel/src/kernel/reconciliation.rs:135`, `crates/economy/chio-anchor/src/lib.rs` | Settlement: direct match. Clearing: absent by design so far |
| - | Market / discovery (not in the brief's six, but load-bearing) | Signed listings with fixed posted prices and SLAs, cheapest-first search and comparison, bilateral bid/ask/accept that mints a capability token, insurance market (quote/bind/claim/adjudicate), deterministic tier pricing and premium pricing, autonomous-pricing envelopes for the insurance side | `crates/economy/chio-listing/src/discovery.rs:48,203,291`, `crates/economy/chio-open-market/src/bidding.rs:101-244`, `crates/economy/chio-market/src/{quote,placement,claim,settlement}.rs`, `crates/economy/chio-appraisal/src/marketplace_pricing.rs:163`, `crates/economy/chio-underwriting/src/premium.rs:299`, `crates/economy/chio-autonomy/src/model.rs` | The venue exists; the good is capacity, the price is posted |
| - | Trust substrate | Key-identified principals, passports (SD-JWT selective disclosure), receipt-corpus reputation with Sybil-gated tiers, stigmergic pheromone signals with proven observation costs | `crates/trust/chio-credentials/src/portable_sd_jwt.rs:263`, `crates/trust/chio-reputation/src/tier.rs:98`, `crates/trust/chio-pheromone/src/lib.rs:204-253,365` | Substrate for seller credibility and buyer-side risk pricing |

Two orientation facts that reframe the brief's taxonomy (code wins):

- **"Market" is three different things in this codebase.** `chio-open-market` is the capability purchase path (bid/ask/accept for tool access). `chio-market` is a liability-insurance marketplace and has nothing to do with buying tools. `chio-listing` is the posted-price discovery registry both feed from. The economic-layer overview enumerates its own gaps explicitly: no auction, no negotiation, no agent-to-agent payment routing (`docs/protocols/ECONOMIC-LAYER-OVERVIEW.md`, section 7; note its "no price comparison" line is stale - cheapest-first comparison ships in `chio-listing/src/discovery.rs:440-465`).
- **The pheromone layer is the unpriced sibling of the negative-results market.** `chio-pheromone` already implements decaying "do not go there" signals between agents, admission-gated by Merkle-proven observation-cost commitments (`crates/trust/chio-pheromone/src/lib.rs:204-253`). It is a cost-to-signal mechanism with no payment, no bond, and no claim verification. The cognition market proposed here is the priced, bonded, verified tier of the same behavior; the pheromone substrate is the natural free tier and discovery hint channel. (Connection is `[speculative]` as product framing; the crate facts are high confidence.)

---

## 4. What can be proven about a computation today (grounding for everything below)

Confidence: high throughout this section (all claims spot-checked in source).

A mediated tool call through the kernel produces, today:

- A signed `ChioReceipt` whose body binds `action` (including `parameter_hash`), `capability_id`, `content_hash` (SHA-256 of the tool output), `policy_hash`, `decision`, `timestamp`, and the kernel key, content-addressed and Ed25519-signed over canonical JSON (`crates/core/chio-core-types/src/receipt/body.rs:34-102`; spec at `spec/PROTOCOL.md:683-847`). WYSIWYS is enforced structurally: the signing handle recomputes `content_hash` from the exact output preimage inside the trust boundary and refuses to sign a body claiming a different hash (`receipt/signing.rs:273`, `body.rs:325`). The 14-slot BBS projection of exactly these fields is defined in `crates/trust/chio-selective-disclosure/src/lib.rs:248`.
- Cost truth: pre-execution worst-case hold, post-execution reconciliation to realized spend, both in the signed financial metadata (`FinancialReceiptMetadata`: `cost_charged`, `budget_remaining`, `delegation_depth`, `root_budget_holder`; `crates/core/chio-core-types/src/receipt/economics.rs:33`), with a truthful guarantee level (`single_node_atomic` / `ha_linearizable` / `partition_escrowed` / `advisory_posthoc`, enforced by `is_recognized_guarantee_level`, `receipt/authoritative_spend.rs`).
- Batch commitment: RFC 6962 Merkle trees over receipts (`crates/core/chio-core-types/src/merkle.rs`) into checkpoints (`crates/kernel/chio-kernel/src/checkpoint.rs`), anchored to EVM, Bitcoin (OTS), Solana, and Rekor witnesses with fail-closed bundle verification (`crates/economy/chio-anchor/src/lib.rs`, `src/batch.rs:46`).
- Runtime identity evidence, two layers: (a) real TEE quote verification for Intel TDX, AMD SEV-SNP, and AWS Nitro behind the `tee-quotes` feature, with genuine ECDSA-P384/COSE signature checks and a binding formula `report_data = SHA256(kernel_pk || receipt_root)` so a quote ties a known-good runtime measurement to the kernel signing key and its receipt tree (`crates/trust/chio-attest-verify/src/quote.rs:162`, `src/sev_snp.rs`, `src/nitro.rs`; consumed by the kernel boot self-quote gate, `crates/kernel/chio-kernel/src/boot.rs:114`); (b) cloud-verifier claims normalization into `RuntimeAssuranceTier` (Azure MAA, AWS Nitro, GCP Confidential VM; `crates/economy/chio-appraisal/src/appraisal.rs:711`), carried on governed receipts as `runtime_assurance.tier` (`spec/PROTOCOL.md:944-953`).
- Selective disclosure: real BBS signatures over the receipt projection (feature `bbs`), with `derive_selective_disclosure_proof` / `verify_selective_disclosure_proof` (`crates/trust/chio-selective-disclosure/src/lib.rs:1203,1269`); SD-JWT passports with holder binding (`crates/trust/chio-credentials/src/portable_sd_jwt.rs:263,375`); a full constrained-reveal artifact family (disclosure capsule, verifier privacy profile with leakage budgets, leakage ledger, signed lineage subgraph; `crates/trust/chio-disclosure-lineage/src/types.rs`).
- Set membership and non-membership: Merkle inclusion for receipts-in-checkpoints, and a sparse-Merkle revocation oracle producing signed epoch roots with both inclusion and non-inclusion proofs (`crates/trust/chio-revocation-oracle/src/api.rs:116`).

The honest ceilings, three of them:

- **The codebase declares its own proof-capability boundary, and it should be quoted rather than paraphrased.** `ChioProofClaims` (`crates/trust/chio-attest-buyer-core/src/claims.rs:12-31`) ships with `bbs_reveal_set: true` and `hidden_range_predicates: false`, `vc_data_integrity_bbs: false`, `zkvm: false`, and `verify_claims` hard-rejects any proof package claiming the three unsupported capabilities (`src/proof_package.rs:51-72`). BBS reveal-set disclosure is the supported advanced proof; hidden range predicates and zkVM execution proofs are explicitly not supported. There is no zk-SNARK/STARK, Bulletproofs, zkVM, or PSI machinery anywhere in the workspace (repo-wide search; the `psi` hits are `EPSILON` false positives), and no blinded commit-reveal scheme (hash commitments only).
- **Hidden predicates are a registry with one entry.** `SUPPORTED_HIDDEN_PREDICATES` contains exactly `amount_lte_100` (kind `amount_cap`), and the verifier structurally matches capsule predicates against this registry (`crates/trust/chio-disclosure-lineage/src/verifier.rs:55-64,998-1056`). The cryptographic verification behind a predicate is delegated to a signed `DisclosureCryptoContextReport` from a trusted crypto-context signer (`types.rs:93-107`); it is not an in-repo general ZK verifier. Adding predicates is the same registry-plus-trusted-verifier pattern, not new cryptography; removing the trusted verifier is new cryptography.
- **Receipts prove kernel-observed events, not world states.** The spec says this in terms: provenance artifacts "prove kernel-observed evaluation events... None of these artifacts alone prove external real-world side effects beyond Chio's observation boundary" (`spec/PROTOCOL.md:1001-1004`), and concrete crypto/clock/storage/chain behavior is assumption-bounded (`spec/PROTOCOL.md:652-656`, `docs/reference/CLAIM_REGISTRY.md`). "This experiment ran and produced digest D at cost C under runtime tier T" is provable; "the hypothesis is false" is not, and never becomes so by adding signatures.

Two implementation caveats on the attestation chain, documented in-code as current limitations and repeated here so this memo does not oversell it: Sigstore verification currently reports `rekor_inclusion_verified = false` on all paths (cert chain and signature are checked; transparency-log inclusion is not yet; `crates/trust/chio-attest-verify/src/lib.rs:244-249`), and the TEE backends pin certificate chains by byte comparison to the vendor root rather than performing full X.509 path validation (`src/sev_snp.rs:420`, `src/nitro.rs:515`), while the report signature itself is cryptographically verified against the leaf key.

---

## 5. Gap analysis (Q1-Q8)

Each verdict is one of `supported today` / `partial` / `missing`, with the smallest honest extension named.

### Q1. Representation of a tradeable finding - **missing** (small extension)

Confidence: high.

No information-good type exists. The tradeable goods today are: scoped tool-invocation rights (`ToolGrant`, `crates/core/chio-core-types/src/capability/scope.rs:63`), resource/prompt grants (same file), liability coverage (`crates/economy/chio-market/src/placement.rs:96`), and marketplace bonds/fees (`crates/economy/chio-open-market/src/fee_schedule.rs:71`). Repo-wide searches for information-good, data-good, knowledge-asset, commit-reveal trading types return nothing load-bearing.

What comes close, and should be extended rather than replaced:

- The signed-listing pattern: `Listing` = registry artifact + operator-signed pricing hint + SLA + freshness (`crates/economy/chio-listing/src/discovery.rs:48,116,203`), with subject kinds currently `ToolServer | CredentialIssuer | CredentialVerifier | LiabilityProvider` (`src/listing.rs:24`).
- The evidence-bundle pattern: transaction-passport evidence graphs with digest-bound artifact closure (`crates/platform/chio-transaction-passport/src/evidence_graph.rs`, `spec/PROTOCOL.md:1070-1116`).
- The receipt lineage + cost metadata that a finding must reference as its proof-of-work (section 4).

A `Finding` artifact therefore needs (fields justified in section 6.1): claim descriptor (what question this answers, machine-matchable), claim predicate + guarantee class (what "verified" means for this finding), reveal-envelope commitment (`payload_sha256`; envelope digest per ARCHITECTURE 4.5, not raw bytes), evidence refs (receipt ids, checkpoint ref, cost rollup, runtime tier), provenance evidence class (`asserted`/`observed`/`verified`, reusing the normative taxonomy at `spec/PROTOCOL.md:545-553`), bond ref, expiry, and a status ref for later retraction. Negative results are the `outcome_class = null_result` case of the same shape, not a separate type.

### Q2. Verifiability today vs. aspirational - **partial**

Confidence: high (section 4 is the inventory).

Feasible today, without revealing the finding content: execution-happened (receipt + checkpoint + anchor), cost-was-burned (financial metadata), output-digest (content_hash), runtime-tier (appraisal), seller-track-record (reputation scorecard over integrity-gated receipts, `crates/trust/chio-reputation/src/lib.rs:50-74`), field-level selective disclosure of receipt slots (BBS), set membership/non-membership (Merkle lanes), and structural constrained-reveal with leakage budgets (disclosure capsules).

Small extension: new hidden-predicate registry entries relevant to findings, e.g. `outcome_class == null`, `test_suite_digest in committed_set`, `cost_charged >= X` - same registry + trusted crypto-context-signer pattern as `amount_lte_100` (`chio-disclosure-lineage/src/verifier.rs:55`). This buys "prove the receipt's outcome slot says null without revealing the experiment parameters" at the price of trusting the crypto-context signer, which is the existing trust model.

Open research (do not claim): arbitrary predicate proofs over experimental payloads ("this dataset shows no effect at p < .05"), trustless replacement of the crypto-context signer, and any ZK statement about what a computation semantically was (as opposed to which server/manifest/runtime executed it). The buyer-verification boundary already refuses packages that claim these capabilities (`ChioProofClaims`, `crates/trust/chio-attest-buyer-core/src/claims.rs:12-31`), which is the right default for the finding market too: findings must not be listable under proof claims the verifier cannot check. Section 7 tags the research rows.

### Q3. Arrow-resolution flow - **partial** (the wiring step is the design in 6.2)

Confidence: high on the pieces; the composition is `[speculative]` until built.

Present today: commitment carriers (content digests, canonical JSON signing), escrow with exactly two predeclared price-free terminal states - release against Merkle-proven receipt evidence or operator settlement signature, refund after deadline (`contracts/src/ChioEscrow.sol`; posture normative in ADR-0015 D1-D4); dual-signature release and Merkle batch release (`crates/economy/chio-settle/src/lib.rs:40-91`); kernel-level prepay/hold with refund-on-abort (`MustPrepay` refund path, `crates/kernel/chio-kernel/src/kernel/dispatch.rs:170`, commit `3383c07f1d`); a bilateral bid/ask/accept handshake whose acceptance references a kernel funds-reservation receipt (`AcceptedBid.bid_receipt_id`, `crates/economy/chio-open-market/src/bidding.rs:186`).

Missing: any binding between "payment releases" and "information was delivered". There is no commit-reveal, no HTLC/hashlock, no two-good atomic swap (searched; the settlement explorer confirmed zero hits beyond concurrency types). The resolution in 6.2 is to make delivery a mediated tool call so the existing receipt (which already binds `content_hash`) becomes the delivery proof the escrow already knows how to consume.

### Q4. Anti-fabrication / bonding - **partial** (mechanism present, trigger vocabulary missing)

Confidence: high on mechanism; the fabricated-null trigger is partly research.

Present: bond requirements per marketplace role with `slashable: bool` (`fee_schedule.rs:56`); penalty actions `HoldBond | SlashBond | ReverseSlash` with effective states, where slashing requires an enforced governance `Sanction` case and a slashable bond, with appeal-gated reversal (`crates/economy/chio-open-market/src/evaluation.rs:356-451`); abuse classes today are `SpamPublication | FraudulentListing | ReplayPublication | UnverifiableListingBehavior` (`src/penalty.rs:21`); on-chain impairment is evidence-gated, bounded by remaining collateral, and requires the beneficiary distribution to sum exactly to the slash amount (`crates/economy/chio-settle/src/evm/prepare.rs:989-1020,1325`; `contracts/src/ChioBondVault.sol`); adjudicators are roster-anchored with predeclared decision rules (`validate_against_roster`, `crates/economy/chio-market/src/claim.rs:38-50`; ADR-0015 follow-up B); slash destinations are constrained to harmed parties or a registered community fund (ADR-0015 D4, comptroller `market_slash` lane, `crates/platform/chio-risk-comptroller/src/ledger.rs`).

Missing: a fabricated-finding abuse class and, more fundamentally, the decision rule that distinguishes a fabricated negative result from an honest one. Three trigger classes are actually decidable and belong in the predeclared rule set (6.3): digest mismatch (delivered payload does not match the committed digest - mechanically checkable), evidence fraud (referenced receipts fail signature/checkpoint verification - checkable today, exactly how claims re-verify receipts fail-closed at `crates/economy/chio-market/src/insurance_flow.rs:390-414`), and reproduction contradiction (a bonded challenger re-runs the committed experiment descriptor under mediation and produces a receipt chain contradicting the claim - checkable but probabilistic for stochastic experiments). The residue (a null that is honest-looking, evidence-backed, and wrong only semantically) is priced risk, not adjudicable fraud; the market must carry it via bonds, reputation, and guarantee-class pricing rather than pretend it away. Note the economics Chio uniquely adds: because findings must reference metered receipts, fabricating convincing evidence costs approximately what honest work costs - metering makes proof-of-burn the anti-spam floor.

### Q5. Capacity leg in the same transaction - **supported today** (one envelope, sequenced not atomic)

Confidence: high.

The receipt metadata already carries a versioned `economic_authorization` envelope with separate typed sub-blocks for budget, metering, rail, and settlement truth (`spec/PROTOCOL.md:920-927`; `EconomicAuthorizationReceiptMetadata` with `amount_bounds`, `pricing_basis`, `metering`, `liability_refs` including `dispute_policy_ref`, `crates/core/chio-core-types/src/receipt/economics.rs:246-262`). Quotes precede execution (`MeteredBillingQuote`, `crates/core/chio-core-types/src/capability/governance.rs:67`), settlement modes are explicit (`MustPrepay | HoldCapture | AllowThenSettle`, `governance.rs:55`), and post-execution usage evidence lands in a mutable sidecar rather than mutating the signed receipt (`spec/PROTOCOL.md:974-978`). A finding purchase whose delivery is a mediated tool call (6.2) gets the information-leg price and the delivery-leg compute metered in the same receipt family with no new machinery. What does not exist is multi-leg atomicity across two goods; the flow in 6.2 is sequenced with fail-closed refunds at each step, which ADR-0015's two-terminal-state posture favors anyway.

### Q6. Memory governance of purchased findings - **partial**

Confidence: high.

Present: governed memory writes produce hash-chained provenance entries binding store/key to the authorizing capability and receipt (`MemoryProvenanceEntry`, `crates/kernel/chio-kernel/src/memory_provenance.rs:63`; SQLite persistence with fork-resistant append, `crates/platform/chio-store-sqlite/src/memory_provenance_store.rs`); reads are provenance-checked and the verdict (`Verified` / `Unverified{NoProvenance|ChainTampered|ChainLinkBroken|StoreUnavailable}`) is annotated into the signed receipt (`memory_provenance.rs:141-158`, wired in `kernel/responses/allow_responses.rs:360,436`) - annotated, not denied; ingestion guards exist but are opt-in (store allowlists + content deny-patterns in `MemoryGovernanceGuard`, `crates/guards/chio-guards/src/memory_governance.rs:60-108`; vector-store gating, `crates/guards/chio-data-guards/src/vector_guard.rs:317`; embedding-anomaly similarity screening, `chio-guards/src/embedding_anomaly.rs:201`); blast radius is queryable (reverse walk from a revoked credential/capability to every dependent receipt, `crates/observability/chio-lineage/src/query.rs:56`, `crates/platform/chio-store-sqlite/src/lineage_cte.rs:76`); revocation freshness is provable (epoch roots with non-inclusion proofs, `crates/trust/chio-revocation-oracle/src/api.rs:116`).

Missing: any retraction of data after distribution. Revoking authority propagates; revoking a datum does not - there is no tombstone, no kill-list, no consumer of the reverse-lineage result that invalidates derived memory entries, and quarantine is advisory annotation rather than an enforced state. Section 6.5 closes this with a finding-status feed on the existing oracle pattern plus a purchase-time non-inclusion check and an opt-in guard rule; automatic downstream invalidation remains future work (engineering, not research).

### Q7. Pricing / elicitation under a budget - **missing** (mechanism), with the right anchors present

Confidence: high on what exists; the mechanism is `[speculative]` design.

What exists: fixed posted prices, unilaterally set by the seller (`ListingPricingHint.price_per_call`, "Fixed price charged per invocation", `crates/economy/chio-listing/src/discovery.rs:48-60`); buyer-side ceilings only - `bid()` rejects `BidCeilingTooLow` and charges the sticker (`crates/economy/chio-open-market/src/bidding.rs:365-371,429`); deterministic price adjustments (reputation-tier discounts, `crates/economy/chio-appraisal/src/marketplace_pricing.rs:148-187`; risk-multiplier premiums, `crates/economy/chio-underwriting/src/premium.rs:299,371`); budget enforcement that makes any bid credible (a reservation receipt proves the funds are held, `bidding.rs:210`). There is no auction, no negotiation, no willingness-to-pay machinery anywhere (zero grep hits, confirmed twice).

The valuation problem itself - what a dead end is worth - is open research and stays open: it is a counterfactual (P(I would have run this) x cost-if-run x redundancy across the swarm) the buyer cannot compute exactly. The elicitation design (6.6) therefore bounds instead of solves: Chio's quote machinery gives the buyer a defensible ceiling (the metered cost estimate of re-deriving the result itself) and the budget-hold machinery makes the resulting bid non-cheap-talk. Posted-price with ceiling-checked bids (the existing shape) is the launch mechanism; batched uniform-price auctions are a later, separately-designed step.

### Q8. Clearing at swarm scale - **missing** at the venue, **supported today** at the budget layer

Confidence: high.

The current market path is one buyer, one listing, one synchronous mint - `bid()` is a pure function over a single `BidRequest` and a single resolved `Listing` (`crates/economy/chio-open-market/src/bidding.rs:308`); the only cross-participant aggregation is read-side cheapest-first ranking (`chio-listing/src/discovery.rs:440-465`). Nothing in the venue assumes or supports many-to-many matching, and the economic overview names auction/negotiation/A2A-routing as explicit gaps (`docs/protocols/ECONOMIC-LAYER-OVERVIEW.md` section 7).

The hierarchy the brief asks about already exists one layer down: signed swarm task graphs carry structural ceilings (`max_depth`, `max_fanout`) that admission enforces over the whole graph, and budget pools do explicit fan-out reservation / fan-in release with per-task allocations (`Reserved | Active | Consumed | Released | Reversed`) and terminal rollups reconciled against the pool (`crates/kernel/chio-swarm-authority/src/types.rs:44-63,247-348`; runtime admission contract at `spec/PROTOCOL.md:1006-1068`). The scaling design in 6.7 therefore puts purchasing at pool granularity (one buyer per sub-swarm budget pool, deduplicating demand inside the pool) rather than inventing a many-agent auction. This matches the market-based-control intuition in the brief: the budget tree is the decomposition; the venue stays bilateral.

---

## 6. Proposed design: the minimal extension set

Design stance: extend the listing/bid/accept + escrow + bond + revocation rails; add no new subsystem. Everything in this section is `[speculative]` design over cited primitives. Interface sketches follow repo idiom (schema consts, `deny_unknown_fields`, fail-closed `validate()`); they are sketches, not implemented APIs - the only code shipped with this memo is a spec-shaped ignored test naming the seams.

### 6.1 The Finding artifact family (new, one crate-module worth of types)

```rust
pub const FINDING_SCHEMA_V1: &str = "chio.finding.v1";
pub const FINDING_STATUS_FEED_SCHEMA_V1: &str = "chio.finding.status-epoch.v1";

/// Machine-matchable statement of what question this finding answers.
/// The descriptor is public at listing time; it is the controlled leak
/// (its leakage is what the disclosure leakage-ledger vocabulary already
/// models, crates/trust/chio-disclosure-lineage/src/types.rs:205).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingDescriptor {
    /// Domain-scoped topic key, e.g. "repo:backbay/chio#test-failure" or
    /// an experiment-space coordinate. Prefix-searchable like
    /// capability_scope_prefix (chio-listing/src/discovery.rs:144).
    pub topic: String,
    /// Digest of the full context object (test suite + commit, or the
    /// experiment protocol). Buyers with the same context recompute and
    /// match on equality; the context itself is not revealed.
    pub context_sha256: String,
    /// What kind of claim is being sold.
    pub outcome_class: FindingOutcomeClass,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingOutcomeClass {
    /// "Doing X fails / has no effect": the negative result.
    NullResult,
    /// "This change makes the committed check pass": the verified fix.
    VerifiedFix,
    /// Positive measurement or artifact with a checkable predicate.
    PositiveResult,
}

/// What "verified" means for this finding, truthful to its backing,
/// mirroring guarantee-level truthfulness for spend
/// (crates/core/chio-core-types/src/receipt/authoritative_spend.rs).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingGuaranteeClass {
    /// Claim re-checkable by deterministic re-execution of the committed
    /// descriptor (the coding-agent case). Strongest; challenge = re-run.
    DeterministicReplay,
    /// Execution + cost + output digest attested by mediated receipts,
    /// optionally TEE-tiered; claim semantics not re-checkable.
    MeteredAttested,
    /// Seller-asserted only. Never upgraded silently (P10 discipline,
    /// spec/PROTOCOL.md:620-623).
    Asserted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub finding_id: String,
    pub descriptor: FindingDescriptor,
    pub guarantee_class: FindingGuaranteeClass,
    /// Commitment to the reveal. SUPERSEDED DETAIL: the final design
    /// defines this as the digest of the canonical reveal ENVELOPE
    /// {media_type, payload_b64}, not of raw payload bytes, because the
    /// kernel receipt hashes the whole canonical JSON response value -
    /// see docs/research/cognition-market/ARCHITECTURE.md section 4.5.
    pub payload_sha256: String,
    /// Receipt ids + checkpoint ref proving the work that produced this
    /// finding ran under mediation, and its metered cost rollup.
    pub evidence_receipt_ids: Vec<String>,
    pub evidence_checkpoint_ref: String,
    pub evidence_cost_units: u64,
    pub evidence_cost_currency: String,
    /// Runtime assurance tier of the producing runtime, if attested
    /// (chio-appraisal). None means unattested.
    pub runtime_assurance_tier: Option<String>,
    /// Normative evidence class of the claim linkage:
    /// asserted | observed | verified (spec/PROTOCOL.md:545-553).
    pub evidence_class: String,
    /// Bond backing this finding (chio-open-market bond requirement id
    /// with slashable = true).
    pub bond_ref: String,
    /// Status feed (6.5) this finding's retraction state is published on.
    pub status_feed_ref: String,
    pub issuer: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}
```

Listing integration - SUPERSEDED DETAIL: the final design does NOT extend `GenericListingActorKind` (it is a closed wire-frozen enum, `crates/economy/chio-listing/src/listing.rs:24`); findings list their seller's server under the existing `ToolServer` actor kind with `metadata_url`/`resolution_url` pointing at the finding artifact, and the pricing hint's `capability_scope` carries `finding:<finding_id>` - see docs/research/cognition-market/ARCHITECTURE.md section 7.3 and the passing `bid()` path test. Price via the existing signed pricing hint. Discovery = the existing prefix query + descriptor match; a buyer holding the same failing context recomputes `context_sha256` and searches for it. `[speculative]` but mechanical.

### 6.2 The Arrow flow on existing rails: reveal as a governed tool call

The load-bearing move: **the seller serves the sealed payload as a Chio tool server, and the reveal is a mediated `read_finding` invocation.** Then every step of commit -> prove -> escrow -> conditional release -> slash lands on machinery that already exists:

1. **Commit.** Seller publishes the `Finding` (6.1) and its listing. The commitment is `payload_sha256`; the controlled leak is the descriptor; the proof-without-disclosure is the evidence bundle (receipts, checkpoint, cost, tier), verifiable offline by the buyer with the existing buyer-verification boundary (`crates/trust/chio-attest-buyer/src/api.rs`, receipt lineage + revocation-oracle checks included).
2. **Bid / accept.** Buyer runs the existing flow: `BidRequest` with `max_price_per_call` = its elicited ceiling (6.6) against the finding listing; seller's `AskResponse` mints a capability token for `read_finding` scoped `max_invocations: 1`, `max_total_cost: price` (`crates/economy/chio-open-market/src/bidding.rs:101-186`). Acceptance references the kernel funds-reservation receipt exactly as today (`AcceptedBid.bid_receipt_id`).
3. **Escrow.** Small/high-frequency purchases: the kernel hold itself is the escrow (`MustPrepay` funds the authorization from the quoted price and mints an execution nonce; abort refunds - `crates/kernel/chio-kernel/src/kernel/dispatch.rs:170`). Large/cross-org purchases: `ChioEscrow.createEscrow` with beneficiary = seller, `maxAmount` = price, committed deadline; two predeclared terminal states only (ADR-0015 D2).
4. **Reveal = delivery proof.** Buyer invokes `read_finding` through the kernel. The signed receipt binds the response digest as `content_hash` (computed over the canonical JSON of the whole response value). Fail-closed check (new, one guard-shaped rule): the kernel-side tool contract for `read_finding` requires `content_hash == finding.payload_sha256`, where `payload_sha256` is defined over the canonical reveal envelope {media_type, payload_b64} - see ARCHITECTURE 4.5, which supersedes this sketch's original raw-byte phrasing - so a seller cannot serve garbage and still produce a valid delivery receipt. This receipt is the evidence the escrow already consumes: release via Merkle inclusion against the operator-signed root (`releaseWithProofDetailed`, `contracts/src/ChioEscrow.sol`; batch form `prepare_merkle_release`, `crates/economy/chio-settle/src/lib.rs`). Non-delivery before the deadline = refund. No third state.
5. **Post-reveal window.** The purchase receipt's `liability_refs.dispute_policy_ref` (`crates/core/chio-core-types/src/receipt/economics.rs:256`) names the predeclared challenge rule and window (settlement already has amount-tiered dispute windows, `crates/economy/chio-settle/src/config.rs:122`). Challenges and slashing per 6.3.

What Arrow's paradox reduces to under this flow, stated honestly: the buyer decides under the descriptor + evidence bundle + seller bond/reputation, not under the finding content. Payment-versus-delivery is solved (digest-bound delivery receipt gates release). Value-versus-content is not solvable in general - the buyer can still find the revealed content useless while the claim is technically true. That residual is handled economically (guarantee-class pricing, bonds, reputation, dispute window for claim-vs-content mismatch), which is the elicitation thesis of the brief rather than a failure of it.

### 6.3 Anti-fabrication stack (defense in depth, mostly existing)

Ordered from mechanical to economic; the first three are adjudicable under predeclared rules (ADR-0015 D5 discipline), the last two are pricing:

1. **Digest fraud** - delivered bytes vs. committed `payload_sha256`: prevented at reveal time (6.2 step 4), so it cannot even reach adjudication.
2. **Evidence fraud** - the finding's receipts fail signature / checkpoint / revocation verification: mechanically checkable today (the insurance claim path already re-verifies receipt evidence fail-closed, `crates/economy/chio-market/src/insurance_flow.rs:390-414`). New abuse class `FabricatedFindingEvidence` alongside the existing four (`crates/economy/chio-open-market/src/penalty.rs:21`); slash via the existing enforced-Sanction + slashable-bond gate (`src/evaluation.rs:356-451`), on-chain impairment with beneficiary distribution to the harmed buyer(s) per ADR-0015 D4.
3. **Reproduction contradiction** - for `DeterministicReplay` findings, a bonded challenger re-runs the committed descriptor under mediation; a contradicting receipt chain is the challenge evidence. The challenger posts the existing `Dispute`-class bond (`fee_schedule.rs:14`) so frivolous challenges cost; adjudication chooses among fixed outcomes only. For stochastic experiments this rule needs a predeclared replication protocol (n runs, agreement threshold) - tagged research-adjacent in section 7.
4. **Proof-of-burn floor** - findings must reference metered receipts whose cost rollup the buyer can check; fabricating credible evidence costs roughly the honest cost. This is Chio-specific leverage: the meter is the spam filter.
5. **Reputation and Sybil resistance** - scorecards are computed only over integrity-gated receipts (`crates/trust/chio-reputation/src/lib.rs:50-74`) and Tier3 requires distinct evidence feeds (`src/tier.rs:98-139`), so burning a fabricator identity is expensive to repeat.

Honest residual (research, section 7): a semantically-wrong-but-honestly-produced null cannot be adjudicated as fraud, and a fabricator willing to pay the full honest compute cost to produce real-looking evidence for a wrong claim defeats layers 2-4 for `MeteredAttested` findings; only replay-checkable guarantee classes and TEE-attested pipelines shrink that hole, and only partially (TEE attests the runtime, not the science).

Agents-as-principals check: buyers, sellers, and challengers in this design are agent subjects. The roster-anchored adjudicator (ADR-0015 follow-up B) is today an institutional role. For `DeterministicReplay` findings the decision rule is mechanical enough that the adjudicator degenerates into a verifier running the replay check - that is the path to de-institutionalizing disputes for the wedge instance. For everything else, a predeclared roster remains, and this memo does not pretend otherwise.

### 6.4 Capacity leg

Nothing new. The reveal call is metered like any tool call; the purchase receipt's `economic_authorization` envelope carries budget, metering, rail, and settlement truth in typed sub-blocks (`crates/core/chio-core-types/src/receipt/economics.rs:262`); a buyer who additionally pays for a verification re-run consumes ordinary metered capacity under the same budget tree. Where the finding's producer consumed instrument time, that consumption is already in the evidence receipts' cost metadata - the capacity history rides inside the information good's evidence rather than being a separate settlement leg.

### 6.5 Memory governance of purchased findings

- **Provenance-in (exists):** the buyer ingests the payload via a governed memory write; the provenance chain binds store/key to the purchase capability and delivery receipt (`crates/kernel/chio-kernel/src/memory_provenance.rs:63`). Reads carry the provenance verdict in the signed receipt.
- **Retraction feed (new, pattern exists):** publish finding status on a dedicated revocation-oracle instance keyed by `finding_id` (`RevocationKey`-per-finding on the sparse-Merkle oracle, `crates/trust/chio-revocation-oracle/src/api.rs:70-116`). Retraction = insert + new signed epoch root. At purchase time the buyer demands a fresh **non-inclusion proof** (the API exists) so it never buys an already-retracted finding; post-purchase, buyers poll or subscribe to epoch roots exactly as passport revocations bridge today (`src/passport_bridge.rs`).
- **Quarantine-on-retraction (new, opt-in guard rule):** extend `MemoryGovernanceGuard` (`crates/guards/chio-guards/src/memory_governance.rs:60`) so reads of memory keys whose provenance traces to a retracted finding deny rather than merely annotate - the annotation plumbing already reaches the receipt; this flips it to enforcement for policy-selected stores.
- **Blast radius (exists):** reverse lineage from the delivery receipt enumerates every dependent action (`crates/observability/chio-lineage/src/query.rs:56`); what to do about derived conclusions is the buyer's policy. Automatic invalidation of derived data is future engineering, not designed here.
- **Poisoning-resistance at ingest (exists, opt-in):** content deny-patterns, vector-store allowlists, embedding-anomaly screening (`chio-guards`, `chio-data-guards`) apply to the payload like any ingested data; a purchased finding gets no ingestion privilege from having been paid for. `Asserted`-class findings can be policy-blocked from memory entirely (evidence-class gating, consistent with P10's never-upgrade rule).

### 6.6 Elicitation interface (pricing without pretending to value)

The buyer-side interface, honest about what it computes:

```rust
/// Inputs a buying agent can actually obtain. No field claims to be
/// "the value of the finding".
pub struct FindingBidBasis {
    /// Metered estimate of re-deriving the result locally: the existing
    /// pre-execution quote for running the committed descriptor
    /// (MeteredBillingQuote, chio-core-types/src/capability/governance.rs:67).
    pub rederivation_quote_units: u64,
    /// Buyer's own prior that it would have run this experiment at all,
    /// in basis points. Planner-supplied; unmodeled here. [open problem]
    pub would_have_run_bps: u16,
    /// Haircut for intra-swarm redundancy: probability a sibling under the
    /// same budget pool buys or derives it anyway, in basis points.
    /// Pool-level purchasing (6.7) drives this toward zero. [open problem]
    pub sibling_redundancy_bps: u16,
    /// Guarantee-class multiplier in bps (DeterministicReplay = 10_000;
    /// MeteredAttested and Asserted discounted by policy).
    pub guarantee_class_bps: u16,
    /// Remaining budget on the purchasing allocation; the hard cap
    /// (SwarmBudgetAllocation, chio-swarm-authority/src/types.rs:281).
    pub budget_remaining_units: u64,
}

/// ceiling = min(budget_remaining,
///     rederivation_quote x would_have_run x (1 - redundancy) x class)
/// Deterministic, auditable, and deliberately an upper bound - the
/// posted price clears only if it sits under this ceiling, preserving
/// buyer surplus whenever the market functions at all.
pub fn finding_bid_ceiling(basis: &FindingBidBasis) -> u64 { /* sketch */ }
```

This bounds the bid by the one counterfactual the platform can meter (re-derivation cost) and makes the two genuinely unknown terms explicit, planner-owned inputs rather than hidden assumptions. The mechanism at launch is the existing posted-price + ceiling check (`BidCeilingTooLow`, `bidding.rs:365`); sellers of expensive dead ends discover demand through listing analytics (receipt volumes already ride the pricing hint, `discovery.rs:48`). Batched uniform-price auctions per topic are a plausible later step and are left undesigned on purpose. Rigorous dead-end valuation stays an open research problem (section 7) - the interface elicits a budget-credible bid, it does not solve credit assignment.

### 6.7 Swarm-scale clearing

Rule: **one purchasing principal per budget pool.** A sub-swarm's planner (which already holds the pool and its per-task allocations, `crates/kernel/chio-swarm-authority/src/types.rs:247`) aggregates its members' failing contexts, deduplicates descriptor matches pool-internally (driving `sibling_redundancy_bps` down), and issues at most one bid per descriptor from a dedicated purchasing allocation. Purchased findings distribute pool-internally as governed memory writes. Cross-pool, the venue stays exactly as bilateral as today - the joint action space never materializes because the budget tree, whose depth and fan-out ceilings are already signed and admission-enforced (`types.rs:53-54`), is the market decomposition. This claims no new clearing theory: it is the existing hierarchy plus a purchasing convention. What would need real mechanism design later: cross-pool demand aggregation for expensive findings (many pools each worth less than the price, jointly worth more) - flagged in section 7, not designed.

### 6.8 What is deliberately not proposed

- No new settlement rail, no new escrow contract, no protocol-level atomic swap (the digest-gated delivery receipt makes it unnecessary).
- No auction engine, no order book, no continuous price discovery.
- No general ZK proof system, no PSI subsystem.
- No finding-content storage inside Chio (payloads live on seller tool servers; Chio holds commitments, receipts, and status - consistent with memory content being out of scope today).
- No autonomous adjudication beyond replay-checkable rules.

---

## 7. Open problems

Tagged `research` (unsolved in the field or genuinely novel) vs `engineering` (known shape, needs building). Ordered by how hard they gate the vision instance.

| # | Problem | Tag | Notes |
|---|---|---|---|
| 1 | Valuing a negative result (counterfactual credit assignment: `would_have_run`, cross-swarm redundancy, information decay) | research | Deliberately externalized to planner inputs in 6.6; any tradeable value-metric invites gaming, which is why the design elicits bids instead |
| 2 | Verifying null results whose claim is not replay-checkable ("we ran it and nothing happened" for stochastic/wet-lab experiments) | research | Predeclared replication protocols (n-run agreement thresholds) are partial; the honest-but-wrong and the paid-full-cost fabricator both survive 6.3 for `MeteredAttested` findings |
| 3 | Rich predicate proofs over sealed payloads (beyond registry predicates with a trusted crypto-context signer) | research | Today's ceiling: one registry predicate (`chio-disclosure-lineage/src/verifier.rs:55`); BBS discloses receipt fields, not payload predicates. General ZK over experimental data is aspirational and must not be claimed |
| 4 | De-institutionalized dispute resolution (adjudicator = verifier) beyond deterministic replay | research | Roster-anchored adjudication (ADR-0015 follow-up B) persists for everything non-mechanical; acceptable for the wedge, unresolved for the vision |
| 5 | Cross-org trust bootstrapping for seller bonds and status feeds (whose oracle, whose sanction authority, between strangers) | research (mechanism) / engineering (transport) | Federation surfaces exist but are curated-bounded by design (`spec/PROTOCOL.md:3451-3461` explicitly excludes permissionless marketplace semantics from v1); ADR-0014 defers the transport |
| 6 | Cross-pool demand aggregation (many pools jointly worth more than a finding's price) | research-adjacent | Classic public-goods/combinatorial territory; deliberately not designed in 6.7 |
| 7 | Finding artifact family + listing subject kind + descriptor search | engineering | 6.1; pure extension of `chio-listing` patterns |
| 8 | `read_finding` tool contract with digest-equality enforcement + escrow release wiring from delivery receipts | engineering | 6.2; the receipt already carries `content_hash`, the escrow already consumes receipt Merkle proofs |
| 9 | `FabricatedFindingEvidence` abuse class + challenge evidence schema + replication decision rules for the deterministic class | engineering | 6.3; extends `chio-open-market` penalty vocabulary and reuses claim-style receipt re-verification |
| 10 | Finding-status feed on the revocation-oracle pattern + purchase-time non-inclusion check + quarantine guard rule | engineering | 6.5; API surface already exists (`chio-revocation-oracle/src/api.rs:116`) |
| 11 | Hidden-predicate registry entries for finding-relevant claims (`outcome_class == null`, `suite_digest in set`, cost floors) | engineering | Same trusted-verifier trust model as today; honest about not being trustless |
| 12 | Pool-level purchasing convention in swarm planners | engineering | 6.7; convention + one allocation dimension, no kernel change |

---

## 8. Feasibility and sequencing recommendation

**Verdict: feasible as an extension, not a new system - provided the first instance is the coding-agent swarm.** Confidence: high on the primitive inventory (sections 3-5), moderate on the composition (6.2 is designed, not built), low on marketplace liquidity questions (out of scope for a repo spike).

Why the coding-agent wedge first:

1. Its findings are `DeterministicReplay`-class: "this patch makes suite digest S pass at commit C" is checkable by a mediated re-run, which collapses open problems 2 and 4 (the two hardest) out of the launch path entirely. The R&D lab instance keeps every interface but inherits both problems at full strength.
2. Its buyers already exist inside the trust boundary Chio governs (coding agents under kernel mediation with budgets and receipts), so seller-side agent-principals and same-org or bilateral federation suffice; open problem 5 defers.
3. Its unit economics are checkable today: re-derivation quotes for "run the failing suite" are exactly what the metering quote path produces, so the 6.6 ceiling is computable with shipped machinery. Its evidence bundle even has a shipped template: `chio-eval-receipt` already verifies "this corpus was run and these signed receipts/verdicts resulted" bundles fail-closed (`crates/sdk/chio-eval-receipt/src/verify.rs:159`), which is structurally a verified-fix evidence package with the corpus digest playing the role of the committed test-suite context.
4. Everything it forces to be built (rows 7-10 in section 7) is the same code the R&D instance needs later; nothing is wedge-throwaway.

Sequencing (each step is independently useful; stop-loss after any):

1. **Spec + types spike** (this branch): finding artifact family, ADR, ignored flow test naming the seams. No production wiring.
2. **Delivery-receipt wiring:** `read_finding` tool contract with digest equality, hold-based settlement for the small-amount path. This alone yields sellable verified fixes inside one operator boundary.
3. **Bond + challenge lane:** `FabricatedFindingEvidence` abuse class, replay-challenge decision rule, slash wiring through the existing sanction gate. This is what makes claims credible to strangers.
4. **Status feed + quarantine guard:** retraction becomes real; buyers get non-inclusion freshness at purchase.
5. **Escrow path for cross-org amounts** (only if bilateral federation demand exists): `ChioEscrow` wiring from delivery-receipt Merkle proofs - the contracts and release functions already exist.
6. **Only then** revisit the R&D instance and the research rows (1-5) with usage data - especially whether elicited ceilings and posted prices actually clear, before any auction work.

The honest bottom line for a reader deciding whether to fund this: Chio is unusually close to this market because the expensive parts (metered proof-of-burn, bonded claims, non-discretionary escrow, provenance-tagged ingestion, hierarchical budgets) are already built and formally disciplined; the genuinely missing piece is small (a good type and a digest-gated delivery step); and the parts that remain hard (pricing dead ends, verifying nulls, trustless predicates) are hard for reasons no codebase fixes, which is exactly why the design elicits bids, bonds claims, and prices guarantee classes instead of pretending to verify science.
