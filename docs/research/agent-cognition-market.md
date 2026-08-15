# Agent-to-Agent Cognition Market on Chio: Design-Research Memo

- Status: founding research snapshot (not a roadmap commitment)
- Date: 2026-07-20
- Evidence snapshot: branch `research/cognition-market`, forked from `feat/roadmap-execution` at `55ec2c4c41`
- Current implementation note (2026-07-27): M0/M1 now implements the `chio-finding` leaf crate, registers `chio.finding.v1`, documents it in `spec/PROTOCOL.md` 6.4.7, and advances the spec-shaped test. Market publication, reveal, settlement, challenge, and status-feed wiring remain unimplemented.
- Companions: `docs/adr/ADR-0017-cognition-market-finding-artifacts.md` and `crates/economy/chio-open-market/tests/cognition_market_flow.rs`
- Question answered: can Chio's existing primitives support a market where autonomous agents trade solved cognition (especially negative results), and what exactly is the gap between "supported today", "small extension", and "open research"?
- Evidence discipline: every codebase claim cites a real path as of the evidence snapshot. Anything not backed by code or a cited doc is marked `[speculative]`. Confidence is stated per section. Treat this memo as historical evidence, not a current-main pipeline audit.
- State discipline: `snapshot` means the 2026-07-20 evidence baseline;
  `current M1` means the implementation on this execution branch; `target
  M2+` means unimplemented design. Reusable primitives are not a composed
  Finding verifier or purchase flow.

---

## 1. Executive summary

Chio ships substantial pieces of five of the six primitives a cognition
market needs: kernel-mediated metering and configurable budget stores, bonded
requirements and adjudicated slashing rails, escrow with predeclared
release/refund entry points, signed execution receipts with Merkle
checkpointing and several anchoring surfaces, and a listing/bid/accept market
for capability access. These are reusable foundations, not a cognition market
already hiding in the tree. Some have important profile boundaries: the
default kernel budget store is process-local, the swarm budget pool is not a
signed artifact, public-witness support differs by anchor lane, and a receipt
attests what the kernel observed rather than an external-world result. What is
missing is specific but spans several enforcement seams:

1. **At the 2026-07-20 evidence snapshot there was no information-good
   type.** The only tradeable good was a scoped tool-invocation right
   (`CapabilityToken` / `ToolGrant`,
   `crates/core/chio-core-types/src/capability/scope.rs:63`), plus liability
   coverage. M0/M1 now supplies the signed type and schema; publish/reveal
   wiring remains absent (see 5.Q1, 5.Q3).
2. **The reveal-vs-payment binding can reuse shipped subsystems, but it is
   not one wiring step.** On content-bearing signing paths, the kernel binds
   the observed response digest (`content_hash`) into the signed receipt,
   supports reversible
   hold/capture settlement, and has an on-chain escrow that releases against
   Merkle-proven settlement evidence (`contracts/src/ChioEscrow.sol` via
   `releaseWithProofDetailed`, per ADR-0015). That contract does not consume
   a raw finding-delivery receipt. The current design still needs
   a generic output-digest constraint and persisted mismatch transition,
   provider-signed finding-purchase binding, accepted-bid/reservation checks,
   fail-closed portable behavior, and crash-recovery authorization. See
   ARCHITECTURE F3/6 and PLAN M3/M4. Modeling reveal as a governed tool call
   preserves the existing kernel and settlement architecture; it does not
   make delivery-versus-payment automatic.
3. **Proof-without-disclosure is real but narrow.** Chio can selectively
   disclose fields from a signed receipt using BBS projections
   (`crates/trust/chio-selective-disclosure/src/lib.rs:248`). The receipt can
   bind the response bytes and financial metadata the kernel observed, plus
   an assumption-bounded runtime-assurance claim. It does not prove the
   semantic truth of an experimental result. The disclosure-lineage registry
   has one trusted-signer-backed amount predicate, but no current carrier maps
   a finding's public `outcome_class` or sealed payload into that verifier.
   Hidden finding predicates and rich ZK predicates over experimental data
   are unsupported.
4. **Pricing a negative result is an open research problem; a buyer-local
   ceiling is implementable.** `MeteredBillingQuote` is a caller-carried data
   type, not a shipped quote-production service. A buyer may obtain or
   estimate the cost of re-deriving a result, then apply deterministic local
   arithmetic to cap its bid. The spike proves that arithmetic and the real
   `bid()` ceiling check, not the provenance of the estimate or a completed
   accept/reservation flow.
5. **Swarm-scale clearing should be hierarchical, and part of the hierarchy
   already exists.** The current market path is strictly one bid against one
   listing, synchronously
   (`crates/economy/chio-open-market/src/bidding.rs:308`). Signed task graphs
   enforce depth and fan-out ceilings, while `SwarmBudgetPool` performs
   fan-out/fan-in accounting against one `total_units` cap. The pool itself
   has no issuer or signature and is not a cryptographic purchasing
   authority. It is still a useful same-authority decomposition substrate
   once the market design supplies the missing authorization boundary. Flat
   auctions are neither present nor proposed.

**Recommendation (section 8): pursue the coding-agent instance first.** A
target "verified fix" is a finding whose replay recipe carries the exact
verdict ("this recipe makes this committed suite pass at this commit") and
can be checked by deterministic re-execution. M1 stores only the recipe
digest; M2/M5 must verify the preimage and rerun. The
R&D negative-result instance shares every interface but pushes the two
genuinely open problems (verifying nulls, pricing dead ends) to their hardest
form; it should be the second instantiation, not the first.

Filter note, held throughout: the market is agent-oriented on the buy side,
but the shipped identity binding is incomplete for the proposed finding
profile. `SignedBidRequest` authenticates a signer, while `agent_id` and the
reservation's `agent_id` are opaque strings; `accept()` separately requires
the acceptor key to equal the offered token subject. M4 must bind those
identities and the authoritative reservation explicitly. Listings remain
operator-signed (`crates/economy/chio-listing/src/discovery.rs:48`).
Making sellers agent-principals therefore requires authorization and bond
policy, not merely a label change. Human institutions also persist in
roster-anchored adjudication (ADR-0015 follow-up B), which section 6.3 treats
honestly.

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
| 1 | Formal verification | Bounded, implementation-linked evidence over the published proof boundary: the snapshot inventory cataloged 83 theorem entries; current M1 catalogs 95 P1-P10-mapped entries, plus Creusot/Kani verification lanes and bounded TLA+ safety/liveness models checked by Apalache. There is no TLC runner or lane. Receipt signatures and Merkle reasoning in Lean are symbolic. Aeneas extracts 15 pure numeric/boolean Rust helpers; generated Lean is not imported into the proof project, while a tracked Lean module hand-restates the semantics and proves 14 equivalence theorems. `KernelTransitionCancelSafe` is a bounded snapshot-equality contract whose `Commit` action is disabled while cancellation is pending, so its invariant holds by construction and does not cover concurrent commit-vs-cancel races. Concrete crypto, I/O, storage, dispatch, and tool behavior remain separately qualified under audited assumptions. Execution attestation is a different layer. `chio-attest-verify` performs signature and report-data checks for TDX / SEV-SNP / Nitro subsets, but TDX uses byte-terminal collateral anchoring, lacks full quote/collateral corpus pinning and a measurement allowlist, and is not a full DCAP stack. `chio-tee` is a replay-capture sidecar | `formal/` (see `docs/formal/CURRENT_STATE.md`, `formal/theorem-inventory.json`), `formal/apalache/KernelTransitionCancelSafe.tla`, `.github/workflows/{apalache-safety,apalache-temporal}.yml`, `docs/reference/CLAIM_REGISTRY.md`, `crates/kernel/chio-kernel-core/src/formal_aeneas.rs`, `formal/lean4/Chio/Chio/Proofs/AeneasEquivalence.lean`, `crates/trust/chio-attest-verify/src/{quote,tdx}.rs`, `crates/trust/chio-tee/src/lib.rs:1` | Strong within the named symbolic and pure-core boundary; concrete execution evidence remains assumption-bounded and kernel-observed |
| 2 | Programmable economic sovereignty | Grant-level invocation and monetary caps plus exposed/realized hold accounting, enforced through a compatible `BudgetStore`. The kernel defaults to process-local `InMemoryBudgetStore`; durable profiles inject `SqliteBudgetStore` or a remote authority, and financial dispatch requires the durable profile unless an unsafe development override is selected. A cumulative `max_total_cost` is effective only when nonzero per-invocation exposure is preauthorized: a total-only shape debits zero, and `MustPrepay` rejects it. Signed swarm task graphs bind depth/fan-out, but `SwarmBudgetPool` itself is unsigned and checks one total-units envelope rather than a signed multidimensional economic authority | `crates/core/chio-core-types/src/capability/scope.rs:63-113`, `crates/kernel/chio-kernel/src/{budget_store,kernel/construction}.rs`, `crates/kernel/chio-kernel/src/kernel/{governed_validation,evaluation/async_evaluation_core}.rs`, `crates/platform/chio-store-sqlite/src/budget_store/`, `crates/kernel/chio-swarm-authority/src/types.rs:41-63,247-287` | Strong for the selected backend/profile; not an unconditional cross-process or swarm-wide sovereignty claim |
| 3 | Metering | Consumption accounting in currency minor units + invocation counts on the selected budget path, plus richer advisory dimensions (compute-ms, bytes, tokens); financial metadata can be stamped into signed receipts. `MeteredBillingQuote` is a validated carrier supplied in governed intent, not a quote producer or proof that the quoted work matches a finding recipe. No accounting of value produced exists (consumption only) | `crates/economy/chio-metering/src/cost.rs:16,69`, `crates/kernel/chio-kernel/src/budget_store.rs:616`, `crates/core/chio-core-types/src/receipt/economics.rs:33`, `crates/core/chio-core-types/src/capability/governance.rs:79` | Reusable accounting carrier; quote provenance and finding semantics are missing |
| 4 | Memory governance | Governed memory writes with hash-chained provenance tied to capability + receipt; opt-in ingestion guards (store allowlists, deny patterns, embedding anomaly, prompt injection); generic execution-lineage DAG queryable in reverse from credential/capability dependencies; append-only Merkle revocation oracle with signed epoch roots and a locally checked non-inclusion query object. The current object has no portable absence proof. No typed Finding-delivery lineage edge, Finding consumer, data tombstones, or automatic retraction propagation exists | `crates/kernel/chio-kernel/src/memory_provenance.rs:63`, `crates/guards/chio-guards/src/memory_governance.rs:108`, `crates/guards/chio-data-guards/src/vector_guard.rs:317`, `crates/observability/chio-lineage/src/query.rs:56`, `crates/trust/chio-revocation-oracle/src/api.rs:110-116`, `src/sparse_merkle.rs:1-79` | Partial: generic provenance-in and reverse-lineage queries exist; the typed Finding relation, authenticated status, and retraction-out do not |
| 5 | Bonding | Bond-requirement classes with `slashable` flags, a penalty state machine gated on an enforced governance Sanction case, and on-chain bond-vault impairment with exact-sum beneficiary distribution. These are reusable rails. A Finding does not yet have a live, exclusive collateral allocation bound to seller/listing/finding, and `ReverseSlash` state alone does not claw back already distributed funds | `crates/economy/chio-open-market/src/fee_schedule.rs:56`, `src/penalty.rs:21-53`, `src/evaluation.rs:356-451`, `crates/economy/chio-settle/src/evm/prepare.rs:989-1020,1325`, `contracts/src/ChioBondVault.sol`, `docs/adr/ADR-0015-predeclared-escrow-circuit-breakers.md` | Mechanism substrate exists; M2/M5 must bind collateral and outcomes to Findings |
| 6 | Settlement / clearing | Single-leg escrow (lock / partial release / release / refund) with receipt-Merkle-gated and dual-signature release and deadline refund; kernel two-phase hold state (`MustPrepay` / `HoldCapture` / `AllowThenSettle`) and payment adapters (x402, ACP, EIP-3009, CCIP, Solana). Confirmed pre-dispatch unwind exists for qualifying reversible/refundable rails, while post-dispatch ambiguity is retained. No shipped adapter currently supplies the complete evidenced, idempotent reversible profile required for output-verified Finding capture. Anchor support is lane-specific: EVM publication/confirmation and Rekor witness verification have online paths; OTS is advisory without trusted Bitcoin headers; Solana helpers validate a supplied memo record without querying finality. No atomic two-good swap, order book, or price discovery | `contracts/src/ChioEscrow.sol`, `crates/economy/chio-settle/src/lib.rs:40-91`, `src/observe.rs:18-55`, `crates/kernel/chio-kernel/src/kernel/dispatch.rs:418-480`, `crates/kernel/chio-kernel/src/kernel/tests/sim_payment.rs:344-365`, `crates/economy/chio-anchor/{ARCHITECTURE.md,src/lib.rs}` | Settlement carriers are substantial; a qualified Finding payment profile and clearing remain absent |
| - | Market / discovery (not in the brief's six, but load-bearing) | Signed listings with fixed posted prices and SLAs, cheapest-first search and comparison, a bilateral path where `bid()` mints a capability and separate `accept()` validates a selected reservation witness, plus an insurance market and pricing-policy idioms | `crates/economy/chio-listing/src/discovery.rs:48,203,291`, `crates/economy/chio-open-market/src/bidding.rs:101-511`, `crates/economy/chio-market/src/{quote,placement,claim,settlement}.rs`, `crates/economy/chio-appraisal/src/marketplace_pricing.rs:163`, `crates/economy/chio-underwriting/src/premium.rs:299` | A capacity venue exists; finding publication, identity cross-binding, and authoritative purchase state do not |
| - | Trust substrate | Key-identified principals, passports (SD-JWT selective disclosure), receipt-corpus reputation with Sybil-gated tiers, and stigmergic pheromone signals with observation-cost commitments | `crates/trust/chio-credentials/src/portable_sd_jwt.rs:263`, `crates/trust/chio-reputation/src/tier.rs:98`, `crates/trust/chio-pheromone/src/lib.rs:204-253,365` | Substrate for seller credibility and buyer-side risk pricing |

Two orientation facts that reframe the brief's taxonomy (code wins):

- **"Market" is three different things in this codebase.** `chio-open-market` is the capability purchase path (bid/ask/accept for tool access). `chio-market` is a liability-insurance marketplace and has nothing to do with buying tools. `chio-listing` is the posted-price discovery registry both feed from. The economic-layer overview enumerates its own gaps explicitly: no auction, no negotiation, no agent-to-agent payment routing (`docs/protocols/ECONOMIC-LAYER-OVERVIEW.md`, section 7; note its "no price comparison" line is stale - cheapest-first comparison ships in `chio-listing/src/discovery.rs:440-465`).
- **The pheromone layer is the unpriced sibling of the negative-results market.** `chio-pheromone` already implements decaying "do not go there" signals between agents, admission-gated by Merkle-linked observation-cost commitments (`crates/trust/chio-pheromone/src/lib.rs:204-253`). It is a cost-to-signal mechanism with no payment, no bond, and no semantic claim verification. The cognition market proposed here is the priced, bonded tier of the same behavior; the pheromone substrate is a plausible free tier and discovery hint channel. (Connection is `[speculative]` as product framing; the crate facts are high confidence.)

---

## 4. What can be proven about a computation today (grounding for everything below)

Confidence: high throughout this section (all claims spot-checked in source).

A mediated tool call through the kernel can produce, today:

- A signed `ChioReceipt` whose body binds `action` (including
  `parameter_hash`), `capability_id`, `content_hash`, `policy_hash`,
  `decision`, `timestamp`, and the kernel key, content-addressed and
  signed by the embedded kernel key over canonical JSON
  (`crates/core/chio-core-types/src/receipt/body.rs:34-102`; spec at
  `spec/PROTOCOL.md:683-847`). The signing handle recomputes
  `content_hash` from the exact response preimage presented inside the trust
  boundary on content-bearing signing paths and refuses to sign a body
  claiming a different hash
  (`receipt/signing.rs:273`, `body.rs:325`). This proves what bytes the
  signer observed on that path, subject to the spec's explicit trusted-relay
  exception. It does not prove that an external instrument, server, or
  experiment produced them honestly. The 14-slot BBS projection of these
  receipt fields is defined in
  `crates/trust/chio-selective-disclosure/src/lib.rs:248`.
- Financial observation: a selected budget backend can preauthorize
  worst-case exposure and reconcile it to reported realized spend, then
  carry those values and its declared guarantee level in signed metadata
  (`FinancialReceiptMetadata`, `crates/core/chio-core-types/src/receipt/economics.rs:33`;
  `receipt/authoritative_spend.rs`). The guarantee level distinguishes
  single-node, HA, partition-escrowed, and advisory profiles. It must be
  evaluated with the backend and evidence source; a signature alone does not
  turn tool-reported usage into independently measured physical cost.
- Batch commitment: RFC 6962 Merkle trees over receipts
  (`crates/core/chio-core-types/src/merkle.rs`) into checkpoints
  (`crates/kernel/chio-kernel/src/checkpoint.rs`). The anchor crate can
  publish and confirm EVM roots. Rekor verifies a pinned-key SET and, when
  supplied, its RFC 6962 inclusion path. Its OTS witness client is advisory
  until trusted Bitcoin-header evidence is carried, and
  Solana memo helpers validate a supplied record but do not query the chain
  or establish finality
  (`crates/economy/chio-anchor/ARCHITECTURE.md:57-74`). A pending or
  structurally valid anchor record is not evidence that an external witness
  observed it.
- Runtime identity evidence, two layers: (a) TDX, SEV-SNP, and Nitro
  verifier profiles behind `tee-quotes` perform quote-signature and
  report-data binding checks against supplied collateral, tying
  `SHA256(kernel_pk || receipt_root)` to the quote
  (`crates/trust/chio-attest-verify/src/quote.rs:162`). The TDX profile does
  not yet perform full X.509 path validation, pin a full production quote and
  collateral corpus, or compare TDX measurements against an allowlist
  (`src/tdx.rs:53-90`). The kernel boot surface accepts an injected quote
  verifier; this tree does not wire a production boot implementation. (b)
  Cloud-verifier claims are
  normalized into `RuntimeAssuranceTier` and carried on governed receipts
  (`crates/economy/chio-appraisal/src/appraisal.rs:711`;
  `spec/PROTOCOL.md:944-953`). These attest a configured runtime identity
  boundary, not the semantic truth of a finding.
- Selective disclosure: real BBS signatures over the receipt projection (feature `bbs`), with `derive_selective_disclosure_proof` / `verify_selective_disclosure_proof` (`crates/trust/chio-selective-disclosure/src/lib.rs:1203,1269`); SD-JWT passports with holder binding (`crates/trust/chio-credentials/src/portable_sd_jwt.rs:263,375`); a full constrained-reveal artifact family (disclosure capsule, verifier privacy profile with leakage budgets, leakage ledger, signed lineage subgraph; `crates/trust/chio-disclosure-lineage/src/types.rs`).
- Set membership and non-membership: Merkle inclusion for
  receipts-in-checkpoints, plus an append-only Merkle revocation oracle producing
  signed epoch roots, inclusion proofs, and a non-inclusion query object
  checked against local oracle state. The current non-inclusion object has no
  portable path (`crates/trust/chio-revocation-oracle/src/api.rs:110-116`);
  M6 adds the strict portable finding-status proof.

The honest ceilings, three of them:

- **The codebase declares its own proof-capability boundary, and it should be quoted rather than paraphrased.** `ChioProofClaims` (`crates/trust/chio-attest-buyer-core/src/claims.rs:12-31`) ships with `bbs_reveal_set: true` and `hidden_range_predicates: false`, `vc_data_integrity_bbs: false`, `zkvm: false`, and `verify_claims` hard-rejects any proof package claiming the three unsupported capabilities (`src/proof_package.rs:51-72`). BBS reveal-set disclosure is the supported advanced proof; hidden range predicates and zkVM execution proofs are explicitly not supported. There is no zk-SNARK/STARK, Bulletproofs, zkVM, or PSI machinery anywhere in the workspace (repo-wide search; the `psi` hits are `EPSILON` false positives), and no blinded commit-reveal scheme (hash commitments only).
- **There is no hidden finding-predicate path.**
  `SUPPORTED_HIDDEN_PREDICATES` contains one amount predicate,
  `amount_lte_100`, whose result is delegated to a signed
  `DisclosureCryptoContextReport` from a trusted crypto-context signer
  (`crates/trust/chio-disclosure-lineage/src/verifier.rs:55-64`;
  `types.rs:93-107`). The current report binds an artifact reference and
  projection-manifest reference, not a canonical digest of each predicate
  and its proof evidence. A finding's `outcome_class` is public and is not a
  receipt-projection slot; its sealed payload is not a disclosure-lineage
  predicate carrier. Supporting a future hidden finding statement therefore
  requires a new typed carrier, canonical predicate/proof binding, an exact
  mapping to authenticated inputs, and a trusted verifier profile or new
  cryptography. It is not a registry edit.
- **Receipts prove kernel-observed events, not world states.** The spec says this in terms: provenance artifacts "prove kernel-observed evaluation events... None of these artifacts alone prove external real-world side effects beyond Chio's observation boundary" (`spec/PROTOCOL.md:1001-1004`), and concrete crypto/clock/storage/chain behavior is assumption-bounded (`spec/PROTOCOL.md:652-656`, `docs/reference/CLAIM_REGISTRY.md`). Under the applicable content-signing path, a receipt can prove that the kernel admitted an action and signed response digest D. Charge C is authoritative only when the separate mediated-spend profile and nonce/hold bindings verify; tier T records the assurance claim accepted by the kernel. Neither proves that the experiment honestly ran or that the hypothesis is false.

Two implementation caveats on the attestation chain, documented in-code as current limitations and repeated here so this memo does not oversell it: Sigstore verification currently reports `rekor_inclusion_verified = false` on all paths (cert chain and signature are checked; transparency-log inclusion is not yet; `crates/trust/chio-attest-verify/src/lib.rs:244-249`), and the TEE backends pin certificate chains by byte comparison to the vendor root rather than performing full X.509 path validation (`src/sev_snp.rs:420`, `src/nitro.rs:515`), while the report signature itself is cryptographically verified against the leaf key.

---

## 5. Gap analysis (Q1-Q8)

Each verdict is one of `supported today` / `partial` / `missing`, with the smallest honest extension named.

### Q1. Representation of a tradeable finding - **missing at snapshot; M0/M1 implemented**

Confidence: high.

At the evidence snapshot, no information-good type existed. The tradeable
goods were scoped tool-invocation rights (`ToolGrant`,
`crates/core/chio-core-types/src/capability/scope.rs:63`), resource/prompt
grants (same file), liability coverage
(`crates/economy/chio-market/src/placement.rs:96`), and marketplace
bonds/fees (`crates/economy/chio-open-market/src/fee_schedule.rs:71`).
M0/M1 has since implemented `chio.finding.v1`; the snapshot inventory still
explains why that extension was selected.

What comes close, and should be extended rather than replaced:

- The signed-listing pattern: `Listing` = registry artifact + operator-signed pricing hint + SLA + freshness (`crates/economy/chio-listing/src/discovery.rs:48,116,203`), with subject kinds currently `ToolServer | CredentialIssuer | CredentialVerifier | LiabilityProvider` (`src/listing.rs:24`).
- The evidence-bundle pattern: transaction-passport evidence graphs with digest-bound artifact closure (`crates/platform/chio-transaction-passport/src/evidence_graph.rs`, `spec/PROTOCOL.md:1070-1116`).
- The receipt lineage + cost metadata that a finding can reference as
  candidate production evidence (section 4).

A `Finding` artifact therefore needs (fields justified in section 6.1): a
claim descriptor (what question this answers, machine-matchable), a guarantee
class (what verification profile is claimed), and a replay-recipe digest for
deterministic replay; a reveal-envelope commitment (`payload_sha256`;
envelope digest per ARCHITECTURE 4.5, not raw bytes); evidence refs (receipt
ids and checkpoint ref); an asserted cost rollup and optional runtime tier;
an evidence class (`asserted`/`observed`/`verified`, reusing the normative
taxonomy at `spec/PROTOCOL.md:545-553`); bond ref, expiry, and a status ref
for later retraction. Negative results are the
`outcome_class = null_result` case of the same shape, not a separate type.
M1 implements and integrity-checks this shape. It does not authenticate the
semantics of its references.

### Q2. Verifiability today vs. aspirational - **partial**

Confidence: high (section 4 is the inventory).

Feasible today over the underlying artifacts: verify receipt signatures,
checkpoint membership, configured anchor evidence, the kernel-observed output
digest, declared runtime-assurance evidence, seller-track-record inputs, and
field-level selective disclosure of actual receipt slots. A full-receipt
profile can independently recompute kernel-accounted metered exposure after
signed reconciliation-nonce checks, and a separate settled-spend result after
qualifying capture or settlement proof. Realized cost may still originate in
tool-server reporting. A projected profile that hides those slots cannot turn
`Finding.evidence_cost` into a cost proof. None of these checks is currently
composed into a finding-aware offline verifier.

Small extension: M2's `FindingEvidenceVerifier` profile. It must start from
strict raw-schema parsing, then verify the finding's integrity; every receipt
body and signature; checkpoint membership and continuity; trusted kernel,
revocation, and acceptable anchor policy; issuer-to-evidence lineage;
full-receipt cost rollup when that mode is selected; liveness; live,
allocated bond backing; replay-recipe availability and digest; and the
permitted `guarantee_class` / `evidence_class` combination. If an intent
commitment is priced, it must resolve to authenticated evidence that predates
the producing receipts and whose `parameter_hash` commits to the finding
context and canonical protocol or replay recipe. The verifier returns an
explicit per-facet report and never silently upgrades an asserted,
unresolved, projected, or stale facet.

An intent commitment narrows one form of protocol hindsight only for the
published finding. It does not prove that the committed protocol is complete,
prevent a seller from making many precommitments, or prevent publication of
only the favorable result. Those remain selection-risk inputs to pricing and
auditing.

Open research (do not claim): arbitrary predicate proofs over experimental payloads ("this dataset shows no effect at p < .05"), trustless replacement of the crypto-context signer, and any ZK statement about what a computation semantically was (as opposed to which server/manifest/runtime executed it). The buyer-verification boundary already refuses packages that claim these capabilities (`ChioProofClaims`, `crates/trust/chio-attest-buyer-core/src/claims.rs:12-31`), which is the right default for the finding market too: findings must not be listable under proof claims the verifier cannot check. Section 7 tags the research rows.

### Q3. Arrow-resolution flow - **partial** (the founding composition is sketched in 6.2)

Confidence: high on the pieces; the composition is `[speculative]` until built.

Present today: commitment carriers (content digests, canonical JSON signing);
escrow entry points for release against the contract's expected Merkle proof
or operator settlement signature and refund after deadline
(`contracts/src/ChioEscrow.sol`; posture normative in ADR-0015 D1-D4);
dual-signature release and Merkle batch release
(`crates/economy/chio-settle/src/lib.rs:40-91`); kernel-level prepay/hold
whose selected reversible/refundable rail unwinds on confirmed pre-dispatch
refusal or abort (`crates/kernel/chio-kernel/src/kernel/dispatch.rs:418-480`).
Post-dispatch ambiguous outcomes deliberately do not receive that generic
refund (`crates/kernel/chio-kernel/src/kernel/tests/sim_payment.rs:344-365`).
Generic `accept()` is a pure validator: it checks a supplied
`SignedReservationReceipt` against a caller-selected public key and copies
its id into `AcceptedBid.bid_receipt_id`. It does not create a reservation,
resolve a configured authority, consult durable state, or capture payment.
That field is therefore not inherently proof of a kernel hold
(`crates/economy/chio-open-market/src/bidding.rs:246-511`).

Missing: any binding between "payment releases" and "information was
delivered". There is no commit-reveal, no HTLC/hashlock, no two-good atomic
swap (searched; the settlement explorer confirmed zero hits beyond
concurrency types). Section 6.2 records the founding composition: make
delivery a mediated tool call so a constraint-bound receipt can become
delivery evidence. Current code does not yet produce that proof. ARCHITECTURE
F3/6 and PLAN M3/M4 supersede the one-step sketch with the required digest,
purchase-context, reservation, portable-runtime, and recovery seams.

### Q4. Anti-fabrication / bonding - **partial** (mechanism present, Finding outcome path missing)

Confidence: high on mechanism; the fabricated-null trigger is partly research.

Present: bond requirements per marketplace role with `slashable: bool`
(`fee_schedule.rs:56`); penalty actions
`HoldBond | SlashBond | ReverseSlash` with effective states, where slashing
requires an enforced governance `Sanction` case and a slashable bond, with an
appeal/reversal state (`crates/economy/chio-open-market/src/evaluation.rs:356-451`);
and a frozen v1 abuse vocabulary that already includes
`FraudulentListing` (`src/penalty.rs:21`). On-chain impairment is
evidence-gated, bounded by remaining collateral, and requires exact-sum
beneficiary distribution
(`crates/economy/chio-settle/src/evm/prepare.rs:989-1020,1325`;
`contracts/src/ChioBondVault.sol`). Adjudicators and slash destinations remain
subject to ADR-0015's predeclared-governance boundaries.

Missing: the finding-specific challenge-outcome artifact and the decision
rule that distinguishes a fraudulent listing from an honest error. The
minimal compatible route does not extend the frozen enum. Target M2 uses
seller-signed `chio.finding.market-terms.v1` and governance-signed
`chio.finding.challenge-verifier-profile.v1`; target M5 adds signed,
registered `chio.finding.challenge.v1` and
`chio.finding.challenge-outcome.v1`. The profile pins the outcome-signing
role and trusted keys. A confirmed, class-specific outcome is referenced by
exactly one `OpenMarketEvidenceKind::External`, and the enforced unchanged-v1
penalty uses `OpenMarketAbuseClass::FraudulentListing`. The generic penalty
evaluator checks only a fee-schedule ceiling; the Finding wrapper must require
the exact computed amount and sealed allocation. Three trigger classes can
feed that route under their predeclared verdict rules (6.3): authenticated
seller-origin digest mismatch, affirmative receipt/checkpoint invalidity at
publication, and a confirmed deterministic replay contradiction. A
stochastic reproduction or indeterminate evaluation is not a fraud finding.
The residue (an honest-looking, evidence-backed result that is wrong
semantically) is priced risk, not adjudicable fraud.

The cost signal is conditional. In M1, `evidence_cost` is an issuer
assertion. In full-receipt mode, M2 can authenticate the selected receipts and
independently recompute the Finding's kernel-accounted metered exposure. A
distinct settled-spend facet additionally requires qualifying capture or
finalized settlement. Those are stronger than the issuer assertion, but
realized cost may still originate in tool-server reporting. A true
economic-burn floor additionally requires a
qualifying captured payment to an independently trusted provider or another
independently attested cost source. Projected evidence remains asserted until
audit, and no cost profile proves scientific honesty.

### Q5. Capacity leg in the same transaction - **partial** (carriers exist; Finding binding does not)

Confidence: high.

The receipt metadata already carries a versioned `economic_authorization`
envelope with separate typed sub-blocks for budget, metering, rail, and
settlement truth (`spec/PROTOCOL.md:920-927`;
`EconomicAuthorizationReceiptMetadata` with `amount_bounds`,
`pricing_basis`, `metering`, `liability_refs` including
`dispute_policy_ref`,
`crates/core/chio-core-types/src/receipt/economics.rs:246-262`).
`MeteredBillingQuote` is a pre-execution carrier in governed intent, but the
kernel does not authenticate its issuer or derive it from a Finding.
Settlement modes are explicit
(`MustPrepay | HoldCapture | AllowThenSettle`, `governance.rs:55`), and
post-execution usage evidence lands in a mutable sidecar rather than mutating
the signed receipt (`spec/PROTOCOL.md:974-978`). These are reusable carriers
for information-leg price and delivery-leg compute. They do not yet bind a
finding purchase, a trusted quote, and a delivered digest into one financial
state machine. Target M3/M4 adds admission and finalization seams, while
ADR-A must decide the exact rail profile and terminal policy. The leading
candidate is durable `HoldCapture` + `ReversibleHold`, with prepayment and
non-output-aware paths rejected and mismatch/ambiguity states defined
explicitly. No shipped payment adapter yet satisfies the full evidenced,
idempotent reversible profile. Multi-leg atomicity remains absent. Section
6.2 is a sequencing sketch, not a current fail-closed refund guarantee.

### Q6. Memory governance of purchased findings - **partial**

Confidence: high.

Present: governed memory writes produce hash-chained provenance entries binding store/key to the authorizing capability and receipt (`MemoryProvenanceEntry`, `crates/kernel/chio-kernel/src/memory_provenance.rs:63`; SQLite persistence with fork-resistant append, `crates/platform/chio-store-sqlite/src/memory_provenance_store.rs`); reads are provenance-checked and the verdict (`Verified` / `Unverified{NoProvenance|ChainTampered|ChainLinkBroken|StoreUnavailable}`) is annotated into the signed receipt (`memory_provenance.rs:141-158`, wired in `kernel/responses/allow_responses.rs:360,436`) - annotated, not denied; ingestion guards exist but are opt-in (store allowlists + content deny-patterns in `MemoryGovernanceGuard`, `crates/guards/chio-guards/src/memory_governance.rs:60-108`; vector-store gating, `crates/guards/chio-data-guards/src/vector_guard.rs:317`; embedding-anomaly similarity screening, `chio-guards/src/embedding_anomaly.rs:201`); generic blast-radius queries can reverse-walk from a revoked credential/capability to dependent receipts (`crates/observability/chio-lineage/src/query.rs:56`, `crates/platform/chio-store-sqlite/src/lineage_cte.rs:76`), but no typed Finding delivery-to-memory relation or Finding-aware consumer exists; signed epoch roots and local-state non-inclusion checks support revocation freshness inside one oracle, but the current query object is not a portable proof (`crates/trust/chio-revocation-oracle/src/api.rs:110-116`).

Missing: any retraction of data after distribution. The generic graph can
identify dependents of revoked authority, but a Finding datum does not yet
have the typed relation needed to enter that graph, and no tombstone,
kill-list, or consumer invalidates derived memory entries. Quarantine is an
advisory annotation rather than an enforced state. Section 6.5 targets this
with a Finding delivery edge, status feed, registered portable proof verified
by the kernel at purchase, durable publication-pending/outbox semantics, and
an injected provenance/status resolver for the opt-in guard. Automatic
downstream invalidation remains future work (engineering, not research).

### Q7. Pricing / elicitation under a budget - **missing** (mechanism), with the right anchors present

Confidence: high on what exists; the mechanism is `[speculative]` design.

What exists: fixed posted prices, unilaterally set by the seller
(`ListingPricingHint.price_per_call`, "Fixed price charged per invocation",
`crates/economy/chio-listing/src/discovery.rs:48-60`); buyer-side ceilings
only, where `bid()` rejects `BidCeilingTooLow` and quotes the sticker
(`crates/economy/chio-open-market/src/bidding.rs:365-371`); deterministic
price-adjustment idioms; a signed reservation-receipt carrier; and
pure `accept()` verification against a caller-selected public key and
supplied witness.
The cognition spike exercises the real `bid()` path, not `accept()` and not
the creation, durability, or economic sufficiency of a reservation. The
reservation body also carries opaque `agent_id`; M4 must bind it to the
buyer key and purchase context before it is authoritative for a finding.
There is no auction, negotiation, or willingness-to-pay machinery.

The valuation problem itself - what a dead end is worth - is open research
and stays open. The elicitation design (6.6) bounds instead of solves: a
buyer supplies a local, fresh re-derivation estimate, applies checked
deterministic arithmetic, and puts the result into the existing bid ceiling.
`MeteredBillingQuote` can carry a quote in governed intent, but the tree has
no general quote producer that authenticates its derivation from a finding
context or replay recipe. Until such a producer and binding exist, the
estimate is buyer-local policy. The signed bid records only the ceiling, not
its basis, so an operator cannot reconstruct or attest the buyer's reasoning.
Posted price plus a local ceiling remains the launch shape; batched auctions
are a later design.

### Q8. Clearing at swarm scale - **missing** at the venue, **partial** at the accounting layer

Confidence: high.

The current market path is one buyer, one listing, one synchronous mint - `bid()` is a pure function over a single `BidRequest` and a single resolved `Listing` (`crates/economy/chio-open-market/src/bidding.rs:308`); the only cross-participant aggregation is read-side cheapest-first ranking (`chio-listing/src/discovery.rs:440-465`). Nothing in the venue assumes or supports many-to-many matching, and the economic overview names auction/negotiation/A2A-routing as explicit gaps (`docs/protocols/ECONOMIC-LAYER-OVERVIEW.md` section 7).

The hierarchy the brief asks about partly exists one layer down: signed swarm
task graphs carry structural ceilings (`max_depth`, `max_fanout`) that
admission enforces over the graph, while unsigned pool/allocation objects do
fan-out reservation, fan-in release, per-task accounting, and terminal
rollups (`crates/kernel/chio-swarm-authority/src/types.rs:44-63,247-348`).
Neither `SwarmBudgetPool` nor `SwarmBudgetAllocation` has an issuer or
signature, the pool's top-level economic bound is one `total_units` value,
and graph signatures do not authenticate either as a portable spending
authorization. The scaling design in 6.7 is therefore a proposed
same-authority purchasing convention over this accounting substrate, not a
supported market-clearing or cross-operator budget layer.

---

## 6. Proposed design: the minimal extension set

Design stance: reuse the listing/bid/accept, escrow, bond, and governance
rails rather than introduce another venue or settlement system. The design
still adds an artifact family, a composed evidence verifier, kernel
constraints/finalization, and a true sparse status-map backend. At spike time
everything in this section was `[speculative]` design over cited primitives.
M0/M1 has since implemented the `Finding` artifact API and registered
`chio.finding.v1`; the evidence verifier, status feed, marketplace, and
kernel wiring remain target M2+. The current crate and protocol section, not
the sketch below, define the implemented wire surface.

### 6.1 The Finding artifact family (new, one crate-module worth of types)

M1 implements only `chio.finding.v1`. The normative wire surface is
`crates/economy/chio-finding/src/types.rs`, its fail-closed
artifact-integrity verifier is `src/validate.rs`, and protocol semantics are
in `spec/PROTOCOL.md` 6.4.7. The implemented `Finding` includes
`payload_media_type`; typed `MonetaryAmount` evidence cost,
`FindingEvidenceClass`, `RuntimeAssuranceTier`, and `PublicKey`; optional
`replay_recipe_sha256`, `intent_commitment_receipt_id`, `license_ref`, and
`price_hint_ref`; plus the descriptor, evidence, bond, status, validity, id,
and signature fields. `deterministic_replay` requires
`replay_recipe_sha256`.

Several M1 references are deliberately opaque strings, not verified foreign
keys. M2 must define `bond_ref` as a canonical fee-schedule requirement
digest plus a live, non-reusable seller-collateral allocation bound to
seller/listing/Finding. `ListingPricingHint` has no native hint id and its
signed scope includes `finding:<finding_id>`. Its signed-envelope digest
therefore cannot also participate in the Finding-id preimage through
`price_hint_ref` without a cycle. The M2 Finding-scoped projection requires
`price_hint_ref` absent and binds the exact Finding and hint envelopes in the
venue admission. Any future use of `price_hint_ref` must be a cycle-free
pre-Finding pricing-policy reference. Publication/search must verify those
bindings rather than infer meaning from nonempty text.

M1's `verify_finding` proves only structural invariants, the
content-addressed id, and the embedded issuer signature for an
already-deserialized `Finding`. Raw ingress must separately validate exact
bytes against the registered schema. Receipt, checkpoint, attestation, bond,
and status components are inputs to future profiles, but no current offline
verifier binds them, issuer lineage, cost, liveness, or
guarantee/evidence-class truth to a Finding. No
`chio.finding.status-epoch.v1` type or constant is implemented; that remains
M6. This outline is not a second normative definition.

Target M2 adds an explicit `FindingEvidenceVerifier`; it must not overload
`verify_finding`. Its inputs are strict raw Finding bytes, atomic canonical
receipt/checkpoint proofs, referenced replay inputs, externally pinned role
authorities, the selected evidence-sharing mode, and current time. It uses
strict signature and weak-key checks, verifies every checkpoint wrapper field
rather than only an inner Merkle path, authenticates producing attribution
through signed capability snapshots and transport identity, and keeps facets
separate: artifact integrity; receipt signatures and checkpoint membership;
trusted kernel identity and revocation; issuer attribution; intent-commitment
semantics; full-receipt authoritative-spend basis; replay-recipe availability
and digest; live, finding-specific bond allocation; Finding liveness; and
support for the claimed evidence and guarantee classes. Projected disclosure
authenticates only disclosed statements and cannot inherit concealed receipt,
checkpoint, or cost facets. Unsupported, unresolved, or unavailable facets
never upgrade the aggregate verdict. Portable finding-status freshness
remains M6.

M1 validates an optional `intent_commitment_receipt_id` only as a nonempty
string. M2 must resolve and authenticate the receipt, require it to predate
the producing receipts through one pinned log sequence or an admitted
anchored cross-log time relation, and bind its `parameter_hash` to the
versioned descriptor, canonical finding context, replay-recipe digest, and
protocol digest. That establishes only protocol-hindsight resistance for the
published Finding. It does not prove registration completeness, prevent many
precommitments, or prevent publishing only favorable outcomes.

Listing integration does not extend `GenericListingActorKind` (it is a
closed wire-frozen enum,
`crates/economy/chio-listing/src/listing.rs:24`). Target M2 lists the
seller's server under `ToolServer` and binds an immutable Finding resolver
and exact signed-pricing-envelope digest to the listing. The M1 test proves
only that a signed Finding id can appear in a hand-built listing/request
scope and clear `bid()`. Generic discovery does not persist or load a
Finding, evaluate its liveness, or match `descriptor.context_sha256`; M2 must
add that authenticated projection and bounded search path. The generic
minted grant also drops the opaque scope, so provider-to-Finding grant
binding remains M4.

### 6.2 Founding Arrow-flow sketch: reveal as a governed tool call

This section preserves the founding composition, not an executable
current-main design. ARCHITECTURE F3/6 and PLAN M3/M4 supersede its original
one-guard-step assumption after pipeline verification exposed separate
digest-finalization, financial-terminal-state, purchase-binding,
portable-runtime, and crash-recovery seams.

The load-bearing move remains: **the seller serves the sealed payload as a
Chio tool server, and the reveal is a mediated `read_finding` invocation.**
That lets commit -> prove -> escrow -> conditional release -> slash reuse
existing machinery, once the missing seams are implemented:

1. **Commit.** Seller publishes the signed `Finding` and listing. At current
   M1 the buyer can verify only artifact integrity. Target M2's
   `FindingEvidenceVerifier` composes strict raw ingress,
   receipt/checkpoint/trust/lineage checks, evidence-mode-specific cost
   treatment, intent semantics, liveness, bond allocation, and
   guarantee-class support into a facet report. Existing attest-buyer APIs
   are component precedents, not a Finding verifier.
2. **Bid / accept.** The current generic `bid()` path can mint a
   one-invocation `read_finding` token and enforce a posted-price ceiling, but
   M1's cognition test stops there. Generic `accept()` separately requires a
   verified reservation witness. In target M4, an authoritative buyer/kernel
   step first reserves budget and produces the exact witness; pure `accept()`
   then validates and binds it. Neither step authorizes or captures external
   payment. The accepted handshake must bind the exact original
   `SignedBidRequest`, signed ask and byte-identical token offer, bid
   signer-to-token-subject mapping, and durable reservation state. The grant
   is DPoP-bound, one-invocation, carries exactly one output digest and one
   purchase marker, and sets both monetary ceilings equal to the accepted
   price. An `AcceptedBid` reference alone is insufficient because it carries
   bid/ask body digests rather than the exact signed envelopes, and only
   `bid_receipt_id` rather than the signed reservation and authoritative
   durable state.
3. **Escrow.** Target M4's small-purchase profile uses durable direct
   evaluation with `MeteredSettlementMode::HoldCapture` and
   `PaymentRailMode::ReversibleHold`. After purchase, policy, and identity
   checks pass, reveal admission authorizes the exact price as a reversible
   `Held` payment before dispatch. It captures only after the identity-profile
   output passes digest and media-type checks. A mismatch persists a signed
   Deny, releases the rail hold plus budget/exposure reservations exactly
   once, and cannot capture; because no transfer completed, that is a hold
   release, not a refund. Reserve-for-caller `MustPrepay`, `PrepaidFinal`,
   legacy financial dispatch, and portable evaluators without atomic
   output-aware finalization are ineligible. A qualifying adapter must provide
   evidenced, idempotent authorize/capture/release/refund terminals; the
   shipped ACP terminal methods are synthetic and x402 is final, so no current
   adapter yet qualifies. Confirmed pre-dispatch refusal can unwind a
   qualifying rail, while post-dispatch ambiguity remains pending for durable
   recovery rather than receiving a generic refund
   (`crates/kernel/chio-kernel/src/kernel/tests/sim_payment.rs:344-365`).
   Large/cross-org purchases use an initially unreleased
   `ChioEscrow.createEscrow` whose verified beneficiary is the seller and
   whose funded amount is the exact accepted price. This M7 path is blocked on
   ADR-C. The current contract's signature and partial-proof release entry
   points can bypass an off-chain Finding wrapper, so a no-contract-change
   deployment is only an audited Experimental TTP profile, not cryptographic
   full-only enforcement. A qualified contract-gated profile allows only one
   full terminal: full release after the authorized settlement receipt or
   full refund after the deadline. Existing partial-release methods, prior
   partial release, mixed release/refund, and amount drift reject only within
   that profile. Release requires a predeclared beneficiary-controlled
   submitter; the external watchdog is not implicit release authority.
   Timeout refund is permissionless only after the deadline, and the escrow
   administrator can pause release through that deadline, so the
   administrator, submitter, and watchdog SLA remain explicit trust. Target
   M7 still needs ADR-C, finding-aware settlement-authority evidence, and the
   mediator trust profile.
4. **Reveal becomes delivery proof after M3/M4.** Buyer invokes
   `read_finding` through the kernel. The target receipt binds the canonical
   reveal-envelope digest as `content_hash`, and kernel finalization compares
   it with the grant's `OutputDigestSha256`. The grant also carries
   `RequireFindingPurchase` with exact finding/listing ids and a signed
   local-hold or cross-org-escrow settlement selector. Cross-org additionally
   commits the exact settlement-profile digest and cannot fall back by
   omitting its escrow-witness context. Admission verifies the signed finding,
   exact bid/ask/token, provider/seller/payee identity, accepted price and
   currency, buyer mapping, and authoritative reservation before the overlay
   can be emitted. The actual request's `finding_id` must equal the marker
   and signed Finding. This is not an ordinary post-invocation guard: the durable and
   legacy payment lanes need the explicit fail-closed transitions in
   ARCHITECTURE 6, while portable profiles must reject until they have
   atomic output-aware finalization. The v1 profile is restricted to an
   authenticated read-only `read_finding` tool and one selected grant with
   exactly one canonical output digest. Once implemented, the resulting receipt
   can feed the later escrow proof wiring (`releaseWithProofDetailed`,
   `contracts/src/ChioEscrow.sol`; batch form `prepare_merkle_release`,
   `crates/economy/chio-settle/src/lib.rs`). It does not do so today.
5. **Post-reveal window.** The purchase receipt's
   `liability_refs.dispute_policy_ref`
   (`crates/core/chio-core-types/src/receipt/economics.rs:256`) names the exact
   seller-signed `chio.finding.market-terms.v1` digest. Those admitted terms
   carry nonzero filing, claim, and appeal windows plus the predeclared
   challenge rules; no generic settlement-window default establishes the
   Finding policy. Challenges and slashing follow 6.3.

What Arrow's paradox would reduce to under the completed flow, stated
honestly: the buyer decides under the descriptor + evidence bundle + seller
bond/reputation, not under the finding content. Payment-versus-delivery is
the M3/M4/M7 target, not a solved current property. Even after that binding
lands, value-versus-content is not solvable in general: the buyer can still
find the revealed content useless while the claim is technically true. That
residual is handled economically (guarantee-class pricing, bonds,
reputation, dispute window for claim-vs-content mismatch), which is the
elicitation thesis of the brief rather than a failure of it.

### 6.3 Anti-fabrication stack (defense in depth, mostly existing)

Ordered from mechanical to economic; the first three are adjudicable under predeclared rules (ADR-0015 D5 discipline), the last two are pricing:

Target M2 freezes those rules in seller-signed
`chio.finding.market-terms.v1` and governance-signed
`chio.finding.challenge-verifier-profile.v1`. The latter pins receipt,
checkpoint, replay, and outcome-signing roles and keys, key rotation and
revocation policy, retention/resolution policy, resource bounds, allowed
closed predicates, and class-specific challenge-bond ceilings. Target M5's
signed `chio.finding.challenge.v1` admits exactly one class-specific evidence
branch. Its signed `chio.finding.challenge-outcome.v1` is accepted only under
the precommitted outcome-signing role and binds the class, exact profile and
evidence digests, and class verdict.

1. **Digest fraud** - delivered bytes vs. committed `payload_sha256`: the
   M3/M4 target prevents it at reveal finalization. Seller-fraud evidence is
   valid only for an authenticated seller-origin mismatch under M4's marked
   identity-output profile; an operator-policy transform is a non-slashable
   policy incompatibility. Until those milestones land, the prevention claim
   is not implemented.
2. **Evidence fraud** - the finding's receipts fail signature / checkpoint /
   revocation verification. The component checks exist today (the insurance
   claim path re-verifies receipt evidence fail-closed,
   `crates/economy/chio-market/src/insurance_flow.rs:390-414`), but no
   finding-aware evaluator composes them. M5 creates a typed finding
   challenge/outcome and re-verifies its evidence
   fail-closed. Only affirmative cryptographic invalidity or
   revoked-at-publication evidence is fabrication evidence. Resolver
   unavailability is an SLA/indeterminate outcome, and later key revocation
   or Finding retraction is not retroactive seller fraud. A verified fraud
   outcome feeds the existing frozen
   `chio.registry.market-penalty.v1` path as
   `OpenMarketAbuseClass::FraudulentListing`, with the outcome referenced by
   exactly one `OpenMarketEvidenceKind::External` carrying the deterministic
   outcome id and digest of the complete canonical signed envelope. No new
   penalty schema or abuse enum is required solely for finding fraud. A
   finding-specific wrapper strict-parses and re-verifies that envelope and
   every Finding, listing, purchase, rule, liability, and evidence binding.
   The generic penalty evaluator enforces only
   `penalty_amount <= fee_schedule.required_amount`; the wrapper therefore
   requires exact equality to the computed amount and sealed live allocation.
   It then admits only the predeclared `HoldBond -> BondHeld`, appeal
   `ReverseSlash` over that unapplied hold, or final
   `SlashBond -> BondSlashed` branch through the existing enforced-Sanction
   architecture. Exact-sum validation does not structurally prove harmed-party
   destinations: until ADR-0015 follow-up A, a signed finding-specific
   operator authorization applies the allowlist at an operator-mediated choke
   point.
3. **Reproduction contradiction** - target M5 uses an effectful governed
   executor to rerun a content-addressed recipe that binds the purchased
   payload, exact inputs/environment, role-authorized runner, and a closed
   verdict predicate. A pure evaluator then verifies completed observation
   bytes against checkpointed receipts and returns
   `ConfirmedContradiction | Consistent | Indeterminate`; generic receipts
   alone do not establish semantic replay. The challenger needs a new live,
   exclusive lock bound to the challenge and existing `Dispute` bond
   requirement (`fee_schedule.rs:14`), not merely an opaque bond reference.
   Its amount comes from the admitted class-specific terms and is bounded by
   the governance profile, not by seller-selected replay cost for every
   class. Timeout, unavailable inputs, runner errors, and unresolved trust
   inputs are `Indeterminate`: they create no fraud outcome, seller hold,
   Sanction, impairment, payout, or retraction and never forfeit the lock for
   infrastructure failure. The same lock may remain through one bounded
   signed retry window, then returns exactly once. `Consistent` follows the
   predeclared failed-challenge disposition; only
   `ConfirmedContradiction` confirms this class. Stochastic replication
   remains research-adjacent.
4. **Evidence-cost signal, mode-bound** - `evidence_cost` is issuer-asserted
   in M1. Full-receipt evidence whose receipt set is authenticated, bound to
   the context or recipe, and independently summed under a compatible
   authority profile supports an authenticated kernel-accounted metered
   exposure rollup. A distinct settled-spend facet requires qualifying
   capture or finalized settlement. Neither becomes an economic-burn floor
   without an independently attested cost source. Projected evidence
   does not support this claim before audit.
5. **Reputation and Sybil resistance** - scorecards are computed only over integrity-gated receipts (`crates/trust/chio-reputation/src/lib.rs:50-74`) and Tier3 requires distinct evidence feeds (`src/tier.rs:98-139`), so burning a fabricator identity is expensive to repeat.

Honest residual (research, section 7): a
semantically-wrong-but-honestly-produced null cannot be adjudicated as fraud.
A fabricator who obtains authentic kernel-accounted charge evidence or even
pays a comparable real cost can still publish a wrong claim. That defeats the
economic signal for `MeteredAttested` findings; only replay-checkable
guarantee classes shrink the semantic hole. Runtime attestation alone does
not verify the science.

Agents-as-principals check: buyers, sellers, and challengers in the target
design are agent subjects. The roster-anchored adjudicator (ADR-0015
follow-up B) is today an institutional role. For `DeterministicReplay`
findings, target M5 can make the decision rule a verifier running the
predeclared replay check. For everything else, a predeclared roster remains,
and this memo does not pretend otherwise.

### 6.4 Capacity leg

No new metering primitive is required. A target reveal call can be metered
like any tool call, and M4 can reuse the receipt
`economic_authorization` envelope for budget, metering, rail, and settlement
observations (`crates/core/chio-core-types/src/receipt/economics.rs:262`).
A buyer who pays for a verification rerun consumes ordinary metered capacity
under the selected budget profile. Evidence receipts may record
kernel-accounted charges for producer capacity. They do not independently
prove instrument time or real resource consumption; a stronger cost profile
must bind an independently trusted provider or captured payment.

### 6.5 Memory governance of purchased findings

- **Provenance-in (primitive exists; Finding edge is new):** governed memory
  writes can bind store/key to an authorizing capability and receipt
  (`crates/kernel/chio-kernel/src/memory_provenance.rs:63`). M4 must add the
  typed purchase-delivery-to-memory edge before a buyer can attribute an
  ingested payload to a Finding. Reads carry the generic provenance verdict
  in the signed receipt.
- **Retraction feed (new, pattern exists):** publish finding status on a
  domain-separated status map keyed by `finding_id`. The current
  revocation-oracle API supplies signed roots over an append-only ordinary
  Merkle log and checks non-inclusion against local state; its root cannot
  support a portable absence proof
  (`crates/trust/chio-revocation-oracle/src/api.rs:70-116`,
  `src/sparse_merkle.rs:1-79`). M6 adds a versioned true sparse authenticated
  map and a fully domain-bound outer epoch artifact over feed id, operator,
  algorithm/version, epoch, root, predecessor, and validity. It registers a
  strict portable proof input, pins the feed/operator and root-signing policy,
  and requires a monotonic trusted latest-root source plus freshness bound:
  a caller-provided internally valid root cannot prove it is latest. Kernel
  admission verifies the proof against that trusted root and durable
  publication-pending/outbox handling before purchase freshness is claimed.
- **Quarantine-on-retraction (new, opt-in guard rule):** inject a synchronous
  resolver into `MemoryGovernanceGuard`
  (`crates/guards/chio-guards/src/memory_governance.rs:60`) backed by verified
  provenance, a typed write-to-delivery lineage edge, and an authenticated
  status cache. Missing, stale, unavailable, or retracted state denies for
  policy-selected stores.
- **Blast radius (query primitive exists):** once M4 writes the typed
  delivery lineage edge, reverse lineage can enumerate dependent actions
  (`crates/observability/chio-lineage/src/query.rs:56`). What to do about
  derived conclusions is buyer policy. Automatic invalidation remains future
  engineering.
- **Poisoning resistance (generic guards exist, opt-in):** content
  deny-patterns, vector-store allowlists, and embedding-anomaly screening
  (`chio-guards`, `chio-data-guards`) can apply to the payload. Payment grants
  no ingestion privilege. Target evidence-class policy can block
  `Asserted` findings rather than silently upgrade them.

### 6.6 Elicitation interface (pricing without pretending to value)

The buyer-side interface, honest about what it computes:

```rust
/// Inputs a buying agent can actually obtain. No field claims to be
/// "the value of the finding".
pub struct FindingBidBasis {
    /// Buyer-local monetary estimate of re-deriving this exact context and
    /// recipe. In M1 this is an injected amount, not an authenticated
    /// MeteredBillingQuote. Raw billing quantity is not money.
    pub rederivation_cost: MonetaryAmount,
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
    /// Buyer-local remaining amount used to limit this calculation.
    /// `SwarmBudgetAllocation` is unsigned accounting state, not authority.
    /// This is a hard enforced cap only when an authenticated spending
    /// envelope and qualifying authoritative budget backend bind it.
    /// Must use the same currency as rederivation_cost.
    pub budget_remaining: MonetaryAmount,
}

/// ceiling = min(budget_remaining,
///     rederivation_cost x would_have_run x (1 - redundancy) x class)
/// Reject currency mismatch, bps outside 0..=10_000, overflow, and
/// non-canonical numeric inputs. Apply one specified integer rounding rule.
pub fn finding_bid_ceiling(
    basis: &FindingBidBasis,
) -> Result<MonetaryAmount, BidBasisError> { /* target sketch */ }
```

The function is deterministic only for a buyer that retains its basis. The
signed bid carries the resulting ceiling, not the basis, so the venue cannot
reconstruct it. The current test injects a raw `u64`, proves bounded
arithmetic, and shows that the real `bid()` path clears at the ceiling and
rejects above it. It does not produce or authenticate a
`MeteredBillingQuote`, exercise `accept()`, or prove a reservation. The
test's local helper clamps basis points and uses saturating conversion; those
are spike conveniences, not the target rule.

Target M8 must specify matching currency, rejection of basis points outside
`0..=10_000`, checked wide-integer arithmetic, and exact rounding. An
optional trusted quote producer would also need signer policy, freshness,
and binding to the finding context, replay recipe, provider, and
`quoted_cost`. `MeteredBillingQuote.quoted_units` is a billing quantity and
must never be treated as monetary minor units. Without that producer, the
ceiling remains buyer-local policy. The launch mechanism is still the
existing posted-price ceiling check (`BidCeilingTooLow`, `bidding.rs:365`);
rigorous dead-end valuation stays open.

### 6.7 Swarm-scale clearing

Target convention: **one purchasing principal per authenticated pool
authority.** A sub-swarm planner aggregates members' failing contexts,
deduplicates matches, and issues at most one bid per descriptor from a
dedicated purchasing allocation. Purchased findings distribute
pool-internally as governed memory writes. The shipped task-graph signatures
cover graph structure, not the unsigned `SwarmBudgetPool` or
`SwarmBudgetAllocation`; target deployment must keep both inside one trusted
authority backed by a qualifying budget store or add an authenticated
spending envelope. Cross-pool, the venue stays bilateral. This is an
accounting and purchasing convention, not new clearing theory. Cross-pool
demand aggregation remains undesigned.

### 6.8 What is deliberately not proposed

- No new settlement rail, no new escrow contract, no protocol-level atomic
  swap. Target M3-M7 instead makes the mediating kernel and settlement
  authority the explicit trusted third party for digest-bound delivery.
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
| 2 | Verifying null results whose claim is not replay-checkable ("we ran it and nothing happened" for stochastic/wet-lab experiments) | research | Predeclared replication protocols are partial; both an honest-but-wrong seller and a fabricator with authentic kernel-accounted charge evidence survive 6.3 for `MeteredAttested` findings |
| 3 | Rich predicate proofs over sealed payloads | research | BBS discloses receipt fields, not payload predicates. The one shipped registry predicate relies on a trusted report that does not provide a safe finding-field mapping or canonical per-predicate proof binding. General ZK over experimental data is aspirational |
| 4 | De-institutionalized dispute resolution (adjudicator = verifier) beyond deterministic replay | research | Roster-anchored adjudication (ADR-0015 follow-up B) persists for everything non-mechanical; acceptable for the wedge, unresolved for the vision |
| 5 | Cross-org trust bootstrapping for seller bonds and status feeds (whose oracle, whose sanction authority, between strangers) | research (mechanism) / engineering (transport) | Federation surfaces exist but are curated-bounded by design (`spec/PROTOCOL.md:3451-3461` explicitly excludes permissionless marketplace semantics from v1); ADR-0014 defers the transport |
| 6 | Cross-pool demand aggregation (many pools jointly worth more than a finding's price) | research-adjacent | Classic public-goods/combinatorial territory; deliberately not designed in 6.7 |
| 7 | Composed Finding evidence verification, publication, bond allocation, and listing/search integration | engineering | The artifact and integrity verifier ship at M1. M2 adds `FindingEvidenceVerifier` and publication under the existing `ToolServer` actor kind |
| 8 | `read_finding` delivery profile, digest enforcement, purchase/reservation binding, and later escrow wiring | engineering | 6.2; current receipts/escrow are reusable carriers, but the M3/M4 enforcement seams remain |
| 9 | Typed finding challenge/outcome + deterministic replay evaluator + v1 penalty mapping | engineering | A role-authorized, class-confirmed outcome maps to frozen v1 `FraudulentListing` with exactly one digest-bound `External` reference; no finding-specific abuse enum is needed |
| 10 | Finding-status feed + registered portable proof/path + kernel purchase check + quarantine resolver | engineering | 6.5; signed-root/local-query substrate exists, but the true sparse backend, fully domain-bound outer epoch artifact, trusted latest-root policy, portable proof, and enforcement do not |
| 11 | Finding-specific selective-proof carrier and trusted-verifier mapping | engineering | `outcome_class` is public and absent from the receipt projection. A future profile needs canonical predicate/proof binding and exact field mapping; removing the trusted signer remains research |
| 12 | Pool-level purchasing convention in swarm planners | engineering | 6.7; the current pool is unsigned, so same-authority deployment or a new authenticated spending envelope is required |
| 13 | Optional context/recipe-bound quote producer | engineering | Without trusted signer, freshness, provider, currency, and `quoted_cost` binding, re-derivation cost remains buyer-local and the venue cannot verify the bid basis |

---

## 8. Feasibility and sequencing recommendation

**Verdict: feasible as an extension, not a new system - provided the first instance is the coding-agent swarm.** Confidence: high on the primitive inventory (sections 3-5), moderate on the composition (6.2 is designed, not built), low on marketplace liquidity questions (out of scope for a repo spike).

Why the coding-agent wedge first:

1. Its target findings are `DeterministicReplay`-class: "this patch makes
   suite digest S pass at commit C" can be checked by a mediated rerun once
   M2 resolves the recipe input and M5 supplies the challenge evaluator. M1
   stores only the recipe digest. The R&D lab instance keeps every interface
   but inherits stochastic verification and institutional adjudication at
   full strength.
2. Its likely buyers already run under Chio mediation with budgets and
   receipts. M4 must still bind the bid signer, token subject, buyer identity,
   and reservation; current generic bidding does not complete that chain.
3. Its re-derivation workload is unusually concrete, so a buyer can form a
   local substitute-cost estimate. That estimate is not authenticated by
   shipped quote machinery today: `MeteredBillingQuote` is caller-carried,
   and the M1 test uses an injected number. `chio-eval-receipt` is a useful
   precedent for fail-closed corpus/receipt verification
   (`crates/sdk/chio-eval-receipt/src/verify.rs:159`), but no current API
   composes it with a Finding. M2 supplies the Finding evidence verifier; M8
   decides whether to add a trusted context-bound quote producer.
4. Everything it forces to be built (rows 7-13 in section 7) is reusable by
   the R&D instance; the wedge primarily avoids the stochastic semantic
   verification problem.

Sequencing (each step is independently useful; stop-loss after any):

1. **Spec + types spike** (achieved by M0/M1): finding artifact family, ADR, registered schema, golden, and flow test naming the seams. No production market wiring.
2. **Publish, delivery contract, and wedge purchase:** M2 supplies the
   composed evidence verifier plus publication/admission, M3 defines generic
   output-digest enforcement and its financial terminal state, and M4 binds
   the provider-minted grant to the exact signed bid/ask, verified finding,
   authoritative reservation, reference server, and explicit crash-recovery
   authorization. The combined M2-M4 work targets a one-operator
   publish/buy/reveal dogfood path; it remains dark and unqualified until M9.
3. **Bond + challenge lane:** a typed finding challenge/outcome, deterministic
   replay rule, and mapping into frozen v1 `FraudulentListing` with exactly
   one role-authorized, digest-bound `External` outcome, then exact-amount
   hold/appeal/slash wiring through the existing sanction gate.
4. **Status feed + quarantine guard:** M6 makes retraction operational with
   portable proof verification, durable publication pending/outbox state,
   and fail-closed lineage/status resolution at purchase and memory read.
5. **Escrow path for cross-org amounts** (only if bilateral federation
   demand exists): first resolve ADR-C. It must choose a contract-level
   Finding/full-only discriminator or an explicitly audited Experimental TTP
   profile, because current alternative release entry points bypass an
   off-chain wrapper. Then add a finding-aware settlement-authority receipt or
   adapter that binds delivery, escrow, capability, accepted bid, parties,
   amount, and finality into the proof shape `ChioEscrow` expects. A qualified
   contract-gated profile admits only an initially unreleased, exactly funded
   escrow with full accepted-price release or full deadline refund. The
   contract and release functions exist; a raw delivery receipt is not
   sufficient today, partial/mixed terminals are outside the Finding profile,
   and release still requires the predeclared beneficiary-controlled
   submitter rather than an implicit watchdog authority.
6. **Only then** revisit the R&D instance and the research rows (1-5) with usage data - especially whether elicited ceilings and posted prices actually clear, before any auction work.

The honest bottom line for a reader deciding whether to fund this: Chio has
unusually relevant foundations, including mode-bound kernel-accounted
charges, bond and sanction machinery, predeclared escrow functions,
provenance-tagged ingestion, and hierarchical task accounting. They are not
yet composed into authenticated Finding evidence or a purchase flow, and
their formal claims remain bounded by the published proof registry. The
engineering program is bounded but not a single digest step: M0/M1 supplies
the good type, M2 the evidence verifier and publication, M3 the generic
kernel delivery contract, and M4 the authenticated one-operator purchase and
recovery path. The parts that remain hard (pricing dead ends, verifying
nulls, trustless predicates) are hard for reasons no codebase fixes, which is
why the target design uses buyer-local ceilings, bonds, audits, and explicit
guarantee classes instead of pretending to verify science.
