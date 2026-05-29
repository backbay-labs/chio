# Chio Post-31 External Programs

> **Date**: 2026-04-16
> **Scope**: Work required after the numbered post-roadmap closure phases end
> in `docs/POST_ROADMAP_ADDENDUM.md`
>
> **Relationship to the roadmap**: This is a companion program document, not a
> continuation of the numbered roadmap.
>
> **Authority rule**: This document does not define ship truth. Ship-facing
> claim authority remains `docs/release/QUALIFICATION.md` and
> `docs/release/RELEASE_AUDIT.md`. This document defines external evidence
> programs and research boundaries only.

---

## Why This Document Exists

The post-roadmap addendum closes the remaining repo-solvable Chio work.
The strongest Chio vision still requires evidence that repository work cannot
manufacture by itself:

- outside standards legitimacy
- trust portability exercised across real peers
- operator and partner dependence on Chio truth
- market evidence that Chio is relied on as control-plane substrate rather than
  merely integrated as optional software

Those are not normal product phases, so they should not be represented as more
numbered roadmap items.

---

## Execution Order

These programs should not start as one undifferentiated blob.
The recommended order is:

1. Program A repo-prep and qualification scaffolding
2. Program A external-peer qualification
3. Program B proof-bundle and pilot scaffolding
4. Program B operator and partner dependence evidence
5. Program B insurance, marketplace, and broader market-validation evidence

This order is deliberate.
Program B claims are weaker and noisier if Chio does not first have a clean
standards, portability, and qualification story with checked artifacts.

---

## Current Repo Baseline

The repo already contains meaningful substrate for both external programs.
What it does not yet contain is independent external evidence that those
surfaces are relied on outside Chio's own operator boundary.

- Standards, claim-boundary, and qualification substrate already exists in
  [`docs/release/QUALIFICATION.md`](../release/QUALIFICATION.md),
  [`docs/release/RELEASE_AUDIT.md`](../release/RELEASE_AUDIT.md),
  [`docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`](../standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md),
  [`docs/standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json`](../standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json),
  and [`spec/PROTOCOL.md`](../../spec/PROTOCOL.md).
- Identity, passport, and federation substrate already exists in
  [`crates/chio-core/src/identity_network.rs`](../../crates/chio-core/src/identity_network.rs),
  [`crates/chio-did/src/lib.rs`](../../crates/chio-did/src/lib.rs),
  [`crates/chio-credentials/src/oid4vci.rs`](../../crates/chio-credentials/src/oid4vci.rs),
  [`crates/chio-credentials/src/oid4vp.rs`](../../crates/chio-credentials/src/oid4vp.rs),
  [`crates/chio-federation/src/lib.rs`](../../crates/chio-federation/src/lib.rs),
  and [`docs/IDENTITY_FEDERATION_GUIDE.md`](../reference/IDENTITY_FEDERATION_GUIDE.md).
- Market-facing and external-proof substrate already exists in
  [`crates/chio-market/src/lib.rs`](../../crates/chio-market/src/lib.rs),
  [`crates/chio-store-sqlite/src/receipt_store/liability_market.rs`](../../crates/chio-store-sqlite/src/receipt_store/liability_market.rs),
  [`crates/chio-store-sqlite/src/receipt_store/liability_claims.rs`](../../crates/chio-store-sqlite/src/receipt_store/liability_claims.rs),
  [`docs/release/PARTNER_PROOF.md`](../release/PARTNER_PROOF.md), and
  [`docs/release/CHIO_COMPTROLLER_MARKET_POSITION_PROOF.md`](../release/CHIO_COMPTROLLER_MARKET_POSITION_PROOF.md).

---

## Program A: Standards And Trust-Portability Qualification

> **Goal**: Prove that Chio semantics are accepted across real peers and that
> trust-portable artifacts remain bounded, qualified, and interoperable outside
> one local operator surface.

### Current Repo Baseline

- [`docs/standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json`](../standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json),
  [`docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`](../standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md),
  and [`spec/PROTOCOL.md`](../../spec/PROTOCOL.md) already define large parts of
  Chio's claim-boundary and interoperability story, but not yet as one checked
  external-facing registry.
- [`crates/chio-core/src/identity_network.rs`](../../crates/chio-core/src/identity_network.rs),
  [`crates/chio-federation/src/lib.rs`](../../crates/chio-federation/src/lib.rs),
  [`crates/chio-did/src/lib.rs`](../../crates/chio-did/src/lib.rs),
  [`crates/chio-credentials/src/oid4vci.rs`](../../crates/chio-credentials/src/oid4vci.rs),
  and [`crates/chio-credentials/src/oid4vp.rs`](../../crates/chio-credentials/src/oid4vp.rs)
  already give Chio real portability and identity substrate. Program A turns
  that repo-local substrate into checked and reviewable peer evidence.

### Evidence Categories

- checked qualification matrices for compatibility, profile, and identity
  claims
- external peer qualification runs for MCP, A2A, identity, federation, and
  trust-portability surfaces
- issuer descriptor, subject continuity, and passport-clearing artifacts used
  with real counterparties
- explicit bounded-profile language for native protocol, compatibility, bridge,
  product, and research claims
- artifact packages that a third party can inspect without relying on prose
  alone

### Exit Criteria

- Chio compatibility and portability claims are backed by checked artifacts and
  external-peer qualification runs
- a relying party can evaluate issuer accountability, subject continuity, and
  trust-portability bounds without bilateral private assumptions
- standards-facing and identity-facing claims are separated cleanly from market
  position claims

### Non-Goals

- proving that Chio already has market dominance
- widening release claims beyond the qualified bounded release boundary
- turning research surfaces into product truth by prose
- treating research-track prototypes, benchmark notes, or feasibility memos as
  Program A evidence or exit-criteria substitutes

### Program A Tracks

#### A1. Claim Taxonomy And Qualification Matrix Closure

**Why**: Chio still needs one explicit distinction between native protocol,
compatibility, bridge, product/platform, external-proof, and research claims.
Here, `research claims` means explicitly non-ship, non-program claim classes
tracked for boundary discipline, not hidden Program A deliverables.

**Existing substrate**:
[`docs/standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json`](../standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json),
[`docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`](../standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md),
and [`spec/PROTOCOL.md`](../../spec/PROTOCOL.md) already cover parts of this
taxonomy. The missing step is unifying them into one checked claim registry.

**Repo-prep work**:
- add one checked claim registry for those claim classes
- add qualification matrices for MCP, A2A, identity, federation, and passport
  portability surfaces
- align README, spec, release docs, standards docs, and planning docs to the
  same claim taxonomy

**Evidence output**:
- machine-readable qualification matrices
- one claim registry or claim-boundary index
- one reviewer-facing standards positioning pack

**Done when**:
- top-level standards and compatibility claims resolve to checked artifacts
- no standards-facing claim survives as prose-only positioning

#### A2. External Peer Qualification Harness

**Why**: Chio cannot claim broad interoperability if qualification only runs
against Chio-owned demos or local adapters.

**Existing substrate**:
[`docs/standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json`](../standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json),
[`crates/chio-core/src/identity_network.rs`](../../crates/chio-core/src/identity_network.rs),
[`crates/chio-federation/src/lib.rs`](../../crates/chio-federation/src/lib.rs),
and the OID portability surfaces in
[`crates/chio-credentials/src/oid4vci.rs`](../../crates/chio-credentials/src/oid4vci.rs)
and [`crates/chio-credentials/src/oid4vp.rs`](../../crates/chio-credentials/src/oid4vp.rs)
already give Chio something to qualify. The gap is repeatable testing against
external peers instead of Chio-owned fixtures alone.

**Repo-prep work**:
- define repeatable peer-qualification harnesses for MCP, A2A, identity, and
  federation scenarios
- define artifact capture rules for peer version, profile, limitations, and
  failure classification
- define one bounded matrix entry format for partial, profile-bound, and
  compatibility-only results

**External evidence work**:
- run the harnesses against real external peers
- publish qualification results with bounded-profile language

**Done when**:
- external peer qualification can be repeated and reviewed without reading
  prose alone
- Chio claims tested compatibility profiles instead of implying general support

#### A3. Issuer Descriptor And Independence Policy

**Why**: trust portability and Sybil resistance depend on first-class issuer
  identity, governance, and independence metadata.

**Existing substrate**:
[`crates/chio-core/src/identity_network.rs`](../../crates/chio-core/src/identity_network.rs),
[`crates/chio-federation/src/lib.rs`](../../crates/chio-federation/src/lib.rs),
and [`docs/IDENTITY_FEDERATION_GUIDE.md`](../reference/IDENTITY_FEDERATION_GUIDE.md)
already model public identity profiles, federation metadata, certification
references, and Sybil-control concepts. This track packages those concepts into
auditable issuer-accountability artifacts and fail-closed policy.

**Repo-prep work**:
- define signed issuer descriptor artifacts with operator, issuer, trust-root,
  governance, and correlation metadata
- define independence-policy evaluation rules for clearing and admission
- define revocation and suspension lifecycle for issuer descriptors

**Evidence output**:
- issuer descriptor schema and examples
- independence-policy rules and qualification fixtures
- reviewer pack showing bounded issuer-accountability semantics

**Done when**:
- portable trust claims reference explicit issuer-accountability artifacts
- clearing and admission can fail closed on missing independence evidence

#### A4. Subject Continuity And Passport Clearing

**Why**: portable trust is not honest if it relies on display-name matching or
  informal migration metadata.

**Existing substrate**:
[`spec/PROTOCOL.md`](../../spec/PROTOCOL.md),
[`crates/chio-credentials/src/oid4vci.rs`](../../crates/chio-credentials/src/oid4vci.rs),
[`crates/chio-credentials/src/oid4vp.rs`](../../crates/chio-credentials/src/oid4vp.rs),
[`crates/chio-did/src/lib.rs`](../../crates/chio-did/src/lib.rs),
[`crates/chio-federation/src/lib.rs`](../../crates/chio-federation/src/lib.rs),
and [`docs/IDENTITY_FEDERATION_GUIDE.md`](../reference/IDENTITY_FEDERATION_GUIDE.md)
already define passport, migration, discovery, and trust-pack substrate. The
missing piece is external clearing discipline and continuity evidence across
real counterparties.

**Repo-prep work**:
- define subject continuity and migration artifacts
- define passport-clearing rules that require continuity, freshness,
  methodology compatibility, and issuer independence
- define output artifacts for network-cleared trust versus local trust

**External evidence work**:
- exercise continuity and clearing with real counterparties or pilot operators
- publish bounded clearing reports that preserve local-admission autonomy

**Done when**:
- Chio can show bounded portable-trust clearing instead of only bilateral
  evidence portability
- imported trust no longer reads like recomputed local truth

#### A5. Standards Reviewer Packs And Companion Docs

**Why**: external qualification needs a reviewable package, not just internal
  test runs.

**Existing substrate**:
[`docs/release/QUALIFICATION.md`](../release/QUALIFICATION.md),
[`docs/release/RELEASE_AUDIT.md`](../release/RELEASE_AUDIT.md),
[`docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`](../standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md),
and the internal review memos already form an internal
reviewer package. This track makes that package standards-facing, bounded, and
reusable by third parties.

**Repo-prep work**:
- create one standards reviewer pack format
- create companion docs for profile limits, external peer results, and known
  incompatibilities
- define one publication lane for standards-facing evidence bundles

**Done when**:
- an outside reviewer can evaluate standards legitimacy and trust portability
  from a bounded evidence package
- compatibility boundaries are visible without deep repo archaeology

---

## Program B: Market Validation And External Proof

> **Goal**: Prove the strongest strategic Chio thesis with external evidence:
> Chio is relied on as control-plane truth by outside operators, partners, and
> economic actors.

### Current Repo Baseline

- [`crates/chio-market/src/lib.rs`](../../crates/chio-market/src/lib.rs),
  [`crates/chio-store-sqlite/src/receipt_store/liability_market.rs`](../../crates/chio-store-sqlite/src/receipt_store/liability_market.rs),
  and [`crates/chio-store-sqlite/src/receipt_store/liability_claims.rs`](../../crates/chio-store-sqlite/src/receipt_store/liability_claims.rs)
  already model market, liability, and claims-shaped workflows.
- [`crates/chio-kernel/src/operator_report.rs`](../../crates/chio-kernel/src/operator_report.rs),
  [`crates/chio-anchor/src/bundle.rs`](../../crates/chio-anchor/src/bundle.rs),
  [`crates/chio-anchor/src/ops.rs`](../../crates/chio-anchor/src/ops.rs), and
  [`crates/chio-web3/src/lib.rs`](../../crates/chio-web3/src/lib.rs) already give
  Chio exportable operator, checkpoint, and proof artifacts. Program B turns
  those internal artifacts into evidence of outside dependence.

### Evidence Categories

- outside operators using Chio receipts, checkpoints, or control-plane semantics
  as authoritative inputs
- partner dependence on bilateral runtime co-signing, reconciliation, or
  evidence exchange
- production usage and repeat economic flows that persist without repo-local
  prompting
- insurance, underwriting, dispute, and claims evidence where Chio artifacts
  materially affect decisions
- marketplace activity, pricing, and placements that depend on verified Chio
  evidence
- external proof bundles that an independent reviewer can verify

### Exit Criteria

- outside parties rely on Chio truth for consequential workflows, not just
  optional integration paths
- operator, partner, and market evidence supports the stronger strategic thesis
  with independent artifacts
- Chio's control-plane thesis is demonstrated by external dependence, not just
  by internal implementation depth

### Non-Goals

- treating SDK completeness or repo breadth as substitute market proof
- counting internal demos as external dependence
- using external-program progress to widen ship claims automatically
- counting research-track prototypes, feasibility notes, or verifier benchmarks
  as operator, partner, insurance, or marketplace proof

### Program B Tracks

#### B1. External Proof Bundle Contract

**Why**: market-position claims need one repeatable artifact shape, not ad hoc
evidence scattered across decks and docs.

**Existing substrate**:
[`docs/release/PARTNER_PROOF.md`](../release/PARTNER_PROOF.md),
[`docs/release/CHIO_COMPTROLLER_MARKET_POSITION_PROOF.md`](../release/CHIO_COMPTROLLER_MARKET_POSITION_PROOF.md),
[`crates/chio-market/src/lib.rs`](../../crates/chio-market/src/lib.rs), and the
liability-market store modules already sketch several evidence categories. This
track standardizes them into one reusable proof-bundle contract.

**Repo-prep work**:
- define one external-proof bundle contract for operator, partner, insurance,
  and marketplace evidence
- define what counts as dependence, what counts as optional integration, and
  what counts as insufficient evidence
- define that research prototypes and feasibility artifacts do not count as
  external-proof bundle substitutes
- define bounded redaction and privacy rules for publishing proof bundles

**Done when**:
- every stronger strategic claim maps to a named evidence bundle type
- reviewers can distinguish adoption evidence from marketing narrative

#### B2. Operator Reliance Pilots

**Why**: the comptroller thesis requires outside operators to rely on Chio
truth for consequential workflows.

**Existing substrate**:
[`crates/chio-kernel/src/operator_report.rs`](../../crates/chio-kernel/src/operator_report.rs),
[`crates/chio-anchor/src/bundle.rs`](../../crates/chio-anchor/src/bundle.rs),
[`crates/chio-anchor/src/ops.rs`](../../crates/chio-anchor/src/ops.rs), and
[`crates/chio-web3/src/lib.rs`](../../crates/chio-web3/src/lib.rs) already produce
machine-verifiable operator and checkpoint artifacts. What is missing is
outside operator dependence on those artifacts.

**External evidence work**:
- identify candidate operators and one narrow high-value workflow per operator
- collect evidence that receipts, checkpoints, or control-plane truth are
  authoritative inputs to real decisions
- capture failure modes, rollback behavior, and reasons operators trust or do
  not trust Chio as authoritative substrate

**Done when**:
- at least one outside operator is using Chio truth as more than optional
  telemetry
- the evidence bundle shows operational dependence instead of superficial
  integration

#### B3. Partner Dependence And Bilateral Runtime Proof

**Why**: partner dependence is stronger than operator self-use and closer to
real market control-plane truth.

**Existing substrate**:
[`docs/release/PARTNER_PROOF.md`](../release/PARTNER_PROOF.md),
[`crates/chio-kernel/src/operator_report.rs`](../../crates/chio-kernel/src/operator_report.rs),
and [`crates/chio-store-sqlite/src/receipt_store/reports.rs`](../../crates/chio-store-sqlite/src/receipt_store/reports.rs)
already give Chio reconciliation and report substrate that can feed bilateral
proof. This track turns that substrate into counterparty-reviewed dependence.

**Repo-prep work**:
- define bilateral co-signing, reconciliation, and dispute-evidence bundle
  requirements
- define what proof is needed to say a partner depends on Chio truth

**External evidence work**:
- run partner pilots where a counterparty consumes Chio evidence in settlement,
  reconciliation, dispute, or admission workflows
- publish bounded partner-proof bundles

**Done when**:
- one or more counterparties rely on Chio artifacts in workflows that matter to
  them operationally or financially

#### B4. Insurance And Underwriting Dependence

**Why**: insurance and underwriting are central to the stronger Chio vision, but
need real dependence evidence rather than protocol completeness.

**Existing substrate**:
[`crates/chio-store-sqlite/src/receipt_store/liability_claims.rs`](../../crates/chio-store-sqlite/src/receipt_store/liability_claims.rs),
[`crates/chio-market/src/lib.rs`](../../crates/chio-market/src/lib.rs), and
[`docs/release/PARTNER_PROOF.md`](../release/PARTNER_PROOF.md) already show that
the repo has claims and liability-shaped primitives. What it does not yet have
is insurer or underwriter evidence that those primitives changed a real
decision.

**Repo-prep work**:
- define underwriting, coverage, claim, and dispute bundle formats
- define what it means for Chio artifacts to materially affect underwriting or
  claims outcomes

**External evidence work**:
- run insurer or underwriter pilots
- collect evidence that Chio receipts, provenance, or controls changed a real
  pricing, coverage, or claim decision

**Done when**:
- insurance-facing claims are backed by observed dependence, not just support
  for insurance-shaped workflows

#### B5. Marketplace And Liquidity Proof

**Why**: marketplace claims require evidence of actual pricing, matching, and
liquidity behavior around Chio-verified artifacts.

**Existing substrate**:
[`crates/chio-market/src/lib.rs`](../../crates/chio-market/src/lib.rs),
[`crates/chio-store-sqlite/src/receipt_store/liability_market.rs`](../../crates/chio-store-sqlite/src/receipt_store/liability_market.rs),
[`crates/chio-store-sqlite/src/receipt_store/liability_claims.rs`](../../crates/chio-store-sqlite/src/receipt_store/liability_claims.rs),
and [`docs/release/CHIO_COMPTROLLER_MARKET_POSITION_PROOF.md`](../release/CHIO_COMPTROLLER_MARKET_POSITION_PROOF.md)
already define marketplace-shaped substrate and strategy claims. The missing
proof is live third-party pricing, matching, and repeated use.

**Repo-prep work**:
- define marketplace evidence bundles for listings, bids, matches, fulfilled
  placements, disputes, and pricing signals
- define anti-fake-activity rules so internal demos cannot masquerade as
  market proof

**External evidence work**:
- run bounded live marketplace or placement pilots
- capture evidence of repeated real usage and third-party willingness to price
  against Chio-backed signals

**Done when**:
- the marketplace story is supported by live economic activity, not just by
  feature availability

---

## Immediate Start Queue

If the question is "what should we work on next once the numbered roadmap is
done," the highest-leverage queue is:

1. Build `A1` first: claim taxonomy, claim registry, and qualification matrices.
2. Build `A2` next: repeatable external-peer qualification harnesses and result
   formats.
3. Build `A3` and `A4`: issuer descriptors, independence policy, subject
   continuity, and passport-clearing artifacts.
4. Build `B1`: external-proof bundle formats and evidence thresholds.
5. Start `B2` and `B3`: operator-reliance and partner-dependence pilots.
6. Start `B4` and `B5` only after the earlier evidence lanes are stable enough
   to be reviewed externally.

That is the concrete answer to "what else should Chio work on after the current
roadmap and post-roadmap addendum are complete."

---

## Standing Controls After The Numbered Roadmap

These do not become new phases, but they must continue:

- release qualification and release-audit claim discipline
- theorem inventory and verified-core claim synchronization
- README, planning, spec, and strategy-doc claim-boundary sync
- explicit separation of ship truth, repo-local stronger addenda, external
  evidence, and research

The numbered roadmap can end while these controls remain active.

---

## Research Tracks

These remain explicit research tracks rather than product or evidence-program
deliverables:

- they do not satisfy Program A or Program B exit criteria
- they do not widen release claims, count as external proof, or gate the
  numbered closure phases
- allowed outputs here are research memos, threat models, prototype code, and
  verifier or proving benchmarks only

- ZK receipt proofs
  See `docs/research/CHIO_ZK_RECEIPT_PROOFS_MEMO.md`.
  Focus: prove narrow predicates over signed receipts, lineage edges, and
  checkpoint proofs after Chio's non-research receipt and append-only substrate
  is already in place.
- TEE-backed execution and receipt binding
  See `docs/research/TEE_RUNTIME_ASSURANCE_BINDING_MEMO.md`.
  Focus: add hardware-rooted session-key or checkpoint provenance that extends,
  but does not replace, Phase 27's verifier-backed runtime-assurance model.

They may later influence the product or evidence story, but they are not
prerequisites for any numbered phase or external evidence program and do not
establish the non-research Chio thesis on their own.

---

## Bottom Line

The numbered roadmap should stop where repo-solvable closure stops.
After that, Chio still has real work left, but it is external-program work and
research. Research remains distinct from Program A and Program B and does not
become another internal product ladder or an implicit dependency of those
programs.
