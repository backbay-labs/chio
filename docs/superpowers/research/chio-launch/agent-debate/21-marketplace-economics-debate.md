# Agent 21 Marketplace Economics Debate

Role: marketplace, trust-network, and economic-systems designer
Status: debate output for launch trust-network research
Inputs:
- `INDEX.md`
- `architecture/02-commerce-order-system.md`
- `architecture/05-public-settlement-passport-system.md`
- `architecture/06-risk-comptroller-system.md`
- `plans/02-commerce-order-implementation.md`
- `plans/06-risk-comptroller-implementation.md`

Confidence: high that the launch package needs a marketplace trust layer; high that live permissionless capital markets are too much for launch; moderate on exact schema placement.

## Verdict

The current launch architecture proves that Chio can bind commerce, settlement, risk, and public verification into a Transaction Passport. That is necessary, but it is not enough to justify the strongest "trust network" claim. A network is not only a receipt graph. It also needs discoverable counterparties, comparable trust signals, enforceable service promises, portable reputation inputs, collateral posture, and a credible path from failure to sanction.

The missing launch feature is not a full marketplace. A full marketplace would be fatal scope creep. The missing launch feature is a verifier-grade trust-market envelope: a bounded set of signed artifacts that explain why a provider was discoverable, why it was admitted, how it was scored under local policy, what SLA it accepted, what collateral or guarantee backed the order, and which adjudication or slashing path applies if it fails.

Launch should add proof surfaces for discovery, scoring, SLA commitment, reputation import, collateral position, guarantee eligibility, and adjudication jurisdiction. Launch should explicitly block claims about permissionless liquidity pools, risk syndication, underwriter markets, autonomous guarantee products, and slashing courts unless those claims are separately backed by registry entries, fixtures, verifier paths, and capital/accounting invariants.

## Debate Frame

### Position A: ship the current plan

The conservative argument is strong. `chio.commerce.order-context.v1` already binds provider passport, reputation snapshot, federation trust bundle, quote, mandate, budget, payment, settlement, dispute, and risk report. `chio.web3-settlement-proof-bundle.v1` already binds escrow, bond, finality, oracle conversion, dispute posture, and identity binding. `chio.risk.comptroller-report.v1` already reconciles underwriting, appraisal, provider passport, reputation, federation, facility, bond, reserve, coverage, claim, payout, settlement, governance, and slashing evidence.

That is enough for a defensible launch if the copy says "verifiable commerce and risk context." It is not enough if the copy says "trust network" in the economic sense. A trust network has selection pressure, comparison, repeat interaction, penalties, imported history, and liquid capacity. The current plan has inputs to those things, but not the network-effect artifacts that make them inspectable.

### Position B: add the whole market

The aggressive argument is tempting and wrong. Provider discovery, portable reputation, collateral staking, liquidity pools, syndication, underwriter markets, guarantees, and slashing courts sound like the features that make Chio feel inevitable. But launching all of them as live systems would blur verifier-grade proof with unproved market operation.

That would weaken the project. If Chio claims a permissionless underwriter market or pooled liquidity at launch, reviewers will ask for actuarial backtests, capital adequacy, participant solvency, adverse-selection controls, reserve governance, cross-currency accounting, recovery lifecycle, dispute appeals, and slashing due process. The current risk plan correctly blocks most of that.

### Position C: add a thin trust-market envelope

This is the right position. Add artifacts that make market participation verifiable without claiming live market clearing:

- provider discovery snapshot;
- provider selection report;
- local trust scorecard snapshot;
- portable reputation import report;
- SLA commitment and performance report;
- collateral position report;
- guarantee decision backed by reserve, bond, or facility;
- adjudication jurisdiction receipt for disputes and slashing.

These are launch-grade because they are projections and commitments, not autonomous markets. They make the proof graph read like a network while preserving the fail-closed verifier posture.

## Capability Gap Analysis

| Capability | Current coverage | Launch addition | Too much for launch |
| --- | --- | --- | --- |
| Provider discovery | Provider admission exists after a provider is known. Cross-protocol discovery exists elsewhere, but commerce has no signed provider candidate set. | Add a signed discovery snapshot and deterministic selection report. | Live search marketplace, auctions, routing incentives, pay-to-rank, and open provider onboarding. |
| Trust scores | Reputation snapshot and federation trust bundle exist as inputs, and the risk register warns against global scores. | Add a local-policy scorecard snapshot with components, weights, issuer trust, freshness, and override receipts. | A universal Chio score, global ranking, or social-credit-style mutable reputation oracle. |
| Attestable SLAs | Fulfillment evidence and dispute refs exist, but no first-class service promise binds to the order. | Add SLA commitment and SLA performance artifacts bound to order, quote, provider, measurement policy, and remedy. | Automated SLA pricing, liquidated damages market, and subjective quality adjudication at launch. |
| Reputation portability | Risk drafts mention portable reputation routes, but the launch registry does not expose a verifier-facing import artifact. | Add a portable reputation import report with issuer, subject binding, negative events, decay, privacy profile, and local weight. | Treating imported reputation as capital, insurance, or a globally authoritative score. |
| Collateral staking | Bond state and market slash exist, and risk ledger separation names market slash. | Add a collateral position report that states locked amount, currency, source, lock window, claim priority, slash authority, and release conditions. | Open staking pools, rehypothecation, leveraged stake, or cross-currency collateral netting. |
| Liquidity pools | Facility, reserve, capital book, and capital instruction refs exist. | Launch only a capital commitment snapshot inside the risk comptroller, not a pool. | Permissionless liquidity pools, LP shares, yield, withdrawal queues, pool loss waterfall, or AMM-style capital pricing. |
| Risk syndication | Risk comptroller can reference capital book and reserve state, but multi-provider capital stacks are explicitly blocked. | Add a future-only syndication placement design note, not a launch claim. | Multi-underwriter allocation, tranche waterfalls, reinsurance, secondary trading, and shared claims reserves. |
| Underwriter markets | Underwriting and curated liability providers exist. | Launch curated underwriter/provider admission evidence only. | Permissionless underwriter offer books, competitive clearing, dynamic premium markets, or automated insurer networks. |
| Guarantee products | Budget guarantees and coverage decisions exist as primitives, but product packaging is absent. | Add a guarantee decision that says whether this order is backed, by which reserve or bond, under which policy, and with which maximum remedy. | Standalone guarantee product catalog, guarantee resale, autonomous pricing, or guarantee pools. |
| Slashing courts | Governance, dispute, adjudication, and slashing refs exist, but no jurisdiction artifact tells a verifier who may slash what. | Add adjudication jurisdiction and slash authority receipts; route slashes through existing claim, dispute, governance, and sanction/reserve ledgers. | A general court system, appeals marketplace, jury/staking governance, precedent engine, or cross-network enforcement. |

## Feature Additions

### 1. Provider Discovery Snapshot

Add `chio.commerce.provider-discovery-snapshot.v1`.

Purpose: freeze the provider candidate set used for a commerce order.

Required fields:
- `snapshot_id`
- `order_intent_ref`
- `market_scope`
- `provider_candidate_refs`
- `provider_passport_refs`
- `service_manifest_refs`
- `availability_refs`
- `pricing_surface_refs`
- `jurisdiction_refs`
- `exclusion_policy_ref`
- `freshness_window`
- `discovery_authority_ref`
- `snapshot_digest`
- `signature`

Verifier rules:
- reject if the selected provider is not in the snapshot;
- reject if the snapshot is stale at quote binding;
- reject if a candidate lacks a provider passport or service manifest required by policy;
- reject if the exclusion policy would have removed the selected provider;
- mark discovery as advisory if the verifier policy does not require competitive selection.

Why this matters: provider admission proves the chosen provider passed a gate. It does not prove the provider was selected from a real candidate set. Discovery is the first network-effect artifact.

### 2. Provider Selection Report

Add `chio.commerce.provider-selection-report.v1`.

Purpose: explain why one provider was chosen from the discovery snapshot.

Required fields:
- `selection_id`
- `order_id`
- `discovery_snapshot_ref`
- `selected_provider_subject`
- `ranking_policy_ref`
- `scorecard_ref`
- `sla_commitment_ref`
- `price_quote_ref`
- `risk_report_ref`
- `override_receipt_ref`
- `selection_reason_codes`
- `rejected_candidate_summaries`
- `signature`

Verifier rules:
- reject if selected provider is absent from discovery snapshot;
- reject if ranking policy inputs do not match scorecard inputs;
- reject if a lower-ranked provider is chosen without an override receipt;
- reject if override authority is missing, expired, or outside order scope;
- reject if rejected candidate summaries leak fields forbidden by disclosure policy.

This is deliberately not an auction. It is a selection proof.

### 3. Local Trust Scorecard Snapshot

Add `chio.trust.scorecard-snapshot.v1`.

Purpose: make "trust score" inspectable without creating a global score.

Required fields:
- `scorecard_id`
- `subject`
- `verifier_policy_ref`
- `component_scores`
- `component_weights`
- `issuer_trust_roots`
- `reputation_snapshot_refs`
- `portable_reputation_import_refs`
- `sla_performance_refs`
- `negative_event_refs`
- `freshness_window`
- `score_floor`
- `score_ceiling`
- `computed_score`
- `downgrade_reasons`
- `signature`

Verifier rules:
- recompute the score from component inputs;
- reject if weights do not sum under policy;
- reject if a component cites stale or untrusted evidence;
- reject if a negative event is omitted from a required source;
- reject if the score is presented as global rather than policy-local.

The phrase "global trust score" should be blocked in launch copy. Chio can support local, verifier-defined scoring. That is stronger and less brittle.

### 4. Attestable SLA Commitment

Add `chio.commerce.sla-commitment.v1` and `chio.commerce.sla-performance-report.v1`.

Purpose: bind a measurable service promise to the order and later attest performance.

SLA commitment fields:
- `sla_id`
- `order_id`
- `provider_subject`
- `buyer_subject`
- `service_scope`
- `metric_definitions`
- `measurement_policy_ref`
- `effective_window`
- `exclusions_ref`
- `remedy_policy_ref`
- `collateral_position_ref`
- `guarantee_decision_ref`
- `signature`

SLA performance report fields:
- `performance_id`
- `sla_ref`
- `fulfillment_ref`
- `measurement_evidence_refs`
- `computed_metric_results`
- `breach_verdict`
- `remedy_ref`
- `dispute_ref`
- `signature`

Verifier rules:
- reject SLA if it is not bound to the same order and provider;
- reject performance report if measurement policy differs from the commitment;
- reject if evidence was captured outside the effective window;
- reject if breach remedy exceeds collateral, reserve, guarantee, or policy limits;
- reject if fulfillment completion contradicts an unresolved SLA breach.

This gives Chio a concrete "attestable SLA" story without pretending to solve every qualitative service dispute.

### 5. Portable Reputation Import Report

Add `chio.trust.reputation-import-report.v1`.

Purpose: import external or federated reputation into local scoring while preserving local policy control.

Required fields:
- `import_id`
- `subject`
- `source_network`
- `issuer`
- `issuer_trust_ref`
- `source_reputation_ref`
- `negative_event_refs`
- `subject_binding_ref`
- `privacy_profile_ref`
- `decay_policy_ref`
- `local_weight`
- `import_verdict`
- `signature`

Verifier rules:
- reject if source subject is not bound to the Chio subject;
- reject if issuer is outside the local trust root;
- reject if negative events are omitted under policy;
- reject if imported fields violate privacy profile;
- reject if local weight exceeds policy maximum;
- reject if import is used as proof of collateral, insurance, or solvency.

Portability is valuable only if it is defeasible. Imported reputation should change priors, not create rights.

### 6. Collateral Position Report

Add `chio.risk.collateral-position-report.v1`.

Purpose: give the verifier one place to inspect stake, bond, reserve, and lock semantics.

Required fields:
- `collateral_id`
- `subject`
- `order_id`
- `currency_or_asset`
- `amount`
- `source_type`
- `source_ref`
- `lock_start`
- `lock_expiry`
- `claim_priority`
- `slash_authority_ref`
- `release_policy_ref`
- `consumed_amount_refs`
- `available_amount`
- `signature`

Verifier rules:
- reject cross-currency collateral netting;
- reject if collateral subject differs from provider, facility, or covered exposure without a signed binding;
- reject if lock expires before required claim or SLA window;
- reject if consumed amount overlaps payout, release, reserve slash, or market slash;
- reject if slash authority is not bound to the collateral source.

This should feed `chio.risk.comptroller-report.v1` and `chio.web3-settlement-proof-bundle.v1` through digest refs.

### 7. Capital Commitment Snapshot

Add `chio.risk.capital-commitment-snapshot.v1` only if launch copy mentions available capacity beyond one reserved facility.

Purpose: show committed capacity without launching a liquidity pool.

Required fields:
- `commitment_id`
- `capital_source_subject`
- `facility_ref`
- `currency`
- `committed_amount`
- `held_amount`
- `drawn_amount`
- `impaired_amount`
- `available_amount`
- `commitment_terms_ref`
- `expiry`
- `signature`

Verifier rules:
- reject if available amount is computed across currencies;
- reject if the same commitment backs two live guarantees beyond policy;
- reject if commitment source is untrusted or expired;
- reject if snapshot is described as a liquidity pool.

Liquidity pool language should be blocked for launch. Capital commitment is the honest claim.

### 8. Guarantee Decision

Add `chio.risk.guarantee-decision.v1`.

Purpose: state whether an order has a bounded guarantee and what backs it.

Required fields:
- `guarantee_id`
- `order_id`
- `provider_subject`
- `beneficiary_subject`
- `guarantee_type`
- `maximum_remedy`
- `currency`
- `backing_refs`
- `coverage_decision_ref`
- `sla_commitment_ref`
- `claim_window`
- `exclusions_ref`
- `adjudication_jurisdiction_ref`
- `verdict`
- `signature`

Verifier rules:
- reject if guarantee is not bound to the order;
- reject if guarantee currency differs from backing currency;
- reject if backing is insufficient or already consumed;
- reject if guarantee starts after the covered event;
- reject if remedy exceeds policy, reserve, bond, or facility limits.

Guarantee products are too much for launch. A guarantee decision for a single order is not.

### 9. Adjudication Jurisdiction Receipt

Add `chio.risk.adjudication-jurisdiction-receipt.v1`.

Purpose: identify who can decide disputes, appeals, remedies, releases, and slashes for this order.

Required fields:
- `jurisdiction_id`
- `order_id`
- `policy_ref`
- `covered_dispute_types`
- `adjudicator_subjects`
- `appeal_authority_refs`
- `slash_authority_refs`
- `remedy_limits`
- `evidence_rules_ref`
- `effective_window`
- `signature`

Verifier rules:
- reject adjudication from an unlisted authority;
- reject slash if the dispute type is outside jurisdiction;
- reject remedy above limit;
- reject appeal that rewrites prior signed artifacts instead of superseding future projection;
- reject release, slash, write-off, or closure while a blocking appeal is active.

This is the launch replacement for "slashing courts." It is jurisdiction proof, not a court system.

## Plan And Schema Deltas

### Deltas to `architecture/02-commerce-order-system.md`

Add these optional refs to `chio.commerce.order-context.v1` when the commerce fixture uses marketplace selection:

- `provider_discovery_snapshot_ref`
- `provider_selection_report_ref`
- `trust_scorecard_ref`
- `sla_commitment_ref`
- `guarantee_decision_ref`
- `collateral_position_ref`
- `adjudication_jurisdiction_ref`

Add these provider admission invariants:

- selected provider must appear in the discovery snapshot;
- discovery snapshot must be fresh at quote binding;
- provider admission must cite the same provider subject as the selection report;
- scorecard must be local-policy scoped;
- SLA commitment must bind order id, provider, metric policy, effective window, and remedy;
- guarantee decision must bind order id, backing, and adjudication jurisdiction;
- selection override must cite an authority receipt.

Add replay rejects:

- selected provider absent from candidate snapshot;
- stale discovery snapshot;
- scorecard computed from untrusted or stale reputation;
- SLA commitment for wrong order id;
- guarantee decision not backed by reserve, bond, collateral, or facility;
- lower-ranked selected provider without override receipt.

### Deltas to `architecture/05-public-settlement-passport-system.md`

Add optional fields to `chio.web3-settlement-proof-bundle.v1` only when relevant:

- `collateral_position_ref`
- `guarantee_decision_ref`
- `sla_remedy_ref`
- `slash_authority_ref`

Add verifier checks:

- collateral lock must cover the settlement, claim, SLA, or slash window claimed by the order;
- guarantee settlement must bind the guarantee id and order id;
- slash transaction must cite an adjudication or governance authority allowed by the jurisdiction receipt;
- release transaction must not conflict with open claim, appeal, dispute, or SLA breach state.

Add negative cases:

- guarantee settlement proof for wrong order id;
- collateral unlocked before finality or claim window;
- slash executed by authority not named in jurisdiction receipt;
- settlement proof treats stake release as claim payout.

### Deltas to `architecture/06-risk-comptroller-system.md`

Add fields to `chio.risk.comptroller-report.v1`:

- `provider_discovery_snapshot_ref`
- `provider_selection_report_ref`
- `trust_scorecard_ref`
- `reputation_import_refs`
- `sla_commitment_ref`
- `sla_performance_report_ref`
- `collateral_position_ref`
- `capital_commitment_refs`
- `guarantee_decision_ref`
- `adjudication_jurisdiction_ref`

Add invariants:

1. Discovery invariant: provider admission must trace to a fresh discovery snapshot unless verifier policy permits direct admission.
2. Score invariant: computed score must be reproducible from listed components, weights, and policy.
3. Reputation import invariant: imported reputation must be subject-bound, issuer-trusted, privacy-profile compliant, and policy-weighted.
4. SLA invariant: performance evidence must use the commitment's measurement policy and effective window.
5. Collateral invariant: one collateral unit cannot back incompatible live obligations unless policy explicitly permits shared backing with a cap.
6. Guarantee invariant: guarantee remedy cannot exceed backing, policy limit, or adjudicated payable amount.
7. Jurisdiction invariant: dispute, appeal, slash, release, and closure actions must come from the authority set bound before the relevant event.

Add launch claim blocks:

- Chio does not operate a permissionless provider market.
- Chio does not publish a global trust score.
- Chio does not operate liquidity pools.
- Chio does not syndicate risk across underwriters at launch.
- Chio does not run an underwriter market at launch.
- Chio does not sell autonomous guarantee products at launch.
- Chio does not run slashing courts at launch.

### Deltas to `plans/02-commerce-order-implementation.md`

Phase 0 additions:

- add protocol text and schemas for provider discovery snapshot, provider selection report, trust scorecard snapshot, SLA commitment, SLA performance report, guarantee decision ref, collateral ref, and adjudication jurisdiction ref;
- add copy gate that blocks global score, liquidity pool, underwriter market, and court claims;
- add registry rows before any verifier accepts the new artifacts.

Phase 1 additions:

- replay provider selection as an event before provider admission;
- include scorecard and SLA commitment in materialized order context;
- reject selection events whose snapshot, scorecard, or override receipt fails.

Phase 2 additions:

- require provider admission to consume discovery, selection, scorecard, reputation import, and federation trust evidence when marketplace mode is enabled;
- require SLA commitment before fulfillment request when the selected service has SLA policy;
- require guarantee decision before order completion when the order claims guaranteed performance.

Phase 5 additions:

- promote one fixture into a marketplace-mode commerce fixture;
- add negative fixtures for stale discovery, wrong selected provider, score drift, SLA mismatch, unsupported guarantee, and unauthorized slash remedy.

### Deltas to `plans/06-risk-comptroller-implementation.md`

Phase 0 additions:

- freeze the public claim as "verifiable trust-market context," not "marketplace operation";
- add unsupported-claim checks for liquidity pools, risk syndication, permissionless underwriter markets, global trust scores, autonomous guarantee products, and slashing courts.

Phase 1 additions:

- assemble trust scorecard, reputation import, SLA, collateral, guarantee, and jurisdiction refs into the risk comptroller report;
- fail reconciliation if those refs disagree with order id, subject, currency, or policy.

Phase 2 additions:

- allow facility state to reference collateral position and guarantee decision;
- block `coverage_bound` if guarantee backing is missing for guaranteed orders.

Phase 3 additions:

- extend double-consumption detector to collateral units;
- require sanction/reserve ledger entries to cite adjudication jurisdiction;
- reject market slash that consumes facility reserve without explicit bridge and jurisdiction.

Phase 4 additions:

- bind trust-market artifacts into Transaction Passport;
- add Proof Room marketplace economics section showing discovery, selection, scorecard, SLA, guarantee, collateral, and jurisdiction verdicts.

Phase 6 additions:

- add a valid marketplace-risk fixture with one provider, one scorecard, one SLA, one guarantee, one collateral position, one comptroller report, and one settlement proof;
- add invalid fixtures listed below.

## What Is Too Much For Launch

The following are useful later, but should be blocked from launch claims:

1. Permissionless provider marketplace.
2. Global trust score.
3. Live bidding or auction-based provider selection.
4. Liquidity pools with pooled loss waterfall.
5. LP shares, yield, withdrawals, or secondary liquidity.
6. Risk syndication across multiple underwriters.
7. Reinsurance or tranche structures.
8. Permissionless underwriter markets.
9. Autonomous premium adequacy or automated reserve adequacy claims.
10. Standalone guarantee product catalog.
11. Guarantee resale or guarantee pool.
12. General slashing courts.
13. Jury, token-holder, or stake-weighted dispute governance.
14. Cross-network enforcement of slashes without explicit jurisdiction and identity binding.

The reason is not product timidity. The reason is verifier integrity. Each of these features changes the accounting model, adverse-selection model, dispute model, or capital model. Launch should expose commitments and projections, not pretend market operations are solved.

## First Slice

Build one canonical marketplace-mode commerce fixture.

Scenario:

1. Buyer intent requests a bounded autonomous service.
2. Discovery snapshot lists three providers.
3. Local ranking policy scores candidates using provider passport, federation trust, native reputation snapshot, imported portable reputation, SLA history, and negative events.
4. Selection report chooses the top provider.
5. Provider admission consumes the selection report.
6. Quote, mandate, budget reservation, and payment evidence bind to the order.
7. Provider signs an SLA commitment.
8. Risk system issues a guarantee decision backed by a collateral position and facility reserve.
9. Fulfillment occurs.
10. SLA performance report passes.
11. Settlement packet dispatches and settlement proof finalizes.
12. Risk comptroller reconciles collateral, reserve, guarantee, coverage, settlement, and no open dispute.
13. Transaction Passport verifier reports marketplace trust context as verified.

Minimum implementation steps:

1. Add schemas and registry entries for the launch additions that are verifier-facing.
2. Add fixture JSON for discovery snapshot, selection report, scorecard, reputation import, SLA commitment, SLA performance report, collateral position, guarantee decision, and adjudication jurisdiction receipt.
3. Extend commerce replay to ingest discovery, selection, scorecard, and SLA events.
4. Extend risk comptroller assembly to ingest collateral, guarantee, and jurisdiction refs.
5. Extend settlement verifier to reject slash or release without the referenced jurisdiction and collateral posture.
6. Add Transaction Passport nodes and typed edges:
   - discovery snapshot `binds` provider selection;
   - selection report `binds` provider admission;
   - scorecard `derives` from reputation inputs;
   - SLA commitment `binds` fulfillment;
   - guarantee decision `binds` collateral and coverage;
   - risk comptroller `reconciles` guarantee, collateral, reserve, claim, and settlement;
   - settlement proof `settles` order and guarantee state.
7. Add CLI verifier section for marketplace economics.
8. Add Proof Room section only after CLI verdicts are deterministic.

First-slice exit standard:

- valid marketplace fixture verifies through Transaction Passport;
- unsupported market claims are reported as unsupported, not silently ignored;
- stale or inconsistent discovery, score, SLA, collateral, guarantee, or jurisdiction evidence fails closed;
- Proof Room and CLI agree on the verdict.

## Negative Fixtures

Commerce and discovery:

1. `marketplace_selected_provider_absent_fails`: selected provider is not in discovery snapshot.
2. `marketplace_discovery_stale_fails`: discovery snapshot freshness window expired before quote binding.
3. `marketplace_selected_lower_rank_without_override_fails`: selected provider loses under ranking policy and no override receipt exists.
4. `marketplace_override_wrong_authority_fails`: override receipt is signed by an actor outside policy scope.
5. `marketplace_provider_passport_mismatch_fails`: selection report provider differs from provider admission subject.
6. `marketplace_rejected_candidate_leakage_fails`: rejected candidate summary discloses fields forbidden by privacy profile.

Trust scoring and reputation portability:

7. `trust_score_recompute_mismatch_fails`: computed score does not match component scores and weights.
8. `trust_score_stale_component_fails`: scorecard uses stale SLA, reputation, or negative-event evidence.
9. `trust_score_untrusted_issuer_fails`: component evidence comes from issuer outside trust roots.
10. `trust_reputation_import_wrong_subject_fails`: imported reputation binds to a different subject.
11. `trust_reputation_import_privacy_violation_fails`: import report discloses fields forbidden by privacy profile.
12. `trust_global_score_claim_fails`: proof copy or claim set describes the score as global.

SLA and guarantee:

13. `sla_wrong_order_fails`: SLA commitment binds a different order id.
14. `sla_measurement_policy_mismatch_fails`: performance report uses a different measurement policy.
15. `sla_evidence_outside_window_fails`: measurement evidence falls outside effective window.
16. `guarantee_without_backing_fails`: guarantee decision has no sufficient reserve, bond, collateral, or facility backing.
17. `guarantee_currency_mismatch_fails`: guarantee currency differs from backing currency.
18. `guarantee_after_event_fails`: guarantee is issued after the covered failure event.

Collateral, capital, and settlement:

19. `collateral_lock_expired_fails`: collateral lock expires before required claim, SLA, or slash window.
20. `collateral_double_consumption_fails`: same collateral backs payout and release, or reserve slash and market slash.
21. `collateral_cross_currency_netting_fails`: collateral availability is computed across currencies.
22. `capital_commitment_double_backing_fails`: one commitment backs two guarantees beyond policy cap.
23. `settlement_guarantee_wrong_order_fails`: guarantee settlement proof binds a different order id.
24. `stake_release_open_dispute_fails`: collateral release advances while claim, appeal, dispute, or SLA breach remains open.

Jurisdiction and slashing:

25. `slash_unlisted_authority_fails`: slash signer is not named in adjudication jurisdiction.
26. `slash_wrong_dispute_type_fails`: slash cites a dispute type outside jurisdiction.
27. `slash_without_adjudication_fails`: slash consumes collateral without required adjudication or governance authority.
28. `appeal_rewrites_prior_artifact_fails`: appeal attempts to mutate a prior signed adjudication instead of superseding future projection.
29. `release_while_blocking_appeal_fails`: reserve or collateral release advances while a blocking appeal is active.
30. `court_claim_without_court_artifact_fails`: proof claim says slashing court when only jurisdiction receipt exists.

Unsupported market claims:

31. `liquidity_pool_claim_without_pool_artifact_fails`: claim set says liquidity pool but only capital commitment snapshot exists.
32. `risk_syndication_claim_without_placements_fails`: claim set says syndicated risk with no participant allocation, tranche, or commitment refs.
33. `underwriter_market_claim_without_offer_book_fails`: claim set says underwriter market but only curated provider admission exists.
34. `autonomous_guarantee_product_claim_fails`: claim set says guarantee product or autonomous guarantee pricing without actuarial and capital adequacy reports.

## Launch Copy Boundary

Allowed:

- "Chio verifies why an autonomous commerce provider was selected."
- "Chio binds local trust scoring, reputation imports, SLA commitments, collateral posture, guarantees, settlement, and risk reconciliation into a Transaction Passport."
- "Chio can show whether a provider was admitted under a verifier policy."
- "Chio can show whether a bounded guarantee was backed by reserve, bond, collateral, or facility evidence."
- "Chio can fail closed when market trust evidence is stale, inconsistent, or unsupported."

Blocked:

- "Chio operates a permissionless provider marketplace."
- "Chio publishes a global trust score."
- "Chio runs liquidity pools."
- "Chio syndicates risk across underwriters."
- "Chio operates an underwriter market."
- "Chio sells autonomous guarantee products."
- "Chio runs slashing courts."

## Final Recommendation

Do not launch the whole market. Launch the evidence layer that a real market would need.

The first implementation slice should make provider discovery, provider selection, local trust scoring, portable reputation import, SLA commitment, collateral posture, guarantee decision, and adjudication jurisdiction visible as signed, replayable, verifier-consumed artifacts. That gives the homepage trust-network claim economic substance without dragging the launch into capital-market, insurance, and governance claims that the current architecture correctly treats as unsupported.
