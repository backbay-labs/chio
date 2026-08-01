# Finding Publish and Discover (M2) Implementation Plan

This is the bite-sized implementation plan for milestone M2 of the
cognition-market program ([../PLAN.md](../PLAN.md) section "M2 Publish and
discover"). It was authored with the target files open, per the plan
maintenance rules (PLAN.md section 6). The M0/M1 plan
([2026-07-20-M0-M1-finding-artifact-family.md](2026-07-20-M0-M1-finding-artifact-family.md))
is the format precedent.

## Goal and boundary

M2 makes a published Finding discoverable and admittable: strict canonical
ingress at the control plane, an immutable by-id surface, a bounded and
paginated descriptor index, the six M2 signed artifact families plus the
unsigned replay-recipe input, the offline `FindingEvidenceVerifier` facet
profile, a live non-reusable collateral allocation replacing the transient
bond-proof toggle, evidenced fee collection into governance-pinned pools,
and a venue-signed admission bundle that trusted search and bid consume.

Out of scope (owning milestones in parentheses): kernel delivery contract
and `Constraint::OutputDigestSha256` (M3, blocked on ADR-A), purchase and
reveal including provider constraint minting and `BidMintContext` growth
(M4), challenge/audit lane (M5), status feed and portable non-inclusion
proofs (M6), cross-org escrow (M7), `chio finding` CLI (M4 per the ladder).
At M2 the verifier reports an authenticated online status observation only;
`status_liveness` cannot be portable-`verified` before M6.

Baseline: branch `codex/cognition-market-m2`, stacked on
`codex/cognition-market-m0-m1` (PR #1032). The M0/M1 gate discipline
(qualified `umask 022` full-workspace gate) carries over.

## Program constraints that bind every task

- Ship dark until M9: at M2 every runtime, service, and storage surface sat
  behind one default-off cargo feature, forwarded crate-to-crate like the
  `pq` chain:
  `crates/platform/chio-control-plane/Cargo.toml:18-20` ->
  `crates/platform/chio-store-sqlite/Cargo.toml:14-16` ->
  `crates/core/chio-core/Cargo.toml:42-44`). Pure artifact types, JSON
  schemas, and their registrations are spec, not runtime surface: they stay
  always-on exactly like the M1 leaf crate and M0 schema (PLAN.md global
  constraints). The M2 exit tested both absence and enabled behavior. M9
  removed that gate after qualification and made the surface part of the
  default build graph.
- Fail-closed everywhere; clippy `unwrap_used`/`expect_used` deny; no em
  dashes; conventional commits; Chio naming.
- Schema discipline: every standalone signed artifact lands in all four
  registration locations (schema file, registry.json + MANIFEST, allowlist
  row in `signed_artifact.rs`, PROTOCOL 6.4.x); the unsigned replay-recipe
  input registers everywhere EXCEPT the signed allowlist
  (ARCHITECTURE.md 7.1). Every family change extends the bidirectional
  parity tables in
  `crates/core/chio-core-types/tests/signed_artifact_schema.rs:768-877`
  (`EXPECTED_SIGNED` at :769, `EXPECTED_REGISTRY_ONLY` at :775).
- Verification gate per change: full workspace build/test/clippy/fmt plus
  `bash scripts/check-chio-schema-registry.sh` and
  `bash scripts/check-chio-owned-v1-only.sh`.

## Design decisions fixed by this plan

These resolve the open points the subsystem mapping surfaced; later tasks
cite them as D1..D15.

- D1 Pagination: the finding descriptor index orders by `finding_id`
  ascending (content-stable). The cursor is the last returned `finding_id`,
  exclusive start-after semantics; a cursor that is not exactly 64 lowercase
  hex characters is a 400. `limit` clamps to 1..=200 with default 50
  (matching `list_limit`,
  `crates/platform/chio-control-plane/src/trust_control/underwriting_and_support/policy_support.rs:972-976`).
  Liveness and admission filtering apply at read time; a listing expiring
  between pages simply stops appearing. Responses carry `results`,
  `next_cursor: Option<String>`, and `count`.
- D2 Search query shape: `topic_prefix: Option<String>` (plain
  string-prefix over `descriptor.topic`, byte length bound 1..=120 to match
  the M1 topic bound in `crates/economy/chio-finding/src/validate.rs`),
  `context_sha256: Option<String>` (exact lowercase 64-hex match), plus
  `limit`/`cursor`. At least one of `topic_prefix`/`context_sha256` is
  required; an unfiltered scan is a 400. GET uses `Query`, POST shares the
  same flat all-Option struct via `Json` (camelCase DTO convention,
  `certify/types.rs:337-348`).
- D3 Publish carries the Finding only. `POST /v1/findings/publish` body IS
  the raw Finding JSON (canonical-only ingress advertised, so raw bytes
  must equal strict canonical bytes). Replay-recipe preimages travel
  through a separate content-addressed upload,
  `POST /v1/findings/recipes` (D4), BEFORE publish; a
  `deterministic_replay` Finding whose `replay_recipe_sha256` has no
  retained preimage rejects at publish. This keeps the load-bearing ingress
  invariant byte-exact on one artifact per request.
- D4 Recipe retention: the recipe endpoint accepts a size-bounded raw
  `chio.finding.replay-recipe-input.v1` preimage, applies the same strict
  raw-first invariant (canonical bytes from raw, schema over parsed value,
  typed deserialize, typed-canonical equality), verifies the embedded
  pre-run template digest is present and cycle-free, and persists the exact
  raw bytes content-addressed by their canonical digest, idempotently.
  Dependencies referenced by digest inside the recipe (runner manifest,
  input bundles, parameter bundle, runtime image, and template) upload
  through the same endpoint and are retained. There is no GC: retention
  through the claim/audit/appeal horizon is achieved by never deleting,
  recorded as an operational note.
- D5 Admission distribution: `GET /v1/findings/{finding_id}/admission`
  serves the current venue-signed admission envelope; finding-index search
  rows carry `{admission_id, admission_envelope_sha256, admission_expires_at}`
  for admitted listings and omit the block otherwise. "Current" means: the
  admission envelope verifies against the pinned venue authority, its
  expiry has not passed, the named collateral allocation is live, and
  participation fees are paid through the current audit epoch (D8).
  Presence of a verified admission block IS the qualified
  cognition-market profile marker; generic listing search responses gain no
  new field, and a feature-on test asserts the finding listing surfaces
  through generic search with no admission marker (that is what "cannot
  advertise the qualified profile" concretely means).
- D6 `base_finding_stake` lives in `chio.finding.market-terms.v1` inside
  its canonical backing requirement, next to `maximum_sale_exposure`
  (which also binds into `chio.finding.bond-backing.v1`). The admission
  sizing check compares the exact signed fee schedule's slashable
  `Listing`-class requirement against
  `base_finding_stake + maximum_sale_exposure` with `checked_add` and
  exact currency equality across all three amounts.
- D7 Fee terminals are typed bindings inside the admission body, not an
  eighth standalone signed schema:
  `fee_terminals: Vec<FindingFeeTerminalBinding>`, each naming the signed
  fee-schedule envelope digest, event
  (`publication` | `participation_epoch { epoch_index }`), payer principal,
  amount and currency, pool principal id, rail-tagged destination, and the
  digests of the rail evidence pair (instruction + observation, D9). The
  venue admission signature authenticates the bindings; the rail evidence
  persists in the activation store. This satisfies "persists terminal
  receipts naming schedule, event, payer, amount/currency, pool principal,
  and rail destination" without expanding the signed-schema census beyond
  ARCHITECTURE 7.1.
- D8 Audit epochs: `chio.finding.market-terms.v1` carries
  `audit_epoch_length_secs: u64` (nonzero). Epoch index 0 begins at
  activation time; the current index derives from venue trusted time.
  Activation collects publication fee + epoch 0.
  `POST /v1/findings/{finding_id}/participation` (authenticated) collects
  later epochs through the same idempotent machinery. Admission currency
  (D5) requires `paid_through_epoch >= current_epoch_index`; an unpaid
  epoch makes the listing non-admitted at read time without touching the
  stored envelope. Epoch renewal scheduling is operator cron per the
  no-in-repo-scheduler posture (ARCHITECTURE.md 8.2).
- D9 Evidenced rail (wedge): fee collection composes the existing
  capital-execution vocabulary
  (`CapitalExecutionInstructionArtifact`/`CapitalExecutionObservation`/
  `validate_capital_instruction_reconciliation`,
  `crates/economy/chio-credit/src/credit/capital_and_execution/capital_execution.rs:27-349`):
  activation persists a signed instruction naming the exact
  governance-pinned pool destination, and the event is marked paid only
  when a matching observation reconciles (`reconciled_state = Matched`,
  exact amount, inside the window). A durable domain/event idempotency key
  `(fee_schedule_envelope_sha256, event, finding_id, listing_id)` fences
  intent before dispatch; identical retry reconciles, any conflicting
  payer/amount/currency/schedule/event rejects (MECHANISMS.md 6). The rail
  observer is injected as a trait so the exit test can drive both the
  reconciled and the crash-before-observation paths.
- D10 Collateral instrument (wedge): allocations are rows in a venue
  collateral store created only by presenting a
  `chio.finding.bond-backing.v1` envelope signed by the pinned collateral
  authority. The backing body's vault reference is a closed enum with the
  single M2 variant `venue_ledger { ledger_account, operator_epoch }`
  (unknown variants fail closed; later milestones add chain vaults). The
  fee schedule's `collateral_reference_kind` for the wedge is
  `ExternalReference`, and M2 defines its verification semantics as: the
  reference resolves through this store to a live, exclusive, currency- and
  amount-matched allocation. `ExternalReference` without a resolving
  allocation stays as unverifiable as today (fail closed);
  `CreditBond`-backed allocations are not wired at M2.
- D11 Exit-test home: `crates/platform/chio-control-plane` (it depends on
  chio-open-market and chio-listing; the reverse direction cannot host the
  HTTP legs). New integration test file
  `tests/finding_market.rs`, which drives the router
  via `tower::ServiceExt::oneshot` wrapped with `apply_server_hygiene`
  (body-cap parity with serve site, router_tests.rs:696-744 precedent) and
  calls the open-market admission-gated bid seam directly for the bid leg.
- D12 Schema access at runtime: chio-control-plane embeds the
  finding-family schemas via `include_str!` at compile time (no filesystem
  dependency at deploy time); `chio-spec-validate` and `chio-finding`
  become normal (feature-gated) dependencies of chio-control-plane.
- D13 Feature-off semantics for shared seams: the generic bond-backing
  dead-end branch
  (`crates/economy/chio-listing/src/trust_activation.rs:563-571`) is NOT
  edited. Generic bond-backed activations remain review-only forever; the
  cognition-market admission path is new, separate, feature-gated code.
  "Replace the transient bond-proof toggle" means the finding market stops
  depending on that toggle, not that the generic evaluator changes.
  Feature-off, the workspace is byte-identical in behavior: no routes, no
  stores, no bid wrapper, no config block (the config field itself is
  feature-gated, so a config file naming it fails closed with an unknown
  field error on a feature-off binary).
- D14 Report-before-backing enforcement: activation rejects a verifier
  report whose `bond_backing` facet is `verified` unless (a) the report
  body names the exact allocation id, (b) that allocation exists and is
  live in the collateral store, and (c) the allocation's venue acceptance
  time (trusted time recorded when the collateral authority registered it)
  is strictly earlier than the report body's `evaluation_time`. All three
  are mechanical store/field comparisons.
- D15 Publish body extractor is `String` (UTF-8 rejection for free;
  `canonical_json_bytes_from_str` takes `&str`), with a route-level
  `DefaultBodyLimit` below the service-wide 1 MiB cap: 256 KiB for
  publish, 1 MiB for recipe upload (matching
  `MAX_PERSISTED_OPERATION_BYTES` scale precedent,
  `crates/platform/chio-store-sqlite/src/admission_operation_store.rs:104-111`),
  each with a doc-comment justification (router.rs:11-28 convention).

## Files

New:
- `crates/economy/chio-finding/src/terms.rs`, `src/authorization.rs`,
  `src/profile.rs`, `src/backing.rs`, `src/report.rs`, `src/admission.rs`,
  `src/recipe.rs` (types + per-concern validators, commerce-order family
  template `crates/platform/chio-commerce-order`).
- `spec/schemas/chio-finding/v1/{challenge-verifier-profile,market-terms,seller-authorization,bond-backing,verifier-report,admission,replay-recipe-input}.schema.json`.
- `crates/trust/chio-attest-buyer/src/finding_verifier/` (the
  `FindingEvidenceVerifier`; siting confirmed in Task 4 against its
  dependency set, fallback is a new `crates/trust/chio-finding-verifier`).
- `crates/platform/chio-store-sqlite/src/finding_market_store.rs` + `.sql`
  + `_tests.rs` (findings, recipes, descriptor index, collateral
  allocations, fee events/epochs, admission bundles; feature-gated).
- `crates/platform/chio-control-plane/src/trust_control/finding_handlers.rs`
  + `service_types` config block + routes (feature-gated).
- `crates/economy/chio-open-market/src/finding_admission.rs`
  (admission verification + `bid_with_finding_admission`; feature-gated).
- `crates/platform/chio-control-plane/tests/finding_market.rs` (exit test).
- Golden fixtures `fixtures/proof-room/finding/<case>/` per new family.

Extended: `crates/core/chio-core-types/src/signed_artifact.rs` (+ lib.rs
re-exports), `spec/schemas/registry.json`, `spec/schemas/MANIFEST.sha256`,
`spec/schemas/COVERAGE.md`, `spec/PROTOCOL.md` 6.4.7.x,
`crates/core/chio-core-types/tests/signed_artifact_schema.rs` parity
tables, `crates/economy/chio-open-market/tests/cognition_market_flow.rs`
seam list, `.github/workflows/ci.yml` lanes,
`docs/research/cognition-market/PLAN.md` ladder row on completion.

## Non-negotiable invariants (repeated at every ingress)

1. Raw-first ingress order (PLAN.md M2, `validate.rs:239-248`): size limit
   -> `canonical_json_bytes_from_str` over the raw text -> raw bytes ==
   strict canonical bytes (canonical-only surfaces) -> schema-validate a
   `Value` parsed from the same accepted input -> typed deserialize ->
   typed canonical bytes == strict canonical bytes -> domain verify ->
   persist/index. Schema-through-parsed-Value cannot see duplicate keys;
   typed deserialization erases alternate encodings and explicit nulls;
   canonicalization normalizes rather than rejects. All three layers are
   load-bearing.
2. Liveness is a surface obligation, both bounds
   (`issued_at <= now && now < expires_at`, the
   `is_live_at` shape at `crates/economy/chio-listing/src/discovery.rs:106-108`):
   publish rejects future-issued AND expired findings; search filters both.
   The M1 validator stays clockless.
3. No authority self-bootstrap: every value-moving check verifies against
   an externally pinned configured authority (key + epoch + validity +
   revocation ref), never an embedded key, and asserts body authority ==
   envelope signer. Strict verification (`verify_canonical_strict` +
   `is_weak_ed25519`, `crates/core/chio-core-types/src/crypto.rs:452,546`)
   everywhere; `SignedExportEnvelope::verify_signature` alone
   (loose, embedded-key, `receipt/lineage.rs:431-434`) is never an
   authority boundary.
4. Acyclic publication order: profile -> recipe -> Finding/listing/hint ->
   seller authorization/terms -> exclusive backing -> verifier report ->
   fee terminals + venue admission. `price_hint_ref` must be absent
   (cycle); terms never bind the backing envelope digest; a report claiming
   `bond_backing: verified` before its named allocation exists rejects
   (D14).
5. Money math: `checked_add`/`checked_mul` only, currency equality before
   addition, lowercase 64-hex digests, `is_hex128` signature prechecks.
6. Every admission failure and every `failed` facet is a typed rejection;
   `asserted` and `unavailable` never satisfy a required facet.

## Task 1: Artifact families - types, validators, schemas, registration

Files: `crates/economy/chio-finding/src/{terms,authorization,profile,backing,report,admission,recipe}.rs`,
`src/lib.rs`, `src/types.rs` (shared enums only), tests; the seven schema
files; four-location registration; parity tables; PROTOCOL 6.4.7.1-6.4.7.7;
COVERAGE.md; golden fixtures.

Artifact shapes (field lists are normative from ARCHITECTURE.md 4.1.1, 5
F1, and PLAN.md M2; all `snake_case`, `deny_unknown_fields`, absence
encodes none):

- `chio.finding.challenge-verifier-profile.v1` (governance-signed
  `SignedExportEnvelope`): receipt signer roles
  (production/delivery/replay), checkpoint logs/signers, BBS projection
  issuer fingerprint/key + registry ref, allowed runner manifests, required
  receipt semantics, resolver/retention policy, resource caps, predicate
  engine + closed predicate list (wedge:
  `baseline_fails_candidate_passes_v1`), verifier-report signer role, M4
  purchase/failed-delivery authority roles, per-key epoch/validity/rotation/
  revocation policy, operator, validity window. MUST NOT contain finding
  id, recipe digest, listing id, report id, or backing id (a
  Finding-scoped profile is a rejected hash cycle). Content-addressed
  `profile_id` (id-and-signature-cleared preimage discipline,
  `validate.rs:178-184`).
- `chio.finding.replay-recipe-input.v1` (UNSIGNED strict wire type):
  `decision_rule_ref`, authorized verifier-profile envelope digest, Finding
  context and payload commitments, mediated runner server/tool + manifest
  digest, ordered baseline/candidate phases with immutable input-bundle
  digests and exact payload-application semantics, canonical parameters,
  runtime image/platform, deterministic
  network/clock/randomness/locale/timezone policy, resource/time bounds,
  closed versioned predicate, pre-run template digest, claimed verdict.
  Companion pre-run template struct commits topic/context, profile,
  runner/tool/manifest, immutable inputs/environment, resource policy, and
  allowed predicate/outcome vocabulary while excluding payload digest,
  producing receipts, outcome class, and verdict. NOT in the signed
  allowlist; `EXPECTED_REGISTRY_ONLY` gains its row.
- `chio.finding.market-terms.v1` (seller-signed): finding/listing/seller,
  canonical backing requirement (`base_finding_stake`,
  `maximum_sale_exposure`, collateral policy; D6), nonzero
  filing/claim/appeal windows, `audit_epoch_length_secs` (D8), audit
  eligibility, decision rules, admitted verifier-profile envelope digest,
  class-specific challenge-bond limits, deterministic payout policy. Never
  binds the backing envelope digest.
- `chio.finding.seller-authorization.v1` (Finding-issuer-signed): exact
  finding id + envelope digest, listing, seller/delegate, provider
  server/tool, payment beneficiary or provider-signed payee mapping,
  validity window, revocation/status reference. Required even when issuer
  == seller.
- `chio.finding.bond-backing.v1` (collateral-authority-signed): seller
  principal, authorization digest, finding, listing, terms/profile digests,
  canonical fee-schedule requirement digest, `Listing` bond class,
  currency, vault reference (closed enum, wedge variant `venue_ledger`;
  D10), operator epoch, locked amount, `maximum_sale_exposure`, nonzero
  claim/audit/appeal/settlement horizons, expiry, unique allocation id.
- `chio.finding.verifier-report.v1` (verifier-authority-signed): finding id
  + exact signed-envelope digest, verifier-profile id + digest, verifier
  implementation id, resolved-evidence bundle digest,
  trust-root/resolver/trusted-time input digests, the 13 typed facet
  outcomes with reasons (`verified | asserted | unavailable | failed`),
  verifier key epoch, `evaluation_time`, content-addressed `report_id`.
  Body authority field must equal envelope signer.
- `chio.finding.admission.v1` (venue-signed): immutable Finding envelope
  digest, seller-authorization digest, signed listing digest, server,
  metadata URL, exact pricing-hint envelope digest, capability scope,
  publisher, payee, fee-schedule envelope digest, verifier-report id +
  envelope digest, terms/profile digests, `fee_terminals` (D7), backing
  allocation id + envelope digest, audit-pool AND
  challenge-administration-pool principal ids/rail destinations/currencies
  + authority epochs (distinct, non-substitutable), community-fund
  destination, status-feed operator profile ref, M4
  purchase/failed-delivery authority identity + key epoch +
  validity/rotation/revocation snapshot, liveness bounds. Body venue
  identity must equal the configured venue authority; admission expiry <=
  earliest constituent expiry (checked min across Finding, seller auth,
  hint, terms, profile, purchase authority, backing, fee epoch, listing).

Schema JSON conventions: draft 2020-12, `$id`
`https://chio.world/schemas/chio-finding/v1/<name>.schema.json`,
`additionalProperties: false` at every level, `const`-pinned `schema`
member, shared `$defs` (`iJsonU64`, `nonBlankString`, `sha256`), signature
`^[0-9a-f]{128}$`, conditional requirements mirroring the Rust validator
(`finding.schema.json` as the worked example). All ids stay `.v1`
(`scripts/check-chio-owned-v1-only.sh`).

Registration checklist per signed family (six times): const in
`signed_artifact.rs` (alphabetical, near :90), spec row
`Some(("<artifact_kind>", "finding-market-v1"))` (:507-510 precedent),
lib.rs re-export, registry.json row (lexicographic; note
`chio.finding.challenge-verifier-profile.v1` sorts BEFORE
`chio.finding.v1`), MANIFEST regeneration (mirror
`scripts/check-chio-schema-registry.sh:79-101` byte format including the
self-hash line), PROTOCOL 6.4.7.x normative section (binding list, encoding
MUSTs, explicit verification non-claims, family-closure paragraph at
PROTOCOL.md:1403-1405 rewritten), COVERAGE.md counts, `EXPECTED_SIGNED`
row. Artifact kinds: `finding_challenge_verifier_profile`,
`finding_market_terms`, `finding_seller_authorization`,
`finding_bond_backing`, `finding_verifier_report`, `finding_admission`;
registry-only kind `finding_replay_recipe_input`.

Red/green: schema-conformance + rejection tests per family
(`validate_finding_schema`/`assert_finding_schema_rejects` pattern,
`tests/finding.rs:34-48`); golden fixture + ignored regenerator per family
(deterministic seeds, README with preimages and non-claims); parity test
extended FIRST and red until all registrations land.

Commits: `feat(chio-finding): M2 market artifact families` (types +
validators), `feat(chio-core-types): register the M2 finding market
families` (registration + schemas + PROTOCOL), `test(chio-finding): golden
fixtures for the M2 families`.

## Task 2: FindingEvidenceVerifier

Files: `crates/trust/chio-attest-buyer/src/finding_verifier/` (mod.rs,
`facets.rs`, `receipts.rs`, `checkpoints.rs`, `cost.rs`, `report.rs`) or
the fallback crate per D-siting; tests.

Confirm siting first: chio-attest-buyer must be able to depend on
chio-kernel (checkpoint machinery), chio-finding, and chio-core-types
without a cycle; if chio-kernel is not admissible there, create
`crates/trust/chio-finding-verifier` and have chio-attest-buyer re-export
the profile (thin, per the crate map). Everything here is feature-gated.

Deliverables, in the normative 9-step order (ARCHITECTURE.md 4.1.1):

- `FindingVerifierTrustRoots` input struct: admitted kernel keys, pinned
  checkpoint signer roles + epochs, receipt crypto floor (explicit, never
  the hardcoded `AllowHybrid` inherited from
  `evidence_export/verification.rs:152-157`), revocation freshness policy
  (`chio-revocation-oracle` `verify_fresh_epoch_root`/`fail_closed`),
  trusted time, resolver policy, profile envelope. Empty admitted-key or
  signer lists DENY (the appraisal/attestation empty-list fail-open trap is
  explicitly inverted).
- Strict receipt verification: reconstruct
  `ChioReceiptSigningBody::from_body_and_bbs` (`receipt/body.rs:486-487`),
  reject weak keys, `verify_canonical_strict`, keep the receipt-id
  recomputation and BBS-binding checks that `verify_signature` performs
  (body.rs:475-489); pin the algorithm. There is no strict receipt verifier
  in-tree today; this is new code, not a reuse of the loose helper.
- Checkpoint composition: copy the `verify_inclusion_proofs` shape
  (`crates/platform/chio-control-plane/src/evidence_export/verification.rs:329-396`)
  and close its five documented gaps: outer-vs-inner `leaf_index` equality,
  `proof.proof.tree_size == checkpoint.body.tree_size`,
  `leaf_index == receipt_seq - batch_start_seq`, log identity via
  `checkpoint_log_id` mapped through the profile, signer key
  epoch/validity/revocation. Pin ONE canonical leaf definition (full
  canonical `ChioReceipt` envelope bytes, the `verification.rs:379` choice)
  in the profile and reject the body-only variant. Route equivocation
  checks through `verify_checkpoint_transparency_records`
  (`chio-kernel/src/checkpoint.rs:645`), never `build_checkpoint_transparency`
  directly; `validate_checkpoint` (:836) runs per checkpoint.
- Exact evidence binding: recomputed receipt ids compared as a whole
  `Vec<String>` (order + cardinality) against `evidence_receipt_ids`;
  every checkpoint identity/ref equal to `evidence_checkpoint_ref`;
  extras, omissions, reorderings, substitution deny.
- Issuer lineage: capability snapshots via `validate_for_transport` ONLY
  (`chio-kernel/src/capability_lineage.rs:88`; the local-read variant
  admits unsigned legacy projections), missing lineage entry is a hard
  error.
- Recipe + intent facets: recipe preimage strict-canonical digest equals
  `replay_recipe_sha256`, runner/manifest/predicate supported by the
  profile, final recipe binds the exact pre-run template digest; intent
  commitment verified only from its own atomic receipt/checkpoint input,
  ordering by single-log continuity
  (`validate_checkpoint_predecessor`/`verify_checkpoint_continuity`,
  checkpoint.rs:881/:737; a `false` is a deny) - the anchored cross-log
  relation is out of wedge scope and reports `unavailable`.
- Cost facets: `metered_exposure_backing` through
  `is_authoritative_spend_receipt`
  (`receipt/authoritative_spend.rs:156`) with externally pinned admitted
  kernel keys and `verify_execution_nonce_without_consume`
  (`execution_nonce.rs:376`; the consuming variant self-denies on
  re-verification); `settled_spend_backing` additionally requires
  `SettlementStatus::Settled` / qualifying capture evidence
  (`receipt/economics.rs:159-185`); checked exact-currency addition;
  `receipt_meets_guarantee_floor` with recognized-level guards on both
  sides (:284-300); `bound_reserved_hold_id() == None` stays an allow.
- Projected mode: wedge profile rejects it outright; the BBS branch
  reports full-receipt/checkpoint/cost facets `unavailable` and the
  verifier only accepts a registry populated from the profile-pinned
  issuer (never a caller-mutable ambient set). Feature-off `bbs` builds
  fail closed at profile load, not silently compile away.
- Runtime assurance: facet exists only when `runtime_assurance_tier` is
  present; requires a non-empty `AttestationTrustPolicy` (a `None`
  policy returns the raw seller tier - explicitly rejected), appraisal
  bound via `matches_evidence` (`chio-appraisal/src/appraisal.rs:62-68`),
  non-`Allow`/reason-coded appraisal outcomes deny.
- Facet report: the 13-facet structured result; any `failed` facet denies,
  and every facet required by the profile or by a present Finding claim must
  be exactly `verified`.
- Report production: `sign_finding_verifier_report` binding the report
  body to the pinned verifier authority (strict sign; body authority ==
  signer), used by the venue at activation; plus
  `verify_finding_verifier_report` against the pinned key + profile
  authorization + validity/revocation snapshot.

Red/green: unit tests per facet with adversarial negatives (weak receipt
key, checkpoint wrapper field mismatch on EACH of the five closed gaps,
reordered receipt ids, substituted checkpoint, stale bond snapshot,
projected-mode rejection under the wedge profile, empty-trust-input
denial, unknown guarantee level, unrecognized floor).

Commits: `feat(chio-attest-buyer): finding evidence verifier profile`,
`test(chio-attest-buyer): adversarial facet coverage`.

## Task 3: Collateral store, fee collection, and open-market glue

Files: `crates/platform/chio-store-sqlite/src/finding_market_store.rs` +
`.sql` + `_tests.rs`; `crates/economy/chio-open-market/src/finding_admission.rs`;
`crates/economy/chio-fiscal` (duplicate-bond-class rejection); all
feature-gated except the fiscal validation tightening.

- Collateral allocation table: allocation id (unique), seller, finding,
  listing, terms/profile digests, fee-requirement digest, currency, locked
  amount, maximum sale exposure, horizons, expiry, acceptance trusted time
  (D14), state (`live | consumed | expired | released`), backing envelope
  digest + raw envelope bytes. Registration API verifies the backing
  envelope against the pinned collateral authority (strict), enforces one
  live allocation per (seller, finding, listing), rejects wrong-party,
  wrong-currency, duplicate-class, underfunded, already-encumbered, stale,
  and reused allocations (the `verify_channel_reservation_proposal`
  single-deny-block discipline, `chio-settle/src/channel/reservation.rs:245-273`).
  Writes `TransactionBehavior::Immediate` + serving-owner fence; reads
  Deferred (`admission_operation_store.rs:190-217` pattern); commit
  failures surface as outcome-unknown.
- Fee event table: idempotency key (D9), event, payer, amount, currency,
  schedule digest, pool principal, rail destination, instruction digest,
  observation digest, state (`intent | reconciled | failed`), epoch index;
  plus `paid_through_epoch` per listing. A failed charge leaves state
  `intent`/`failed` and activation cannot complete; identical retry
  reconciles idempotently; conflicting parameters reject.
- Duplicate-bond-class rejection: `OpenMarketFeeScheduleArtifact::validate`
  gains a same-class duplicate check
  (`crates/economy/chio-fiscal/src/fee_schedule.rs:108-113` currently
  accepts duplicates while the penalty evaluator takes first-match,
  `chio-open-market/src/evaluation.rs:341-345`). This is a strictness fix
  on an always-on type: new rejection, no accepted-input change, noted in
  the commit.
- `finding_admission.rs`: `VerifiedFindingAdmission` witness (private
  fields, accessor methods) produced by `verify_finding_admission` from the
  raw admission envelope + pinned venue authority + store lookups: strict
  envelope verification, body venue identity == configured authority,
  every constituent digest re-verified against stored exact bytes
  (Finding, seller auth, terms, profile, hint, report, backing), liveness,
  sizing inequality (D6) through
  `authorize_fiscal_open_market_fee_schedule`
  (`fiscal_adapter.rs:97-125`; fiscal governance modes keep working) with
  `signed_fee_schedule_digest` binding (:167-173), slashable Listing-class
  requirement, collateral liveness, fee currency (D8), earliest-expiry
  bound. `bid_with_finding_admission(request, context, admission)` then
  delegates to the real `bid()`
  (`crates/economy/chio-open-market/src/bidding.rs:308`), so the public
  marketplace path is exercised unchanged; provider-constraint minting
  stays M4 (the spec test already pins that `BidMintContext` grows then,
  `cognition_market_flow.rs:255-261`).

Red/green: store tests covering exclusivity, reuse rejection, crash/retry
idempotency (kill between intent and observation, between charge and
index), expiry; admission verification negatives (each binding wrong one
at a time); sizing-inequality negatives (undersized, non-slashable,
wrong-currency, duplicate-class).

Commits: `feat(chio-store-sqlite): finding market durable store`,
`fix(chio-fiscal): reject duplicate bond classes in a fee schedule`,
`feat(chio-open-market): finding admission verification and gated bid`.

## Task 4: Control-plane surfaces and activation transaction

Files: `crates/platform/chio-control-plane/src/trust_control/finding_handlers.rs`,
`service_types/paths.rs`, `service_types/config.rs`,
`service_runtime/router.rs`, Cargo.toml (deps: chio-finding,
chio-spec-validate, feature-gated); all routes under the feature.

- Config: `finding_market: Option<FindingMarketConfig>` (feature-gated
  field) with the pinned authority roster (governance root, venue
  identity + key + epoch, verifier-report, collateral, M4
  purchase/failed-delivery), both pool principals with rail-tagged
  destinations + currencies (distinct principals enforced at
  `validate()`), community-fund destination, status-feed operator profile
  ref, sqlite path, service auth posture. `validate()` fail-closed on any
  missing role, unparseable or weak key, or identical pool principals
  (config.rs:106-141 precedent). Surfaces return 409 when the block is
  absent on a feature-on binary (`fiscal_runtime.is_some()` gating
  precedent).
- Paths (in `trust_control/service_types/paths.rs`, NOT the
  `service_types/paths.rs` the architecture doc cites - the doc path is
  stale): `FINDINGS_PUBLISH_PATH = "/v1/findings/publish"`,
  `FINDING_PATH = "/v1/findings/{finding_id}"`,
  `FINDINGS_SEARCH_PATH = "/v1/findings/search"`,
  `FINDINGS_RECIPES_PATH = "/v1/findings/recipes"`,
  `FINDING_ADMISSION_PATH = "/v1/findings/{finding_id}/admission"`,
  `FINDING_ACTIVATE_PATH = "/v1/findings/{finding_id}/activate"`,
  `FINDING_PARTICIPATION_PATH = "/v1/findings/{finding_id}/participation"`,
  `FINDING_PROFILES_PATH = "/v1/findings/profiles"`. Axum 0.8 brace
  syntax; routes registered before `.with_state` (router.rs:654).
- `POST /v1/findings/recipes` (auth, D4/D15) and
  `POST /v1/findings/profiles` (auth; governance-root strict verification,
  content-addressed persist, idempotent).
- `POST /v1/findings/publish` (auth, D3/D15): the invariant-1 pipeline
  verbatim, then liveness (invariant 2, future-issued rejection test),
  `price_hint_ref` absence, `deterministic_replay` retained-recipe check,
  persist EXACT accepted bytes (`CanonicalBytes` witness,
  `receipt_store.rs:3298` precedent), index descriptor. 400 on every
  rejection with a typed reason string.
- `GET /v1/findings/{finding_id}` (public): serve the stored exact bytes
  verbatim as `application/json` (never `Json(value)` re-serialization);
  digest-check on the read path (receipt_store.rs:2684 precedent); 404 on
  unknown.
- `GET/POST /v1/findings/search` (public, D1/D2): bounded, paginated,
  liveness-filtered, admission block per D5.
- `POST /v1/findings/{finding_id}/activate` (auth): the durable idempotent
  activation transaction, composed inside the store's write fence: verify
  every constituent (profile-first acyclic order, invariant 4; D14
  report-before-backing; D6 sizing; seller-authorization strict
  verification against the Finding issuer with issuer==seller still
  requiring it), collect publication fee + epoch 0 (D9), consume the
  allocation exclusively, verify + persist the venue admission envelope
  (venue signs out-of-process; the endpoint accepts the signed envelope
  and verifies it binds exactly what the store holds), index the listing
  admitted - atomically or through the replay-safe outbox; crash/retry
  cannot double-charge or index an incomplete listing. Leader-forwarding
  decision follows the fiscal precedent
  (`certification_handlers.rs:242-248`) when `fiscal_runtime` is present.
- `POST /v1/findings/{finding_id}/participation` (auth, D8).
- `GET /v1/findings/{finding_id}/admission` (public, D5).

Red/green: handler tests per surface (router oneshot with hygiene wrap):
noncanonical raw ingress (duplicate keys, uppercase digest, explicit
null, `1.0` float token), oversized body, future-issued, expired,
`price_hint_ref` present, unretained recipe, wrong issuer, cursor
invalid, unfiltered search, admission absent -> no block in search row,
activation replay, charge-failure -> not indexed, participation renewal,
feature-on 409 when unconfigured.

Commits: `feat(chio-control-plane): finding publish, resolve, and search
surfaces`, `feat(chio-control-plane): finding activation and admission
transaction`.

## Task 5: Exit test, feature lanes, and seam updates

- `finding_publish_discover_admission`
  (`crates/platform/chio-control-plane/tests/finding_market.rs`, D11):
  builds the full stack (temp sqlite, configured authorities, injected
  rail observer), then proves in order: publish + by-id resolution of the
  exact bytes; bounded paginated search by context digest (two pages);
  bid through the REAL `bid()` via `bid_with_finding_admission` only after
  a current admission bundle exists; exact envelope bindings for Finding,
  seller authorization, backing, verifier report, pricing digest; first
  participation epoch + publication charge with exact pool destinations;
  earliest-expiry bound; dedicated live allocation. Then the full
  rejection sweep from the M2 exit definition: missing/invalid/stale
  bundle, wrong/reused collateral, undersized or non-slashable Listing
  requirement, wrong hint/metadata binding, unpaid epoch, noncanonical
  ingress, future-issued and expired findings, wrong
  issuer/delegate/provider/payee, authority self-bootstrap (embedded-key
  admission), report-before-backing order, projected evidence under the
  wedge profile, weak receipt key, inconsistent checkpoint wrapper fields,
  crash/retry double-charge and partial-indexing fault injection.
- Feature-off: `cargo tree` absence lane in ci.yml (no chio-finding /
  chio-spec-validate in chio-control-plane's default graph), plus
  `#[cfg(not(feature))]` absence tests asserting the routes 404 and the
  modules are gone; feature-on build/clippy/test lane.
- Update the `#[ignore]`d spec test seam list in
  `cognition_market_flow.rs` (M2 seams now real; first missing seam
  becomes the M3 delivery gate) and the PLAN.md ladder row for M2 on
  completion, per the section 6 maintenance rules.
- PROTOCOL explicit-gaps paragraph and ADR-0017 partial-implementation
  note extended to cover M2.

Commits: `test(chio-control-plane): M2 publish-discover-admission exit
test`, `ci: add cognition-market lanes`,
`docs(cognition-market): record M2 in the program ladder`.

## Task 6: Full gate and review

`umask 022` full workspace gate (build, test, clippy -D warnings, fmt
--check), `scripts/check-chio-schema-registry.sh`,
`scripts/tests/check-chio-schema-registry.test.sh`,
`scripts/check-chio-owned-v1-only.sh`, both feature lanes locally, then an
adversarial review pass over the whole branch diff before it is declared
ready. Record exact results (counts, HEAD, umask qualification) in this
file under a "Recorded results" heading, following the M0/M1 precedent.

### Recorded results at `32d1d92dd`

Full workspace gate under explicit `umask 022`:

- `cargo build --workspace`: clean.
- `cargo test --workspace`: 480 green targets, 8,199 passed, 22 ignored.
  One target reported a failure, `chio-mcp-edge`'s
  `execute_bridge_mcp_tool_call_async_skips_receipt_write_error_for_request_cancelled`.
  It is a parallelism flake, not a regression: the test passes in
  isolation and the full `chio-mcp-edge` lib suite passes 105/105 on
  three consecutive reruns. This branch touches neither that crate nor
  its receipt-write dependencies; its last change is `51e46336b`, an
  ancestor of this branch. This records a qualified gate, not a claim
  that the single parallel workspace run was green.
- `cargo clippy --workspace --lib --bins --examples -- -D warnings`: clean.
- `cargo fmt --all -- --check`: clean.
- `scripts/check-chio-schema-registry.sh` and
  `scripts/check-chio-owned-v1-only.sh`: pass.

Feature lanes, both under `umask 022`:

- Feature-on: `chio-control-plane` 440 lib tests (including the ten
  publish-discover-admission cases), `chio-store-sqlite` finding-market
  10, `chio-open-market` 17 admission plus 16 bidding plus 31 lib,
  `chio-finding` 88 across three suites, `chio-finding-verifier` 12.
- Feature-off: `chio-control-plane` 430 lib tests including the
  route-absence proof that every finding path answers 404 in a default
  build; `cargo tree -p chio-control-plane -e normal` shows zero
  `chio-finding` edges, which CI enforces.

Known unrelated lints: `cargo clippy -p chio-store-sqlite --all-targets`
reports seven `expect_used` errors in sibling test files this milestone
does not touch (`channel_lifecycle_store_tests.rs`,
`channel_release_publisher_store_tests.rs`, `fiscal_store_tests.rs`,
`receipt_store/tests/retention.rs`). The set is byte-identical with the
feature off, so it predates this work; the workspace gate's lint scope
(`--lib --bins --examples`) does not include it.

## M2 exit criteria

1. All six signed families + the unsigned recipe input registered in every
   required location with bidirectional parity green.
2. `finding_publish_discover_admission` green, covering every rejection in
   the M2 exit definition (PLAN.md), including both fault-injection legs.
3. Feature-off workspace behaviorally unchanged (absence lane green);
   feature-on lane green.
4. The full qualified workspace gate passes at the branch HEAD.
5. PLAN.md ladder, spec-test seam list, PROTOCOL gaps, and ADR-0017 note
   updated in the same branch.
