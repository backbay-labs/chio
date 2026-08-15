# Cognition Market Program Plan

> **For agentic workers:** This is the program-level plan. M0/M1 has been
> executed through the bite-sized plan under [plans/](plans/). Later
> milestone plans are authored fresh when their dependencies and ADR
> decisions land (rule in section 6).

**Goal:** Ship the agent-to-agent cognition market on Chio - coding-agent
verified fixes first, R&D negative results second - as an extension of
shipped primitives, per [ARCHITECTURE.md](ARCHITECTURE.md).

**Architecture:** Finding artifacts listed through the existing registry,
reveal as a governed tool call with a kernel digest gate, settlement on
existing holds/escrow, fraud handled by bonded challenges plus published-rate
audits feeding the existing sanction/slash lane, retraction via a
revocation-oracle status feed. See ARCHITECTURE sections 3-8.

**Tech Stack:** Rust workspace (MSRV 1.93), existing Chio crates; no new
external dependencies anticipated before M7.

## Global Constraints

- No em dashes anywhere (CLAUDE.md); conventional commits; fail-closed
  everywhere; clippy `unwrap_used`/`expect_used` deny.
- Verification gate per change: `cargo build --workspace && cargo test
  --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all
  -- --check`.
- Schema evolution: additive optional fields only; new enum variants on
  frozen `deny_unknown_fields`-style wire enums are forbidden (new `.v2`
  schemas instead). The `Constraint` vocabulary is the deliberate
  exception this program proposes: it is adjacently tagged with
  hard-reject-on-unknown, so the two planned variants are fail-closed
  vocabulary extensions (old kernels refuse the token rather than running
  it without the new enforcement). `OutputDigestSha256` is gated on ADR-A,
  a PROTOCOL.md update, and verdict-matrix rotation at M3.
  `RequireFindingPurchase` with exact finding/listing ids and a closed
  `LocalReversibleHold | CrossOrgEscrow { settlement_profile_sha256 }`
  selector is gated on the M4 provider-mint design, a PROTOCOL.md update, and
  a second verdict-matrix rotation at M4. M4 registers both selector shapes
  while leaving cross-org disabled until M7. `Constraint::Custom` is rejected
  as the digest carrier
  because it is input-side and semantically ignored by old kernels
  (fail-open; `chio-kernel/src/request_matching.rs:420`). Every standalone
  signed-artifact schema id registers in `signed_artifact.rs` and
  `spec/schemas/registry.json`. The current generic
  `signed_artifact_schema` test proves allowlist-to-registry correspondence,
  not reverse parity, so each milestone adds explicit rows plus a
  bidirectional parity assertion. `cargo test -p chio-core-types --test
  signed_artifact_schema` and `scripts/check-chio-schema-registry.sh` are
  both required. Receipt-metadata block schemas
  register under `spec/schemas/chio-wire/v1/receipt/` and the public
  registry/manifest, but are signed by the enclosing receipt and do not
  enter the standalone allowlist. They require typed structs, reserved keys,
  PROTOCOL text, and enclosing-receipt canonical/signature round-trip tests.
- Ship dark until qualified: M2+ runtime, service, and CLI surfaces sit
  behind a consistently named `cognition-market-experimental` feature on
  each owning crate and outside the bounded operational profile until M9
  (`docs/release/QUALIFICATION.md`, bounded gate `cargo xtask qualify
  bounded-chio`). Each milestone tests both feature-off absence and
  feature-on behavior. The pure M1 leaf crate and M0 public schema are
  protocol foundations, not enabled operational market surfaces. M9 repeats
  qualification against the exact source and feature set proposed for the
  flip; passing while still dark is not release evidence.
- Proof-claim discipline: nothing listable under capabilities
  `ChioProofClaims` rejects; evidence classes never upgraded.

## 0. Baseline: PR #974 has landed; M3 requires re-anchoring

PR #974 landed as `51e46336b` and is an ancestor of the current
`9ec6814a2` implementation baseline. Its durable admission and payment
pipeline invalidates the earlier M3 placement assumptions:

- Production financial dispatch uses the durable terminal lane, which runs
  post-invocation transforms and computes the final output hash before
  payment planning and terminal settlement.
- A durable hook `Block` becomes `KernelError::DurableAdmission`, not a
  signed Deny or compensation transition.
- The durable finalizer signs receipts directly, so the legacy Allow builder
  is not universal.
- The unsafe legacy charged lane still reconciles before its Allow builder
  and must be covered or rejected fail-closed.
- `PrepaidFinal` may settle before dispatch. A post-return digest mismatch
  therefore needs a rail restriction or explicit durable compensation, not
  an assumed release.

The `OutputDigestSha256` carrier remains the leading candidate because
unknown constraint variants fail closed and PR #974 established in-v1
constraint extension precedent. Gate placement, durable mismatch state,
legacy coverage, and `PrepaidFinal` policy remain undecided. M3 is blocked
until a fresh ADR-A and kernel-owner review resolve them.

## 1. Milestone ladder

Each milestone is independently shippable and independently stoppable; a
stop after any milestone leaves the repo strictly better documented and no
production surface half-wired.

| M | Name | One-line scope | Depends on | Plan status |
|---|---|---|---|---|
| M0 | Spec and registration | `chio.finding.v1` registered (challenge/status schemas deferred to M5/M6 per review); ADR-0017 remains Proposed | - | implemented with M1 |
| M1 | `chio-finding` crate | artifact types, strict validators/signing, golden | M0 | implemented; qualified workspace gate passed |
| M2 | Publish and discover | descriptor search surface; listing publish path; bond-proof admission gate | M1 | implemented dark behind `cognition-market-experimental`; plan [plans/2026-07-28-M2-publish-and-discover.md](plans/2026-07-28-M2-publish-and-discover.md) |
| M3 | Kernel delivery contract | candidate `Constraint::OutputDigestSha256`; durable and legacy digest enforcement; generic `chio.delivery-contract.v1` receipt block; verdict-matrix rotation; bounded Lean settlement-admission model | M1 | implemented on `codex/cognition-market-m3`; ADR-A landed as [ADR-0019](../../adr/ADR-0019-kernel-delivery-contract.md); plan and recorded results [plans/2026-07-28-M3-kernel-delivery-contract.md](plans/2026-07-28-M3-kernel-delivery-contract.md) |
| M4 | Wedge purchase E2E | reference finding server; ADR-A-selected output-aware durable hold/capture; `chio finding` CLI (publish/search/verify/buy) | M2, M3 | implemented on `codex/cognition-market-m4`, including authenticated live purchase route exit; plan and recorded results [plans/2026-07-28-M4-wedge-purchase-e2e.md](plans/2026-07-28-M4-wedge-purchase-e2e.md) |
| M5 | Challenge and audit lane | frozen-v1 `FraudulentListing` mapping plus signed finding challenge outcome; challenge evaluator; verifiable audit schedule; slash wiring | M4 | implemented on `codex/cognition-market-m5`; plan and recorded results [plans/2026-07-30-M5-challenge-and-audit-lane.md](plans/2026-07-30-M5-challenge-and-audit-lane.md) |
| M6 | Status feed and retraction | oracle instance; control-plane root/proof surfaces; purchase-time non-inclusion; challenge-outcome outbox; quarantine guard rule; ops runbook | M4, M5 | implemented; plan and recorded results [plans/2026-07-31-M6-status-feed-retraction.md](plans/2026-07-31-M6-status-feed-retraction.md) |
| M7 | Cross-org escrow path | delivery-receipt settlement-authority bridge; bilateral evidence flow; funded escrow and watchdog runbook | M4, M5, M6 | blocked pending bilateral demand and ADR-C |
| M8 | Pool purchasing and SDK | swarm purchasing convention; elicitation ceiling in SDKs; pheromone hint convention | M4 | implemented; plan and recorded results [plans/2026-07-31-M8-pool-purchasing-sdk.md](plans/2026-07-31-M8-pool-purchasing-sdk.md) |
| M9 | Qualification and claims | bounded-matrix entries; CLAIM_REGISTRY rows; RC guarantee entries; R&D-instance extensions | M5, M6 | plan after M6 |

## 2. Per-milestone definition

### M0 + M1 (implemented)

Deliverables and steps: [plans/2026-07-20-M0-M1-finding-artifact-family.md](plans/2026-07-20-M0-M1-finding-artifact-family.md).
Commits `015381975` through `04f5d3e66` implement the paired foundation,
with progress-spec and workspace-clippy follow-ups through `88d4bde1f`.
Overnight on 2026-07-27/28, exact HEAD `88d4bde1f` passed the full workspace
build, test, clippy, and format gate under explicit `umask 022`, plus
`scripts/check-chio-owned-v1-only.sh`,
`scripts/check-chio-schema-registry.sh`, schema tests, and the focused
Finding/open-market tests. The workspace test run reported 855 green targets,
12,275 passed tests, zero failures, 43 ignored, and 788 filtered. The first
run under host `umask 002` failed ten pre-existing `chio-cli` permission
fixtures; the same failure reproduced on untouched `origin/main`. This
records a qualified `umask 022` gate, not a claim that the default
host-umask run was green. `chio.finding.v1` is accepted by
`validate_signed_artifact_schema`; the golden fixture validates against
schema and struct. Post-gate refinements `e429963d8`, `20cdc7f83`,
`1efbbc112`, and `ea105498d` passed their focused tests, test-target clippy,
and formatting checks. Challenge and status-feed schemas are deliberately NOT
registered here - they land with M5/M6. The status artifact may embed the
oracle root envelope, but its own signature must also bind the status backend,
feed, nonce, and proof-semantics domain (ARCHITECTURE 4.4).

### M2 Publish and discover

Status: implemented on `codex/cognition-market-m2` (stacked on the M0/M1
branch) per the bite-sized plan
[plans/2026-07-28-M2-publish-and-discover.md](plans/2026-07-28-M2-publish-and-discover.md),
which fixes the fifteen design points this definition left open (D1-D15)
and records the recorded-results gate. Every runtime surface ships dark
behind `cognition-market-experimental`; the artifact families and their
registrations are always-on spec. The definition below remains the
normative scope statement.


- Control-plane `POST /v1/findings/publish`: the REUSABLE `Finding`-ingress
  invariant (review finding) - FIRST apply a request-size limit and run
  `canonical_json_bytes_from_str` over the raw request to reject duplicate
  keys and non-I-JSON numbers, retaining its strict canonical bytes, and
  require the raw body bytes to equal those canonical bytes if this endpoint
  advertises canonical-only ingress. Canonicalization by itself normalizes
  whitespace and key order; it does not reject a noncanonical spelling. THEN
  schema-validate a parsed value from that same accepted input, deserialize,
  require the typed canonical bytes to equal the strict canonical bytes, and
  run `verify_finding` (structure + content-addressed id + strict issuer
  signature), then index. The order is load-bearing: schema validation
  through a parsed `Value` cannot recover duplicate keys, while typed
  deserialization can erase alternate encodings and explicit `null` fields.
  This same invariant applies at M4 (buyer-presented overlay `Finding`) and
  M5 (challenge-evaluator `Finding`), each with rejection coverage.
  Add immutable `GET /v1/findings/{finding_id}` with canonical artifact
  digest binding for `metadata_url` resolution, plus bounded and paginated
  `GET/POST /v1/findings/search` over a length-bounded topic prefix and exact
  `context_sha256`, following the three-step surface pattern (ARCHITECTURE
  8.1; precedent
  `chio-control-plane/src/trust_control/certification_handlers.rs:143`).
- Listing publish path: finding server listed under `ToolServer` actor kind
  with `metadata_url` pointing at the finding artifact (ARCHITECTURE 7.3);
  pricing hint carries `capability_scope` = `finding:<finding_id>` (colon
  segments per `capability_scope_covers`, `bidding.rs:534`; verified
  end-to-end in the spec test).
- Before authoring a deterministic recipe or Finding, define and register a
  reusable governance-signed
  `chio.finding.challenge-verifier-profile.v1`. It binds receipt signers by
  role (production, delivery, replay), checkpoint logs/signers, the externally
  trusted BBS projection issuer fingerprint/key and registry, allowed runner
  manifests, required receipt semantics, resolver/retention policy, resource
  caps, predicate engine and allowed closed predicates, the verifier-report
  signer and M4 purchase/failed-delivery authority roles, each key's epoch,
  validity/rotation/revocation policy, operator, and validity window. Those
  role keys are also independently pinned by deployment governance; naming
  them in the profile does not let the profile self-authorize. It
  contains no Finding id, recipe digest, listing id, report id, or backing id.
  The recipe commits this profile's signed-envelope digest and the Finding
  then commits the recipe digest. A Finding-scoped profile is a rejected hash
  cycle.
- Define and register the unsigned
  `chio.finding.replay-recipe-input.v1` verifier-input schema and strict
  typed validator. It canonically binds `decision_rule_ref`, an authorized
  replay-verifier-profile digest, Finding context and payload commitments,
  mediated runner server/tool and manifest digest, ordered baseline/candidate
  phases with immutable input-bundle digests and exact payload-application
  semantics, canonical parameters with no substitution ambiguity, runtime
  image/platform, deterministic network/clock/randomness/locale/timezone
  policy, resource/time bounds, a closed versioned predicate (the wedge starts
  with `baseline_fails_candidate_passes_v1`), the digest of a cycle-free
  pre-run descriptor/protocol template, and the claimed verdict. The pre-run
  template commits topic/context, profile, runner/tool/manifest, immutable
  inputs/environment, resource policy, and allowed predicate/outcome
  vocabulary, but excludes the final payload digest, producing receipts,
  selected outcome class, and claimed verdict. The final recipe adds those
  outcome-derived commitments and links the exact template digest. A
  `deterministic_replay` publication must supply a size-bounded strict raw
  preimage whose canonical digest equals `Finding.replay_recipe_sha256`;
  missing, duplicate-key, unknown-field, non-canonical, or hash-mismatched
  inputs reject. The venue retains the recipe and every digest-addressed
  dependency through the full claim/audit/appeal horizon; seller availability
  cannot control adjudication. It registers in the public schema
  registry/manifest but not the independently signed-artifact allowlist.
- Define and register seller-signed `chio.finding.market-terms.v1` and
  Finding-issuer-signed `chio.finding.seller-authorization.v1`. Terms bind
  the Finding/listing/seller, canonical backing requirement and policy,
  nonzero filing/claim/appeal windows, audit eligibility, decision rules,
  verifier profile, class-specific challenge-bond limits, and deterministic
  payout policy; they do not bind the later backing-envelope digest. Seller
  authorization binds the exact Finding, listing, seller/delegate, provider
  server/tool, payment beneficiary or provider-signed payee mapping,
  validity, and revocation/status reference. Require it even when issuer and
  seller are equal. Deployment
  configuration independently pins governance-root, venue-admission,
  verifier-report, collateral, seller-authorization, and BBS projection
  authorities, including key/fingerprint and epoch, validity, rotation,
  revocation/status source, trusted registry, and resolver. An embedded key,
  mutable ambient trusted-key set, challenger-selected rule, or
  report/profile pair cannot bootstrap value-moving authority.
  Governance also pins distinct audit-pool and challenge-administration pool
  principals, rail-tagged beneficiary destinations, currencies, and authority
  epochs. They are non-substitutable and are repeated in venue admission.
- Define the M2 `FindingEvidenceVerifier`, distinct from M1
  `verify_finding`. It strict-parses the raw Finding, resolves every evidence
  and intent reference into atomic canonical receipt/checkpoint inputs, and
  verifies receipt bodies with strict Ed25519/weak-key rejection. It
  cross-checks checkpoint/log identity, wrapper sequences and roots, range,
  index, tree size, canonical leaf, signer/key epoch, validity, revocation,
  and inclusion path; `ReceiptInclusionProof::verify` alone is insufficient.
  Recomputed receipt ids, order, and cardinality must exactly equal
  `Finding.evidence_receipt_ids`, and every supplied checkpoint identity/ref
  must equal `Finding.evidence_checkpoint_ref`; extras, omissions, reorderings,
  and checkpoint substitution deny.
  It verifies trusted kernel state, issuer/evidence attribution through
  signed capability snapshots plus transport validation, recipe and
  descriptor context, evidence-class and guarantee-class boundaries,
  runtime-assurance backing when the tier is present, and bond/liveness
  facets. Runtime assurance requires the exact appraisal and runtime
  attestation to verify under the profile and bind the producing receipts; an
  unrelated attestation or seller label is not backing. The intent reference
  gets its own checkpoint input; it commits the cycle-free pre-run template
  above and proves ordering through one log sequence or an admitted anchored
  cross-log relation. The final recipe must link that exact template digest.
  Full-receipt cost exposes two distinct typed
  facets. `metered_exposure_backing` uses checked exact-currency addition
  after admitted-kernel, mediated-reconciliation, and matching signed-nonce
  checks; it proves only kernel-accounted metered exposure.
  `settled_spend_backing` additionally requires qualifying capture or
  finalized settlement evidence and proves kernel-accounted settled spend.
  Neither proves paid honest work or compute burn. A projected disclosure
  authenticates only disclosed statements; full receipt, checkpoint, hidden
  semantic, and both cost facets remain unavailable unless separately proven.
  A `failed` facet always denies activation or purchase because it records a
  check that ran and contradicted its evidence. Every facet required by the
  profile or by a present Finding claim must be exactly `verified`; `asserted`
  and `unavailable` deny when that facet is required. The deterministic wedge
  rejects projected mode.
  Define and register signed
  `chio.finding.verifier-report.v1` rather than leaving the result as an
  untyped blob. Its body binds the Finding id and exact signed-envelope
  digest, verifier-profile id and digest, resolved-evidence bundle digest,
  trust-root/resolver/trusted-time input digests, per-facet typed outcomes and
  reasons, verifier key epoch, evaluation time, and report id. Only an
  externally pinned, profile-authorized verifier key that was valid and
  unrevoked at evaluation may sign it, and the body authority must equal the
  envelope signer. Produce the report only after the collateral authority has
  created the live backing allocation, so `bond_backing: verified` cannot
  predate its evidence. Unsigned recipes and resolved verifier inputs remain
  content-addressed non-authority attachments. Persist the exact signed report
  envelope and bind its canonical digest into admission and later offline
  verification; no caller-authored report, embedded-key-only verification,
  or body-only digest is authoritative.
- Define durable Finding storage and exact publication bindings. Treat
  the Finding-scoped pricing hint as a venue-admission binding, not
  `Finding.price_hint_ref`: the hint signs `finding:<finding_id>`, so hashing
  its signed envelope into the Finding would create a cycle. M2 requires
  `price_hint_ref` absent for this projection. Persist and serve the exact
  accepted signed Finding bytes at the immutable metadata URL, and reject any
  URL response whose canonical envelope digest differs. Bind the immutable
  signed Finding, seller authorization, signed listing, server, metadata URL,
  exact signed pricing-hint envelope digest, capability scope, publisher,
  payee, fee schedule, exact signed verifier-report envelope digest, and every
  validity bound in one venue-signed admission bundle. The bundle also pins
  the profile-authorized M4 purchase/failed-delivery authority identity, key
  epoch, validity, rotation, and revocation snapshot before any sale; a
  runtime-selected kernel signer is not sufficient. Require the admission
  body venue identity and envelope signer to equal the externally configured
  venue authority. Admission expiry is no later than the earliest Finding,
  seller authorization, pricing hint, terms, verifier profile, purchase
  authority, backing, fee-epoch, or listing expiry.
- Replace the transient bond-proof toggle with a live, non-reusable
  collateral allocation bound to seller principal, finding, listing, fee
  schedule, Listing bond class, currency, locked amount, vault/reference,
  maximum sale exposure, nonzero claim/audit/appeal horizons, and expiry.
  The wedge dedicates one allocation to one finding listing and rejects
  wrong, stale, already allocated, or reused collateral. Expiry must extend
  past every admitted sale's claim, appeal, and settlement buffer. Admission
  also verifies a slashable `Listing` requirement in the exact signed fee
  schedule, with matching currency and
  `required_amount.units >= base_finding_stake + maximum_sale_exposure`;
  otherwise the generic penalty evaluator would cap a later finding penalty
  below the promised backing.
- Enforce the acyclic publication order:
  reusable governance profile -> recipe -> Finding/listing/hint -> seller
  authorization/terms -> exclusive backing allocation -> verifier report ->
  fee terminals and venue admission.
  Backing may bind terms/profile, while terms bind only its requirement and
  policy. Admission binds all exact envelopes. Reject any report that claims
  bond verification before the named allocation exists.
- Make activation a durable idempotent publication transaction. It collects
  the publication charge and the first recurring
  `market_participation_fee` audit epoch on an evidenced rail to the exact
  governance-pinned audit-pool beneficiary, persists terminal receipts naming
  schedule, event, payer, amount/currency, pool principal, and rail
  destination, consumes the collateral allocation, writes the admission
  bundle, and indexes the listing atomically or through a replay-safe outbox.
  Admission repeats both the audit-pool and challenge-administration pool
  identities/destinations and authority epochs. One hundred percent of the
  participation fee is restricted to the audit pool. A failed charge cannot publish for free;
  crash/retry cannot double-charge or index an incomplete listing. Later
  unpaid epochs make the listing non-admitted.
- Liveness at publish/search time, BOTH bounds
  (`finding.issued_at <= now && now < finding.expires_at`, matching the
  marketplace helpers): publish rejects future-issued AND expired findings
  fail-closed and search filters them (a correctly signed but expired OR
  not-yet-live artifact must not be indexable or pairable with a fresh
  pricing hint; the M1 validator is clockless by design, so liveness
  belongs to these surfaces). Future-issued rejection test included.
- Trusted search, bid, and later purchase accept only a current venue-signed
  admission bundle and reverify its Finding/listing/hint/liveness/collateral
  and fee-terminal bindings. Generic marketplace search remains available
  but cannot advertise the qualified cognition-market profile.
- Exit: `finding_publish_discover_admission` publishes and resolves a signed
  finding by id,
  searches it through bounded pagination by context digest, and bids through
  the real public marketplace path only after a current admission bundle is
  present. It proves the exact signed Finding, seller authorization, backing,
  and verifier-report envelopes, pricing digest, first participation epoch,
  publication charge,
  earliest-expiry bound, and dedicated live allocation are bound. It rejects
  missing/invalid/stale bundles, wrong or reused collateral, an undersized or
  nonslashable Listing requirement, wrong hint/metadata binding, unpaid fee,
  noncanonical raw ingress, future-issued and expired Findings, wrong
  issuer/delegate/provider/payee, authority self-bootstrap, report-before-
  backing order, projected evidence under the full-receipt wedge profile,
  loose or weak receipt keys, inconsistent checkpoint wrapper fields, and
  crash/retry double charge or partial indexing. The workspace gate is green.

### M3 Kernel delivery contract (blocked pending ADR-A)

- Write ADR-A against current main before implementation. It must decide the
  carrier, durable mismatch transition, legacy-lane policy, `PrepaidFinal`
  policy, generic transform semantics, the M4 finding-profile compatibility
  boundary, and receipt metadata insertion points.
- Leading carrier: `Constraint::OutputDigestSha256(String)`. Add explicit
  exhaustive handling in core serialization, governed validation, portable
  normalization, the production request matcher, and both terminal lanes.
  Input matching is only carrier admission, not output enforcement. Browser,
  mobile, and direct portable-core evaluators must reject the constraint
  before Allow unless M3 adds an atomic output-aware finalizer; their
  separate receipt-signing APIs do not hold the expected constraint.
- Resolve the selected `matched_grant_index` before dispatch and require that
  selected grant to contain exactly one canonical lowercase 64-hex output
  digest. Freeze `(grant_index, digest)` in durable admission so restart
  cannot select a different grant. An unselected grant cannot supply or
  override the digest. Missing, malformed, duplicate, conflicting,
  alternate-matching-grant, grant-selection-ambiguity, and budget-fallthrough
  cases reject before dispatch.
- Shared semantics: compare the expected digest with
  `receipt_content_for_output` over the final post-transform value preimage.
  M4 specializes that value to the Finding reveal envelope. `Stream` denies
  fail-closed unless ADR-A defines an exact committed stream representation.
  This M3 result is generic delivery evidence, not finding-specific
  seller-fraud evidence.
- Durable lane: evaluate after durable post-invocation transforms and before
  payment disposition or settlement. Mismatch must become a persisted,
  replay-stable signed Deny with explicit financial terminal state. The
  existing durable hook `Block` error is not sufficient.
- Legacy lane: evaluate before `reconcile_budget_charge`, or reject
  digest-constrained requests before dispatch whenever unsafe legacy
  financial dispatch is active. This includes the no-charge-result
  `MustPrepay` branch that can capture before the post-invocation transform,
  not only `reconcile_budget_charge`. The legacy Allow builder may be a
  local backstop but is not a universal gate.
- Reserve-for-caller, API Protect, HTTP authority, and every other
  authorization-only or no-output surface must reject this constraint before
  nonce minting or budget/payment mutation unless it gains the same atomic
  output-aware finalizer. Browser, mobile, portable-core, portable verifier,
  `MustPrepay`, and `PrepaidFinal` paths likewise reject before any budget or
  payment mutation unless their owning ADR-selected implementation proves the
  same output-aware terminal ordering. Merely adding the constraint to their
  input matcher is not support.
- Limit the generic no-capture mismatch profile to authenticated read-only
  tools whose side-effect classification is part of admission. Unknown or
  side-effecting tools reject predispatch unless ADR-A defines a separate
  evidenced terminal policy for irreversible effects.
- `PrepaidFinal` and reserve-for-caller `MustPrepay`: disallow them for the M3
  qualified profile. A future profile may add a durable, evidenced,
  replay-safe compensation transition, but M3 does not claim that mismatch
  implies release, reversal, or zero realized spend on either prepayment
  path.
- Receipt metadata at M3 is only the generic
  `chio.delivery-contract.v1` block. The expected digest comes from the
  externally authored provider-signed token constraint; the observed digest
  and comparison are kernel-derived. The block contains only expected digest,
  observed digest, and `matched | mismatched`, with `matched` restricted to
  Allow and `mismatched` restricted to a persisted Deny. Selected grant and
  settlement bindings stay in existing authorization/payment metadata. The
  finding-specific
  `chio.finding.delivery.v1` overlay and provider-to-finding binding remain
  M4 work; M4 attaches both blocks to a verified purchase-context mismatch
  Deny so M5 has authenticated finding-specific evidence.
- Rotate the verdict matrix with one `delivery_contract` scenario class, and
  add the Kani and Lean delivery-soundness hooks after the executable
  transition is chosen.
- Exit: the named `output_digest_delivery_contract` integration test proves
  that every admitted lane either enforces "Allow implies
  content_hash equals expected digest" or rejects the constrained request
  before dispatch. Durable reversible-hold mismatch produces a signed Deny
  with no capture; transformed-output and stream cases are covered; the
  chosen `PrepaidFinal` behavior is proved; legacy financial dispatch is
  gated or rejected; browser/mobile/portable pre-dispatch surfaces reject or
  gain atomic output enforcement. A matched Allow contains a signed
  `delivery_contract` block with the frozen expected digest, observed digest,
  and `matched`; the enclosing receipt's existing authorization/payment
  metadata identifies the selected grant and intended settlement. Exact-digest
  cardinality and alternate-grant negatives pass. The ADR-selected Kani
  harness, bounded Lean proof-manifest entry, verdict matrix, and workspace
  gate are green.

### M4 Wedge purchase E2E

- Seam ownership: M3 supplies generic output-digest enforcement. M4
  completes reveal seam (a) by adding provider-supplied constraints to the
  minted grant, including a provider-signed
  `RequireFindingPurchase` marker with exact finding/listing ids and a closed
  settlement selector, binding them to the verified signed `Finding`, and
  serving the payload through the
  reference `read_finding` tool server. Register and document the marker
  additively in every constraint serializer, normalizer, and matcher; unknown
  or unsupported portable profiles reject it fail-closed.
- The marker selects the v1 identity-output profile. Before dispatch, reject
  every marked reveal whose `PostInvocationPipeline` is non-empty; the
  current hook trait has no static effect declaration, so v1 cannot classify
  hooks safely. Freeze the empty hook-identity sequence in durable admission,
  reject replay/restart under a different plan, and at finalization assert
  the canonical seller-origin envelope was not mutated. Record
  kernel-verified `transform_profile: identity` in the finding overlay. A
  redaction, replacement, or any non-empty hook pipeline is an
  operator-policy incompatibility Deny with the selected financial terminal
  state, never a seller `digest_mismatch`. Add regressions for empty-pipeline
  admission, pre-dispatch rejection of an Allow-only hook and a redactor,
  frozen-plan change, no funds captured, no finding overlay claiming
  mismatch, and no sanction evidence. Transform-aware finding delivery is
  deferred.
- Reference finding tool server (serves sealed payload bytes for
  `read_finding(finding_id)`; buyer-blind per ARCHITECTURE 6.3) under
  `examples/` or a small crate, registered via
  `register_tool_server`.
- Purchase flow glue: bid/ask/accept with the seller minting exactly one
  DPoP-required grant for the exact server and `read_finding` tool, with
  `SignedBidRequest.body.requested_scope.max_invocations = Some(1)`,
  `SignedAskResponse.body.token_offer.scope.grants.len() = 1`, and
  `SignedAskResponse.body.token_offer.scope.grants[0].max_invocations =
  Some(1)`. That one selected grant carries exactly one
  `OutputDigestSha256`, exactly one `RequireFindingPurchase` with
  `LocalReversibleHold` for the M4 wedge,
  `dpop_required = Some(true)`, and
  `max_cost_per_invocation = max_total_cost = Some(accepted_price)`.
  The buyer cannot choose the provider/tool/cardinality profile.
  The current pure `chio_open_market::bidding::accept()` does not reserve
  funds: it only checks a `VerifiedReservationReceipt` and copies its
  `receipt_id` into `SignedAcceptedBid.body.bid_receipt_id`. M4 therefore adds
  an explicit single-operator `FindingPurchaseCoordinator` at the
  kernel/control-plane boundary. After `bid()`, that coordinator authenticates
  the buyer key, verifies the exact signed ask, quote, and venue-admission
  envelope, preallocates stable `purchase_intent_id` and
  `authoritative_payment_operation_id`, and atomically opens durable kernel
  budget and seller-exposure reservations keyed by those ids, ask digest,
  payer, listing/Finding, admission digest, amount, currency, and expiry. It
  commits that rich coordinator record and only then signs the existing
  minimal `SignedReservationReceipt` as a compatibility pointer under the
  configured reservation authority. The caller derives
  `VerifiedReservationReceipt::from_signed(receipt,
  expected_reservation_authority)` and passes it to `accept()`. `accept()`
  validates the compatibility receipt; it does not create the reservation or
  capture external payment. The coordinator store, not a caller-shaped
  receipt, remains authoritative, is re-resolved through the accepted bid's
  `bid_receipt_id`, and supplies the same preallocated ids at reveal.
  Reveal uses ADR-A's durable
  direct-evaluation `MeteredSettlementMode::HoldCapture` with
  `PaymentRailMode::ReversibleHold`; capture occurs only after the identity
  output passes digest and media-type checks. Reserve-for-caller
  `MustPrepay`, `PrepaidFinal`, legacy financial dispatch, portable
  evaluators, x402 final prepayment, and ACP's currently synthetic terminal
  effects are ineligible. Postdispatch ambiguity remains pending for durable
  recovery and is not called a refund.
  This includes the
  small open-market extension this requires: `bid()` mints grants with
  `constraints: Vec::new()` and `dpop_required: None` hardcoded
  (`bidding.rs:396` region), so `BidMintContext` grows BOTH
  provider-supplied grant constraints and a `dpop_required` flag. The
  provider-signed constraints include the generic output digest and
  `RequireFindingPurchase` with exact ids plus
  `LocalReversibleHold | CrossOrgEscrow { settlement_profile_sha256 }`, which
  makes missing finding or rail context fail closed instead of
  indistinguishable from a generic digest-constrained call. Local mode rejects
  an escrow-witness key; cross-org mode requires it and the exact profile
  digest. Without the DPoP flag, M7's escrow grants cannot bind the buyer and
  the no-buyer replay stays open.
  The buyer's accept path checks both constraints against the finding and
  listing, and `read_finding` admission denies unless a verified
  `SignedAcceptedBid` binds that exact token to the kernel-authoritative
  reservation.
- Exact economic bindings: venue-admission envelope, listing price, ask quote,
  accepted-bid quote, governed quote, budget reservation, seller exposure,
  payment authorization/operation, and capture are bound end-to-end, with all
  amounts equal in units and currency. The token subject is the bid signer or is
  linked by an authenticated immutable mapping; the reservation binds that
  payer public key, not only opaque `agent_id`. The provider, listing seller,
  payee, payment beneficiary, token issuer, and Finding issuer are equal or
  connected by the exact issuer-signed
  `chio.finding.seller-authorization.v1` and provider-signed payee mapping.
  M4 atomically encumbers `k * accepted_price` (`k >= 1`) from
  the M2 live allocation before reveal, releases it on an unsuccessful sale,
  and retains it through the liability horizon after capture. Reject lower
  caller quotes, wrong currency/payee/payer, copier relisting, expired
  allocation, concurrent overcommit, and a sixteenth distinct buyer payout
  destination in the unbatched v1 EVM profile (one of 16 vault slots remains
  reserved for the admission-pinned community-fund destination). The
  rail-tagged buyer destination and its canonical digest are frozen into the
  authoritative purchase record at capture finalization and can never be
  resolved again at challenge time. Repeated purchases to an already admitted
  immutable destination do not consume another slot.
- Bind the seller-signed market-terms and governance verifier-profile digests
  plus the exact venue-admission envelope digest through the listing and ask,
  accepted bid's resolved reservation, exact grant, budget/exposure
  reservation, payment operation, purchase record, challenge, outcome, and
  enforcement. A challenger cannot substitute a rule, window, backing,
  runner, or payout policy after sale.
- The actual request argument must contain one typed `finding_id` equal to
  the grant marker and signed Finding before hold authorization. Missing,
  wrong, duplicate, or wrong-typed arguments deny without a new nonce, debit,
  capture, or invocation. The coordinator idempotently cancels/releases the
  already-existing budget and seller-exposure reservations under that failure
  terminal, or their explicit expiry transition does so. Reserve
  `context.chio_finding_purchase_context_b64` for a size-bounded base64
  canonical `chio.finding.purchase-context.v1` JSON carrier holding exactly
  the signed Finding, `SignedGenericListing`,
  `SignedListingPricingHint`, venue-signed admission, seller-signed market
  terms, Finding-issuer-signed seller authorization, governance-signed
  verifier profile, authority-signed seller backing, signed verifier report,
  original `SignedBidRequest`, `SignedAskResponse`, `SignedAcceptedBid`, the
  coordinator-issued `SignedReservationReceipt`, its authoritative store key,
  and the exact token offer. No ambient lookup may fill an omitted authority
  artifact. Admission decodes and strict-parses
  raw bytes, schema-validates, and
  cross-binds the complete token bytes to `SignedAskResponse.token_offer`;
  the separately carried token must be byte-identical to that embedded token,
  so matching only token id, subject, and expiry is insufficient.
  Same-subject alternate tokens, extra grants/constraints, and substituted
  artifacts deny.
- `chio finding publish|search|verify|buy` CLI following the documented
  family pattern (ARCHITECTURE 8.3). `verify` runs M2's integrated
  `FindingEvidenceVerifier` and prints every facet; M1 integrity verification
  alone is never labeled offline evidence verification.
- Rotate the verdict matrix again with a finding-purchase scenario class.
  Cover provider mint rejecting an absent required marker, malformed or
  unknown markers failing closed, finding/listing mismatch, missing purchase
  artifacts when the marker is present, legitimate unmarked generic digest
  calls receiving no finding overlay, and portable profiles rejecting the
  marker unless they gain equivalent purchase-aware admission.
- Delivery idempotency (ARCHITECTURE F3 step 6, load-bearing per review):
  choose and test an explicit second authorization for
  buyer-crash-after-Allow recovery. The leading no-kernel-change candidate
  is a seller-minted, DPoP-bound no-charge recovery grant/tool issued to the
  original delivery-token subject and bound to the verified signed receipt
  id, original capability id, and finding id. Give it a zero monetary
  ceiling, no capture path, and a bounded retry count; recovery admission
  re-verifies the trusted-kernel receipt and all
  subject/capability/finding bindings. The original one-shot grant has
  already been consumed, a public checkpoint receipt is not bearer
  authority, and a receipt alone is not invocation authority. The
  `Operation::ReadResult`-on-the-grant option also does NOT work today
  (`grant_matches_request` matches `Invoke`-only,
  `request_matching.rs:337-347`; no kernel ReadResult path); a kernel-native
  receipt-keyed read-result matcher is the alternative M4 design choice.
- `chio.finding.delivery.v1` overlay block (moved here from M3):
  purchase-context fields derive from the buyer-presented signed artifacts
  and venue admission bundle,
  each verified before the kernel echoes anything (ARCHITECTURE 4.2);
  `digest_check` and `transform_profile` are kernel-owned, and reservation
  backing comes from kernel state (or the verified signed reservation receipt
  cross-org). The signed `Finding` is the ANCHOR that binds identity to
  commitment: (1) the
  signed `Finding` - strict M2 evidence verification + recomputed
  content-addressed id - with `finding.payload_sha256 == token
  OutputDigestSha256` and pricing scope's finding id ==
  `finding.finding_id` (this id-to-digest binding is the round-6 fix; a
  provider could otherwise scope a pricing hint to finding B while the
  token constraint commits to payload A and every signature still
  verifies); (2) `SignedAskResponse` (envelope signature against the
  token ISSUER; token id/subject/expiry and listing id against the
  token); (3) original `SignedBidRequest` plus `SignedAcceptedBid` (envelope
  signatures under the authenticated bidder/token-subject mapping;
  `canonical_digest(ask.body) == accepted.ask_digest`; requested
  server/tool/scope/cardinality, bid digest, agent_id, listing_id, and
  quoted_price cross-bound); (4)
  `SignedListingPricingHint` and current venue-signed admission bundle
  (authorized provider/payee and
  `pricing.listing_id == ask.listing_id`); (5) the funds RESERVATION -
  the accepted bid's `bid_receipt_id` is buyer-supplied text
  (`SignedAcceptedBid::sign` is public), NOT reservation-backed until
  checked, so the mediating kernel proves it from its OWN verified
  reservation state keyed by `bid_receipt_id` (single-operator wedge). The
  shipped `SignedReservationReceipt` itself authenticates only receipt id,
  agent, listing, ask digest, amount, and currency against a caller-supplied
  expected signer; it does not prove payer key, expiry, replay state, or
  funded value. Those facts come from the authoritative coordinator store.
  Cross-org uses M7's separate funded escrow witness and stronger reservation
  state. The witness is not nested in `purchase-context.v1`; M7 carries it in
  its own bounded context key and binds it to the exact canonical
  purchase-context digest. `finding_id` is stamped from
  the anchor, never from caller-controlled request arguments. Malformed or
  missing, extra, or settlement-mode-incompatible artifacts when the signed
  grant carries `RequireFindingPurchase` DENY (no silent omission or local
  fallback); a generic digest grant without the marker
  remains eligible only for generic delivery metadata.
  The overlay records `transform_profile: identity`; only a
  kernel-authenticated seller-origin mismatch under that profile may carry
  both mismatch blocks for M5. Includes registering the metadata block's
  schema id. The
  `status_proof` sub-block is NOT in M4 (review: this was an M4-to-M6
  cycle) - M6 completes the overlay additively.
- Liveness at buy time: the purchase path re-checks BOTH bounds
  (`finding.issued_at <= now && now < finding.expires_at`) fail-closed
  before minting/reveal (the M1 validator is pure and clockless; liveness
  is a caller check), with a future-issued rejection test.
- Media-type check (ARCHITECTURE 4.5): the buyer/CLI rejects the reveal
  when `envelope.media_type != finding.payload_media_type`, but this is only a
  usability backstop. The finding-aware finalizer MUST perform the same check
  before financial finalization and persist a signed Deny with ADR-A's
  selected no-capture and verified-hold-release state. A digest-valid reveal under a
  misleading advertised type cannot produce a payable Allow. Wrong media is
  not automatically seller-fraud evidence.
- M4 chooses release-only mismatch semantics for its qualified
  `HoldCapture` + `ReversibleHold` profile. An identity-output digest or media
  mismatch persists a signed Deny, releases the exact open hold, captures
  zero, records zero realized spend, and never enters a compensation or
  refund branch. The words "refund" and "reversal" are reserved for money
  already captured or settled; M4 has neither on this path. A failure to
  prove release after a postdispatch crash remains an ambiguous recovery
  state and cannot be reported as a successful release.
- Before any capture, durably stage the validated output and the complete
  replayable Allow template: frozen selected grant and purchase bindings,
  receipt nonce/timestamp, signer and key epoch, policy-result digest, every
  metadata block, the capture operation, and the ordered pending-purchase
  slot. Recovery must reproduce that one Allow byte-for-byte in all
  identity-bearing fields; it cannot select a new timestamp, nonce, signer,
  policy result, or metadata after observing capture.
- Register and persist `chio.finding.failed-delivery.v1` only for an
  authenticated marked identity-profile digest mismatch. First sign and
  persist the Deny and close the pending-purchase slot to that terminal, then
  checkpoint it. Only after that checkpoint is available may the purchase
  authority sign buyer, complete
  signed-accepted-bid envelope digest, authoritative reservation and
  preallocated payment-operation ids, hold attempt and exact release terminal,
  exact checkpointed Deny, Finding/listing/delivery blocks, zero realized
  spend, and `payout_eligible: false`. Before the second phase completes,
  standing remains pending. The final artifact is standing for an M5
  `digest_mismatch` buyer submission; a mismatch correctly creates no
  finalized purchase record. Checkpoint outage cannot leave the cutoff slot
  open. Restart and duplicate checkpoint delivery reproduce the same artifact
  and one already-closed slot terminal.
- Buyer ingress of the overlay `Finding` uses the strict-raw-first
  invariant: bound the input size, strictly parse and canonicalize the raw
  bytes, schema-validate a value from that accepted input, deserialize,
  require strict/typed canonical-byte equality, then call `verify_finding`.
  Typed verification alone cannot recover wire distinctions erased by
  deserialization.
- Purchased-payload ingestion uses a governed memory write and records a
  signed `ReceiptLineageStatement` with the finding-delivery receipt as
  `parent_receipt_id`, the governed memory-write receipt as
  `child_receipt_id`, and `relation_kind = LocalChild`; the write capability
  binding is persisted alongside it. M6 starts from the child write receipt
  and follows its verified parent to the delivery receipt for quarantine.
  Reversing those endpoints or using arbitrary metadata tags is insufficient.
- Persist a signed `chio.finding.purchase-record.v1` atomically with payment
  finalization. Before capture, reserve a monotonically ordered
  pending-purchase slot under the same listing-scoped authoritative fence M5
  uses to block sales and freeze its cutoff. It binds
  `purchase_key = H("chio.finding.purchase.v1",
  signed_accepted_bid_envelope_digest,
  authoritative_payment_operation_id)`, where the coordinator allocated that
  operation id in the rich pre-effect reservation record resolved by the
  accepted bid. It also binds buyer/payer, exact venue-admission envelope
  digest, accepted price and realized spend, Finding/listing/seller backing,
  liability encumbrance, delivery evidence, original payment artifact, and an
  immutable rail-tagged refund/compensation destination. M5 derives victims and destinations from
  this authoritative index, never from mutable challenge-time mappings. The
  finalizer closes the pending slot with either this record or a signed Deny;
  an M5 snapshot waits for every slot at or below its cutoff, preventing a
  concurrent capture from landing after the cutoff or being omitted.
- Exit: `cognition_market_wedge_purchase_e2e` plus one CLI round trip on a
  local kernel publishes, searches,
  verifies all evidence facets offline, buys, reveals, writes through memory
  governance, and obtains a delivery receipt with `finding_delivery` plus
  exact budget/hold/capture and liability-encumbrance state. Failure tests
  cover digest mismatch, wrong media, seller down, predispatch abort,
  postdispatch ambiguity, buyer crash after Allow, underquoted price, wrong
  currency/payer/payee, alternate token, wrong request argument, copied
  listing, missing/stale admission bundle, ACP/x402/PrepaidFinal/legacy
  rejection, collateral overcommit, failed-delivery standing,
  cutoff/capture races, and recovery replay. Each ends with
  funds, payload, nonce, budget, and collateral in a documented idempotent
  state. The positive identity Allow and every Deny carry the correct signed
  generic/finding metadata; the `finding_purchase` verdict matrix and
  workspace gate are green.

### M5 Challenge and audit lane

- Define and register `chio.finding.challenge.v1` (deferred from M1). Its JSON
  Schema and Rust validator enforce two independent
  closed `oneOf` unions. The authorization union is either
  `buyer_submission` with `challenger: PublicKey`, a terminal dispute-fee
  receipt, a live exclusive `Dispute` lock, and class-specific standing, or
  `venue_audit` with exact signed audit-epoch authorization and no challenger,
  Dispute lock, dispute fee, forfeiture, or reward fields. The evidence union
  requires delivery Deny/checkpoint refs only for `digest_mismatch`,
  challenged evidence receipt/checkpoint refs only for `evidence_invalid`,
  and reproduction receipt/checkpoint plus the strict canonical
  `chio.finding.replay-recipe-input.v1` preimage only for
  `replay_contradiction`; cross-class fields reject. The closed compatibility
  matrix is normative: `digest_mismatch` accepts any Finding guarantee/evidence
  class only under the marked identity-output profile and requires the exact
  signed `chio.finding.failed-delivery.v1`; `evidence_invalid` requires
  `evidence_class` `observed` or `verified`, evidence required by admission,
  and a finalized purchase record; `replay_contradiction` requires
  `guarantee_class = deterministic_replay`, `evidence_class = verified`, a
  committed recipe, and a finalized purchase record. Every other pairing
  rejects before evaluation. Common `affected_deliveries` entries use
  `{receipt_id, receipt_sha256, checkpoint_ref, checkpoint_sha256}` so every
  standing reference is content-bound and atomic. They carry no
  caller-asserted buyer identity, amount, or payout address.
- Reproduction evidence is an ordered, size-bounded set of atomic
  `{receipt, checkpoint, observation_bytes}` tuples sharing one
  `replay_run_id`. Each strict canonical observation binds recipe and
  verifier-profile digests, phase id, runner manifest, resolved input bundle,
  environment, terminal result, exit code, and report digest; the receipt
  action binds run/recipe/profile/phase and its `content_hash` equals the
  observation digest. Loose ids or a single checkpoint for unrelated
  receipts are inadmissible.
- Seller coverage is hard, not merely expected. For every captured sale,
  atomically reserve `encumbrance_per_sale = k * accepted_price`, `k >= 1`,
  and enforce checked
  `base_finding_stake + sum(open_encumbrances) <=
  min(locked_amount - slashed_amount,
  Listing.required_amount.units)` plus
  `sum(open_encumbrances) <= maximum_sale_exposure`, all in one currency.
  Allocation expiry must exceed sale time plus the nonzero claim, audit,
  appeal, and settlement horizons. The unbatched v1 EVM-compatible profile
  caps one liability horizon at 15 distinct immutable buyer payout
  destinations, reserving one vault slot for the community fund, unless a
  global replay-safe multi-batch allocation is designed. Bonds cover finalized fraud exposure;
  there is no revenue vesting or clawback in v1.
- Keep the frozen `chio.registry.market-penalty.v1` and evidence enums
  unchanged. Define and register signed
  `chio.finding.challenge-outcome.v1`. Its class-independent top-level
  `verdict` is exactly `Upheld | Rejected | Indeterminate`; class-specific
  facets are nested beneath the selected evidence branch. For replay, the
  nested predicate result is
  `ConfirmedContradiction | Consistent | Indeterminate` and maps respectively
  to those three top-level verdicts. The outcome body binds the exact signed
  challenge-envelope digest, Finding/listing/backing, source authorization
  branch, class, verifier-profile and evidence-bundle digests, nested facet
  result, reason, trigger digest, checked penalty calculation, evaluator key
  identity, key, epoch, validity interval, revocation-status reference, and
  evaluation time. Derive `outcome_id` from a domain-separated
  canonical body preimage excluding only `outcome_id` and the envelope
  signature. Only an evaluator key authorized for that role by the committed
  profile, valid in its epoch, and not revoked at evaluation may sign.
  The canonical signed-outcome envelope digest is separately mandatory. All
  three verdicts are signed for auditability; only `Upheld` can enter the
  penalty lane.
- An `Upheld` outcome maps to existing
  `OpenMarketAbuseClass::FraudulentListing` with exactly one
  `OpenMarketEvidenceKind::External` reference whose `reference_id` equals
  `outcome_id` and whose `sha256` equals the canonical signed-outcome envelope
  digest. A body-only digest, absent `sha256`, generic or multiple External
  refs, wrong abuse class, untyped evidence, signer substitution, and
  downgrade reject.
- Compose, do not bypass, the shipped governance and penalty evaluators.
  First evaluate the signed generic governance case against the exact signed
  charter, listing, activation, operator/namespace, authority scope, validity
  window, and allowed case kind; require no evaluator findings. Only then
  issue and evaluate the open-market penalty. The finding wrapper permits
  exactly these typed branches:

  - pending appeal: an `Enforced` `Sanction` case and `HoldBond` penalty for
    the full checked finding amount, producing `BondHeld`;
  - successful appeal: an `Enforced` `Appeal` case naming the exact Sanction
    in both `appeal_of_case_id` and `supersedes_case_id`, resolved as the
    authoritative case head, producing effective `Appealed` with no
    governance findings, plus a `ReverseSlash` penalty in state `Reversed`
    that supersedes only the exact prior `HoldBond`, matches its listing,
    schedule, Listing class, currency, and full amount, and produces effective
    `Reversed`; the resulting `ReversedBeforeImpairment` admission head
    supersedes the original Sanction block, and the generic evaluator's
    broader ability to target a prior `SlashBond` is narrowed out;
  - appeal-final impairment: either no filing by the signed deadline or a
    terminal denied Appeal authorizes one `Enforced` Sanction plus
    `SlashBond` for the same full amount, producing `BondSlashed`, with
    `supersedes_penalty_id` naming the exact prior `HoldBond`. Open,
    Escalated, expired-with-findings, unresolved, or unavailable Appeal state
    remains held and quarantined; it is not treated as denial.

  The generic penalty evaluator does not by itself enforce the Finding
  wrapper's exact Hold/Slash case-state rules. The wrapper checks every
  branch above before treating a clean generic result as authorization.
  Every branch requires an empty penalty-evaluator findings list,
  `bond_class = Listing`, the exact finalized bond snapshot, and a penalty
  amount equal to the checked finding amount. Checked arithmetic computes
  `min(live_allocated_collateral,
  base_finding_stake + open_per_sale_encumbrances)` and rejects overflow,
  currency mismatch, or any result above the exact signed Listing
  `bond_requirement.required_amount`; it never silently clamps a misconfigured
  promise. The Sanction, HoldBond, and signer/key-status evidence remain
  valid through claim, appeal, and finalization, or a signed successor
  protocol preserves their exact semantic identities. `penalty_id` is never
  an effect key because its current preimage omits material abuse, amount,
  evidence, subject, and issuer fields. Register the existing frozen
  `chio.registry.market-penalty.v1` body and
  envelope in the public schema registry, manifest, protocol text, and core
  signed-artifact allowlist without changing its fields or enums. Pin a
  distinct market-penalty authority: envelope signer, body `issued_by`, and
  governing operator must all equal the profile-authorized role. A generic
  caller-supplied trusted signer is insufficient. The v1-only script remains
  green.
- Replay execution and evaluation are separate. An effectful governed
  `ReplayExecutor` resolves retained blobs and performs the recipe before
  adjudication. The pure fail-closed challenge evaluator consumes a signed
  `FindingChallenge` + a signed `Finding` (via the strict-raw-first
  ingress invariant above, not `verify_finding` alone) plus exactly the
  evidence selected by its class. For `digest_mismatch`, verify the
  signed failed-delivery record, checkpointed signed Deny, marked grant,
  generic and finding delivery blocks, kernel-proved identity profile, exact
  released hold, and zero realized spend. For `evidence_invalid`,
  cross-check the challenged subset and checkpoint against the Finding,
  then reuse claim-style receipt re-verification
  (`chio-market/src/insurance_flow.rs:390-414` pattern). Only affirmative
  invalidity under the profile effective at publication can support fraud:
  a bad signature, contradictory checkpoint proof, semantic cross-binding
  failure, or a key proven revoked or compromised at that time. Resolver
  unavailability, a missing retained blob, an availability-SLA breach, or
  later key revocation/retraction is indeterminate or a separate operator/SLA
  event, not retroactive seller fabrication. For
  `replay_contradiction`, strict-parse the versioned recipe preimage, hash it
  to `Finding.replay_recipe_sha256`, verify the governance-authorized profile
  and each role-scoped reproduction observation, then apply the recipe's
  closed predicate to completed observations. The evaluator performs no
  fetching, tool invocation, clock read, or storage access. Each class
  produces a typed nested facet and then the class-independent
  `Upheld | Rejected | Indeterminate` verdict. The replay facet alone uses
  `ConfirmedContradiction | Consistent | Indeterminate`; missing dependencies,
  unavailability, timeout, resource exhaustion, runner error, malformed
  output, or key/profile ambiguity are `Indeterminate` at both layers and
  cannot sanction the seller. The digest and evidence branches likewise
  return `Indeterminate`, not `Rejected`, when authority, retention, resolver,
  or infrastructure inputs cannot be established. Missing or tampered recipe
  preimages reject the submission before evaluation. Generic digest mismatch
  and output-policy transform denials cannot feed the seller
  Sanction -> SlashBond gate
  (`evaluation.rs:356-451`).
- Keep pure evidence evaluation separate from a durable challenge
  coordinator. For the `buyer_submission` authorization branch, verify a live
  exclusive dispute-bond lock bound to challenger, challenge id, active
  schedule, Dispute class, class-specific amount/currency, expiry, and unspent
  state. The amount is derived from the admitted market terms and capped by
  the governance profile, not seller-selected replay cost for every class. It
  transitions exactly once from `locked` to `returned` or `forfeited`.
  String references, stale or reused locks, wrong
  class/schedule/owner/currency, and concurrent consumption reject before
  evaluation. The `venue_audit` branch instead verifies its signed audit
  authorization and rejects any bond or dispute-fee fields.
- Payout derivation: use the authoritative M4 purchase-record index at the
  frozen cutoff. Reverify each record's Finding, delivery, accepted bid,
  payment operation, realized spend, seller allocation, and immutable
  rail-tagged destination. For `evidence_invalid` and
  `replay_contradiction`, challenge-carried purchase refs establish standing
  and are cross-checked to those records. For `digest_mismatch`, the signed
  failed-delivery record establishes standing but is payout-ineligible. No
  supplied ref defines victims or destinations. Never accept a
  challenge-supplied or newly resolved mutable
  address. Distribution is capped by verified harm and available bond and must sum
  exactly. The signed finding-specific operator authorization applies the
  ADR-0015 policy allowlist; exact-sum validation alone does not prevent
  arbitrary destinations, and on-chain structural enforcement remains
  ADR-0015 follow-up A. A
  buyer-initiated challenge needs at least one affected receipt for standing,
  but supplied refs do not define payout completeness. Slashed collateral
  pays only verified harmed buyers or the registered community fund.
  Independent successful challengers can receive capped verified
  reproduction-cost reimbursement only from the separately collected
  dispute-fee challenge-administration pool, never from the seller slash or
  audit-only participation pool.
- Use a predeclared amount formula:
  checked `candidate = base_finding_stake + open_per_sale_encumbrances`;
  require matching currency and
  `candidate <= Listing.bond_requirement.required_amount.units`, then
  `slash = min(live_allocated_collateral, candidate)`;
  `buyer_pool = min(slash, total_uncompensated_realized_spend)`; the remainder
  goes only to the community-fund destination pinned in the M2 admission.
  Overflow or a required-amount mismatch rejects rather than truncating the
  promised penalty. Allocate the buyer pool pro rata by realized spend with
  deterministic remainder order by `purchase_key`.
  Qualified M4 `digest_mismatch` releases the hold and has zero realized
  monetary harm, so it cannot manufacture a buyer payout; finalized
  `evidence_invalid` and `replay_contradiction` purchases may qualify.
- Incident/idempotency boundary: one defect and liability span every
  challenge class and evidence subset for the same backed listing. Derive
  `defect_key = H("chio.finding.defect.v1", finding_id)` and
  `liability_key = H("chio.finding.liability.v1", defect_key, venue_id,
  listing_id, seller_collateral_allocation_id, chain_id, vault_contract,
  vault_id)`. Challenge, class-evidence, and replay-run digests are separate
  dedup/corroboration keys and MUST NOT authorize another slash. Drive
  challenges through `Submitted -> Evaluating -> Rejected |
  IndeterminateRetryable | IndeterminateClosed | Upheld` and the
  liability through a CAS head `Open -> UpheldPendingClaims -> PendingAppeal
  -> Finalizing -> Settled`, with `ReversedBeforeImpairment` as the appeal
  terminal. The first Upheld coordinator transaction linearizes the
  `Open -> UpheldPendingClaims` CAS, sales block, and purchase cutoff in the
  same listing-scoped store used by M4. No new pending-purchase slot may open
  after that transaction, and the claim snapshot waits for all pre-cutoff
  slots to reach signed Allow/purchase-record or Deny. Evaluation never
  atomically claims that an external impairment completed. The M4
  `purchase_key` caps cumulative compensation across every class/liability at
  authoritative realized spend.
- Challenge-bond disposition follows the evaluator result:
  top-level `Upheld` returns the buyer lock; top-level `Rejected` applies the
  predeclared failed-challenge return/forfeit rule; `Indeterminate` creates no
  liability transition, seller hold, sanction, or audit reward and never
  forfeits for an infrastructure or availability failure. It may retain the
  same buyer lock only through one bounded, signed retry window. Retry reuses
  the same challenge, fee, lock, profile, and evidence identity rather than
  charging or locking again. If that retry is still indeterminate or the
  retry window expires, transition to `IndeterminateClosed` and return the
  lock exactly once. A bondless venue audit has no disposition under any
  verdict.
- Add the missing durable effect publishers with domain-specific keys, not one
  coarse `(vault, liability, effect_kind)` key:

  - the single unbatched-v1 seller impairment uses
    `H("chio.finding.effect.seller-impair.v1", chain_id, vault_contract,
    liability_key, allocation_digest)`;
  - buyer challenge-bond disposition uses
    `H("chio.finding.effect.challenge-bond.v1", challenge_id, lock_id)`;
    its canonical intent digest separately commits `returned | forfeited`,
    amount, currency, and destination so conflicting dispositions collide and
    reject;
  - dispute-fee or audit-cost reimbursement uses
    `H("chio.finding.effect.fee.v1", buyer_submission_id_or_audit_run_id,
    fee_operation_id)`;
  - enforcement/root semantic intent uses
    `H("chio.finding.effect.root-intent.v1", operator_id, root_domain,
    liability_key, outcome_id, final_penalty_envelope_digest,
    allocation_digest)`;
  - retraction uses
    `H("chio.finding.effect.retraction.v1", finding_id, feed_id,
    retraction_intent_id)`.

  Persist and fence each sequence-independent semantic intent before
  broadcast; identical retry reconciles and conflicting retry rejects. The
  publisher later acquires the serialized strict-next sequence lease and
  derives
  `H("chio.finding.effect.root-publish.v1", root_intent_id,
  assigned_sequence)` as its attempt key. The attempt key, prepared root
  calldata, and transaction nonce are publisher state, not fields in the
  earlier enforcement artifact. `prepare_bond_impair` alone is preparation,
  not publication.
- The evaluator signs the outcome before the pending `HoldBond` transition.
  At appeal finality, require the already sealed claim snapshot and
  allocation, construct and cleanly evaluate the exact final `SlashBond`
  penalty, then sign the enforcement artifact over that outcome and final
  penalty. One local transaction persists the enforcement and semantic
  intents, moves the liability to `Finalizing`, marks `publication_pending`,
  and durably enqueues the exact retraction and enforcement-anchor intents
  before any external impairment. The worker publishes the enforcement/bond
  proof root only after appeal finality, records its finalized receipt, and
  only then may the separately fenced seller-impairment effect broadcast.
  The retraction/status root remains dispatch-ineligible until that impairment
  is confirmed final. Purchases stay blocked throughout. A crash at any
  boundary resumes from the durable state rather than producing a slash
  without a status intent.
  `Finalizing -> Settled` is a separate CAS requiring confirmed final
  impairment/distribution, every required challenge-lock and fee terminal,
  and the post-impairment status insertion evidenced by the exact signed epoch
  and inclusion proof. Missing or ambiguous effects leave the liability
  `Finalizing`, keep `publication_pending`, and continue blocking purchases.
- Produce one unique canonical enforcement receipt, anchor it, and use its
  exact leaf hash as the bond-vault `evidenceHash`. Freeze challenge/outcome,
  Finding, enforced case and penalty, finalized bond snapshot, amount, ordered
  allowlisted exact-sum distribution, prepared call, target, and acquired
  nonce in the impairment intent. `EvidenceAlreadyUsed` counts as success only
  if a stored raw transaction plus finalized receipt and decoded input match
  the frozen intent, or a contract event/getter extension exposes enough data
  to prove the same match. Today's private consumed-evidence map and
  under-specified `BondImpaired` observation are insufficient; ambiguity
  quarantines the liability.
- Victim completeness: challenger-supplied affected refs are hints. During a
  predeclared claim window, query the authoritative indexed set of
  M4 purchase records for the liability at the frozen cutoff, publish a
  committed
  snapshot, accept omission proofs, then finalize one capped allocation. If
  a deployment lacks that complete index, label first-come/omitted-victim
  insolvency as a residual and do not claim complete compensation.
- After the claim and appeal windows, sign
  `chio.finding.challenge-enforcement.v1` over the final liability key,
  purchase-snapshot and deterministic-allocation digests, exact v1 penalty
  digest, seller allocation/vault, amount, ordered destinations, and effect
  semantic-intent ids. Publisher-only sequence/transaction attempt keys are
  excluded. The finding-specific settlement authorization is derived solely
  from this artifact and the finalized bond snapshot. Until ADR-0015 follow-up A
  constrains destinations in the contract, this is an operator-mediated
  choke point, not an on-chain harmed-party theorem.
- Define and register
  `chio.finding.finalized-bond-snapshot.v1` as the content-bound wrapper that
  makes "finalized bond snapshot" executable. A configured settlement/chain
  observer signs chain id, vault contract/id, seller/allocation, locked,
  held, and slashed amounts, currency, block number/hash, finality policy,
  observed finality, identity-registry record, operator key hash/epoch, and
  observation time. M5 extends `chio-settle` with the finding-specific
  enforcement verifier and durable publisher that consume this wrapper plus
  `chio.finding.challenge-enforcement.v1`; `chio-open-market` does not
  pretend preparation is settlement. Recheck the observed block hash and
  live identity/operator qualification before anchoring and again after the
  impairment receipt reaches finality. Reorg, rotation, expiry, or changed
  bond state returns to reconciliation or quarantine, never an assumed slash.
- Signer roles are disjoint and explicit. The M4 purchase record is signed by
  the configured kernel purchase authority after capture finalization; the M5
  outcome by the profile-authorized evaluator key; the final enforcement by
  the venue finalization authority; the generic market-penalty envelope by
  the exact profile-authorized penalty authority with body `issued_by` and
  governing operator equality; the bond snapshot by the configured
  settlement/chain observer; and each external effect by its configured
  settlement or feed authority. Every verifier pins role, key epoch,
  validity, rotation, and revocation policy and rejects one key substituted
  into another role.
- Audit scheduler: define and register
  `chio.finding.audit-epoch.v1` before execution, binding the exact
  eligible-listing snapshot/digest, epoch and fee schedule, committed
  seed/reference, deterministic selection algorithm, published rate,
  available restricted budget, and authorization. After the seed is revealed
  and attempts run, sign `chio.finding.audit-report.v1` over the exact epoch
  envelope digest, revealed seed, selected Findings, attempt receipt ids,
  missed-attempt reasons, and signed outcomes. Precommit and result are not
  one mutable artifact. The operator's completeness remains an audited
  assumption, but selection and omission become reproducible. Renew each
  active listing's recurring participation fee before the epoch or remove
  its admission.
- A recognized venue audit is not economically an ordinary bonded challenge:
  it carries signed audit authorization, no dispute bond, no dispute fee, no
  forfeiture, and no reward. The restricted audit pool reimburses only
  verified mediated re-execution cost; a clean audit transfers nothing to
  the seller. Fraud still uses the same typed evaluator and Sanction lane.
  Buyer challenges collect the configured dispute fee exactly once to the
  admission-pinned challenge-administration pool rail destination, and the
  terminal receipt binds schedule, event, payer, amount/currency, beneficiary,
  and destination. They lock their own verified challenge bond separately.
- Appeals are pre-impairment. A passing challenge creates `HoldBond`, blocks
  new sales, and must evaluate to effective `BondHeld` for the full computed
  amount. The listing-scoped transaction atomically changes the liability
  head, blocks new pending-purchase slots, and freezes the authoritative
  cutoff; snapshot sealing waits for all older slots to close. It completes
  the signed claim/omission window and seals the purchase snapshot and
  deterministic allocation before entering `PendingAppeal` or starting the
  signed nonzero finding-specific appeal window. A timely successful appeal
  must be `Enforced`, effective `Appealed`, have no governance findings, name
  the original Sanction in both appeal and supersession fields, and resolve
  as the authoritative case head. It uses `ReverseSlash` in state `Reversed`
  against only that exact full `HoldBond`, producing effective `Reversed` and
  `ReversedBeforeImpairment` as the admission head. No filing by the signed
  deadline or a terminal denied Appeal authorizes one full `SlashBond` whose
  `supersedes_penalty_id` is that hold and that produces `BondSlashed`. An
  Open, Escalated, expired-with-findings, unresolved, or unavailable Appeal
  remains held and quarantined. The Sanction/Hold authority and validity must
  span this horizon or use an exact signed successor protocol. The
  appeal-final transition first persists `publication_pending` and the durable
  outbox; enforcement/bond proof-root finality precedes the separately fenced
  impairment, while retraction/status publication follows confirmed
  impairment. Reject unenforced or wrong-target appeals, wrong
  case/bond/finding, partial amount, and post-impairment reversal. A later
  correction requires separate restitution outside the distributed slash.
- Cross-kernel receipt trust comes only from the exact M2
  replay/evidence-verifier profile committed by the Finding and outcome.
  Verify delivery, production, reproduction, and checkpoint signers under
  distinct roles, including validity, rotation, revocation, log identity,
  runner manifest, and resolver policy. A mutable flat
  `trusted_kernel_keys` setting cannot authorize a value-moving sanction.
- `chio finding challenge` CLI.
- Exit: `finding_challenge_enforcement` and its fail-closed negatives cover
  all three class
  branches, reject every cross-class field combination, and reject missing,
  non-canonical, or hash-mismatched recipe preimages. An authenticated
  identity-profile digest mismatch, invalid Finding evidence, and a replay
  contradiction can each reach an enforced sanction and penalty artifact;
  generic mismatch and transform-policy denial cannot. Verified affected
  purchases produce allowlisted, capped, exact-sum harmed-buyer allocations;
  no challenger bounty comes from the slash. A clean venue audit returns no
  seller payment, auditor reward, forfeiture, or bond transition.
  Top-level `Rejected` buyer challenges follow the signed failed-challenge
  disposition, `Upheld` returns the live bond, and `Indeterminate` never
  forfeits: bounded retry success reaches a normal verdict, while retry
  exhaustion or expiry reaches `IndeterminateClosed` and returns the same
  lock exactly once without another fee. Replay tests additionally prove the nested
  `Consistent`, `ConfirmedContradiction`, and `Indeterminate` mapping. Signed
  audit plans reproduce their eligible snapshot, selection, attempts, and
  outcomes; wrong seeds and omissions reject or surface as audit failures.
  Concurrent and
  post-restart duplicate challenges prove one slash and at-most-once payout;
  omitted-victim and sybil-first cases prove the authoritative snapshot
  rule. A concurrent purchase/cutoff test proves no captured sale lands after
  or is omitted from the cutoff. Timely enforced appeal prevents impairment,
  supersedes the original Sanction head, and clears the exact full hold;
  finalization durably writes the pending outbox before enforcement/bond
  proof-root publication, finalized proof-root publication precedes the
  separately fenced full impairment, and retraction/status publication
  follows confirmed impairment. Final impairment rejects `ReverseSlash`. Wrong
  destinations, allocation/exposure overflow, a sixteenth distinct buyer
  destination without batched settlement,
  fee-pool misuse, signer-role substitution, invalid penalty
  signer/`issued_by`/operator equality, partial hold/reverse/slash,
  stale/reorged bond snapshots, ambiguous `EvidenceAlreadyUsed`, and
  venue-bond subsidy attempts reject. The workspace gate and v1-only script
  are green.

### M6 Status feed and retraction

- Implementation and named qualification record:
  [2026-07-31-M6-status-feed-retraction.md](plans/2026-07-31-M6-status-feed-retraction.md).

- Finding-status oracle instance (generic `RevocationKey` reuse,
  `chio-revocation-oracle/src/api.rs:70`); control-plane surfaces
  `/v1/findings/status/{feed}/root` and `/proof/{finding_id}`
  (ARCHITECTURE 8.1).
- Define and register the status-feed artifact (deferred from M1): it
  canonically binds `feed_id`, the selected numeric `key_domain_nonce`, a
  distinct monotonically advancing `map_epoch`, `operator_key`,
  backend/proof-semantics version, sparse root data, anchoring refs, validity
  bounds, and outer signature (`epoch.rs:12`, `api.rs:86-98`). The outer
  signature covers that complete domain binding;
  today’s `SignedEpochRoot` alone is insufficient because its signing preimage
  omits feed and backend semantics. Verification cross-checks the outer
  issuer and any embedded root signer against a governance-pinned feed
  operator authorization, role, key epoch, validity, rotation, and revocation
  state. The kernel accepts exact canonical signed epoch bytes, or obtains
  those same bytes from an authenticated resolver pinned by that
  authorization; caller-supplied root fields or an unsigned resolver answer
  never advance local state.
  `EpochNonce` is a `u64`, so ADR-B selects one numeric
  `key_domain_nonce` for the `chio.finding.status.v1` protocol domain; every
  insert and proof uses that key domain. `map_epoch` advances root
  generations and is the rollback floor; it never changes the retraction key
  (ARCHITECTURE 4.4).
- Portable non-inclusion (review finding: today's `NonInclusionProof`
  carries no path bytes and is checked against local oracle state, so
  `/proof/{finding_id}` is not portable, and the current append-only root
  cannot prove absence merely by adding a path): implement a
  domain-separated true sparse authenticated-map backend for finding status,
  rejecting the ordinary append-only tree under this verifier. Existing
  root-envelope structs may be nested only under the separately signed
  status artifact, not treated as a portable proof by themselves. Define and
  register the unsigned, strict
  `chio.finding.status-proof-input.v1` wire type as a tagged `oneOf` for
  `non_inclusion` and `inclusion`. Both branches bind feed id, fixed
  key-domain nonce, advancing map epoch, finding id, status-epoch artifact
  id/digest, exact signed epoch/root bytes, sparse-map path, and freshness
  bounds; inclusion additionally binds the exact status value and
  retraction-intent digest. Cross-branch fields reject.
  Reject ordinary-tree roots under this verifier. V1 requires this portable
  type; a later authenticated trusted-query mode must remain explicitly
  non-portable.
- Kernel carrier and P10 boundary: reserve
  `context.chio_finding_status_proof_b64` for base64 of size-bounded
  canonical proof JSON. This preserves exact bytes through the
  already-deserialized context. Admission decodes, strict-parses, and
  schema-validates them, verifies the epoch artifact, operator/root
  signature, path, artifact digest,
  key/feed/key-domain-nonce/map-epoch/finding cross-bindings, and freshness,
  then emits kernel-owned proof/root digests in the overlay.
  Wire the same verifier into `chio finding buy` and SDKs, but their checks
  never substitute for kernel verification.
- Prevent replay of an old but otherwise fresh non-inclusion proof. Maintain
  a durable monotonic `(map_epoch, epoch_id, root_hash)` floor per feed from
  verified signed epoch bytes, plus sticky local `pending`/`retracted` state
  per Finding. A lower numeric epoch rejects; the same numeric epoch with a
  different id or root also rejects. Once an inclusion or local pending intent
  is observed, an older or later contradictory non-inclusion can never clear
  it. Only the pinned feed operator's signed epoch or authenticated resolver
  may advance the floor. Rollback, same-epoch equivocation, missing floor state
  after restart, stale proof, and caller-proposed "latest" roots deny.
- Completeness coupling: only the appeal-final M5 incident transition into
  `Finalizing` atomically persists the outcome, `publication_pending`, and an
  idempotent retraction outbox item. An evaluation or reversible `HoldBond`
  alone cannot append to the status feed. New purchases deny while pending.
  The outbox survives restart but is dispatch-ineligible until the exact
  seller impairment reaches confirmed finality. Only then does it retry the
  exact key insert and clear pending after recording a signed epoch plus
  inclusion proof. After every other required effect is also final, this
  evidence authorizes the one `Finalizing -> Settled` CAS. A failed,
  ambiguous, or quarantined impairment leaves
  publication pending and never emits an irreversible retraction.
  Voluntary/cross-operator retractions
  carry authenticated intent receipts and an inclusion SLA. M6 admission
  requires a live status-operator service bond with objective missed-inclusion
  and equivocation conditions; it is not optional language in the qualified
  profile. Fresh roots and a bond still do not prove insert completeness,
  which remains an audited operator assumption.
- Completes the `chio.finding.delivery.v1` overlay with the
  signature-safe `status_proof` sub-block (additive per ARCHITECTURE 7.3).
  It is optional only when decoding backward-compatible M4 receipts; every
  M6-qualified purchase/reveal requires it, and an absent block cannot earn
  `claim.finding.status_fresh`.
- Quarantine resolution: M4 ingestion records a signed lineage statement with
  the verified finding-delivery receipt as parent and the governed
  memory-write receipt as child.
  M6 injects a synchronous `FindingRetractionResolver` into the opt-in
  `MemoryGovernanceGuard`, backed by verified memory provenance,
  receipt/capability lineage, and an authenticated local status-root cache.
  It resolves store/key -> write receipt/capability -> delivery receipt ->
  finding id -> status. Missing/tampered provenance, broken lineage,
  unavailable store/cache, stale root, pending publication, or retracted
  status all deny fail-closed. Restart, stale-cache, unavailable-store,
  tampered-lineage, and happy-path tests cover the resolver; the default
  non-market memory profile is unchanged.
- Ops: `docs/release/CHIO_FINDING_MARKET_RUNBOOK.md` covering epoch
  cadence via operator cron (the workspace has no job daemon -
  ARCHITECTURE 8.2), anchoring cadence, equivocation, stalled-outbox, and
  inclusion-SLA response.
- Exit: `finding_status_retraction` covers voluntary retraction and an
  enforced M5 outcome; the latter atomically enters pending, blocks purchase,
  survives restart/duplicate delivery, reaches an included signed epoch, and
  clears pending exactly once. A fresh root that omits the pending intent
  remains denied. Portable inclusion and non-inclusion verification reject
  wrong feed, nonce, operator/epoch, root, path, artifact digest, finding,
  value, intent, and freshness. Old-proof replay below the durable floor,
  contradictory non-inclusion after local retraction, resolver substitution,
  unsigned epoch input, and missing/expired operator bond reject; the next
  purchase fails on inclusion, and the holder's guarded read denies. The
  workspace gate is green.

### M7 Cross-org escrow path (conditional)

- M7 is blocked on bilateral demand and ADR-C. That ADR must choose a
  contract-level Finding/full-only/authority discriminator or an explicitly
  audited TTP profile. Current `ChioEscrow` does not inspect Finding
  artifacts, disable `releaseWithSignature`, or disable partial proof release,
  so an off-chain wrapper alone cannot make a cryptographic full-only or
  settlement-authority claim. Alternative shipped release methods remain a
  bypass. The no-contract-change profile stays Experimental.
- Require the provider-signed grant marker to select
  `CrossOrgEscrow { settlement_profile_sha256 }`, with the digest equal to the
  verified governance-signed profile. A local selector, missing or extra
  escrow-witness context key, or profile mismatch denies before nonce, budget,
  payment, or invocation mutation. Cross-org never falls back to M4 local
  hold/capture.
- Define and register governance-signed
  `chio.finding.settlement-profile.v1` and bond-authority-signed
  `chio.finding.mediator-backing.v1`. The profile pins role keys and epochs,
  the exact contract path, chain, operator, token address/decimals/config
  epoch and currency mapping, release-receipt producer, deadline stages,
  full-only terminal policy, admin/rotation posture, response-forwarding and
  checkpoint SLAs, and objective penalty mapping. The non-reusable backing
  allocation binds operator, chain, contract, profile, amount/currency,
  liability horizon, expiry, and one exact effect path. Missing, reused, or
  underfunded backing rejects; the service bond is not optional.
- Order is load-bearing. Before `accept()`, the buyer or an explicitly
  authorized sponsor first verifies the exact governance-signed settlement
  profile and atomically reserves the live, non-reusable mediator-backing
  allocation for the expected chain, contract, escrow terms, purchase,
  mediator, amount/currency, liability horizon, and effect path. Only then may
  it create and finally fund the escrow, and the
  authoritative reservation service verifies and binds signed bid/ask,
  Finding/listing, buyer key, `EscrowTerms.depositor` address or signed
  sponsor/delegation, capital-instruction id and signer, immutable refund
  destination equal to `EscrowTerms.depositor` and the `createEscrow` caller,
  contract-derived `escrowId`, seller beneficiary, exact amount/currency,
  expiry, settlement-profile envelope digest, and consumed
  mediator-backing envelope digest/allocation id. Sponsor authorization
  acknowledges that timeout refunds return to that sponsor/depositor, not a
  separate buyer address. It derives the compatibility
  `SignedReservationReceipt`, whose shipped body still proves only receipt
  id, agent, listing, ask digest, amount, and currency. The pure `accept()`
  then creates `SignedAcceptedBid`. Only afterward may the settlement
  authority re-observe the same finalized funds and sign
  `chio.finding.escrow-witness.v1`.
- The escrow witness binds chain, contract and contract-derived escrow ids,
  every observed ABI `EscrowTerms` field, block/hash/finality, Finding,
  listing, the SHA-256 digest of the exact canonical
  `chio.finding.purchase-context.v1` bytes, accepted-bid digest, token/grant,
  settlement-profile and mediator-backing envelope digests,
  backing-allocation consumption id, buyer/payer/depositor-or-sponsor mapping,
  capital instruction, immutable refund destination equal to the depositor,
  seller beneficiary, mediating operator, exact amount, currency, token
  address/decimals/config epoch, deadline, and reservation id. Do not invent a
  canonical-JSON `EscrowTerms` digest as the contract identity. Reject absent,
  unfunded, underfunded, overfunded,
  wrong-party/token/config/currency, non-final, expired, or reorged witnesses.
  Fee-on-transfer, rebasing, and other non-exact-transfer tokens are outside
  the profile.
- Reserve `context.chio_finding_escrow_witness_b64` for only the strict
  canonical signed escrow-witness envelope as size-bounded base64. The kernel
  checks both encoded and decoded bounds, strict-parses this key and
  `context.chio_finding_purchase_context_b64` before any mutation, recomputes
  the purchase-context digest, and requires the witness binding to match. The
  witness is not nested in the purchase context, so the M7 carrier has no
  self-hash cycle.
- Implement the exact settlement bridge. After the matched Finding delivery
  receipt is checkpointed and anchored, the settlement authority verifies it
  and signs `chio.finding.settlement-release.v1`. The release body binds the
  escrow-witness, delivery receipt/checkpoint, accepted-bid, purchase-context,
  settlement-profile, and mediator-backing envelope digests, plus Finding,
  listing, capability, escrow, parties, amount/currency, backing-allocation
  consumption id, and authority epoch. It does not bind its own envelope
  digest or `settlement_reference`. After signing, the
  finding-aware wrapper verifies the complete release envelope and defines
  `settlement_reference` as lowercase
  `sha256_hex(canonical_json_bytes(input))`. The strict
  `chio.finding.settlement-reference-input.v1` preimage contains exactly seven
  lowercase hex64 fields: signed release-envelope, escrow-witness-envelope,
  delivery-receipt-and-checkpoint, signed-accepted-bid-envelope,
  purchase-context, settlement-profile-envelope, and
  mediator-backing-envelope digests. It rejects unknown fields. Add a
  checked-in golden vector freezing canonical bytes and the output digest.
  This internal digest preimage is not signed and contains no self-reference,
  so the construction order is cycle-free.
  A profile-pinned operator-kernel then produces the standard Chio settlement
  receipt whose
  signing nonce equals the dispatch capital instruction's
  `governed_receipt_id` and whose content hash is
  `settlement_anchor_receipt_content_hash_parts(execution_receipt_id,
  settlement_reference, dispatch_id, governed_receipt_id)`. Checkpoint it
  into `AnchorInclusionProof`, pair it with the exact
  `SettlementAnchorContentBinding`, and have the finding-aware wrapper call
  `prepare_merkle_release(..., EscrowExecutionAmount::Full)`, require
  `prepared.partial == false`, and publish the typed escrow proof root before
  the beneficiary submits release. Delivery inclusion, authority-receipt
  inclusion, and escrow-root publication are three distinct stages. Wrong
  signer, nonce, content binding, receipt, grant, bid, escrow, beneficiary,
  amount, root, or replay rejects.
- The funding deadline is derived and covers the full token/reveal window,
  delivery checkpoint and anchor finality, authority-receipt checkpoint and
  anchor finality, escrow-root publication/finality, and safety margin. The
  witness records every selected bound. A tighter caller-selected deadline
  rejects.
- The Finding profile calls only
  `prepare_merkle_release(..., EscrowExecutionAmount::Full)` and tracks
  internal `FullReleased` or `FullRefunded` economic terminals. It rejects
  partial selectors, partial/mixed value movement, amount drift, and positive
  remainder. The contract requires the seller beneficiary to submit the
  release transaction; any operator settlement signature authorizes proof
  content but does not delegate `msg.sender`. The watchdog may prepare proof,
  publish roots, notify, monitor,
  and trigger permissionless full refund after timeout, but cannot impersonate
  the beneficiary. A final observer requires the beneficiary token-balance
  delta to equal the accepted amount before recording `FullReleased`.
  Admin pause can force refund by blocking release through the deadline. A
  later zero-value refund flag after full release is recorded as observer
  drift, not a second monetary terminal.
- Operator-key rotation is drain-or-refund, not transparent rebinding. Stop
  opening escrows under the old key hash, fully release eligible escrows or
  let them fully refund, confirm terminal state, then activate the new epoch.
  Existing `EscrowTerms` stay pinned to the old key hash; substitution rejects.
  Emergency rotation may force refund and is an explicit bonded SLA failure,
  not seamless liveness.
- DPoP proves buyer initiation, not receipt of response bytes. A seller-aligned
  mediator can attest, withhold, and release; that profile is prohibited.
  Even a neutral mediator remains a trusted third party. Objective missed
  checkpoint/authority-root/settlement-root deadlines can feed the mediator
  penalty path; response nonreceipt cannot be proven without an
  acknowledgment rule that creates inverse theft risk. The design states
  this residual and makes no incentive-compatible fair-exchange claim.
- Keep progress-meter exits separate. The single-operator wedge ignored test
  can pass after M4/M5/M6 without M7. A separate conditional
  `cognition_market_cross_org_escrow` test covers M7 and remains ignored
  until a real bilateral pair triggers implementation. It includes
  withhold-root exact balances, withhold-response residual risk, invalid
  funding/finality, sponsor/depositor mismatch, wrong contract escrow id,
  token/config mismatch, short deadline, each of the three missing proof
  stages, authority substitution, restart, duplicate terminal action,
  partial/mixed or alternative-method bypass, unauthorized release submitter,
  wrong beneficiary balance delta, admin pause through deadline, zero-value
  refund after full release, missing service bond/effect mapping, reorg, and
  drain-or-refund key-rotation cases. The settlement-reference golden vector
  and one-field-at-a-time substitution tests are mandatory.
- A matched delivery opens a durable `matched_pending_escrow_settlement`
  purchase slot under the M4/M5 listing fence and cutoff, with no realized
  spend or signed final purchase record. Confirmed `FullReleased` closes it
  with a signed `chio.finding.purchase-record.v1` binding the exact settlement
  profile, consumed mediator backing, release/receipt/root/transaction
  evidence, beneficiary balance delta, realized spend equal to the accepted
  amount, immutable buyer destination, and `payout_eligible: true`.
  Confirmed `FullRefunded` closes it with zero realized spend, exact refund
  evidence, and `payout_eligible: false`. M5 standing and payouts accept only
  finalized capture or `FullReleased` records with positive authoritative
  realized spend. Restart, reorg, dual-terminal, pending-record, and
  refunded-as-loss tests fail closed.
- Trigger condition: at least one real bilateral seller/buyer pair wants
  it; otherwise stays unbuilt (YAGNI).

### M8 Pool purchasing and SDK

- Implementation and named qualification record:
  [2026-07-31-M8-pool-purchasing-sdk.md](plans/2026-07-31-M8-pool-purchasing-sdk.md).
- Elicitation ceiling (`finding_bid_ceiling`) in TypeScript/Python SDK buyer
  helpers is buyer-local policy. The shipped `MeteredBillingQuote` is an
  unsigned caller-carried input and is not an authenticated re-derivation
  quote producer. If M8 adds a producer, its signed artifact binds producer,
  context and replay-recipe digests, currency, estimate provenance, validity,
  and rounding policy. Operators cannot reconstruct an undisclosed bid basis
  from `SignedBid`, which carries only the ceiling.
- Specify the arithmetic over canonical decimal-string integers with checked
  wide intermediates, currency equality, explicit rounding, and basis points
  restricted to `0..=10_000`. Reject overflow, negative/fractional/NaN
  encodings, currency mismatch, stale or substituted sources, unsafe
  JavaScript numeric values beyond the safe-integer range, and inputs above
  the Rust `u64` boundary rather than rounding them. Canonical decimal strings
  remain exact and accepted through the full `u64` domain.
- One-purchaser-per-pool is only a convention until the pool is authoritative:
  current `SwarmBudgetPool` amounts are unsigned and substitutable under the
  same string id, and remote budget mode is advisory. Add a signed/digested
  companion pool-allocation envelope and kernel-ledger debit binding, then
  restrict the hard-ceiling claim to a qualifying atomic or linearizable
  backend. The signed allocation fixes one persistent qualified-ledger domain,
  and pool projections are bounded before canonicalization. Otherwise label
  the helper advisory.
- A finding pheromone is a fully admitted deposit, not indicator JSON alone:
  define its subject/namespace, listing scope, signer/passport, severity,
  confidence, decay, nonce, `SubjectClassPolicy`, and cost. It grants no
  purchase authority and the buyer always re-resolves the signed current
  listing under a receiver-pinned registry authority and the M2 admission
  bundle.
- Exit: named TypeScript and Python SDK parity tests produce the same
  `finding_bid_ceiling` for golden buyer-estimate inputs, including values
  above `2^53`, and prove at-ceiling bids clear and above-ceiling bids reject
  through the real marketplace fixture. Negative arithmetic vectors cover
  bounds, overflow, encodings, currency, provenance, and rounding. A
  concurrent restart test shows the authenticated pool allocation and
  qualifying backend never exceed the signed amount. Pheromone tests reject
  stale, unadmitted, wrong-signer/passport, wrong-scope, replayed, and
  over-cost deposits; the positive hint re-resolves the intended current
  listing without granting purchase authority. SDK tests and the workspace
  gate are green.

### M9 Qualification, claims, and the R&D turn

- Bounded-matrix entries + feature-flag removal for qualified surfaces;
  CLAIM_REGISTRY approved-claim rows + two `audited_assumption` rows
  (status-feed operator, seller tool server); RC Supported-Guarantee
  entries; ADR-0017 Proposed -> Accepted.
- Proof-bundle integration (ARCHITECTURE 7.2): the finding verifier's
  claim ids (`claim.finding.delivery_digest_bound`,
  `claim.finding.evidence_bound`, `claim.finding.status_fresh`,
  `claim.finding.bond_backed`) bound through the existing `ClaimSet`
  role with digest pins, plus a transaction-passport golden. Unsigned replay
  recipes and status-proof verifier inputs travel only as content-addressed
  non-authority attachments, never in a signed-artifact evidence role. A
  signed registered finding-verifier report commits to their digests and an
  independent verifier rechecks them. Add wrong-role, wrong-schema,
  wrong-digest, and substituted-attachment negatives, and name the
  transaction-passport integration owner in the crate map.
  `claim.finding.status_fresh` means only that the named feed/root/path was
  authentic and fresh at the checked time; it does not prove external
  operator insert completeness. The single-operator pending/outbox guarantee
  and the external audited-completeness assumption remain distinct claim
  rows.
- R&D-instance extensions begin only here: replication decision rules for
  stochastic recipes, descriptor taxonomy for experiment spaces,
  `evidence_cost` bucketing defaults (threat model X2), cross-org feed
  governance - each gated on wedge usage data. Stochastic challenge semantics
  use a new sibling `.v1` artifact family and do not append variants to the
  frozen M5 challenge vocabulary.
- Exit: the named `cognition_market_qualified_profile` integration traverses
  publish, discover, verified purchase, identity-profile reveal, challenge,
  outbox-backed retraction, portable status rejection, and governed-memory
  quarantine under the bounded profile. The proof bundle and transaction
  passport verify from persisted goldens; every approved claim maps to
  qualification evidence and every operator assumption stays labeled.
  `cargo xtask qualify bounded-chio`, the full workspace gate, and release
  documentation checks pass before feature flags are removed or ADR-0017 is
  accepted.

## 3. Verification strategy (cross-cutting)

- Every milestone ends on the workspace gate plus its own integration
  test named in its exit criteria.
- Formal hooks, in order of value: (1) delivery-contract soundness - Kani
  harness over the gate function (public-API style, like
  `kani_public_harnesses.rs`) plus a bounded Lean model "Allow implies
  digest equality" wired into the theorem inventory; (2) challenge-outcome
  envelope (award never exceeds bond; distribution sums exactly) - Kani;
  (3) status-feed freshness monotonicity (epoch roots strictly advance;
  non-inclusion proofs never accepted past `valid_until`) - Lean bounded
  model. These follow the proof-manifest process
  (`formal/proof-manifest.toml`) and are scoped inside M3/M5/M6.
- Conformance: family goldens from M1 onward; verdict-matrix rotations at
  M3 for the generic digest gate and M4 for the purchase-required marker.
- The spec-shaped ignored test
  (`crates/economy/chio-open-market/tests/cognition_market_flow.rs`)
  is the progress meter. M3 supplies the generic digest constraint and
  terminal enforcement, but does not delete seam (a). M4 replaces the
  diagnostic stub and deletes seam (a) after the provider-minted grant,
  signed-finding binding, and `read_finding` server are wired. At that point
  it splits cross-org seam (b) into M7's separate conditional ignored test,
  while converting challenge seam (c) and status seam (d) from comments into
  executable fail-first assertions. M5 deletes (c) and M6 deletes (d). The
  single-operator wedge is functionally complete only when its test can be
  un-ignored and passes; M7 qualification is independent and conditional.

## 4. Decision backlog (future ADRs, written when their milestone starts)

| ADR | Decision | Milestone | Current lean (from ARCHITECTURE) |
|---|---|---|---|
| ADR-A | Delivery carrier, durable mismatch transition, legacy coverage, `PrepaidFinal` policy, and metadata insertion | M3 | DECIDED in [ADR-0018](../../adr/ADR-0018-kernel-delivery-contract.md): `OutputDigestSha256` carrier; compare at the post-transform durable boundary; new `DeniedAfterDelivery` terminal with `ContractualZeroCharge`; legacy and prepayment rejected predispatch |
| ADR-B | Status-feed governance: who operates feeds, epoch cadence, anchor lanes, equivocation slashing | M6 | venue-operated, anchored, operator-bonded (threat model O2/O3) |
| ADR-C | Cross-org Finding escrow enforcement: contract discriminator versus audited TTP profile | M7 | prefer a contract-level full-only/authority gate; otherwise classify the current-contract profile Experimental and discretionary |
| ADR-D | Auction mechanism (batched uniform-price per topic) | only with M4+ demand data | posted-price holds until data says otherwise (MECHANISMS 3) |
| ADR-E | Receipt-metadata key registry (repo-wide hygiene found during research) | M3 (folded into ADR-0018 item 7) | named consts + PROTOCOL 6.4 table; lands in M3 because the delivery-contract block's security depends on the reserved-key policy |
| ADR-F | Existence-tier product (paid dead-end check) | M8+ | one-bit reveal priced per MECHANISMS 3/9 |

## 5. Risk register (program-level)

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Durable digest mismatch has no signed terminal transition yet | high until ADR-A | M3 blocked | design and owner-review the persisted Deny plus release/refund/compensation state before writing implementation tasks |
| Current reserve-for-caller `MustPrepay` and `PrepaidFinal` can settle before output verification | certain on those paths | paid invalid delivery | exclude both from M4; ADR-A must prove direct durable `HoldCapture` ordering and real idempotent rail effects |
| Verdict-matrix rotation friction across 7+ drivers | medium | M3 and M4 tails | add one scoped scenario class with each new constraint and stage each rotation with its owning change, not after |
| Honest-cost fabrication on `metered_attested` (threat S2) | high for R&D | trust in vision instance | wedge ships `deterministic_replay` only; R&D gated to M9 with audit-rate data |
| Declarative or overcommitted seller/challenge bonds | high until M2/M5 | uncompensated fraud or challenge replay | dedicated authority-verified allocations, atomic per-sale exposure, exactly-once challenge custody, and a 15-distinct-buyer unbatched payout cap |
| Audit fees or selection are not actually enforced | high until M2/M5 | deterrence claim is fictional | recurring admission-gating participation fee, segregated pool, and signed reproducible audit epochs |
| Cross-org mediator suppresses response or checkpoint | high without aligned operator | buyer or seller loss | M7 remains Experimental under explicit SLA; performance bond only for observable omission and separate response-delivery residual |
| Current escrow alternatives bypass an off-chain Finding full-only/authority profile | certain without ADR-C contract work | discretionary or partial release can evade the claimed settlement gate | block M7 qualification on ADR-C; require a contract discriminator or label the deployment an audited TTP profile with no non-discretionary claim |
| No job daemon for epoch/audit cadence | certain | ops burden | operator cron per runbook (existing anchor/settle precedent); revisit only if ops data demands a daemon |
| Demand-side flop (nobody buys) | unknown | program value | M4 exit includes a dogfood loop on this repo's own CI failures; M7+ gated on demand evidence |
| Cross-org confidentiality objections (operator sees reveals, O1/T1) | medium | limits vision instance | documented posture + TEE-tier deployment guidance; no overclaim in CLAIM_REGISTRY |
| Post-reveal resale collapses prices (B2) | high by nature | seller participation | priced-in decay/versioning (MECHANISMS 3/7); wedge contexts are org-internal where resale is moot |

## 6. Plan maintenance rules

- One bite-sized implementation plan per milestone, authored with the
  target files open (never from memory of them), stored in
  [plans/](plans/) as `YYYY-MM-DD-M<N>-<name>.md`.
- A milestone's plan is written only when its dependencies have landed and
  its ADR-backlog decisions are made; until then the milestone definition
  above is the spec.
- Every landed milestone updates the ignored spec test's seam list and this
  file's ladder table. Every registered schema receives its normative
  `PROTOCOL.md` section in the same milestone, beginning with M0.
