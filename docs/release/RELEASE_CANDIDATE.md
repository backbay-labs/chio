# Chio Release Candidate Surface

> Version posture: Chio is pre-release. Chio-owned protocol, schema, SDK, and
> runtime surfaces are current v1-only. The `v2.x`, `v3.x`, and phase labels
> in this release history are internal milestone labels, not public wire or
> compatibility versions.

This document is an internal pre-release v1 candidate inventory. Internal
`v2.x`, `v3.x`, and phase labels name implementation milestones only. They do
not define public protocol versions, compatibility levels, or release history.
The public Chio-owned surface remains v1-only and unreleased.

The current pre-release v1 branch contains locally qualified
implementation and evidence for the **release SKU subset** named in the
sections below (not every internal milestone surface).

It is intentionally limited to behavior backed by the current codebase,
qualification scripts, and release docs.

## Document Roles

Use the release documents this way:

- this file defines the supported production-candidate surface only
- [RELEASE_AUDIT.md](RELEASE_AUDIT.md) is the repo-local pre-release evidence
  inventory and release-hold record
- [QUALIFICATION.md](QUALIFICATION.md) defines the evidence lanes and command
  contract
- [GA_CHECKLIST.md](GA_CHECKLIST.md) is the operator-facing publication
  checklist
- [PARTNER_PROOF.md](PARTNER_PROOF.md) and
  [CHIO_WEB3_PARTNER_PROOF.md](CHIO_WEB3_PARTNER_PROOF.md) are reviewer-facing
  evidence packages

## Launch Decision Contract

Promotion from "qualified candidate" to an externally published Chio release
requires three gate classes:

- local evidence gates: `./scripts/ci-workspace.sh`,
  `./scripts/check-formal-proofs.sh`,
  `./scripts/check-portable-kernel.sh`,
  `./scripts/check-sdk-parity.sh`, `./scripts/check-web3-contract-parity.sh`,
  `./scripts/qualify-release.sh`,
  `./scripts/qualify-portable-browser.sh`, and
  `./scripts/qualify-mobile-kernel.sh` must all pass, and the release docs
  must be updated together
- hosted publication gates: GitHub `CI` and `Release Qualification` workflows
  must be green on the exact candidate commit; the hosted `Release
  Qualification` workflow now also runs `./scripts/qualify-web3-runtime.sh`,
  `./scripts/qualify-web3-e2e.sh`,
  `./scripts/qualify-web3-ops-controls.sh`, and
  `./scripts/qualify-web3-promotion.sh` and stages the resulting web3
  evidence bundle under `target/release-qualification/web3-runtime/`,
  including generated end-to-end settlement evidence under
  `target/release-qualification/web3-runtime/e2e/` and generated ops runtime
  reports, control-state snapshots, control traces, and the incident audit
  under `target/release-qualification/web3-runtime/ops/`
- operator decision gates: release tag and package publication must be
  explicitly approved after the hosted gates are observed

## Current Decision Status

As of `2026-04-19`, the local evidence gates are satisfied for the current Chio
candidate, including the underwriting surfaces added in `v2.10`, the
portable-credential interop surfaces added in `v2.11`, the workload-identity
and trusted-verifier surfaces added in `v2.12`, and the standards-native
portable lifecycle surfaces added in `v2.13`, the verifier-side OID4VP bridge
added in `v2.14`, plus the multi-cloud appraisal surface added in `v2.15` and
the enterprise-IAM profile surface added in `v2.16`, plus the governed public
certification-marketplace surface added in `v2.17`, plus the credit backtest
and provider-risk-package surface added in `v2.18`, plus the bonded-execution
simulation and operator-control surface added in `v2.19`, plus the curated
liability-provider, quote/bind, claim/dispute/adjudication, and
marketplace-proof surface added in `v2.20`, plus the standards-native
portable claim/binding, multi-format credential, and hosted request-time
authorization surface added in `v2.21`, plus the wallet exchange, identity
continuity, and sender-constrained authorization surface added in `v2.22`,
plus the portable appraisal result import/export and mixed-provider
qualification surface added in `v2.23`, plus the live capital-book,
capital-instruction, and simulation-first capital-allocation surface added in
`v2.25`, plus the bounded open-market economics and slashing surface added in
phase `122`, plus the adversarial multi-operator open-market qualification
surface added in phase `123`, the final endgame boundary closure added in
phase `124`, and the official-stack plus extension-SDK contract added in
phases `125` through `128`, plus the official web3 trust, anchoring, oracle,
dispatch, and settlement surface added in phases `129` through `132`, plus
the official web3 runtime contracts, bindings, deployment templates, and
qualification surface added in phases `145` through `148`, plus the
bounded `chio-link` operator inventory, sequencer gating, runtime reporting,
and conservative cross-currency budget-enforcement surface added in phases
`149` through `152`, plus the bounded `chio-anchor` EVM publication,
OpenTimestamps linkage, Solana memo normalization, discovery, and
qualification surface added in phases `153` through `156`, plus the bounded
`chio-settle` escrow dispatch, anchored release, timeout refund, bond
lifecycle, Solana-preparation, and runtime-devnet qualification surface added
in phases `157` through `160`, plus the bounded Functions fallback,
automation-job, CCIP settlement-coordination, and machine-payment interop
surface added in phases `161` through `164`, plus the bounded web3
operations-report, promotion-policy, readiness-audit, and partner-proof
surface added in phases `165` through `168`, plus
the concurrency-safe settlement identity, mandatory evidence gating, bond or
oracle authority reconciliation, generated contract-binding parity surface,
hosted qualification, reviewed-manifest promotion, exercised ops-control, and
generated end-to-end settlement proof surface added in phases `169` through
`176`, plus
the bounded autonomous pricing, capital-pool optimization, execution,
rollback, and qualification surface added in phases `133` through `136`, plus
the bounded federation-activation exchange, quorum, open-admission, shared-
reputation clearing, and qualification surface added in phases `137` through
`140`, plus the bounded public identity-profile, wallet-directory,
wallet-routing, and identity-interop qualification surface added in phases
`141` through `144`.
External tag/publication remains on hold until the hosted workflow results are
observed. The hosted release lane is now wired to publish the bounded web3
qualification bundle, including the generated ops-control artifact family,
alongside the existing release-qualification artifact corpus. The local gate
now also includes the bounded formal-boundary checks plus the portable
kernel/browser/mobile qualification lanes.

## Supported Guarantees

- capability-scoped mediation remains the root trust contract for local,
  wrapped, and hosted runtime surfaces
- allow, deny, cancelled, and incomplete outcomes always produce signed
  receipts
- governed transaction approvals, x402, ACP-Commerce/shared-payment-token commerce, and
  settlement reconciliation preserve truthful execution-versus-payment
  semantics instead of collapsing them into one status bit
- governed receipts can be projected into external authorization-details and
  delegated transaction-context reports derived from signed receipt metadata
  instead of operator-authored side documents
- Chio now ships machine-readable authorization-profile metadata and
  reviewer-pack evidence artifacts so enterprise IAM teams can inspect the
  supported profile, discovery boundary, and one governed action end to end
  without reverse-engineering Chio internals
- Chio now also ships one bounded hosted request-time authorization contract
  over the same profile, including explicit `authorization_details` and
  `chio_transaction_context` parameters, protected-resource/resource-indicator
  convergence, and fail-closed runtime-versus-audit artifact boundaries
- non-rail metered billing evidence stays operator-reconcilable through
  explicit sidecar state without mutating signed receipt truth
- trust-control centralizes authority, revocation, receipt, budget,
  certification, and federation state for supported operator deployments
- hosted remote sessions expose documented lifecycle and admin diagnostics
  through `/admin/health`, `/admin/sessions`, and session trust detail
- enterprise-provider and verifier-policy state is operator-visible through
  trust-control health and registry surfaces
- portable trust ships as `did:chio`, Chio-primary passport and verifier-policy
  schemas, challenge/response presentation, evidence export/import, and
  parent-bound federated delegation continuation, with legacy pre-Chio
  artifacts still accepted for verification
- Chio now ships one qualified portable credential family over
  OID4VCI-compatible issuer metadata, with a native `AgentPassport` response,
  projected `application/dc+sd-jwt` and `jwt_vc_json` responses, portable
  issuer `JWKS`, portable type metadata, and operator-scoped lifecycle
  distribution and public resolution semantics over the same passport truth
- Chio now ships one qualified verifier-side OID4VP bridge over that portable
  credential lane, with signed `request_uri` request objects, one
  transport-neutral wallet exchange descriptor and canonical transaction
  state, one optional verifier-scoped identity assertion continuity lane,
  same-device and cross-device launch artifacts, Chio verifier metadata,
  verifier `JWKS`, and `direct_post.jwt` response verification, plus the
  existing public Chio-native challenge fetch and response submit routes
- Chio now also ships one bounded hosted sender-constrained continuation
  contract over that verifier/auth surface, with DPoP, mTLS thumbprint
  binding, and one attestation-confirmation profile that never widens runtime
  authority from attestation alone
- Chio now also ships one bounded cross-issuer portfolio contract over those
  passport artifacts, with explicit native/imported/migrated entry kinds, one
  signed trust-pack activation surface, one signed migration artifact for
  subject rebinding, and fail-closed visibility-versus-admission semantics
- the insurer-facing behavioral feed exports signed decision, settlement,
  governed-action, and scoped reputation evidence from canonical Chio state
- Chio now also ships one signed portable reputation-summary artifact and one
  signed portable negative-event artifact over explicit issuer, subject,
  evidence, and freshness state, plus one local weighting evaluation lane
  that accepts imported reputation only through explicit issuer allowlists,
  attenuation or penalty weights, and fail-closed rejection of stale, future,
  duplicate, blocked, or contradictory inputs
- Chio now also ships one signed open-market fee-schedule artifact over
  explicit namespace, actor-kind, publisher-operator, and admission-class
  scope plus publication, dispute, and market-participation fees and bond
  requirements, and one signed market-penalty artifact over matched listing,
  trust activation, governance sanction or appeal case, abuse class, and bond
  class, with fail-closed evaluation for stale authority, scope mismatch,
  unsupported or non-slashable bond requirements, currency mismatch,
  oversized penalties, or invalid reversal linkage
- Chio now also locally qualifies that registry and open-market surface under
  adversarial multi-operator conditions: invalid mirrored listing signatures
  remain visible but untrusted, divergent replica freshness blocks admission,
  portable reputation remains locally weighted, and governance or
  market-penalty evaluation rejects trust activations that were not issued by
  the governing local operator
- Chio now ships signed underwriting policy inputs, deterministic
  underwriting-decision reports, persisted signed underwriting decisions, and
  explicit appeal records without mutating canonical receipt truth, including
  fail-closed issue validation, evidence-linked findings, and currency-safe
  premium handling
- Chio now ships non-mutating underwriting simulation so operators can compare
  baseline versus proposed policy outcomes over one canonical evidence package
- Chio now ships signed exposure-ledger and credit-scorecard exports, bounded
  facility-policy evaluation plus signed facility artifacts, deterministic
  credit backtests over historical windows, and signed provider-facing risk
  packages suitable for external capital review
- Chio now ships one signed live capital-book and source-of-funds report over
  canonical receipt, facility, bond, and loss-lifecycle evidence instead of
  forcing operators to infer live capital posture from separate records
- Chio now ships one signed custody-neutral capital instruction artifact with
  explicit authority-chain, execution-window, intended-state, and reconciled-
  state truth instead of implying external movement from approval alone
- Chio now ships one signed simulation-first capital-allocation decision for
  one governed receipt, one live source-of-funds story, one optional reserve
  source, and one bounded execution envelope as pre-dispatch planning truth
  instead of overloading allocation with proof of external execution
- Chio now also ships executable reserve release and reserve slash lifecycle
  artifacts over one capital-book reserve source with explicit authority-chain,
  execution-window, reconciliation-state, and appeal-window truth instead of
  inferring reserve movement from loss accounting alone
- Chio now also ships one machine-readable web3 trust profile, contract
  package, chain configuration, anchor inclusion proof, and oracle-evidence
  contract for one official Base-first web3 stack
- Chio now also ships the corresponding packaged Solidity contract family,
  artifact-derived Alloy bindings crate, Base and Arbitrum deployment
  templates, and one bounded local-devnet qualification report for that
  official web3 stack
- Chio now also ships one bounded `chio-link` runtime over pinned Base-first
  operator inventory, Chainlink primary plus Pyth fallback policy, sequencer
  downtime and recovery gating, explicit pause or disable controls, optional
  degraded stale-cache grace, one runtime-report artifact, conservative
  receipt-side cross-currency conversion margins, and the sole supported
  runtime FX authority model for official web3 lanes
- Chio now also ships one bounded `chio-anchor` runtime over Base-first root
  publication, explicit publisher-authorization and sequence guards, imported
  Bitcoin OpenTimestamps secondary evidence, imported Solana memo secondary
  evidence, one `did:chio` discovery artifact, and one shared proof-bundle
  verification contract that fails closed on missing, undeclared, or
  cryptographically inconsistent secondary lanes
- Chio now also ships one bounded `chio-settle` runtime over the official
  escrow and bond-vault contracts, with explicit Merkle-proof and
  dual-signature release lanes, timeout refund, bond lifecycle observation,
  Solana-native Ed25519 settlement preparation, finality/recovery state
  projected back into canonical web3 settlement receipts, explicit
  collateral-versus-reserve-requirement parity on the bond lane, and one
  generated end-to-end settlement proof bundle for FX-backed dual-sign and
  recovery posture
- Chio now also ships one bounded Functions fallback over prepared Chio receipt
  batches, one bounded anchor/settlement automation surface with replay-safe
  job state, one bounded CCIP settlement-coordination message family, and one
  bounded payment-interop layer for x402, EIP-3009, Circle-managed custody,
  and ERC-4337/paymaster compatibility, all without turning schedulers,
  bridges, or facilitators into a replacement truth source
- Chio now also ships one bounded web3 operations contract over oracle,
  anchoring, and settlement runtime reports, explicit indexer lag/drift or
  replay classes, and emergency modes that narrow write authority instead of
  widening trust
- Chio now also ships one signed web3 settlement-dispatch artifact and one
  signed web3 settlement-execution-receipt artifact that bind governed capital
  instruction, escrow, bond-vault, anchor-proof, and FX-provenance state into
  one reconciled external-rail record
- Chio now also locally qualifies that official web3 lane across settled,
  partial-settlement, custody-boundary, and reversal-recovery cases without
  treating chain observation as a replacement for canonical Chio truth
- Chio now also ships one reproducible web3 qualification lane, one explicit
  approval-gated reviewed-manifest deployment runner with explicit rollback
  artifacts, one deployment-promotion policy with gas and latency budgets,
  one focused web3 readiness audit, and one reviewer-facing web3 partner-proof
  package that keep remaining external publication dependencies explicit
- Chio now also ships one signed autonomous pricing-input, authority-envelope,
  and pricing-decision family over underwriting, scorecard, loss, capital,
  and optional web3-settlement evidence, with fail-closed validation for
  mixed-currency posture, missing provenance, stale envelope windows, and
  out-of-envelope coverage or premium recommendations
- Chio now also ships one signed capital-pool optimization artifact and one
  signed capital-pool simulation report so reserve strategy, facility shifts,
  and bind-capacity posture stay explicit, scenario-comparable, and
  operator-reviewable instead of becoming model side effects
- Chio now also ships one signed autonomous execution-decision, rollback-plan,
  comparison-report, drift-report, and qualification-matrix family so
  automatic reprice, renew, decline, and bind behavior remains interruptible,
  explainable, fail-safe, and subordinate to explicit authority envelopes plus
  the official web3 settlement lane
- Chio now ships one non-mutating bonded-execution simulation lane so
  operators can compare baseline reserve-backed execution versus an explicit
  control policy with kill-switch and clamp-down semantics over the same bond
  and loss-lifecycle evidence
- Chio now ships one curated liability-provider registry with signed provider
  policy artifacts, supersession-aware publication, and fail-closed
  jurisdiction, coverage-class, currency, and evidence-requirement resolution
  before quote, placement, or claims state can be accepted
- Chio now also ships provider-neutral liability quote-request,
  quote-response, placement, and bound-coverage artifacts over one signed
  provider-risk package, with fail-closed stale-provider, quote-expiry,
  placement-mismatch, and unsupported-policy handling
- Chio now also ships immutable liability claim-package, provider-response,
  dispute, and adjudication artifacts linked back to bound coverage,
  exposure, bond, loss, and receipt evidence, with fail-closed oversized-claim
  and invalid-dispute handling
- Chio now locally qualifies that liability-market surface end to end across
  curated provider resolution, quote-and-bind, and claim/dispute lifecycle
  evidence, with release and partner materials updated to keep the marketplace
  claim bounded and honest
- Chio now also ships one bounded delegated pricing-authority artifact plus one
  automatic coverage-binding decision artifact over provider policy,
  underwriting, facility, and capital-book truth, with fail-closed rejection
  for stale provider state, stale authority, and out-of-envelope coverage or
  premium requests
- runtime assurance is a first-class issuance and governed-execution input,
  with explicit assurance tiers and minimum-runtime-assurance constraints on
  economically sensitive grants
- workload identity and concrete attestation trust now ship with one typed
  SPIFFE-derived mapping contract, one canonical runtime-attestation
  appraisal contract, concrete Azure Attestation, AWS Nitro, and Google
  Confidential VM verifier bridges, and explicit trusted-verifier rebinding
  rules that fail closed on stale or unmatched evidence
- operators can export one signed runtime-attestation appraisal report from
  local state or trust-control so verifier family, normalized assertions,
  vendor-scoped claims, and policy-visible outcomes are exchangeable without
  re-querying the verifier path
- Chio now also ships one signed runtime-attestation appraisal-result contract
  plus one explicit local import-policy evaluation lane over the same
  Azure/AWS Nitro/Google/enterprise-verifier appraisal boundary, with
  qualification-backed fail-closed handling for stale results, stale evidence,
  unsupported verifier-family policy, and contradictory portable claims
- Chio also now ships one signed verifier-descriptor, signed reference-value,
  and signed trust-bundle contract over that same bounded appraisal boundary,
  with explicit versioning and fail-closed rejection of stale, ambiguous, or
  contract-mismatched verifier metadata
- Chio also now ships one signed public issuer-discovery document, one signed
  public verifier-discovery document, and one signed transparency snapshot
  over those existing metadata surfaces, all with explicit informational-only,
  explicit-import, and manual-review guardrails so visibility never widens
  local trust automatically
- Chio now projects runtime-assurance schema and verifier family into the
  standards-facing authorization context and forces manual facility review
  when bounded runtime evidence spans multiple verifier families
- public claims are bounded by executable diff-tests, runtime/integration
  verification, and release qualification; standalone Lean proof files are not
  part of the shipped release gate while they remain outside the root import
  surface or contain `sorry`
- `Chio Certify` ships as a signed operator evidence artifact plus a
  fail-closed registry with `active`, `superseded`, `revoked`, and `not-found`
  resolution states
- portable passport lifecycle discovery now requires explicit TTL-backed
  public status distribution and exposes fail-closed `stale` resolution state
  instead of treating over-aged lifecycle truth as implicitly current
- `Chio Certify` now also ships one governed public discovery surface with
  versioned evidence profiles, public publisher metadata, public search and
  transparency feeds, explicit dispute state, and policy-bound consume flows
  that do not widen runtime trust from listing visibility alone
- Chio now also ships one signed operator-owned namespace artifact plus one
  generic listing projection over current tool-server, issuer, verifier, and
  liability-provider surfaces, with explicit origin/mirror/indexer publisher
  roles, deterministic search-policy metadata, freshness windows, fail-closed
  ownership or stale/divergent-state checks, and no trust activation implied
  by listing visibility alone
- Chio now also ships one signed local trust-activation artifact over those
  generic listings, plus bounded `public_untrusted`, `reviewable`,
  `bond_backed`, and `role_gated` admission classes with explicit eligibility,
  review, expiry, and fail-closed evaluation semantics so public visibility
  still never becomes runtime trust by itself
- Chio now also ships one signed governance-charter artifact and one signed
  governance-case artifact family over the generic registry, with explicit
  namespace, listing, operator, and optional activation scope, cross-operator
  escalation counterparties, and fail-closed evaluation for dispute, freeze,
  sanction, and appeal actions without claiming permissionless global
  arbitration
- Chio now also ships one signed federation-activation exchange artifact over
  trust-activation, listing, optional governing-charter references, explicit
  scope, delegation attenuation, and fail-closed local import controls so
  cross-operator visibility stays reviewable and never becomes ambient runtime
  trust
- Chio now also ships one signed federation-quorum report over origin, mirror,
  and indexer observations with explicit freshness, conflict, and anti-eclipse
  evidence, and fails closed on missing origin coverage, insufficient distinct
  operators, stale replica state, or conflicting publisher truth
- Chio now also ships one signed federated open-admission policy and one signed
  federated reputation-clearing artifact so bond-backed participation,
  governance-visible review, local weighting, independent-issuer diversity,
  and corroborated blocking negative events remain machine-readable instead of
  operator folklore
- Chio now also locally qualifies that federated lane under hostile publisher,
  conflicting activation, insufficient quorum, eclipse-attempt, reputation-
  sybil, and governance-interop scenarios without claiming permissionless
  federation or universal trust scoring
- Chio now also ships one machine-readable public identity profile, one public
  wallet-directory entry, one public wallet-routing manifest, and one
  identity-interop qualification matrix over `did:chio` plus bounded
  `did:web`, `did:key`, and `did:jwk` compatibility inputs, projected
  portable passport families, verifier-bound directory state, replay-safe
  routing anchors, and fail-closed subject or issuer mismatch handling
- the A2A adapter covers the current shipped matrix of discovery, blocking and
  streaming message execution, follow-up task management, push-notification
  config CRUD, durable task correlation, and fail-closed auth negotiation
- Chio now also ships one machine-readable extension inventory, one official
  first-party stack package, one extension manifest and negotiation contract,
  and one qualification matrix for official-versus-custom extension cases,
  with fail-closed rejection on Chio-version mismatch, unsupported components,
  unsupported privileges or isolation, missing policy activation for
  evidence-capable extensions, truth mutation, or trust widening
- the TypeScript, Python, and Go SDKs are release-qualified against the
  supported HTTP/session surface rather than treated as unverified examples

## Supported Defaults And Limits

| Limit or default | Value | Source |
| --- | --- | --- |
| default max capability TTL | `3600s` | `crates/products/chio-cli` |
| default delegation depth | `5` | `crates/products/chio-cli` |
| default streamed tool duration limit | `300s` | `crates/kernel/chio-kernel/src/lib.rs` |
| default streamed tool total-byte limit | `256 MiB` | `crates/kernel/chio-kernel/src/lib.rs` |
| default MCP page size | `50` | `crates/protocol/chio-mcp-edge/src/runtime.rs` |
| background-task progression per edge tick | `8 tasks` | `crates/protocol/chio-mcp-edge/src/runtime.rs`, `crates/protocol/chio-mcp-adapter/src/transport.rs` |
| remote session idle expiry | `15 min` | `crates/protocol/chio-mcp-remote/src/remote_mcp/` |
| remote session drain grace | `5 s` | `crates/protocol/chio-mcp-remote/src/remote_mcp/` |
| remote session tombstone retention | `30 min` | `crates/protocol/chio-mcp-remote/src/remote_mcp/` |

Release qualification depends on those defaults being covered by tests and on
stricter user-provided values continuing to fail closed.

## Explicit Non-Goals

The current Chio candidate does not claim:

- multi-region or consensus trust replication
- a permissionless or auto-trusting public certification marketplace
- automatic SCIM provisioning lifecycle
- synthetic cross-issuer passport trust aggregation
- public identity, issuer, verifier, or wallet discovery that automatically
  widens local trust
- generic OID4VP, SIOP, DIDComm, or permissionless public wallet-network
  compatibility beyond Chio's documented passport profile family plus bounded
  public identity-profile, wallet-directory, and routing-manifest contracts
- generic sender-constrained interoperability or attestation-only sender
  authorization beyond Chio's documented DPoP, mTLS, and paired
  attestation-confirmation profile
- generic attestation-result interoperability beyond Chio's documented
  canonical appraisal contract, concrete Azure, AWS Nitro, or Google verifier
  bridges, signed appraisal-result import/export contract, and explicit local
  import-policy mapping
- one-time consume or replay-registry semantics for imported appraisal
  results; Chio's current replay defense at that boundary is explicit signature
  plus freshness validation
- arbitrary plugin execution that mutates signed Chio truth, bypasses local
  policy activation, or widens trust outside Chio's named extension points
- permissionless or arbitrary external capital dispatch, implicit regulated-
  actor status, or unsupported autonomous insurer-rate setting beyond Chio's
  documented official web3 rail plus bounded autonomous-pricing, capital-pool,
  execution, and rollback surface
- external recovery clearing or insurer-network messaging beyond Chio's
  documented liability-market orchestration boundary, including its bounded
  payout-instruction, payout-receipt, settlement-instruction, and
  settlement-receipt lane
- portable reputation as a universal trust oracle, automatic cross-issuer
  score, or ambient trust-admission mechanism
- permissionless or auto-trusting federation beyond Chio's documented
  federation-activation exchange, quorum, open-admission, reputation-clearing,
  and qualification surfaces
- permissionless mirror/indexer publication as automatic trust, sanction, or
  market-penalty authority
- permissionless or ambient open-market penalties, slashing, or trust
  widening outside Chio's documented fee-schedule, trust-activation, and
  governance-case surfaces
- first-principles theorem-prover completion for concrete crypto, platform, or
  external-service behavior beyond the audited assumption registry
- performance-first throughput tuning beyond the documented qualification lane

## Migration Story

- existing wrapped MCP servers can be hosted through `chio mcp serve` and
  `chio mcp serve-http`
- trust-control-backed deployments can centralize authority, revocation,
  receipts, budgets, federation registries, and certification state through
  `chio trust serve`
- new policy work should start from
  `examples/policies/canonical-hushspec.yaml`
- existing deployments should migrate policy authoring to HushSpec before
  adopting this candidate
- Chio-branded schema issuance is now primary, while legacy pre-Chio artifacts
  remain verifiable/importable
- `did:chio` remains the currently shipped canonical DID method and provenance
  anchor, while the bounded public identity profile may also name `did:web`,
  `did:key`, and `did:jwk` as compatibility inputs
- portable trust and cross-org workflows start from
  [AGENT_PASSPORT_GUIDE.md](../reference/AGENT_PASSPORT_GUIDE.md) and
  [IDENTITY_FEDERATION_GUIDE.md](../reference/IDENTITY_FEDERATION_GUIDE.md)
- A2A integrations start from [A2A_ADAPTER_GUIDE.md](../reference/A2A_ADAPTER_GUIDE.md)

## Operator And Release Guidance

- use `./scripts/ci-workspace.sh` for routine validation
- use `./scripts/qualify-release.sh` before treating a branch as a production
  candidate
- use [QUALIFICATION.md](QUALIFICATION.md) as the release-proof matrix
- use [ECONOMIC_INTEROP_GUIDE.md](../reference/ECONOMIC_INTEROP_GUIDE.md) when IAM,
  finance, or partner reviewers need the focused economic-context walkthrough
- use `chio trust credit-backtest export` and
  `chio trust provider-risk-package export` when capital reviewers need replay
  evidence or one signed provider-facing credit package
- use [CREDENTIAL_INTEROP_GUIDE.md](../reference/CREDENTIAL_INTEROP_GUIDE.md) when a
  verifier, wallet, or standards reviewer needs the focused portable
  credential interop boundary, portable lifecycle semantics, and raw-HTTP
  proof lane
- use [CHIO_PUBLIC_IDENTITY_PROFILE.md](../standards/CHIO_PUBLIC_IDENTITY_PROFILE.md)
  when a reviewer needs the bounded public identity-profile, wallet-directory,
  routing, and multi-wallet qualification contract
- use `chio trust appraisal export`, `chio trust appraisal export-result`, and
  `chio trust appraisal import` when an operator needs one signed multi-cloud
  runtime-attestation appraisal artifact, one signed portable appraisal
  result, or one explicit local import-policy decision over foreign appraisal
  evidence
- use the trust-service `/v1/reputation/portable/summaries/issue`,
  `/v1/reputation/portable/events/issue`, and
  `/v1/reputation/portable/evaluate` endpoints when an operator needs
  provenance-preserving portable reputation exchange with explicit local
  weighting and fail-closed import evaluation
- use the trust-service `/v1/registry/market/fees/issue`,
  `/v1/registry/market/penalties/issue`, and
  `/v1/registry/market/penalties/evaluate` endpoints when an operator needs
  one explicit fee schedule, bond requirement, or market-penalty evaluation
  over listing, activation, and governance truth
- use `chio trust underwriting-decision simulate` when an operator needs to
  inspect policy deltas before issuing a new signed underwriting decision
- use [PARTNER_PROOF.md](PARTNER_PROOF.md) when a partner, insurer, or
  standards reviewer needs the compact evidence package instead of raw build
  logs
- use [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) and
  [OBSERVABILITY.md](OBSERVABILITY.md) for deployment and incident response
- use [RELEASE_AUDIT.md](RELEASE_AUDIT.md), [GA_CHECKLIST.md](GA_CHECKLIST.md),
  and [RISK_REGISTER.md](RISK_REGISTER.md) as the go/no-go record instead of
  relying on tribal knowledge
- do not tag from local evidence alone; hosted workflow observation is still a
  required publication gate
