# Release Audit

**Prepared:** 2026-04-19
**Role:** repo-local pre-release evidence inventory for the current v1-only
Chio candidate, not a public release-go record

> **Evidence inventory only:** Tables in **Findings Closure** and related
> sections record internal release disposition. They are not publication-ready
> claims for customers, auditors, or partners. Use [PARTNER_PROOF.md](PARTNER_PROOF.md)
> for reviewer packaging and [GA_CHECKLIST.md](GA_CHECKLIST.md) for operator gates.

## Internal planning artifacts (not publication evidence)

The following are engineering-planning snapshots only. They are not partner
proof, external audit evidence, or release-go records:

- `audits/evidence/close-bar-current.json` and
  `audits/evidence/close-bar-snapshot.json` (gitignored) - machine-readable
  close-bar row disposition for trajectory closeout tracking
- `.planning/trajectory-*/closeout/CLOSE-BAR-TRACKER.md` - human tracker for
  the same rows

Do not cite close-bar JSON or snapshots in partner packages, external
attestation pages, or public release claims. When a gitignored close-bar
snapshot disagrees with `releases.toml` (for example, a retracted pre-release
tag still marked `DONE`), treat `releases.toml` and the release docs in this
directory as canonical for publication status.

The internal readiness draft PDF
(`releases/audit-reports/m08-internal-readiness-draft-2026-05-02.pdf`) is
retained outside the public release bundle until an external vendor review is
engaged. `releases.toml` records the internal `draft_path` and hash only; there
is no public GitHub URL for that PDF today.

## Scope

This audit tracks the current Chio pre-release candidate surface described in
[RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md).

It is a repo-local evidence inventory, not a substitute for observing hosted
CI and release-qualification workflows after merge.

Use the release documents this way:

- [RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md) defines the supported candidate
  surface and support boundary
- [QUALIFICATION.md](QUALIFICATION.md) defines the required evidence lanes and
  commands
- this audit records local pre-release evidence and remaining release holds
- [GA_CHECKLIST.md](GA_CHECKLIST.md) is the operator-facing pre-publication
  checklist
- [PARTNER_PROOF.md](PARTNER_PROOF.md) and
  [CHIO_WEB3_PARTNER_PROOF.md](CHIO_WEB3_PARTNER_PROOF.md) are reviewer-facing
  packages, not the release decision record

The web3-runtime ladder now also has focused audit and reviewer material in
[CHIO_WEB3_READINESS_AUDIT.md](CHIO_WEB3_READINESS_AUDIT.md) and
[CHIO_WEB3_PARTNER_PROOF.md](CHIO_WEB3_PARTNER_PROOF.md).

Web3 contract external assurance: the prior web3 contract security review and
local devnet qualification are historical evidence only. Non-testnet web3
contract deployment, custody, and promotion are blocked until external audit,
testnet soak, artifact digest, runtime codehash, minimum-bar checklist, and
security-owner sign-off complete.

## Bounded Chio Ship Addendum

This file now records one primary ship-facing decision boundary for the current
repo state: bounded Chio. Stronger internal claim gates still exist as
repo-local addenda, but they are not Chio-owned protocol versions and are no
longer the front-door release framing.

**Local bounded-ship status:** bounded Chio evidence was collected locally on
2026-04-19. The current retained decision is to continue pre-release
evaluation. External release, production, and GA claims remain on hold until a
public v1 release decision is explicitly taken.

Qualified claim:

- The current pre-release v1 branch contains locally verified implementation
  and evidence for a cryptographically signed, fail-closed governance and
  evidence control plane with signed receipts, checkpoints, bounded
  delegated-authority semantics, bounded hosted/auth profiles, and explicit
  provenance classes on the current candidate surfaces.
- Chio's supported clustered control-plane story is leader-local and bounded,
  not consensus-grade HA.
- Chio's supported monetary budget story is single-node atomic with an explicit
  clustered overrun bound, not distributed-linearizable spend truth.
- Chio's supported public evidence story is signed local audit evidence plus one
  bounded trust-anchor or witness publication path with explicit publication
  policy, freshness, and conflict visibility; it is not yet a general public
  transparency-log or strong non-repudiation surface.

Not qualified by the formal lane:

- first-principles theorem-prover completion for concrete crypto, OS, storage,
  transport, subprocess, hosted-registry, chain, or settlement implementations
- broad Lean 4 verification claims beyond the implementation-linked proof
  manifest, theorem inventory, assumption registry, and claim registry
- authenticated recursive delegation ancestry beyond the preserved presented
  chain
- verifier-backed runtime assurance as the sole admission boundary
- consensus-grade HA or distributed-linearizable budget authority
- public transparency-log semantics
- stronger universal-control-plane or comptroller-capable packaging claims as
  the ship-facing release boundary
- a proved "comptroller of the agent economy" market position

Primary bounded-ship evidence commands:

- `cargo xtask qualify bounded-chio`
- `./scripts/qualify-release.sh`
- `./scripts/check-formal-proofs.sh`
- `cargo test -p chio-formal-diff-tests`

Primary bounded-ship machine-readable gate:

- [CHIO_BOUNDED_QUALIFICATION_MATRIX.json](../standards/CHIO_BOUNDED_QUALIFICATION_MATRIX.json)

Formal boundary artifacts:

- [`../../formal/proof-manifest.toml`](../../formal/proof-manifest.toml)
- [`../../formal/assumptions.toml`](../../formal/assumptions.toml)
- [`../../formal/theorem-inventory.json`](../../formal/theorem-inventory.json)
- [../CLAIM_REGISTRY.md](../reference/CLAIM_REGISTRY.md)

## Decision

**Decision:** Continue pre-release evaluation for the current bounded Chio
candidate defined in
[RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md).

Qualified local evidence includes bounded web3 runtime work, including concurrency-safe
settlement identity, mandatory checkpoint evidence gates, artifact-derived
contract/runtime parity, hosted qualification, reviewed-manifest promotion,
exercised operator controls, and the generated end-to-end settlement proof
bundle. Internal labels are not public protocol versions.

Meaning:

- release inputs, workspace correctness, dashboard packaging, SDK packaging,
  live conformance, repeat-run clustered trust qualification, portable
  kernel/browser/mobile qualification, formal boundary and diff gates, and the
  bounded web3 runtime qualification lanes are green locally
- operator deployment, backup/restore, upgrade/rollback, and observability
  contracts are documented explicitly
- release-governance documents now separate scope, evidence, decision, and
  reviewer-package roles explicitly
- standards and launch artifacts exist for receipts, portable trust, the
  bounded web3 ladder, and the final release decision package
- hosted `CI` and `Release Qualification` workflows are still required before
  tagging a release from `main`

**Local qualification date:** 2026-04-19

## Evidence

Primary local qualification commands:

- `./scripts/ci-workspace.sh`
- `./scripts/check-formal-proofs.sh`
- `./scripts/check-portable-kernel.sh`
- `./scripts/check-sdk-parity.sh`
- `./scripts/check-web3-contract-parity.sh`
- `./scripts/qualify-release.sh`
- `./scripts/qualify-portable-browser.sh`
- `./scripts/qualify-mobile-kernel.sh`
- `./scripts/qualify-web3-runtime.sh`
- `./scripts/qualify-web3-e2e.sh`
- `./scripts/qualify-web3-ops-controls.sh`
- `./scripts/qualify-web3-promotion.sh`
- `./scripts/qualify-trust-control.sh`
- `cargo test -p chio-formal-diff-tests`
- `cargo clippy -p chio-cli -- -D warnings`
- `cargo test -p chio-cli --test provider_admin trust_service_health_reports_enterprise_and_verifier_policy_state -- --nocapture`
- `cargo test -p chio-cli --test mcp_serve_http mcp_serve_http_admin_health_reports_runtime_state -- --nocapture`
- `cargo test -p chio-cli --test certify certify_registry_remote_publish_list_get_resolve_and_revoke_work -- --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-cli --test certify certify_public_generic_registry_namespace_and_listings_project_current_actor_families -- --exact --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-cli --test certify certify_generic_registry_trust_activation_requires_explicit_local_activation_and_fails_closed -- --exact --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-core open_market -- --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-cli --test certify certify_open_market_fee_schedules_and_slashing_require_explicit_bounded_authority -- --exact --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-core --lib generic_listing_search_rejects_reports_with_invalid_listing_signatures -- --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-core --lib non_local_activation_authority -- --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-cli --test certify certify_adversarial_multi_operator_open_market_preserves_visibility_without_trust -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query test_metered_billing_reconciliation_report_and_action_endpoint -- --exact`
- `cargo test -p chio-cli --test receipt_query test_authorization_context_report_and_cli -- --exact`
- `cargo test -p chio-core underwriting -- --nocapture`
- `cargo test -p chio-cli --test receipt_query test_underwriting_decision_issue_and_list_surfaces -- --exact`
- `cargo test -p chio-cli --test receipt_query test_underwriting_appeal_and_supersession_lifecycle -- --exact`
- `cargo test -p chio-cli --test receipt_query test_underwriting_decision_issue_requires_anchor -- --exact`
- `cargo test -p chio-cli --test receipt_query test_underwriting_rejected_appeal_cannot_link_replacement_decision -- --exact`
- `cargo test -p chio-cli --test receipt_query test_underwriting_decision_issue_with_mixed_currency_exposure_withholds_premium -- --exact`
- `cargo test -p chio-cli --test receipt_query test_underwriting_decision_list_partitions_premium_totals_by_currency -- --exact`
- `cargo test -p chio-cli --test receipt_query test_underwriting_decision_links_failed_settlement_evidence -- --exact`
- `cargo test -p chio-cli --test receipt_query test_underwriting_simulation_report_surfaces -- --exact`
- `cargo test -p chio-core credit -- --nocapture`
- `cargo test -p chio-cli --test receipt_query test_credit_backtest_report_surfaces_drift_and_failure_modes -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query test_provider_risk_package_export_surfaces -- --exact --nocapture`
- `cargo test -p chio-core capital_book -- --nocapture`
- `cargo test -p chio-core capital_execution_instruction -- --nocapture`
- `cargo test -p chio-core capital_allocation_decision -- --nocapture`
- `cargo test -p chio-cli --test receipt_query capital_book -- --nocapture`
- `cargo test -p chio-cli --test receipt_query capital_instruction -- --nocapture`
- `cargo test -p chio-cli --test receipt_query test_capital_allocation -- --nocapture`
- `cargo test -p chio-cli --test receipt_query credit_bonded_execution -- --nocapture`
- `cargo test -p chio-cli --test receipt_query liability_provider -- --nocapture`
- `cargo test -p chio-cli --test receipt_query liability_market -- --nocapture`
- `cargo test -p chio-cli --test receipt_query liability_claim -- --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-cli --test receipt_query test_liability_claim_workflow_surfaces -- --exact --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-cli --test receipt_query test_liability_claim_rejects_oversized_claims_and_invalid_disputes -- --exact --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-credentials portable_reputation -- --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-cli --test local_reputation trust_service_portable_reputation_issue_and_evaluate_respects_local_weighting -- --exact --nocapture`
- `cargo test -p chio-cli --test passport passport_public_holder_transport_fetch_submit_and_fail_closed_on_replay -- --nocapture`
- `cargo test -p chio-cli --test passport passport_external_http_issuance_and_verifier_roundtrip_is_interop_qualified -- --nocapture`
- `cargo test -p chio-cli --test passport passport_oid4vp_request_uri_and_direct_post_roundtrip_is_replay_safe -- --nocapture`
- `cargo test -p chio-cli --test passport passport_oid4vp_cli_holder_adapter_supports_same_device_and_cross_device_launches -- --nocapture`
- `cargo test -p chio-cli --test passport passport_portable_sd_jwt_metadata_and_issuance_roundtrip -- --nocapture`
- `cargo test -p chio-cli --test passport passport_portable_sd_jwt_status_reference_projects_active_superseded_and_revoked_states -- --nocapture`
- `cargo test -p chio-cli --test passport passport_issuance_metadata_rejects_public_status_distribution_without_cache_ttl -- --nocapture`
- `cargo test -p chio-cli --test passport passport_portable_lifecycle_stale_state_fails_closed_on_offer_and_public_resolution -- --nocapture`
- `cargo test -p chio-cli --test passport passport_portable_metadata_endpoints_require_signing_key_configuration -- --nocapture`
- `CARGO_TARGET_DIR=target/identity-check CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check -p chio-core --lib`
- `CARGO_TARGET_DIR=target/identity-test CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p chio-core --lib identity_network -- --nocapture`
- `for f in docs/standards/CHIO_PUBLIC_IDENTITY_PROFILE.json docs/standards/CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_EXAMPLE.json docs/standards/CHIO_PUBLIC_WALLET_ROUTING_EXAMPLE.json docs/standards/CHIO_PUBLIC_IDENTITY_QUALIFICATION_MATRIX.json; do jq empty "$f"; done`
- `cargo test -p chio-cli --test mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange -- --exact --nocapture`
- `cargo test -p chio-cli --test mcp_auth_server mcp_serve_http_local_auth_server_rejects_stale_or_mismatched_identity_assertion -- --exact --nocapture`
- `cargo test -p chio-cli --test mcp_auth_server mcp_serve_http_local_auth_server_enforces_dpop_sender_constraint_across_token_and_mcp_runtime -- --exact --nocapture --test-threads=1`
- `cargo test -p chio-cli --test mcp_auth_server mcp_serve_http_local_auth_server_enforces_mtls_and_attestation_bound_sender_constraint -- --exact --nocapture --test-threads=1`
- `cargo test -p chio-cli --test mcp_auth_server mcp_serve_http_local_auth_server_rejects_attestation_bound_sender_without_dpop_or_mtls -- --exact --nocapture --test-threads=1`
- `cargo test -p chio-core appraisal -- --nocapture`
- `cargo test -p chio-core runtime_attestation_trust_policy -- --nocapture`
- `cargo test -p chio-policy runtime_assurance_validation -- --nocapture`
- `cargo test -p chio-control-plane azure_maa -- --nocapture`
- `cargo test -p chio-control-plane aws_nitro -- --nocapture`
- `cargo test -p chio-control-plane google_confidential_vm -- --nocapture`
- `cargo test -p chio-control-plane runtime_assurance_policy -- --nocapture`
- `cargo test -p chio-kernel governed_request_denies_untrusted_attestation_when_trust_policy_is_configured -- --nocapture`
- `cargo test -p chio-kernel governed_monetary_allow_rebinds_trusted_attestation_to_verified -- --nocapture`
- `cargo test -p chio-kernel governed_monetary_allow_rebinds_google_attestation_to_verified -- --nocapture`
- `cargo test -p chio-cli --test receipt_query test_runtime_attestation_appraisal_export_surfaces -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query test_runtime_attestation_appraisal_result_import_export_surfaces -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query test_runtime_attestation_appraisal_result_qualification_covers_mixed_providers_and_fail_closed_imports -- --exact --nocapture`
- `cargo test -p chio-credentials signed_public_ -- --nocapture`
- `cargo test -p chio-cli --test passport public_discovery -- --nocapture`
- `cargo test -p chio-cli --test certify certify_check_emits_signed_pass_artifact_and_report -- --exact --nocapture`
- `cargo test -p chio-cli --test certify certify_registry_discover_fails_closed_on_stale_and_mismatched_public_metadata -- --exact --nocapture`
- `cargo test -p chio-cli --test certify certify_marketplace_search_transparency_consume_and_dispute_work -- --exact --nocapture`

Primary release artifacts:

- `target/release-qualification/conformance/mcp-core/report.md`
- `target/release-qualification/conformance/tasks/report.md`
- `target/release-qualification/conformance/auth/report.md`
- `target/release-qualification/conformance/notifications/report.md`
- `target/release-qualification/conformance/nested-callbacks/report.md`
- `target/release-qualification/browser-kernel/report.md`
- `target/release-qualification/browser-kernel/summary.json`
- `target/release-qualification/logs/trust-cluster-repeat-run.log`
- `target/release-qualification/mobile-kernel/report.md`
- `target/release-qualification/mobile-kernel/summary.json`
- `target/release-qualification/trust-control/qualification-report.md`
- `target/release-qualification/web3-runtime/artifact-manifest.json`
- `target/release-qualification/web3-runtime/logs/qualification.log`
- `target/release-qualification/web3-runtime/logs/e2e-qualification.log`
- `target/release-qualification/web3-runtime/logs/promotion-qualification.log`
- `target/release-qualification/web3-runtime/e2e/partner-qualification.json`
- `target/release-qualification/web3-runtime/e2e/scenarios/reorg-recovery.json`
- `target/release-qualification/web3-runtime/promotion/promotion-qualification.json`
- `target/release-qualification/web3-runtime/promotion/run-a/promotion-report.json`
- `target/release-qualification/web3-runtime/promotion/negative-rollback/rollback-plan.json`
- `target/release-qualification/web3-runtime/contracts/reports/local-devnet-qualification.json`
- `target/release-qualification/web3-runtime/contracts/reports/CHIO_WEB3_CONTRACT_SECURITY_REVIEW.md`
- `target/release-qualification/web3-runtime/contracts/reports/CHIO_WEB3_CONTRACT_GAS_AND_STORAGE.md`

Primary release docs:

- [RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md)
- [QUALIFICATION.md](QUALIFICATION.md)
- [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md)
- [OBSERVABILITY.md](OBSERVABILITY.md)
- [GA_CHECKLIST.md](GA_CHECKLIST.md)
- [PARTNER_PROOF.md](PARTNER_PROOF.md)
- [CHIO_WEB3_READINESS_AUDIT.md](CHIO_WEB3_READINESS_AUDIT.md)
- [CHIO_WEB3_PARTNER_PROOF.md](CHIO_WEB3_PARTNER_PROOF.md)
- [ECONOMIC_INTEROP_GUIDE.md](../reference/ECONOMIC_INTEROP_GUIDE.md)
- [CREDENTIAL_INTEROP_GUIDE.md](../reference/CREDENTIAL_INTEROP_GUIDE.md)
- [WORKLOAD_IDENTITY_RUNBOOK.md](../reference/WORKLOAD_IDENTITY_RUNBOOK.md)
- [RISK_REGISTER.md](RISK_REGISTER.md)
- [CHIO_RECEIPTS_PROFILE.md](../standards/CHIO_RECEIPTS_PROFILE.md)
- [CHIO_PORTABLE_TRUST_PROFILE.md](../standards/CHIO_PORTABLE_TRUST_PROFILE.md)
- [README.md](../../README.md)
- [PROTOCOL.md](../../spec/PROTOCOL.md)

## Findings Closure

Internal evidence inventory (not external closure claims):

| Former gap | Release disposition |
| --- | --- |
| release-input drift and generated artifacts in source control | closed through package guards, ignore rules, and release-input checks |
| ad hoc qualification and packaging confidence | closed through one scripted release lane plus focused dashboard and SDK package checks |
| operator deployment and upgrade tribal knowledge | closed through the runbook and repeatable smoke checks |
| opaque production diagnostics | closed for the supported surface through trust-control and hosted-edge health/admin contracts plus operator reporting |
| protocol doc drift | closed by aligning `spec/PROTOCOL.md` and normative companions to the current v1-only pre-release contract |
| release/standards ambiguity | closed through standards profiles, GA checklist, and explicit risk register |
| economic interop legibility for IAM/finance/partner reviewers | closed for the shipped local surface through the authorization-context report, metered-billing reconciliation report, and focused interop guide |
| enterprise IAM review still depended on Chio-specific explanation rather than machine-readable profile artifacts and end-to-end receipt trace packs | closed for the shipped local surface through authorization-profile metadata, authorization-review-pack exports, fail-closed assurance and call-chain projection validation, and focused qualification coverage |
| underwriting decisioning legibility and operator what-if inspection | closed for the shipped local surface through deterministic decision reports, signed lifecycle artifacts, appeal handling, and non-mutating simulation |
| post-audit underwriting contract defects on fail-closed issue behavior, appeal invariants, evidence linkage, and currency truth | closed through the fix sweep that tightened trust-control error propagation, rejected contradictory appeal resolution, withheld mixed-currency premium amounts, partitioned premium totals by currency, and added regression coverage |
| portable credential interop remained a standards-alignment claim without one concrete external-client proof | closed for the shipped local surface through the raw-HTTP issuer/challenge qualification lane and focused credential interop guide |
| portable credential lifecycle, type metadata, and verifier-facing status semantics remained only partially explicit | closed for the shipped local surface through projected SD-JWT VC metadata, portable issuer `JWKS`, TTL-backed lifecycle distribution and public resolution, explicit `stale` fail-closed semantics, and focused qualification coverage over `active`, `stale`, `superseded`, and `revoked` states |
| verifier portability still lacked one supported OID4VP bridge and public verifier trust bootstrap | closed for the shipped local surface through signed `request_uri` requests, same-device and cross-device launch artifacts, Chio verifier metadata, trusted-key `JWKS` rotation semantics, and focused passport regressions |
| workload identity and verifier-backed attestation trust remained normalized evidence only, without explicit rebinding and operator failure guidance | closed for the shipped local surface through SPIFFE workload mapping, the Azure MAA bridge, trusted-verifier rebinding policy, fail-closed governed-runtime enforcement, and the workload-identity runbook |
| the verifier boundary remained Azure-shaped and lacked one signed operator-facing appraisal artifact | closed for the shipped local surface through the canonical appraisal contract, Azure/AWS Nitro/Google/enterprise-verifier bridges, policy-aware rebinding, and the signed runtime-attestation appraisal export surface |
| portable appraisal-result interop remained underqualified across provider families and negative-path import behavior | closed for the shipped local surface through signed appraisal-result import/export, explicit local import-policy mapping, mixed-provider Azure/AWS Nitro/Google/enterprise-verifier qualification, and fail-closed stale, unsupported-family, and contradictory-claim regressions |
| assurance-aware auth and economic policy still lacked explicit runtime provenance narrowing | closed for the shipped local surface through transaction-context projection of runtime-assurance schema and verifier family, fail-closed export on incomplete assurance projection, and manual facility review when verifier-family provenance is heterogeneous |
| verifier identity, signer material, and reference-value distribution were still local-only and under-specified | closed for the shipped local surface through signed verifier descriptors, signed reference-value sets, one versioned trust-bundle contract, and fail-closed rejection of stale, ambiguous, or contract-mismatched bundle contents |
| public issuer or verifier discovery still depended on implicit metadata fetch and lacked explicit transparency plus local-import guardrails | closed for the shipped local surface through signed issuer-discovery and verifier-discovery documents, one signed transparency snapshot, explicit informational-only/manual-review import guardrails, and fail-closed rejection of missing authority material or incomplete discovery objects |
| certification discovery remained operator-scoped and under-documented relative to the research marketplace direction | closed for the shipped local surface through versioned evidence profiles, public publisher metadata, public search and transparency feeds, explicit dispute semantics, and policy-bound consume flows with stale or mismatched metadata failing closed |
| open registry semantics still stopped at one local publication view without explicit replication, freshness, and ranking behavior | closed for the shipped local surface through origin/mirror/indexer publisher roles, freshness windows, deterministic search-policy metadata, replica-collapse rules, and fail-closed stale or divergent aggregation semantics |
| open registry still lacked a portable governance and sanction layer over listings and local trust activation | closed for the shipped local surface through signed governance-charter and governance-case artifacts, explicit namespace/listing/operator scope, cross-operator escalation counterparties, activation-bound freeze or sanction evaluation, and fail-closed rejection of expired, unsupported, or unauthorized governance actions |
| underwriting still stopped short of replayable credit qualification and one provider-facing capital review package | closed for the shipped local surface through signed exposure and scorecard artifacts, bounded facility policy, deterministic backtests, and a signed provider-risk package with honest recent-loss history |
| Chio still stopped short of an honest live-capital execution claim with explicit regulated-role boundaries | closed for the shipped local surface through the signed capital book, custody-neutral capital instructions, simulation-first capital-allocation artifacts, the combined qualification matrix, and explicit release/partner/protocol language that keeps Chio from implicitly claiming regulated-custodian or insurer-of-record status |
| reserve control still stopped short of executable authority, reconciliation, and appeal semantics | closed for the shipped local surface through signed reserve-release and reserve-slash lifecycle artifacts, explicit execution-window and custody-rail validation, observed-execution reconciliation, machine-readable appeal state, and focused loss-lifecycle regression coverage |
| Chio still stopped short of a bounded liability-market proof over provider policy, delegated pricing authority, quote/bind, and claims workflow state | closed for the shipped local surface through curated provider-registry artifacts, signed delegated pricing-authority and auto-bind artifacts, provider-neutral quote/bind state, immutable claim/dispute/adjudication artifacts, focused marketplace qualification coverage, and updated partner/release boundary docs |
| the endgame market claim still lacked adversarial proof across hostile mirrors, divergent registry views, imported reputation, and forged remote activation authority | closed for the shipped local surface through adversarial multi-operator qualification that preserves visibility without trust, rejects invalid mirrored listing signatures, blocks divergent freshness from admission, keeps imported reputation locally weighted, and fails closed when governance or market-penalty artifacts rely on non-local activation authority |
| the shipped identity surface still stopped short of broader DID/VC compatibility and public wallet-routing semantics | closed for the shipped local surface through one bounded public identity-profile, wallet-directory, routing-manifest, and qualification-matrix family that preserves `did:chio` provenance, verifier-bound routing, replay anchors, and fail-closed mismatch handling |
| the public release, partner, protocol, and standards boundary still stopped short of the strongest honest maximal-endgame claim | closed for the shipped local surface through the final boundary rewrite across release candidate, qualification, partner proof, protocol, and standards docs with residual non-goals kept explicit |

## Formal/Spec Closure Inventory

This section records the accepted closure boundary for the formal/spec slice.
It is not the final GA decision artifact; it defines what public claims the
next release is allowed to rely on.

| Gap | Launch disposition | Evidence |
| --- | --- | --- |
| executable spec drift versus current `ChioScope` subset behavior | closed | `formal/diff-tests`, `cargo test -p chio-formal-diff-tests` |
| protocol lacked an explicit distinction between formal, empirical, and qualification evidence | closed | `spec/PROTOCOL.md`, this audit, `docs/release/QUALIFICATION.md` |
| Lean root and comments implied stronger proof closure than the repo actually ships | closed | `formal/lean4/Chio/Chio.lean`, `formal/lean4/Chio/Chio/Spec/Properties.lean` |
| standalone Lean proof completion for every current Chio surface | consciously deferred | `formal/lean4/Chio/Chio/Proofs/Monotonicity.lean` covers the bounded model only and is not a Rust refinement proof |
| theorem-prover coverage for governed approvals, payment rails, federation maturity, and runtime assurance | consciously deferred | public claims rely on runtime tests, integration tests, and qualification rather than Lean proofs |

### Accepted Release Evidence Boundary

For the current v1-only pre-release candidate, Chio has local evidence for:

- executable reference/spec alignment for scope attenuation semantics
- empirical verification for fail-closed kernel and trust-control behavior
- conformance and release-qualification evidence for mediated protocol and
  operator flows

Chio does not currently claim:

- complete theorem-prover coverage for every protocol property
- that standalone Lean proof files are part of the release gate while they
  remain outside the root import surface or contain `sorry`

## Current Pre-Release Decision Contract

The current v1-only pre-release decision is explicit rather than implied:

| Gate class | Requirement | Status |
| --- | --- | --- |
| local qualification | `./scripts/ci-workspace.sh`, `./scripts/check-formal-proofs.sh`, `./scripts/check-portable-kernel.sh`, `./scripts/check-sdk-parity.sh`, `./scripts/check-web3-contract-parity.sh`, `./scripts/qualify-release.sh`, `./scripts/qualify-portable-browser.sh`, and `./scripts/qualify-mobile-kernel.sh` green, with the bounded web3 runtime lanes green locally | historical local evidence |
| release materials | release, partner, operational, and standards-facing docs updated to the current Chio surface | pre-release evidence |
| hosted publication | hosted `CI` and `Release Qualification` observed green on the candidate commit, including the staged runtime, `e2e`, `ops`, and promotion bundles under `target/release-qualification/web3-runtime/` | pending external observation |

The resulting decision is:

- local evidence supports continued pre-release evaluation for the current Chio candidate
- external release hold until hosted workflow evidence is observed

## Remaining Non-Goals

These are intentionally not blockers for the current v1-only pre-release candidate:

- multi-region or consensus trust replication
- permissionless or auto-trusting certification marketplace semantics
- portable reputation as a universal trust oracle or automatic cross-issuer
  trust score
- permissionless mirror/indexer publication as automatic trust, sanction, or
  market-penalty authority
- permissionless or ambient open-market penalties, slashing, or trust
  widening outside Chio's documented fee-schedule, trust-activation, and
  governance-case surfaces
- automatic SCIM lifecycle management
- synthetic cross-issuer passport trust aggregation
- public identity, issuer, verifier, or wallet discovery that auto-admits
  visible trust material
- first-principles theorem-prover completion for concrete crypto, OS, storage,
  transport, subprocess, hosted-registry, chain, or settlement implementations
- performance-first rewrite work

## Procedural Note

This audit was produced from the local development environment.

It does not claim that GitHub Actions has already run on the updated
workflows. The repository is ready for that hosted verification, and the
explicit release decision above keeps external release publication on hold until
those workflow results are observed.
