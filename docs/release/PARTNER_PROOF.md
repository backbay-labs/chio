# Chio Partner Proof Package

**Prepared:** 2026-04-02
**Surface:** current v1-only pre-release Chio candidate
**Role:** reviewer-facing evidence package, not the authoritative release-go
record

This document is the compact partner/security-review package for Chio's current
pre-release candidate. It is derived from the same local evidence set used by
[RELEASE_AUDIT.md](RELEASE_AUDIT.md) and
[QUALIFICATION.md](QUALIFICATION.md).

The web3-runtime ladder now also has a focused reviewer pack in
[CHIO_WEB3_PARTNER_PROOF.md](CHIO_WEB3_PARTNER_PROOF.md). That document should
be used for contract/oracle/anchor/settlement/interop/ops review rather than
forcing partners to infer the web3 boundary from the broader repository pack.

## Current Decision

Local technical evidence qualifies the current Chio candidate for **internal
and partner technical review**. It is not a public GA or production-ship
decision. External tag/publication remains **on hold** until hosted `CI` and
`Release Qualification` workflow results are observed on the candidate commit.

For the shipped web3-runtime stack specifically, external deployment and
publication remain on hold until the hosted web3 bundle is observed on the
candidate commit and the operator approves the exact reviewed manifest,
target-chain factory, and rollout environment explicitly.

## What Partners Can Rely On

- capability-scoped mediation, fail-closed guard evaluation, and signed
  receipts
- truthful governed approval, payment, settlement, and reconciliation
  semantics
- derived authorization-context reports that map governed receipts into
  standards-legible authorization details and delegated transaction context
- machine-readable authorization-profile metadata and reviewer-pack exports
  that tie the enterprise IAM projection back to typed governed transaction
  metadata and full signed receipt truth
- portable-trust artifacts built on `did:chio`, Chio-primary passport/verifier
  schemas, certification discovery, and conservative imported-trust handling
- governed public certification marketplace metadata, search, transparency,
  dispute, and consume surfaces that preserve operator provenance and keep
  listing visibility separate from runtime admission
- one signed operator-owned namespace plus one generic listing projection over
  current tool-server, issuer, verifier, and liability-provider surfaces, with
  explicit origin/mirror/indexer publisher roles, deterministic ranking and
  freshness metadata, and fail-closed stale/divergent handling while still
  keeping visibility separate from trust activation or admission
- one signed local trust-activation artifact over those generic listings, with
  explicit `public_untrusted`, `reviewable`, `bond_backed`, and `role_gated`
  admission classes, bounded eligibility semantics, expiry and review state,
  and fail-closed evaluation so visibility still does not imply runtime trust
- one signed governance-charter artifact and one signed governance-case
  family over that same generic registry, with explicit namespace/listing
  scope, escalation counterparties, appeal linkage, and fail-closed
  evaluation for dispute, freeze, sanction, and appeal actions
- one signed portable reputation-summary artifact plus one signed portable
  negative-event artifact with explicit issuer, subject, evidence, and
  freshness state, and one local weighting evaluation lane that rejects
  stale, future, duplicate, blocked, disallowed-issuer, or contradictory
  imported reputation instead of treating it as canonical trust
- one signed open-market fee-schedule artifact over explicit namespace,
  actor-kind, publisher-operator, and admission-class scope plus publication,
  dispute, and market-participation fees and bond requirements, and one
  signed market-penalty artifact over matched listing, trust activation,
  governance sanction or appeal case, abuse class, and bond class, with
  fail-closed evaluation for stale authority, scope mismatch, unsupported or
  non-slashable bond requirements, currency mismatch, oversized penalties, or
  invalid reversal linkage
- one locally qualified adversarial multi-operator open-market proof where
  invalid mirrored listing signatures remain visible but untrusted, divergent
  replica freshness blocks admission, imported portable reputation stays
  locally weighted, and governance or market-penalty evaluation rejects trust
  activations that were not issued by the governing local operator
- one qualified portable credential family over OID4VCI-compatible issuer
  metadata, with a native `AgentPassport` lane, projected
  `application/dc+sd-jwt` and `jwt_vc_json` lanes, portable issuer `JWKS`,
  portable type metadata, and read-only TTL-backed lifecycle distribution or
  public resolution with explicit fail-closed `stale` state
- one qualified verifier and holder path over that portable surface, with one
  transport-neutral wallet exchange descriptor and canonical transaction
  state, one optional verifier-scoped identity assertion continuity lane,
  same-device and cross-device launch artifacts, public challenge fetch and
  response submit routes, and one bounded hosted sender-constrained
  continuation contract over DPoP, mTLS thumbprint binding, and one
  attestation-confirmation profile
- one bounded public identity profile, one verifier-bound wallet-directory
  entry, one replay-safe wallet-routing manifest, and one identity-interop
  qualification matrix over `did:chio` plus explicit `did:web`, `did:key`, and
  `did:jwk` compatibility inputs, projected passport profile families, and
  fail-closed subject or issuer mismatch handling
- one official non-proxy web3 contract family with fixed deployed bytecode
  for the root registry, escrow, bond vault, and price resolver, plus explicit
  governed surfaces for identity records, price feeds, token allowlists, pause
  controls, delegates, and operator records
- one bounded web3 operations contract over runtime reports, indexer
  drift/replay visibility, emergency modes, promotion policy, readiness audit,
  and one dedicated web3 partner-proof package with remaining external
  dependencies kept explicit
- signed insurer-facing behavioral-feed exports derived from canonical receipt,
  settlement, and reputation state
- signed underwriting policy inputs, deterministic underwriting decisions,
  persisted signed decision artifacts, and explicit appeal lifecycle records
- non-mutating underwriting simulation that compares baseline and proposed
  policy outcomes over the same canonical evidence
- signed exposure-ledger and credit-scorecard exports, bounded facility-policy
  evaluation plus signed facility artifacts, deterministic historical credit
  backtests, and one signed provider-facing risk package for external capital
  review
- one signed live capital-book and source-of-funds report, one custody-neutral
  capital-instruction artifact, and one simulation-first capital-allocation
  decision lane with explicit authority-chain and execution-window truth
- executable reserve release and reserve slash lifecycle artifacts over one
  reserve-book source with explicit authority-chain, execution-window,
  reconciliation, and appeal-window truth
- one bounded bonded-execution simulation lane with explicit operator
  kill-switch and clamp-down semantics over signed bond and loss-lifecycle
  state
- one curated liability-provider registry with fail-closed jurisdiction,
  coverage-class, currency, and evidence-requirement resolution before quote
  or claim state is accepted
- one provider-neutral liability quote, placement, and bound-coverage lane
  over a signed provider-risk package
- immutable liability claim-package, provider-response, dispute, and
  adjudication artifacts linked back to bound coverage, exposure, bond, loss,
  and receipt evidence
- one locally qualified bounded marketplace proof across provider resolution,
  quote-and-bind, and claim/dispute lifecycle evidence
- explicit runtime-assurance tiers that can constrain issuance and later
  governed execution
- one typed SPIFFE-derived workload-identity mapping surface plus one
  canonical multi-cloud appraisal contract, Azure/AWS Nitro/Google plus one
  bounded enterprise-verifier bridge, explicit trusted-verifier rebinding,
  fail-closed stale or unmatched evidence handling, one signed appraisal
  export artifact, and one signed appraisal-result import/export lane with
  explicit local issuer, signer, freshness, verifier-family, and portable-
  claim policy mapping
- one signed verifier-descriptor, signed reference-value, and signed
  trust-bundle distribution layer over that same bounded appraisal contract,
  with fail-closed stale, ambiguous, and contract-mismatch handling
- one standards-facing authorization-context export that now carries runtime-
  assurance schema and verifier-family provenance, plus one bounded economic
  rule that downgrades mixed-family runtime provenance to manual review
- checked-in conformance scenarios plus live JS, Python, and Go peer
  qualification

## Core Evidence Set

- `./scripts/qualify-release.sh`
- `./scripts/check-web3-contract-parity.sh`
- `./scripts/qualify-web3-runtime.sh`
- `cargo test -p chio-formal-diff-tests`
- `cargo test -p chio-core underwriting -- --nocapture`
- `cargo test -p chio-cli --test receipt_query credit_bonded_execution -- --nocapture`
- `cargo test -p chio-cli --test passport passport_public_holder_transport_fetch_submit_and_fail_closed_on_replay -- --nocapture`
- `cargo test -p chio-cli --test passport passport_external_http_issuance_and_verifier_roundtrip_is_interop_qualified -- --nocapture`
- `cargo test -p chio-cli --test passport passport_oid4vp_request_uri_and_direct_post_roundtrip_is_replay_safe -- --nocapture`
- `cargo test -p chio-cli --test passport passport_oid4vp_cli_holder_adapter_supports_same_device_and_cross_device_launches -- --nocapture`
- `cargo test -p chio-cli --test passport passport_portable_sd_jwt_metadata_and_issuance_roundtrip -- --nocapture`
- `cargo test -p chio-cli --test passport passport_portable_sd_jwt_status_reference_projects_active_superseded_and_revoked_states -- --nocapture`
- `cargo test -p chio-cli --test passport passport_issuance_metadata_rejects_public_status_distribution_without_cache_ttl -- --nocapture`
- `cargo test -p chio-cli --test passport passport_portable_lifecycle_stale_state_fails_closed_on_offer_and_public_resolution -- --nocapture`
- `cargo test -p chio-cli --test passport passport_portable_metadata_endpoints_require_signing_key_configuration -- --nocapture`
- `cargo test -p chio-cli --test mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange -- --exact --nocapture`
- `cargo test -p chio-cli --test mcp_auth_server mcp_serve_http_local_auth_server_rejects_stale_or_mismatched_identity_assertion -- --exact --nocapture`
- `cargo test -p chio-cli --test mcp_auth_server mcp_serve_http_local_auth_server_enforces_dpop_sender_constraint_across_token_and_mcp_runtime -- --exact --nocapture --test-threads=1`
- `cargo test -p chio-cli --test mcp_auth_server mcp_serve_http_local_auth_server_enforces_mtls_and_attestation_bound_sender_constraint -- --exact --nocapture --test-threads=1`
- `cargo test -p chio-cli --test mcp_auth_server mcp_serve_http_local_auth_server_rejects_attestation_bound_sender_without_dpop_or_mtls -- --exact --nocapture --test-threads=1`
- `cargo test -p chio-core appraisal -- --nocapture`
- `cargo test -p chio-core trust_bundle -- --nocapture`
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
- `cargo test -p chio-cli --test receipt_query test_authorization_context_report_and_cli -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query test_authorization_metadata_and_review_pack_surfaces -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query test_authorization_context_report_rejects_invalid_chio_oauth_profile_projection -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query test_authorization_context_report_rejects_missing_sender_binding_material -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query test_authorization_context_report_rejects_incomplete_runtime_assurance_projection -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query test_authorization_context_report_rejects_invalid_delegated_call_chain_projection -- --exact --nocapture`
- `cargo test -p chio-cli --test mcp_serve_http mcp_serve_http_serves_oauth_authorization_server_metadata_for_local_issuer -- --exact --nocapture`
- `cargo test -p chio-cli --test mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange -- --exact --nocapture`
- `cargo test -p chio-cli --test certify certify_check_emits_signed_pass_artifact_and_report -- --exact --nocapture`
- `cargo test -p chio-cli --test certify certify_registry_discover_fails_closed_on_stale_and_mismatched_public_metadata -- --exact --nocapture`
- `cargo test -p chio-cli --test certify certify_marketplace_search_transparency_consume_and_dispute_work -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query test_underwriting_decision_issue_and_list_surfaces -- --exact`
- `cargo test -p chio-cli --test receipt_query test_underwriting_appeal_and_supersession_lifecycle -- --exact`
- `cargo test -p chio-cli --test receipt_query test_underwriting_simulation_report_surfaces -- --exact`
- `cargo test -p chio-core credit -- --nocapture`
- `cargo test -p chio-cli --test receipt_query test_credit_backtest_report_surfaces_drift_and_failure_modes -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query test_provider_risk_package_export_surfaces -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query credit_loss_lifecycle -- --nocapture`
- `cargo test -p chio-cli --test receipt_query credit_bonded_execution -- --nocapture`
- `cargo test -p chio-credentials signed_public_ -- --nocapture`
- `cargo test -p chio-cli --test passport public_discovery -- --nocapture`
- `cargo test -p chio-core market -- --nocapture`
- `cargo test -p chio-cli --test receipt_query liability_provider -- --nocapture`
- `cargo test -p chio-cli --test receipt_query liability_market -- --nocapture`
- `cargo test -p chio-cli --test receipt_query liability_claim -- --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-credentials portable_reputation -- --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-cli --test local_reputation trust_service_portable_reputation_issue_and_evaluate_respects_local_weighting -- --exact --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-core --lib generic_listing_search_rejects_reports_with_invalid_listing_signatures -- --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-core --lib non_local_activation_authority -- --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p chio-cli --test certify certify_adversarial_multi_operator_open_market_preserves_visibility_without_trust -- --exact --nocapture`
- `target/release-qualification/conformance/mcp-core/report.md`
- `target/release-qualification/conformance/tasks/report.md`
- `target/release-qualification/conformance/auth/report.md`
- `target/release-qualification/conformance/notifications/report.md`
- `target/release-qualification/conformance/nested-callbacks/report.md`
- `target/release-qualification/logs/trust-cluster-repeat-run.log`
- `target/release-qualification/web3-runtime/artifact-manifest.json`
- [CHIO_WEB3_READINESS_AUDIT.md](CHIO_WEB3_READINESS_AUDIT.md)
- [CHIO_WEB3_PARTNER_PROOF.md](CHIO_WEB3_PARTNER_PROOF.md)
- [CHIO_RECEIPTS_PROFILE.md](../standards/CHIO_RECEIPTS_PROFILE.md)
- [CHIO_PORTABLE_TRUST_PROFILE.md](../standards/CHIO_PORTABLE_TRUST_PROFILE.md)
- [PROTOCOL.md](../../spec/PROTOCOL.md)
- [ECONOMIC_INTEROP_GUIDE.md](../reference/ECONOMIC_INTEROP_GUIDE.md)
- [CREDENTIAL_INTEROP_GUIDE.md](../reference/CREDENTIAL_INTEROP_GUIDE.md)
- [WORKLOAD_IDENTITY_RUNBOOK.md](../reference/WORKLOAD_IDENTITY_RUNBOOK.md)

## Explicit Non-Claims

Chio does not currently claim:

- full theorem-prover coverage for every shipped protocol property
- consensus or multi-region trust replication
- automatic SCIM lifecycle management
- synthetic cross-issuer trust aggregation
- public identity, issuer, verifier, or wallet discovery as an automatic
  trust-admission path
- that the behavioral feed itself is the underwriting model rather than a
  truthful evidence input to the separate underwriting surfaces
- that authorization-context exports are independent source-of-truth documents
  rather than derived projections from signed receipts
- generic OID4VP, DIDComm, SIOP, or permissionless public wallet-network
  compatibility beyond Chio's documented passport profile family plus bounded
  public identity-profile, wallet-directory, and routing-manifest contracts
- attestation-bound sender semantics as standalone authorization outside the
  documented paired DPoP/mTLS confirmation profile
- generic attestation-result interoperability or automatic trust in arbitrary
  cloud attestation providers beyond Chio's documented appraisal contract,
  concrete verifier bridges, signed appraisal-result import/export contract,
  and trusted-verifier plus import-policy surfaces
- one-time consume or replay-registry semantics for imported appraisal
  results beyond explicit signature and freshness validation
- permissionless or auto-trusting certification marketplace semantics
- portable reputation as a universal trust oracle or ambient trust-admission
  mechanism
- permissionless mirror/indexer publication as automatic trust, sanction, or
  market-penalty authority
- permissionless or ambient open-market penalties, slashing, or trust
  widening outside Chio's documented fee-schedule, trust-activation, and
  governance-case surfaces
- cross-network recovery clearing or insurer-network messaging beyond Chio's
  documented liability-market orchestration boundary, including its bounded
  payout-instruction, payout-receipt, settlement-instruction, and
  settlement-receipt lane
- automatic coverage binding beyond Chio's documented delegated
  pricing-authority envelope
- implicit regulated-actor status, automatic external capital dispatch,
  autonomous insurer-rate setting, or open-market capital execution beyond Chio's
  documented live capital-book, custody-neutral instruction,
  simulation-first allocation, and executable reserve-control surface

## Integration Posture

Chio is the rights-and-receipts control plane under MCP, A2A, payment rails,
portable trust, bounded public identity routing, and higher-assurance runtime
evidence. It is not positioned as a replacement transport, universal wallet
network, or standalone payment network.
