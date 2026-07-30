//! M2 exit coverage for the finding market: publish and by-id resolution
//! of the exact bytes, bounded paginated discovery, the venue-signed
//! admission transaction, the qualified-profile search marker, the real
//! marketplace bid through `bid_with_finding_admission`, participation
//! renewal, the full rejection sweep from the M2 exit definition, and the
//! evidenced-rail fault-injection legs. Requests travel through the serve
//! router wrapped with the service-wide hygiene layer so route body caps
//! bind exactly as they do at the serve site.

use super::super::super::*;
use super::build_router;

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use chio_core::canonical_json_bytes;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use chio_core::merkle::MerkleTree;
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::receipt::kinds::TrustLevel;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_core::sha256_hex;
use chio_finding::{
    compute_admission_id, compute_allocation_id, compute_authorization_id, compute_finding_id,
    compute_profile_id, compute_report_id, compute_terms_id, sign_finding, Finding,
    FindingAdmission, FindingAuthorityKeyPolicy, FindingBackingRequirement, FindingBbsIssuerPolicy,
    FindingBondBacking, FindingBondClass, FindingChallengeBondLimit,
    FindingChallengeVerifierProfile, FindingCheckpointLogPolicy, FindingClaimedVerdict,
    FindingCollateralVault, FindingDescriptor, FindingEvidenceClass, FindingFacetKind,
    FindingFacetOutcome, FindingFeeEvent, FindingFeeTerminalBinding, FindingGuaranteeClass,
    FindingMarketTerms, FindingOutcomeClass, FindingPayee, FindingPoolBinding, FindingPredicate,
    FindingReceiptRole, FindingReceiptSignerRole, FindingRecipeEnvironment, FindingRecipePhase,
    FindingRecipePhaseKind, FindingReplayRecipeInput, FindingResourceCaps,
    FindingSellerAuthorization, SignedFindingAdmission, SignedFindingBondBacking,
    SignedFindingChallengeVerifierProfile, SignedFindingMarketTerms,
    SignedFindingSellerAuthorization, SignedFindingVerifierReport, FINDING_ADMISSION_SCHEMA_V1,
    FINDING_BOND_BACKING_SCHEMA_V1, FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1,
    FINDING_MARKET_TERMS_SCHEMA_V1, FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, FINDING_SCHEMA_V1,
    FINDING_SELLER_AUTHORIZATION_SCHEMA_V1,
};
use chio_finding_verifier::{
    sign_finding_verifier_report, verify_finding_evidence, FindingBondSnapshot,
    FindingEvidenceBundle, FindingVerifierTrustRoots, NoNonceEvidence, ResolvedReceiptEvidence,
};
use chio_http_serve::{apply_server_hygiene, ServeHygieneConfig};
use chio_kernel::checkpoint::{
    build_checkpoint, build_checkpoint_transparency, build_inclusion_proof, checkpoint_log_id,
    KernelCheckpoint,
};
use chio_open_market::bidding::{
    BidMintContext, BidRequest, RequestedScope, SignedBidRequest, BID_REQUEST_SCHEMA,
};
use chio_open_market::fee_schedule::{
    build_open_market_fee_schedule_artifact, OpenMarketBondClass, OpenMarketBondRequirement,
    OpenMarketCollateralReferenceKind, OpenMarketEconomicsScope, OpenMarketFeeScheduleIssueRequest,
    SignedOpenMarketFeeSchedule,
};
use chio_open_market::finding_admission::{
    bid_with_finding_admission, verify_finding_admission, FindingAdmissionContext,
    FindingAllocationSnapshot as SeamAllocationSnapshot, FindingAllocationStatus,
    FindingConstituentExpiryBounds, FindingFeeScheduleGate,
};
use chio_open_market::fiscal_adapter::signed_fee_schedule_digest;
use chio_open_market::listing::{
    GenericListingActorKind, GenericListingArtifact, GenericListingBoundary,
    GenericListingCompatibilityReference, GenericListingFreshnessState,
    GenericListingReplicaFreshness, GenericListingStatus, GenericListingSubject,
    GenericNamespaceOwnership, GenericRegistryPublisher, GenericRegistryPublisherRole, Listing,
    ListingPricingHint, ListingSla, SignedGenericListing, SignedListingPricingHint,
    GENERIC_LISTING_ARTIFACT_SCHEMA, LISTING_PRICING_HINT_SCHEMA,
};
use chio_store_sqlite::finding_market_store::{
    finding_fee_idempotency_key, FindingActivationAttemptState, FindingAllocationState,
    FindingFeeState, SqliteFindingMarketStore,
};
use tower::ServiceExt;

type AnyError = Box<dyn std::error::Error>;
type TestResult = Result<(), AnyError>;

const SERVICE_TOKEN: &str = "service-secret";
const VENUE_ID: &str = "venue-wedge";
const LISTING_ID: &str = "listing-finding-admitted-0001";
const SERVER_ID: &str = "finding-server.seller.example";
const PUBLISHER_OPERATOR_ID: &str = "seller-operator";
const AUDIT_POOL_PRINCIPAL: &str = "pool:audit";
const AUDIT_POOL_DESTINATION: &str = "rail:venue-ledger:audit-pool";
const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ISSUED_AT: u64 = 1_700_000_000;
const WINDOW_EXPIRES_AT: u64 = 1_900_000_000;
const ADMISSION_EXPIRES_AT: u64 = 1_890_000_000;
const LONG_EPOCH_SECS: u64 = 2_592_000;
const PUBLICATION_FEE_UNITS: u64 = 5;
const PARTICIPATION_FEE_UNITS: u64 = 3;
const STAKE_UNITS: u64 = 50;
const EXPOSURE_UNITS: u64 = 450;
const LOCKED_UNITS: u64 = 500;
const REQUIREMENT_UNITS: u64 = 5_000;

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn hex64(fill: char) -> String {
    fill.to_string().repeat(64)
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn digest_of<T: serde::Serialize>(value: &T) -> Result<String, AnyError> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

fn canonical_string<T: serde::Serialize>(value: &T) -> Result<String, AnyError> {
    Ok(String::from_utf8(canonical_json_bytes(value)?)?)
}

fn missing(context: &'static str) -> AnyError {
    Box::new(std::io::Error::other(context))
}

fn authority_pin(seed: u8, label: &str) -> FindingAuthorityPin {
    FindingAuthorityPin {
        authority_id: format!("authority-{label}"),
        key_hex: keypair(seed).public_key().to_hex(),
        key_epoch: 1,
        valid_from: ISSUED_AT,
        valid_until: WINDOW_EXPIRES_AT,
        revocation_status_ref: "revocations/finding-market".to_string(),
    }
}

fn listing_authority_pin() -> FindingAuthorityPin {
    let mut pin = authority_pin(24, "listing");
    pin.authority_id = PUBLISHER_OPERATOR_ID.to_string();
    pin
}

fn key_policy(seed: u8, label: &str) -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: format!("authority-{label}"),
        key: keypair(seed).public_key(),
        key_epoch: 1,
        valid_from: ISSUED_AT,
        valid_until: WINDOW_EXPIRES_AT,
        rotation_policy_ref: "rotation-policy-v1".to_string(),
        revocation_status_ref: "revocations/finding-market".to_string(),
    }
}

fn audit_pool_binding() -> FindingPoolBinding {
    FindingPoolBinding {
        principal_id: AUDIT_POOL_PRINCIPAL.to_string(),
        rail_destination: AUDIT_POOL_DESTINATION.to_string(),
        currency: "USD".to_string(),
        authority_epoch: 1,
    }
}

fn market_config() -> FindingMarketConfig {
    FindingMarketConfig {
        venue_id: VENUE_ID.to_string(),
        venue: authority_pin(6, "venue"),
        listing: listing_authority_pin(),
        governance_root: authority_pin(1, "governance"),
        verifier_report: authority_pin(15, "verifier-report"),
        collateral: authority_pin(4, "collateral"),
        purchase: authority_pin(16, "purchase"),
        failed_delivery: authority_pin(17, "failed-delivery"),
        challenge_evaluator: authority_pin(31, "challenge-evaluator"),
        venue_finalization: authority_pin(32, "venue-finalization"),
        market_penalty: authority_pin(33, "market-penalty"),
        settlement_observer: authority_pin(34, "settlement-observer"),
        audit_authority: authority_pin(35, "audit-authority"),
        audit_pool: FindingPoolPin {
            principal_id: AUDIT_POOL_PRINCIPAL.to_string(),
            rail_destination: AUDIT_POOL_DESTINATION.to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        challenge_administration_pool: FindingPoolPin {
            principal_id: "pool:challenge-admin".to_string(),
            rail_destination: "rail:venue-ledger:challenge-admin".to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        community_fund_destination: "rail:venue-ledger:community-fund".to_string(),
        status_feed_operator_ref: "status-feed/venue-wedge".to_string(),
        fee_schedule_operator_keys: vec![keypair(24).public_key().to_hex()],
    }
}

/// Rail observer that always refuses to settle, driving the
/// crash-before-observation activation leg.
struct FailingRail;

impl FindingRailObserver for FailingRail {
    fn dispatch(
        &self,
        _instruction: &FindingRailInstruction,
    ) -> Result<FindingRailObservation, String> {
        Err("injected rail outage".to_string())
    }
}

fn market_state(
    joint: Arc<SqliteAuthorityStore>,
    config: FindingMarketConfig,
    rail: Arc<dyn FindingRailObserver>,
) -> TrustServiceState {
    let config = TrustServiceConfig {
        listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        service_token: SERVICE_TOKEN.to_string(),
        tenant_read_tokens: std::collections::BTreeMap::new(),
        receipt_db_path: None,
        revocation_db_path: None,
        authority_seed_path: None,
        authority_db_path: None,
        budget_db_path: None,
        joint_authority_db_path: None,
        fiscal_runtime: None,
        enterprise_providers_file: None,
        federation_policies_file: None,
        scim_lifecycle_file: None,
        verifier_policies_file: None,
        verifier_challenge_db_path: None,
        passport_statuses_file: None,
        passport_issuance_offers_file: None,
        certification_registry_file: None,
        certification_discovery_file: None,
        issuance_policy: None,
        runtime_assurance_policy: None,
        advertise_url: None,
        allow_local_peer_urls: true,
        certification_public_metadata_ttl_seconds: 300,
        peer_urls: Vec::new(),
        cluster_sync_interval: std::time::Duration::from_millis(25),
        roster_policy: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        finding_market: Some(config),
    };
    TrustServiceState {
        config,
        joint_authority_store: Some(joint),
        fiscal_runtime: None,
        budget_store: None,
        revocation_store: None,
        enterprise_provider_registry: None,
        verifier_policy_registry: None,
        federation_admission_rate_limiter: Arc::new(std::sync::Mutex::new(
            FederationAdmissionRateLimiter::default(),
        )),
        cluster: None,
        cluster_progress: None,
        finding_rail: Some(rail),
        finding_purchase_executor: None,
    }
}

fn secure_directory(path: &std::path::Path) -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn hygiene() -> ServeHygieneConfig {
    // Mirror the service-wide 1 MiB body cap the trust-control serve site
    // applies around the router.
    ServeHygieneConfig {
        max_body_bytes: Some(1024 * 1024),
        request_timeout: None,
        ..ServeHygieneConfig::default()
    }
}

async fn send(
    state: &TrustServiceState,
    request: Request<Body>,
) -> Result<(StatusCode, Vec<u8>), AnyError> {
    let router = apply_server_hygiene(build_router(state.clone()), &hygiene());
    let response = router.oneshot(request).await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    Ok((status, bytes.to_vec()))
}

fn authed_post(uri: &str, body: impl Into<Body>) -> Result<Request<Body>, AnyError> {
    Ok(Request::builder()
        .method("POST")
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {SERVICE_TOKEN}"))
        .header("content-type", "application/json")
        .body(body.into())?)
}

fn public_get(uri: &str) -> Result<Request<Body>, AnyError> {
    Ok(Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())?)
}

fn json_body(bytes: &[u8]) -> Result<serde_json::Value, AnyError> {
    Ok(serde_json::from_slice(bytes)?)
}

/// One evidence receipt signed by the admitted kernel key.
fn receipt(kernel: &Keypair, index: u32) -> Result<ChioReceipt, AnyError> {
    let body = ChioReceiptBody {
        id: String::new(),
        timestamp: 1_750_000_000 + u64::from(index),
        capability_id: format!("cap-evidence-{index}"),
        tool_server: SERVER_ID.to_string(),
        tool_name: "finding.produce".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({ "step": index }))?,
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: HEX64.to_string(),
        policy_hash: "policy-wedge".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: kernel.public_key(),
        bbs_projection_version: None,
    };
    Ok(ChioReceipt::sign(body, kernel)?)
}

fn resource_caps() -> FindingResourceCaps {
    FindingResourceCaps {
        max_recipe_bytes: 262_144,
        max_evidence_receipts: 64,
        max_runtime_secs: 900,
        max_memory_bytes: 2_147_483_648,
    }
}

fn recipe_environment(runtime_image_sha256: &str) -> FindingRecipeEnvironment {
    FindingRecipeEnvironment {
        runtime_image_sha256: runtime_image_sha256.to_string(),
        platform: "linux/amd64".to_string(),
        network_policy: "deny_all".to_string(),
        clock_policy: "fixed:1700000000".to_string(),
        randomness_policy: "seed:42".to_string(),
        locale: "C".to_string(),
        timezone: "UTC".to_string(),
    }
}

struct RecipeDependencies {
    blobs: Vec<Vec<u8>>,
    baseline_input_sha256: String,
    candidate_input_sha256: String,
    parameters_sha256: String,
    pre_run_template_sha256: String,
    runner_manifest_sha256: String,
    runtime_image_sha256: String,
}

fn recipe_dependencies() -> RecipeDependencies {
    let blobs = vec![
        b"baseline input bundle".to_vec(),
        b"candidate input bundle".to_vec(),
        b"canonical parameter bundle".to_vec(),
        b"cycle-free pre-run template".to_vec(),
        b"pinned runner manifest".to_vec(),
        b"immutable runtime image".to_vec(),
    ];
    RecipeDependencies {
        baseline_input_sha256: sha256_hex(&blobs[0]),
        candidate_input_sha256: sha256_hex(&blobs[1]),
        parameters_sha256: sha256_hex(&blobs[2]),
        pre_run_template_sha256: sha256_hex(&blobs[3]),
        runner_manifest_sha256: sha256_hex(&blobs[4]),
        runtime_image_sha256: sha256_hex(&blobs[5]),
        blobs,
    }
}

fn build_recipe(
    profile_envelope_sha256: &str,
    dependencies: &RecipeDependencies,
) -> FindingReplayRecipeInput {
    FindingReplayRecipeInput {
        schema: FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1.to_string(),
        decision_rule_ref: "decision/replay-v1".to_string(),
        verifier_profile_envelope_sha256: profile_envelope_sha256.to_string(),
        context_sha256: HEX64.to_string(),
        payload_sha256: HEX64.to_string(),
        runner_server: SERVER_ID.to_string(),
        runner_tool: "finding.replay".to_string(),
        runner_manifest_sha256: dependencies.runner_manifest_sha256.clone(),
        phases: vec![
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Baseline,
                input_bundle_sha256: dependencies.baseline_input_sha256.clone(),
                payload_application: "not_applied".to_string(),
            },
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Candidate,
                input_bundle_sha256: dependencies.candidate_input_sha256.clone(),
                payload_application: "apply_patch_v1".to_string(),
            },
        ],
        parameters_sha256: dependencies.parameters_sha256.clone(),
        environment: recipe_environment(&dependencies.runtime_image_sha256),
        resource_bounds: resource_caps(),
        predicate: FindingPredicate::BaselineFailsCandidatePassesV1,
        pre_run_template_sha256: dependencies.pre_run_template_sha256.clone(),
        claimed_verdict: FindingClaimedVerdict::PredicateHolds,
    }
}

fn build_profile(
    governance: &Keypair,
    log_id: String,
    runner_manifest_sha256: &str,
) -> Result<SignedFindingChallengeVerifierProfile, AnyError> {
    let mut profile = FindingChallengeVerifierProfile {
        schema: FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1.to_string(),
        profile_id: String::new(),
        governance_authority: governance.public_key(),
        operator: "venue-operator".to_string(),
        receipt_signers: vec![
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Production,
                policy: key_policy(21, "production"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Delivery,
                policy: key_policy(12, "delivery"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Replay,
                policy: key_policy(13, "replay"),
            },
        ],
        checkpoint_logs: vec![FindingCheckpointLogPolicy {
            log_id,
            signer: key_policy(21, "checkpoint"),
        }],
        bbs_projection_issuer: FindingBbsIssuerPolicy {
            issuer_fingerprint: "bbs-issuer-fp".to_string(),
            key_hex: HEX64.to_string(),
            registry_ref: "registry/bbs-issuers".to_string(),
            key_epoch: 1,
            valid_from: ISSUED_AT,
            valid_until: WINDOW_EXPIRES_AT,
            revocation_status_ref: "revocations/bbs".to_string(),
        },
        allowed_runner_manifests: vec![runner_manifest_sha256.to_string()],
        required_receipt_semantics: "chio.mediated_spend.v1".to_string(),
        resolver_policy_ref: "resolver-policy-v1".to_string(),
        retention_policy_ref: "retention-forever-v1".to_string(),
        resource_caps: resource_caps(),
        predicate_engine: "chio-replay-v1".to_string(),
        allowed_predicates: vec![FindingPredicate::BaselineFailsCandidatePassesV1],
        required_facets: vec![
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetKind::CheckpointMembership,
            FindingFacetKind::RecipeBinding,
            FindingFacetKind::BondBacking,
            FindingFacetKind::GuaranteeConsistency,
        ],
        verifier_report_signer: key_policy(15, "verifier-report"),
        purchase_authority: key_policy(16, "purchase"),
        failed_delivery_authority: key_policy(17, "failed-delivery"),
        issued_at: ISSUED_AT,
        expires_at: WINDOW_EXPIRES_AT,
    };
    profile.profile_id = compute_profile_id(&profile)?;
    Ok(SignedExportEnvelope::sign(profile, governance)?)
}

fn build_finding(
    issuer: &Keypair,
    topic: &str,
    replay_recipe_sha256: &str,
    receipt_ids: &[String],
    evidence_checkpoint_ref: &str,
) -> Result<Finding, AnyError> {
    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: topic.to_string(),
            context_sha256: HEX64.to_string(),
            outcome_class: FindingOutcomeClass::VerifiedFix,
        },
        guarantee_class: FindingGuaranteeClass::DeterministicReplay,
        payload_sha256: HEX64.to_string(),
        payload_media_type: "application/json".to_string(),
        evidence_receipt_ids: receipt_ids.to_vec(),
        evidence_checkpoint_ref: evidence_checkpoint_ref.to_string(),
        evidence_cost: usd(10),
        runtime_assurance_tier: None,
        evidence_class: FindingEvidenceClass::Verified,
        replay_recipe_sha256: Some(replay_recipe_sha256.to_string()),
        intent_commitment_receipt_id: None,
        bond_ref: "bond:pending-allocation".to_string(),
        status_feed_ref: "status-feed/venue-wedge".to_string(),
        license_ref: None,
        price_hint_ref: None,
        issuer: issuer.public_key(),
        issued_at: ISSUED_AT,
        expires_at: WINDOW_EXPIRES_AT,
        signature: String::new(),
    };
    finding.finding_id = compute_finding_id(&finding)?;
    Ok(sign_finding(finding, issuer)?)
}

fn build_schedule(
    operator: &Keypair,
    requirement_units: u64,
    slashable: bool,
    currency: &str,
) -> Result<SignedOpenMarketFeeSchedule, AnyError> {
    let request = OpenMarketFeeScheduleIssueRequest {
        scope: OpenMarketEconomicsScope {
            namespace: "https://registry.seller.example".to_string(),
            allowed_listing_operator_ids: Vec::new(),
            allowed_actor_kinds: Vec::new(),
            allowed_admission_classes: Vec::new(),
            policy_reference: None,
        },
        publication_fee: usd(PUBLICATION_FEE_UNITS),
        dispute_fee: usd(25),
        market_participation_fee: usd(PARTICIPATION_FEE_UNITS),
        bond_requirements: vec![OpenMarketBondRequirement {
            bond_class: OpenMarketBondClass::Listing,
            required_amount: MonetaryAmount {
                units: requirement_units,
                currency: currency.to_string(),
            },
            collateral_reference_kind: OpenMarketCollateralReferenceKind::ExternalReference,
            slashable,
        }],
        issued_by: "governance@seller.example".to_string(),
        issued_at: Some(ISSUED_AT),
        expires_at: None,
        note: None,
    };
    let artifact = build_open_market_fee_schedule_artifact(
        "https://registry.seller.example",
        None,
        &request,
        ISSUED_AT,
    )?;
    Ok(SignedOpenMarketFeeSchedule::sign(artifact, operator)?)
}

fn build_terms(
    seller: &Keypair,
    finding: &Finding,
    artifact_sha256: &str,
    profile_sha256: &str,
    audit_epoch_length_secs: u64,
) -> Result<SignedFindingMarketTerms, AnyError> {
    let mut terms = FindingMarketTerms {
        schema: FINDING_MARKET_TERMS_SCHEMA_V1.to_string(),
        terms_id: String::new(),
        finding_id: finding.finding_id.clone(),
        finding_artifact_sha256: artifact_sha256.to_string(),
        listing_id: LISTING_ID.to_string(),
        seller: seller.public_key(),
        backing_requirement: FindingBackingRequirement {
            base_finding_stake: usd(STAKE_UNITS),
            maximum_sale_exposure: usd(EXPOSURE_UNITS),
            collateral_policy: "venue_ledger_exclusive_v1".to_string(),
        },
        filing_window_secs: 86_400,
        claim_window_secs: 604_800,
        appeal_window_secs: 259_200,
        audit_epoch_length_secs,
        audit_eligible: true,
        decision_rule_refs: vec!["decision/replay-v1".to_string()],
        verifier_profile_envelope_sha256: profile_sha256.to_string(),
        challenge_bond_limits: vec![FindingChallengeBondLimit {
            guarantee_class: FindingGuaranteeClass::DeterministicReplay,
            min_bond: usd(10),
            max_bond: usd(100),
        }],
        payout_policy: "pro_rata_capped_v1".to_string(),
        issued_at: ISSUED_AT,
        expires_at: WINDOW_EXPIRES_AT,
    };
    terms.terms_id = compute_terms_id(&terms)?;
    Ok(SignedExportEnvelope::sign(terms, seller)?)
}

fn build_authorization(
    issuer: &Keypair,
    seller: &Keypair,
    finding: &Finding,
    artifact_sha256: &str,
) -> Result<SignedExportEnvelope<FindingSellerAuthorization>, AnyError> {
    let mut authorization = FindingSellerAuthorization {
        schema: FINDING_SELLER_AUTHORIZATION_SCHEMA_V1.to_string(),
        authorization_id: String::new(),
        finding_id: finding.finding_id.clone(),
        finding_artifact_sha256: artifact_sha256.to_string(),
        listing_id: LISTING_ID.to_string(),
        issuer: issuer.public_key(),
        seller: seller.public_key(),
        provider_server_id: SERVER_ID.to_string(),
        provider_tool: "read_finding".to_string(),
        payee: FindingPayee::Beneficiary {
            destination: "rail:venue-ledger:seller-42".to_string(),
            currency: "USD".to_string(),
        },
        revocation_status_ref: "revocations/seller-auth".to_string(),
        issued_at: ISSUED_AT,
        expires_at: WINDOW_EXPIRES_AT,
    };
    authorization.authorization_id = compute_authorization_id(&authorization)?;
    Ok(SignedExportEnvelope::sign(authorization, issuer)?)
}

struct BackingDigests<'a> {
    authorization_sha256: &'a str,
    terms_sha256: &'a str,
    profile_sha256: &'a str,
    schedule_sha256: &'a str,
}

fn build_backing(
    collateral: &Keypair,
    seller: &Keypair,
    finding: &Finding,
    digests: &BackingDigests<'_>,
) -> Result<SignedFindingBondBacking, AnyError> {
    let mut backing = FindingBondBacking {
        schema: FINDING_BOND_BACKING_SCHEMA_V1.to_string(),
        allocation_id: String::new(),
        collateral_authority: collateral.public_key(),
        seller: seller.public_key(),
        authorization_envelope_sha256: digests.authorization_sha256.to_string(),
        finding_id: finding.finding_id.clone(),
        listing_id: LISTING_ID.to_string(),
        terms_envelope_sha256: digests.terms_sha256.to_string(),
        profile_envelope_sha256: digests.profile_sha256.to_string(),
        fee_requirement_sha256: HEX64.to_string(),
        fee_schedule_envelope_sha256: digests.schedule_sha256.to_string(),
        bond_class: FindingBondClass::Listing,
        locked_amount: usd(LOCKED_UNITS),
        maximum_sale_exposure: usd(EXPOSURE_UNITS),
        claim_horizon_secs: 604_800,
        audit_horizon_secs: 2_592_000,
        appeal_horizon_secs: 259_200,
        settlement_buffer_secs: 86_400,
        vault: FindingCollateralVault::VenueLedger {
            ledger_account: "vault:finding-collateral".to_string(),
            operator_epoch: 1,
        },
        issued_at: ISSUED_AT,
        expires_at: WINDOW_EXPIRES_AT,
    };
    backing.allocation_id = compute_allocation_id(&backing)?;
    Ok(SignedExportEnvelope::sign(backing, collateral)?)
}

fn metadata_url(finding_id: &str) -> String {
    format!("https://registry.seller.example/finding/{finding_id}")
}

fn build_listing(operator: &Keypair, finding_id: &str) -> Result<SignedGenericListing, AnyError> {
    let body = GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id: LISTING_ID.to_string(),
        namespace: "https://registry.seller.example".to_string(),
        published_at: ISSUED_AT,
        expires_at: Some(WINDOW_EXPIRES_AT),
        status: GenericListingStatus::Active,
        namespace_ownership: GenericNamespaceOwnership {
            namespace: "https://registry.seller.example".to_string(),
            owner_id: PUBLISHER_OPERATOR_ID.to_string(),
            owner_name: Some("Seller Operator".to_string()),
            registry_url: "https://registry.seller.example".to_string(),
            signer_public_key: operator.public_key(),
            registered_at: 1,
            transferred_from_owner_id: None,
        },
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::ToolServer,
            actor_id: SERVER_ID.to_string(),
            display_name: Some("Finding server".to_string()),
            metadata_url: Some(metadata_url(finding_id)),
            resolution_url: None,
            homepage_url: None,
        },
        compatibility: GenericListingCompatibilityReference {
            source_schema: "chio.certify.check.v1".to_string(),
            source_artifact_id: format!("artifact-{LISTING_ID}"),
            source_artifact_sha256: format!("sha-{LISTING_ID}"),
        },
        boundary: GenericListingBoundary::default(),
    };
    Ok(SignedGenericListing::sign(body, operator)?)
}

fn build_pricing_hint(
    operator: &Keypair,
    capability_scope: &str,
) -> Result<SignedListingPricingHint, AnyError> {
    Ok(SignedListingPricingHint::sign(
        ListingPricingHint {
            schema: LISTING_PRICING_HINT_SCHEMA.to_string(),
            listing_id: LISTING_ID.to_string(),
            namespace: "https://registry.seller.example".to_string(),
            provider_operator_id: PUBLISHER_OPERATOR_ID.to_string(),
            capability_scope: capability_scope.to_string(),
            price_per_call: usd(900),
            sla: ListingSla {
                max_latency_ms: 200,
                availability_bps: 9_995,
                throughput_rps: 100,
            },
            revocation_rate_bps: 5,
            recent_receipts_volume: 2_500,
            issued_at: ISSUED_AT,
            expires_at: WINDOW_EXPIRES_AT,
        },
        operator,
    )?)
}

fn clone_receipts(receipts: &[ResolvedReceiptEvidence]) -> Vec<ResolvedReceiptEvidence> {
    receipts
        .iter()
        .map(|evidence| ResolvedReceiptEvidence {
            receipt: evidence.receipt.clone(),
            canonical_receipt_bytes: evidence.canonical_receipt_bytes.clone(),
            inclusion_proof: evidence.inclusion_proof.clone(),
        })
        .collect()
}

/// Run the offline evidence verifier over the real receipts, checkpoint,
/// recipe, and bond snapshot, then sign the report under the
/// profile-authorized verifier key.
struct ReportInputs<'a> {
    governance: &'a Keypair,
    kernel: &'a Keypair,
    profile: &'a SignedFindingChallengeVerifierProfile,
    raw_finding: &'a str,
    receipts: &'a [ResolvedReceiptEvidence],
    checkpoint: &'a KernelCheckpoint,
    recipe_bytes: &'a [u8],
    backing: &'a SignedFindingBondBacking,
    collateral: &'a Keypair,
}

fn make_signed_report(
    inputs: &ReportInputs<'_>,
    trusted_time: u64,
) -> Result<SignedFindingVerifierReport, AnyError> {
    let trust = FindingVerifierTrustRoots {
        governance_authority: inputs.governance.public_key(),
        profile: inputs.profile.clone(),
        admitted_kernel_keys: vec![inputs.kernel.public_key()],
        collateral_authority: inputs.collateral.public_key(),
        runtime_attestation_authority: None,
        appraisal_authority: None,
        attestation_trust_policy: None,
        trusted_time,
        trust_root_snapshot_sha256: HEX64.to_string(),
        resolver_policy_sha256: HEX64.to_string(),
        trusted_time_input_sha256: HEX64.to_string(),
    };
    let bundle = FindingEvidenceBundle {
        receipts: clone_receipts(inputs.receipts),
        checkpoints: vec![inputs.checkpoint.clone()],
        checkpoint_transparency: build_checkpoint_transparency(std::slice::from_ref(
            inputs.checkpoint,
        ))?,
        recipe_preimage: Some(inputs.recipe_bytes),
        runtime_attestation: None,
        runtime_appraisal: None,
        bond_snapshot: Some(FindingBondSnapshot {
            backing: inputs.backing.clone(),
            live: true,
            accepted_at: trusted_time.saturating_sub(7_200),
        }),
        nonce_resolver: &NoNonceEvidence,
    };
    let draft = verify_finding_evidence(inputs.raw_finding, &trust, &bundle)?;
    if !draft.satisfies_required_facets(&trust.profile.body) {
        return Err(format!(
            "draft does not satisfy the required profile facets: {:?}",
            draft.facets
        )
        .into());
    }
    Ok(sign_finding_verifier_report(
        &draft,
        &trust,
        "chio-finding-verifier/0.1",
        &keypair(15),
    )?)
}

fn fee_terminal_binding(
    schedule_sha256: &str,
    event: FindingFeeEvent,
    amount: MonetaryAmount,
    finding_id: &str,
) -> Result<FindingFeeTerminalBinding, AnyError> {
    let idempotency_key =
        finding_fee_idempotency_key(schedule_sha256, &event, finding_id, LISTING_ID);
    let instruction = FindingRailInstruction {
        idempotency_key,
        payer: PUBLISHER_OPERATOR_ID.to_string(),
        amount_units: amount.units,
        currency: amount.currency.clone(),
        pool_principal_id: AUDIT_POOL_PRINCIPAL.to_string(),
        rail_destination: AUDIT_POOL_DESTINATION.to_string(),
    };
    let instruction_sha256 = digest_of(&instruction)?;
    let observation = FindingRailObservation {
        instruction_sha256: instruction_sha256.clone(),
        amount_units: amount.units,
        currency: amount.currency.clone(),
        rail_destination: AUDIT_POOL_DESTINATION.to_string(),
        rail: "venue-ledger".to_string(),
    };
    let observation_sha256 = digest_of(&observation)?;
    Ok(FindingFeeTerminalBinding {
        fee_schedule_envelope_sha256: schedule_sha256.to_string(),
        event,
        payer: PUBLISHER_OPERATOR_ID.to_string(),
        amount,
        pool_principal_id: AUDIT_POOL_PRINCIPAL.to_string(),
        rail_destination: AUDIT_POOL_DESTINATION.to_string(),
        instruction_sha256,
        observation_sha256,
    })
}

/// Every digest the venue binds into an admission, resolved from the
/// exact artifact bytes.
struct AdmissionInputs<'a> {
    venue: &'a Keypair,
    finding_id: &'a str,
    artifact_sha256: &'a str,
    authorization_sha256: &'a str,
    listing_sha256: &'a str,
    hint_sha256: &'a str,
    scope: &'a str,
    terms_sha256: &'a str,
    profile_sha256: &'a str,
    allocation_id: &'a str,
    backing_sha256: &'a str,
}

fn admission_body_from(
    inputs: &AdmissionInputs<'_>,
    schedule_sha256: &str,
    report: &SignedFindingVerifierReport,
    expires_at: u64,
) -> Result<FindingAdmission, AnyError> {
    let mut admission = FindingAdmission {
        schema: FINDING_ADMISSION_SCHEMA_V1.to_string(),
        admission_id: String::new(),
        venue: inputs.venue.public_key(),
        venue_id: VENUE_ID.to_string(),
        finding_id: inputs.finding_id.to_string(),
        finding_artifact_sha256: inputs.artifact_sha256.to_string(),
        seller_authorization_envelope_sha256: inputs.authorization_sha256.to_string(),
        listing_id: LISTING_ID.to_string(),
        listing_envelope_sha256: inputs.listing_sha256.to_string(),
        server_id: SERVER_ID.to_string(),
        metadata_url: metadata_url(inputs.finding_id),
        pricing_hint_envelope_sha256: inputs.hint_sha256.to_string(),
        capability_scope: inputs.scope.to_string(),
        publisher_operator_id: PUBLISHER_OPERATOR_ID.to_string(),
        payee_destination: "rail:venue-ledger:seller-42".to_string(),
        fee_schedule_envelope_sha256: schedule_sha256.to_string(),
        verifier_report_id: report.body.report_id.clone(),
        verifier_report_envelope_sha256: digest_of(report)?,
        terms_envelope_sha256: inputs.terms_sha256.to_string(),
        profile_envelope_sha256: inputs.profile_sha256.to_string(),
        fee_terminals: vec![
            fee_terminal_binding(
                schedule_sha256,
                FindingFeeEvent::Publication,
                usd(PUBLICATION_FEE_UNITS),
                inputs.finding_id,
            )?,
            fee_terminal_binding(
                schedule_sha256,
                FindingFeeEvent::ParticipationEpoch { epoch_index: 0 },
                usd(PARTICIPATION_FEE_UNITS),
                inputs.finding_id,
            )?,
        ],
        backing_allocation_id: inputs.allocation_id.to_string(),
        backing_envelope_sha256: inputs.backing_sha256.to_string(),
        audit_pool: audit_pool_binding(),
        challenge_administration_pool: FindingPoolBinding {
            principal_id: "pool:challenge-admin".to_string(),
            rail_destination: "rail:venue-ledger:challenge-admin".to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        community_fund_destination: "rail:venue-ledger:community-fund".to_string(),
        status_feed_operator_ref: "status-feed/venue-wedge".to_string(),
        purchase_authority: key_policy(16, "purchase"),
        failed_delivery_authority: key_policy(17, "failed-delivery"),
        issued_at: ISSUED_AT,
        expires_at,
    };
    admission.admission_id = compute_admission_id(&admission)?;
    Ok(admission)
}

fn sign_admission(
    mut body: FindingAdmission,
    signer: &Keypair,
) -> Result<SignedFindingAdmission, AnyError> {
    body.admission_id = compute_admission_id(&body)?;
    Ok(SignedExportEnvelope::sign(body, signer)?)
}

/// The full artifact web behind one admitted finding listing, with real
/// receipts, a real checkpoint, and every digest bound exactly.
struct MarketWeb {
    operator: Keypair,
    venue: Keypair,
    finding: Finding,
    finding_id: String,
    raw_finding: String,
    artifact_sha256: String,
    second_raw_finding: String,
    second_finding_id: String,
    recipe_bytes: Vec<u8>,
    recipe_sha256: String,
    recipe_dependencies: Vec<Vec<u8>>,
    profile_raw: String,
    profile_sha256: String,
    schedule: SignedOpenMarketFeeSchedule,
    schedule_sha256: String,
    terms: SignedFindingMarketTerms,
    terms_sha256: String,
    backing: SignedFindingBondBacking,
    backing_sha256: String,
    allocation_id: String,
    listing: SignedGenericListing,
    listing_sha256: String,
    pricing_hint: SignedListingPricingHint,
    hint_sha256: String,
    authorization: SignedFindingSellerAuthorization,
    authorization_sha256: String,
    report: SignedFindingVerifierReport,
    stale_report: SignedFindingVerifierReport,
    admission: SignedFindingAdmission,
    admission_json: String,
    scope: String,
    checkpoint: KernelCheckpoint,
}

impl MarketWeb {
    fn build(audit_epoch_length_secs: u64, admission_expires_at: u64) -> Result<Self, AnyError> {
        let operator = keypair(24);
        let governance = keypair(1);
        let seller = keypair(2);
        let issuer = keypair(3);
        let collateral = keypair(4);
        let venue = keypair(6);
        let kernel = keypair(21);

        // Receipts and their checkpoint come first: the finding binds the
        // recomputed receipt ids in order and the checkpoint reference.
        let first = receipt(&kernel, 0)?;
        let second = receipt(&kernel, 1)?;
        let first_bytes = canonical_json_bytes(&first)?;
        let second_bytes = canonical_json_bytes(&second)?;
        let tree = MerkleTree::from_leaves(&[first_bytes.clone(), second_bytes.clone()])?;
        let checkpoint = build_checkpoint(
            1,
            100,
            101,
            &[first_bytes.clone(), second_bytes.clone()],
            &kernel,
        )?;
        let log_id = checkpoint_log_id(&checkpoint);
        let evidence_checkpoint_ref = format!("{log_id}#1");
        let receipts = vec![
            ResolvedReceiptEvidence {
                receipt: first.clone(),
                canonical_receipt_bytes: first_bytes,
                inclusion_proof: build_inclusion_proof(&tree, 0, 1, 100)?,
            },
            ResolvedReceiptEvidence {
                receipt: second.clone(),
                canonical_receipt_bytes: second_bytes,
                inclusion_proof: build_inclusion_proof(&tree, 1, 1, 101)?,
            },
        ];

        // Acyclic publication order: profile, then recipe, then finding.
        // The profile admits the exact retained runner manifest the recipe
        // will commit, so the verifier cannot accept an unrelated manifest.
        let recipe_dependencies = recipe_dependencies();
        let profile = build_profile(
            &governance,
            log_id,
            &recipe_dependencies.runner_manifest_sha256,
        )?;
        let profile_raw = canonical_string(&profile)?;
        let profile_sha256 = sha256_hex(profile_raw.as_bytes());
        let recipe = build_recipe(&profile_sha256, &recipe_dependencies);
        let recipe_bytes = canonical_json_bytes(&recipe)?;
        let recipe_sha256 = sha256_hex(&recipe_bytes);

        let receipt_ids = vec![first.id.clone(), second.id.clone()];
        let finding = build_finding(
            &issuer,
            "repo:backbay/chio#m2-exit-criterion",
            &recipe_sha256,
            &receipt_ids,
            &evidence_checkpoint_ref,
        )?;
        let raw_finding = canonical_string(&finding)?;
        let artifact_sha256 = sha256_hex(raw_finding.as_bytes());
        let second_finding = build_finding(
            &issuer,
            "repo:backbay/chio#m2-exit-criterion-page-two",
            &recipe_sha256,
            &receipt_ids,
            &evidence_checkpoint_ref,
        )?;
        let second_raw_finding = canonical_string(&second_finding)?;
        let second_finding_id = second_finding.finding_id.clone();

        let schedule = build_schedule(&operator, REQUIREMENT_UNITS, true, "USD")?;
        let schedule_sha256 = signed_fee_schedule_digest(&schedule)?;
        let terms = build_terms(
            &seller,
            &finding,
            &artifact_sha256,
            &profile_sha256,
            audit_epoch_length_secs,
        )?;
        let terms_sha256 = digest_of(&terms)?;
        let authorization = build_authorization(&issuer, &seller, &finding, &artifact_sha256)?;
        let authorization_sha256 = digest_of(&authorization)?;
        let backing = build_backing(
            &collateral,
            &seller,
            &finding,
            &BackingDigests {
                authorization_sha256: &authorization_sha256,
                terms_sha256: &terms_sha256,
                profile_sha256: &profile_sha256,
                schedule_sha256: &schedule_sha256,
            },
        )?;
        let backing_sha256 = digest_of(&backing)?;
        let allocation_id = backing.body.allocation_id.clone();
        let listing = build_listing(&operator, &finding.finding_id)?;
        let listing_sha256 = digest_of(&listing)?;
        let scope = format!("finding:{}", finding.finding_id);
        let pricing_hint = build_pricing_hint(&operator, &scope)?;
        let hint_sha256 = digest_of(&pricing_hint)?;

        let report_inputs = ReportInputs {
            governance: &governance,
            kernel: &kernel,
            profile: &profile,
            raw_finding: &raw_finding,
            receipts: &receipts,
            checkpoint: &checkpoint,
            recipe_bytes: &recipe_bytes,
            backing: &backing,
            collateral: &collateral,
        };
        // The current report's evaluation time sits strictly after the
        // wall-clock collateral acceptance the venue records at
        // registration; the stale one sits strictly before it (the D14
        // report-before-backing rejection input).
        let now = unix_timestamp_now();
        let report = make_signed_report(&report_inputs, now.saturating_add(3_600))?;
        let stale_report = make_signed_report(&report_inputs, ISSUED_AT.saturating_add(10))?;

        let admission_inputs = AdmissionInputs {
            venue: &venue,
            finding_id: &finding.finding_id,
            artifact_sha256: &artifact_sha256,
            authorization_sha256: &authorization_sha256,
            listing_sha256: &listing_sha256,
            hint_sha256: &hint_sha256,
            scope: &scope,
            terms_sha256: &terms_sha256,
            profile_sha256: &profile_sha256,
            allocation_id: &allocation_id,
            backing_sha256: &backing_sha256,
        };
        let admission_body = admission_body_from(
            &admission_inputs,
            &schedule_sha256,
            &report,
            admission_expires_at,
        )?;
        let admission = sign_admission(admission_body, &venue)?;
        let admission_json = canonical_string(&admission)?;

        Ok(MarketWeb {
            operator,
            venue,
            finding_id: finding.finding_id.clone(),
            finding,
            raw_finding,
            artifact_sha256,
            second_raw_finding,
            second_finding_id,
            recipe_bytes,
            recipe_sha256,
            recipe_dependencies: recipe_dependencies.blobs,
            profile_raw,
            profile_sha256,
            schedule,
            schedule_sha256,
            terms,
            terms_sha256,
            backing,
            backing_sha256,
            allocation_id,
            listing,
            listing_sha256,
            pricing_hint,
            hint_sha256,
            authorization,
            authorization_sha256,
            report,
            stale_report,
            admission,
            admission_json,
            scope,
            checkpoint,
        })
    }

    fn admission_inputs(&self) -> AdmissionInputs<'_> {
        AdmissionInputs {
            venue: &self.venue,
            finding_id: &self.finding_id,
            artifact_sha256: &self.artifact_sha256,
            authorization_sha256: &self.authorization_sha256,
            listing_sha256: &self.listing_sha256,
            hint_sha256: &self.hint_sha256,
            scope: &self.scope,
            terms_sha256: &self.terms_sha256,
            profile_sha256: &self.profile_sha256,
            allocation_id: &self.allocation_id,
            backing_sha256: &self.backing_sha256,
        }
    }

    fn admission_body(
        &self,
        schedule_sha256: &str,
        report: &SignedFindingVerifierReport,
        expires_at: u64,
    ) -> Result<FindingAdmission, AnyError> {
        admission_body_from(
            &self.admission_inputs(),
            schedule_sha256,
            report,
            expires_at,
        )
    }

    fn activate_request(
        &self,
        admission: &SignedFindingAdmission,
        schedule: &SignedOpenMarketFeeSchedule,
        report: &SignedFindingVerifierReport,
    ) -> Result<String, AnyError> {
        self.activate_request_with_listing(admission, schedule, report, &self.listing)
    }

    fn activate_request_with_listing(
        &self,
        admission: &SignedFindingAdmission,
        schedule: &SignedOpenMarketFeeSchedule,
        report: &SignedFindingVerifierReport,
        listing: &SignedGenericListing,
    ) -> Result<String, AnyError> {
        let body = serde_json::json!({
            "admission": serde_json::to_value(admission)?,
            "sellerAuthorization": serde_json::to_value(&self.authorization)?,
            "terms": serde_json::to_value(&self.terms)?,
            "backing": serde_json::to_value(&self.backing)?,
            "feeSchedule": serde_json::to_value(schedule)?,
            "verifierReport": serde_json::to_value(report)?,
            "listing": serde_json::to_value(listing)?,
            "pricingHint": serde_json::to_value(&self.pricing_hint)?,
        });
        Ok(body.to_string())
    }
}

/// One provisioned control plane over a temp sqlite authority store, with
/// the deterministic venue-ledger rail wired.
struct MarketStack {
    _temp: tempfile::TempDir,
    store: SqliteFindingMarketStore,
    state: TrustServiceState,
    web: MarketWeb,
}

fn provision_stack(
    audit_epoch_length_secs: u64,
    admission_expires_at: u64,
) -> Result<MarketStack, AnyError> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    std::fs::create_dir(&lock_root)?;
    secure_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let joint = Arc::new(SqliteAuthorityStore::open_serving(&database, &lock_root)?);
    let store = joint.finding_market_store();
    let web = MarketWeb::build(audit_epoch_length_secs, admission_expires_at)?;
    let config = market_config();
    config.validate()?;
    let state = market_state(joint, config, Arc::new(VenueLedgerRailObserver));
    Ok(MarketStack {
        _temp: temp,
        store,
        state,
        web,
    })
}

impl MarketStack {
    fn failing_rail_state(&self) -> TrustServiceState {
        let mut state = self.state.clone();
        state.finding_rail = Some(Arc::new(FailingRail));
        state
    }

    /// Register the profile, retain the recipe, publish the finding, and
    /// register its collateral allocation: everything an activation needs.
    async fn seed_market(&self) -> TestResult {
        let (status, body) = send(
            &self.state,
            authed_post("/v1/findings/profiles", self.web.profile_raw.clone())?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            json_body(&body)?["envelopeSha256"],
            serde_json::json!(self.web.profile_sha256)
        );

        let (status, body) = send(
            &self.state,
            authed_post("/v1/findings/recipes", self.web.recipe_bytes.clone())?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            json_body(&body)?["canonicalSha256"],
            serde_json::json!(self.web.recipe_sha256)
        );

        for dependency in &self.web.recipe_dependencies {
            let expected_digest = sha256_hex(dependency);
            let (status, body) = send(
                &self.state,
                authed_post("/v1/findings/recipes", dependency.clone())?,
            )
            .await?;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
            assert_eq!(
                json_body(&body)?["canonicalSha256"],
                serde_json::json!(expected_digest)
            );
        }

        let (status, body) = send(
            &self.state,
            authed_post("/v1/findings/publish", self.web.raw_finding.clone())?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            json_body(&body)?["artifactSha256"],
            serde_json::json!(self.web.artifact_sha256)
        );

        let (status, body) = send(
            &self.state,
            authed_post(
                "/v1/findings/collateral",
                serde_json::to_string(&self.web.backing)?,
            )?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            json_body(&body)?["allocationId"],
            serde_json::json!(self.web.allocation_id)
        );
        Ok(())
    }

    async fn activate(&self) -> Result<(StatusCode, Vec<u8>), AnyError> {
        let body =
            self.web
                .activate_request(&self.web.admission, &self.web.schedule, &self.web.report)?;
        send(
            &self.state,
            authed_post(
                &format!("/v1/findings/{}/activate", self.web.finding_id),
                body,
            )?,
        )
        .await
    }

    async fn search_row(&self, finding_id: &str) -> Result<Option<serde_json::Value>, AnyError> {
        let uri = format!("/v1/findings/search?contextSha256={HEX64}&limit=200");
        let (status, body) = send(&self.state, public_get(&uri)?).await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let value = json_body(&body)?;
        let rows = value["results"]
            .as_array()
            .ok_or_else(|| missing("search results array"))?;
        Ok(rows
            .iter()
            .find(|row| row["findingId"] == serde_json::json!(finding_id))
            .cloned())
    }

    async fn admission_marker(&self) -> Result<Option<serde_json::Value>, AnyError> {
        let row = self
            .search_row(&self.web.finding_id)
            .await?
            .ok_or_else(|| missing("published finding missing from search"))?;
        Ok(row
            .get("admission")
            .filter(|value| !value.is_null())
            .cloned())
    }

    fn publication_fee_key(&self) -> String {
        finding_fee_idempotency_key(
            &self.web.schedule_sha256,
            &FindingFeeEvent::Publication,
            &self.web.finding_id,
            LISTING_ID,
        )
    }

    fn epoch_fee_key(&self, epoch_index: u64) -> String {
        finding_fee_idempotency_key(
            &self.web.schedule_sha256,
            &FindingFeeEvent::ParticipationEpoch { epoch_index },
            &self.web.finding_id,
            LISTING_ID,
        )
    }

    fn allocation_state(&self) -> Result<FindingAllocationState, AnyError> {
        Ok(self
            .store
            .get_allocation(&self.web.allocation_id)?
            .ok_or_else(|| missing("allocation missing from the collateral store"))?
            .state)
    }
}

async fn assert_not_admitted_with_allocation(
    stack: &MarketStack,
    expected_allocation_state: FindingAllocationState,
) -> TestResult {
    assert!(stack
        .store
        .get_current_admission(&stack.web.finding_id)?
        .is_none());
    assert!(stack.admission_marker().await?.is_none());
    let (status, _) = send(
        &stack.state,
        public_get(&format!("/v1/findings/{}/admission", stack.web.finding_id))?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(stack.allocation_state()?, expected_allocation_state);
    Ok(())
}

/// A rejection before durable prepare leaves no admission and keeps the
/// collateral allocation live.
async fn assert_nothing_admitted(stack: &MarketStack) -> TestResult {
    assert_not_admitted_with_allocation(stack, FindingAllocationState::Live).await
}

async fn assert_activation_rejected(
    stack: &MarketStack,
    request_body: String,
    expected_fragment: &str,
) -> TestResult {
    let (status, body) = send(
        &stack.state,
        authed_post(
            &format!("/v1/findings/{}/activate", stack.web.finding_id),
            request_body,
        )?,
    )
    .await?;
    let text = String::from_utf8_lossy(&body).to_string();
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(
        text.contains(expected_fragment),
        "expected {expected_fragment:?} in {text:?}"
    );
    assert_nothing_admitted(stack).await?;
    Ok(())
}

#[tokio::test]
async fn finding_publish_discover_admission() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let web = &stack.web;
    stack.seed_market().await?;

    // Immutable by-id resolution serves the EXACT accepted bytes.
    let (status, body) = send(
        &stack.state,
        public_get(&format!("/v1/findings/{}", web.finding_id))?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, web.raw_finding.as_bytes());

    // Second finding shares the context digest so the index has two rows.
    let (status, _) = send(
        &stack.state,
        authed_post("/v1/findings/publish", web.second_raw_finding.clone())?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);

    // Bounded pagination by context digest: two pages of one, then the
    // exhausted page. Cursor order is finding_id ascending.
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..2 {
        let uri = match &cursor {
            Some(cursor) => {
                format!("/v1/findings/search?contextSha256={HEX64}&limit=1&cursor={cursor}")
            }
            None => format!("/v1/findings/search?contextSha256={HEX64}&limit=1"),
        };
        let (status, body) = send(&stack.state, public_get(&uri)?).await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let page = json_body(&body)?;
        assert_eq!(page["count"], serde_json::json!(1));
        let row = page["results"][0].clone();
        // No admission exists yet, so no row may carry the qualified
        // cognition-market profile marker.
        assert!(row.get("admission").is_none() || row["admission"].is_null());
        seen.push(
            row["findingId"]
                .as_str()
                .ok_or_else(|| missing("findingId in search row"))?
                .to_string(),
        );
        cursor = page["nextCursor"].as_str().map(str::to_string);
        assert!(cursor.is_some(), "full page must carry a next cursor");
    }
    let mut expected = vec![web.finding_id.clone(), web.second_finding_id.clone()];
    expected.sort();
    assert_eq!(seen, expected);
    let final_cursor = cursor.ok_or_else(|| missing("cursor after two pages"))?;
    let (status, body) = send(
        &stack.state,
        public_get(&format!(
            "/v1/findings/search?contextSha256={HEX64}&limit=1&cursor={final_cursor}"
        ))?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let page = json_body(&body)?;
    assert_eq!(page["count"], serde_json::json!(0));
    assert!(page.get("nextCursor").is_none() || page["nextCursor"].is_null());

    // No admission yet: the public admission surface is empty.
    let (status, _) = send(
        &stack.state,
        public_get(&format!("/v1/findings/{}/admission", web.finding_id))?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Reused collateral: the same allocation registers exactly once.
    let (status, body) = send(
        &stack.state,
        authed_post(
            "/v1/findings/collateral",
            serde_json::to_string(&web.backing)?,
        )?,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert!(String::from_utf8_lossy(&body).contains("already registered"));

    // Rejection sweep over the activation surface. Every leg asserts the
    // specific status and that nothing was admitted.

    // Wrong pricing-hint binding.
    let mut wrong_hint =
        web.admission_body(&web.schedule_sha256, &web.report, ADMISSION_EXPIRES_AT)?;
    wrong_hint.pricing_hint_envelope_sha256 = hex64('f');
    let wrong_hint = sign_admission(wrong_hint, &web.venue)?;
    assert_activation_rejected(
        &stack,
        web.activate_request(&wrong_hint, &web.schedule, &web.report)?,
        "pricing hint envelope digest mismatch",
    )
    .await?;

    // The admission must pin an ACTIVE listing signed by the configured
    // listing authority. Every terminal listing status rejects even when
    // its envelope is otherwise valid and exactly bound.
    for status in [
        GenericListingStatus::Suspended,
        GenericListingStatus::Superseded,
        GenericListingStatus::Revoked,
        GenericListingStatus::Retired,
    ] {
        let mut listing_body = web.listing.body.clone();
        listing_body.status = status;
        let listing = SignedGenericListing::sign(listing_body, &web.operator)?;
        let mut admission_body =
            web.admission_body(&web.schedule_sha256, &web.report, ADMISSION_EXPIRES_AT)?;
        admission_body.listing_envelope_sha256 = digest_of(&listing)?;
        let admission = sign_admission(admission_body, &web.venue)?;
        assert_activation_rejected(
            &stack,
            web.activate_request_with_listing(&admission, &web.schedule, &web.report, &listing)?,
            "finding listing is not active",
        )
        .await?;
    }

    // Exact digest binding cannot turn a tampered listing into a valid
    // signed artifact.
    let mut tampered_listing = web.listing.clone();
    tampered_listing.body.subject.display_name = Some("Tampered finding server".to_string());
    let mut tampered_admission_body =
        web.admission_body(&web.schedule_sha256, &web.report, ADMISSION_EXPIRES_AT)?;
    tampered_admission_body.listing_envelope_sha256 = digest_of(&tampered_listing)?;
    let tampered_admission = sign_admission(tampered_admission_body, &web.venue)?;
    assert_activation_rejected(
        &stack,
        web.activate_request_with_listing(
            &tampered_admission,
            &web.schedule,
            &web.report,
            &tampered_listing,
        )?,
        "finding listing signature is invalid",
    )
    .await?;

    // A self-consistent listing authority embedded by the request cannot
    // replace the deployment pin.
    let attacker = keypair(25);
    let mut forged_body = web.listing.body.clone();
    forged_body.namespace_ownership.signer_public_key = attacker.public_key();
    let forged_listing = SignedGenericListing::sign(forged_body, &attacker)?;
    let mut forged_admission_body =
        web.admission_body(&web.schedule_sha256, &web.report, ADMISSION_EXPIRES_AT)?;
    forged_admission_body.listing_envelope_sha256 = digest_of(&forged_listing)?;
    let forged_admission = sign_admission(forged_admission_body, &web.venue)?;
    assert_activation_rejected(
        &stack,
        web.activate_request_with_listing(
            &forged_admission,
            &web.schedule,
            &web.report,
            &forged_listing,
        )?,
        "configured listing authority",
    )
    .await?;

    // Wrong metadata binding.
    let mut wrong_metadata =
        web.admission_body(&web.schedule_sha256, &web.report, ADMISSION_EXPIRES_AT)?;
    wrong_metadata.metadata_url = "https://attacker.example/finding".to_string();
    let wrong_metadata = sign_admission(wrong_metadata, &web.venue)?;
    assert_activation_rejected(
        &stack,
        web.activate_request(&wrong_metadata, &web.schedule, &web.report)?,
        "listing metadata url mismatch",
    )
    .await?;

    // A failed optional facet is a contradictory check result, not an
    // unavailable optional input. It denies even though status liveness is
    // not required by this profile.
    let mut failed_report_body = web.report.body.clone();
    let status_facet = failed_report_body
        .facets
        .iter_mut()
        .find(|facet| facet.facet == FindingFacetKind::StatusLiveness)
        .ok_or_else(|| missing("status liveness facet"))?;
    status_facet.outcome = FindingFacetOutcome::Failed;
    status_facet.reason = "signed status proof contradicted the snapshot".to_string();
    failed_report_body.report_id = String::new();
    failed_report_body.report_id = compute_report_id(&failed_report_body)?;
    let failed_report = SignedExportEnvelope::sign(failed_report_body, &keypair(15))?;
    let failed_report_admission = sign_admission(
        web.admission_body(&web.schedule_sha256, &failed_report, ADMISSION_EXPIRES_AT)?,
        &web.venue,
    )?;
    assert_activation_rejected(
        &stack,
        web.activate_request(&failed_report_admission, &web.schedule, &failed_report)?,
        "failed facet",
    )
    .await?;

    // Wrong collateral: the admission names an allocation the venue never
    // registered.
    let mut unknown_allocation =
        web.admission_body(&web.schedule_sha256, &web.report, ADMISSION_EXPIRES_AT)?;
    unknown_allocation.backing_allocation_id = hex64('e');
    let unknown_allocation = sign_admission(unknown_allocation, &web.venue)?;
    assert_activation_rejected(
        &stack,
        web.activate_request(&unknown_allocation, &web.schedule, &web.report)?,
        "unknown collateral allocation",
    )
    .await?;

    // Undersized, non-slashable, and wrong-currency Listing requirements,
    // each through the admission verifier's sizing gate.
    for (schedule, fragment) in [
        (
            build_schedule(&web.operator, STAKE_UNITS + EXPOSURE_UNITS - 1, true, "USD")?,
            "below base_finding_stake",
        ),
        (
            build_schedule(&web.operator, REQUIREMENT_UNITS, false, "USD")?,
            "not slashable",
        ),
        (
            build_schedule(&web.operator, REQUIREMENT_UNITS, true, "EUR")?,
            "currencies must all match",
        ),
    ] {
        let variant_sha256 = signed_fee_schedule_digest(&schedule)?;
        let body = web.admission_body(&variant_sha256, &web.report, ADMISSION_EXPIRES_AT)?;
        let admission = sign_admission(body, &web.venue)?;
        assert_activation_rejected(
            &stack,
            web.activate_request(&admission, &schedule, &web.report)?,
            fragment,
        )
        .await?;
    }

    // Stale bundle: an admission whose window has already closed.
    let stale = web.admission_body(&web.schedule_sha256, &web.report, ISSUED_AT + 1_000)?;
    let stale = sign_admission(stale, &web.venue)?;
    assert_activation_rejected(
        &stack,
        web.activate_request(&stale, &web.schedule, &web.report)?,
        "admission has expired",
    )
    .await?;

    // Authority self-bootstrap: an admission signed by a key that is not
    // the pinned venue authority carries no weight, whatever it embeds.
    let interloper_body =
        web.admission_body(&web.schedule_sha256, &web.report, ADMISSION_EXPIRES_AT)?;
    let interloper = sign_admission(interloper_body, &keypair(9))?;
    assert_activation_rejected(
        &stack,
        web.activate_request(&interloper, &web.schedule, &web.report)?,
        "admission envelope rejected",
    )
    .await?;

    // Report-before-backing order (D14): a bond-verified report evaluated
    // before the allocation was accepted rejects.
    let stale_report_body = web.admission_body(
        &web.schedule_sha256,
        &web.stale_report,
        ADMISSION_EXPIRES_AT,
    )?;
    let stale_report_admission = sign_admission(stale_report_body, &web.venue)?;
    assert_activation_rejected(
        &stack,
        web.activate_request(&stale_report_admission, &web.schedule, &web.stale_report)?,
        "before the allocation existed",
    )
    .await?;

    // Fault injection, first leg: the rail refuses to settle. The charge
    // stays durable and failed, and nothing is admitted.
    let failing = stack.failing_rail_state();
    let (status, body) = send(
        &failing,
        authed_post(
            &format!("/v1/findings/{}/activate", web.finding_id),
            web.activate_request(&web.admission, &web.schedule, &web.report)?,
        )?,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let publication_event = stack
        .store
        .get_fee_event(&stack.publication_fee_key())?
        .ok_or_else(|| missing("publication fee intent must survive the rail outage"))?;
    assert_eq!(publication_event.state, FindingFeeState::Failed);
    assert!(publication_event.observation_sha256.is_none());
    let epoch_zero_event = stack
        .store
        .get_fee_event(&stack.epoch_fee_key(0))?
        .ok_or_else(|| missing("all fee intents must exist before activation prepare"))?;
    assert_eq!(epoch_zero_event.state, FindingFeeState::Intent);
    assert!(epoch_zero_event.observation_sha256.is_none());
    assert_not_admitted_with_allocation(&stack, FindingAllocationState::Consumed).await?;
    let attempt = stack
        .store
        .get_activation_attempt(&web.admission.body.admission_id)?
        .ok_or_else(|| missing("durable activation prepare must survive the rail outage"))?;
    assert_eq!(attempt.state, FindingActivationAttemptState::Prepared);
    assert_eq!(attempt.envelope_json, web.admission_json);

    // Second leg: the SAME activation request retries against the working
    // rail and reconciles without double-charging.
    let (status, body) = stack.activate().await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json_body(&body)?["outcome"], serde_json::json!("Activated"));

    let publication_terminal = web
        .admission
        .body
        .fee_terminals
        .iter()
        .find(|terminal| terminal.event == FindingFeeEvent::Publication)
        .ok_or_else(|| missing("publication terminal"))?;
    let epoch_terminal = web
        .admission
        .body
        .fee_terminals
        .iter()
        .find(|terminal| terminal.event == FindingFeeEvent::ParticipationEpoch { epoch_index: 0 })
        .ok_or_else(|| missing("epoch-zero terminal"))?;
    for (key, terminal) in [
        (stack.publication_fee_key(), publication_terminal),
        (stack.epoch_fee_key(0), epoch_terminal),
    ] {
        let event = stack
            .store
            .get_fee_event(&key)?
            .ok_or_else(|| missing("reconciled fee event"))?;
        assert_eq!(event.state, FindingFeeState::Reconciled);
        assert_eq!(event.instruction_sha256, terminal.instruction_sha256);
        assert_eq!(
            event.observation_sha256.as_deref(),
            Some(terminal.observation_sha256.as_str())
        );
        assert_eq!(event.pool_principal_id, AUDIT_POOL_PRINCIPAL);
        assert_eq!(event.rail_destination, AUDIT_POOL_DESTINATION);
    }
    assert_eq!(stack.allocation_state()?, FindingAllocationState::Consumed);
    assert_eq!(
        stack
            .store
            .get_activation_attempt(&web.admission.body.admission_id)?
            .ok_or_else(|| missing("activation attempt after finalization"))?
            .state,
        FindingActivationAttemptState::Activated
    );

    // The qualified-profile marker: search now carries the admission
    // block, and the public admission surface serves the exact envelope.
    let marker = stack
        .admission_marker()
        .await?
        .ok_or_else(|| missing("admitted listing must carry the admission marker"))?;
    assert_eq!(
        marker["admissionId"],
        serde_json::json!(web.admission.body.admission_id)
    );
    assert_eq!(
        marker["envelopeSha256"],
        serde_json::json!(sha256_hex(web.admission_json.as_bytes()))
    );
    assert_eq!(
        marker["expiresAt"],
        serde_json::json!(web.admission.body.expires_at)
    );
    let (status, body) = send(
        &stack.state,
        public_get(&format!("/v1/findings/{}/admission", web.finding_id))?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, web.admission_json.as_bytes());

    // Replay: the identical activation is an idempotent no-op and the fee
    // events stay reconciled exactly once per terminal.
    let (status, body) = stack.activate().await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        json_body(&body)?["outcome"],
        serde_json::json!("ExactReplay")
    );
    for (key, terminal) in [
        (stack.publication_fee_key(), publication_terminal),
        (stack.epoch_fee_key(0), epoch_terminal),
    ] {
        let event = stack
            .store
            .get_fee_event(&key)?
            .ok_or_else(|| missing("fee event after replay"))?;
        assert_eq!(event.state, FindingFeeState::Reconciled);
        assert_eq!(
            event.observation_sha256.as_deref(),
            Some(terminal.observation_sha256.as_str())
        );
    }
    assert_eq!(stack.allocation_state()?, FindingAllocationState::Consumed);

    // Consumed collateral cannot back a second admission.
    let reuse_body =
        web.admission_body(&web.schedule_sha256, &web.report, ADMISSION_EXPIRES_AT - 1)?;
    let reuse = sign_admission(reuse_body, &web.venue)?;
    let (status, body) = send(
        &stack.state,
        authed_post(
            &format!("/v1/findings/{}/activate", web.finding_id),
            web.activate_request(&reuse, &web.schedule, &web.report)?,
        )?,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert!(String::from_utf8_lossy(&body).contains("not available for activation"));

    // The bid leg: the REAL marketplace path, gated by the verified
    // admission witness over the pinned deployment authorities.
    let allocation = stack
        .store
        .get_allocation(&web.allocation_id)?
        .ok_or_else(|| missing("allocation snapshot after activation"))?;
    let venue_key = keypair(6).public_key();
    let collateral_key = keypair(4).public_key();
    let trusted_signers = vec![web.operator.public_key()];
    let context = FindingAdmissionContext {
        venue_authority: &venue_key,
        venue_id: VENUE_ID,
        now: unix_timestamp_now(),
        fee_schedule: &web.schedule,
        fee_schedule_gate: FindingFeeScheduleGate::Legacy,
        trusted_local_operator_signers: &trusted_signers,
        terms: &web.terms,
        backing: &web.backing,
        allocation_snapshot: SeamAllocationSnapshot {
            allocation_id: allocation.backing.allocation_id.clone(),
            backing_envelope_sha256: allocation.backing_envelope_sha256.clone(),
            expires_at: allocation.backing.expires_at,
            status: FindingAllocationStatus::Consumed,
            active_admission_id: allocation.active_admission_id.clone(),
            prepared_admission_id: None,
            accepted_at: allocation.accepted_at,
        },
        collateral_authority: &collateral_key,
        constituent_expiry_bounds: FindingConstituentExpiryBounds {
            finding: web.finding.expires_at,
            listing: web.listing.body.expires_at.unwrap_or(u64::MAX),
            pricing_hint: web.pricing_hint.body.expires_at,
            seller_authorization: web.authorization.body.expires_at,
            profile: WINDOW_EXPIRES_AT,
        },
    };
    let witness = verify_finding_admission(&web.admission, &context)?;
    assert_eq!(witness.capability_scope(), web.scope);
    assert_eq!(witness.finding_id(), web.finding_id);
    assert_eq!(witness.listing_id(), LISTING_ID);

    let agent = keypair(31);
    let listing_entry = Listing {
        rank: 1,
        listing: web.listing.clone(),
        pricing: web.pricing_hint.clone(),
        publisher: GenericRegistryPublisher {
            role: GenericRegistryPublisherRole::Origin,
            operator_id: PUBLISHER_OPERATOR_ID.to_string(),
            operator_name: Some("Seller Operator".to_string()),
            registry_url: "https://registry.seller.example".to_string(),
            upstream_registry_urls: Vec::new(),
        },
        freshness: GenericListingReplicaFreshness {
            state: GenericListingFreshnessState::Fresh,
            age_secs: 20,
            max_age_secs: 300,
            valid_until: WINDOW_EXPIRES_AT,
            generated_at: unix_timestamp_now(),
        },
    };
    let request = SignedBidRequest::sign(
        BidRequest {
            schema: BID_REQUEST_SCHEMA.to_string(),
            agent_id: "buyer-agent-7".to_string(),
            listing_id: LISTING_ID.to_string(),
            max_price_per_call: usd(900),
            window_seconds: 3_600,
            requested_scope: RequestedScope {
                server_id: SERVER_ID.to_string(),
                tool_name: "read_finding".to_string(),
                max_invocations: Some(1),
                capability_scope_prefix: web.scope.clone(),
            },
            issued_at: unix_timestamp_now(),
        },
        &agent,
    )?;
    let ask = bid_with_finding_admission(
        &request,
        BidMintContext {
            listing: &listing_entry,
            issuer_keypair: &web.operator,
            agent_subject: agent.public_key(),
            token_id: "finding-token-0001".to_string(),
            now: unix_timestamp_now(),
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
        &witness,
    )?;
    assert_eq!(ask.body.listing_id, LISTING_ID);
    assert_eq!(ask.body.quoted_price.units, 900);
    let grant = ask
        .body
        .token_offer
        .scope
        .grants
        .first()
        .ok_or_else(|| missing("minted grant"))?;
    assert_eq!(grant.server_id, SERVER_ID);
    assert_eq!(grant.tool_name, "read_finding");
    assert_eq!(grant.max_invocations, Some(1));

    // Participation renewal advances the paid-through epoch.
    let renewal = serde_json::json!({
        "feeSchedule": serde_json::to_value(&web.schedule)?,
    });
    let (status, body) = send(
        &stack.state,
        authed_post(
            &format!("/v1/findings/{}/participation", web.finding_id),
            renewal.to_string(),
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json_body(&body)?["paidThroughEpoch"], serde_json::json!(1));
    assert_eq!(
        stack
            .store
            .paid_through_epoch(&web.finding_id, LISTING_ID)?,
        Some(1)
    );
    Ok(())
}

#[tokio::test]
async fn noncanonical_publish_ingress_rejects() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let web = &stack.web;
    stack.seed_market().await?;

    let parsed: serde_json::Value = serde_json::from_str(&web.second_raw_finding)?;

    // Duplicate member names never reach the schema layer.
    let duplicate_keys = r#"{"schema":"chio.finding.v1","schema":"chio.finding.v1"}"#.to_string();

    // Uppercase hex survives canonicalization byte-for-byte and is caught
    // by the registered schema's lowercase digest pattern.
    let mut uppercase = parsed.clone();
    uppercase["payload_sha256"] = serde_json::json!(HEX64.to_uppercase());
    let uppercase = canonical_string(&uppercase)?;

    // An explicit null option is either rejected by the schema or erased
    // by typed deserialization, breaking typed-canonical equality.
    let mut explicit_null = parsed.clone();
    explicit_null["license_ref"] = serde_json::Value::Null;
    let explicit_null = canonical_string(&explicit_null)?;

    // A float token spells the same number noncanonically.
    let float_token = web
        .second_raw_finding
        .replacen("\"units\":10}", "\"units\":10.0}", 1);
    assert_ne!(float_token, web.second_raw_finding);

    // Whitespace padding breaks raw-equals-canonical.
    let padded = format!(" {}", web.second_raw_finding);

    for raw in [
        duplicate_keys,
        uppercase,
        explicit_null,
        float_token,
        padded,
    ] {
        let (status, body) = send(&stack.state, authed_post("/v1/findings/publish", raw)?).await?;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{}",
            String::from_utf8_lossy(&body)
        );
    }
    // Nothing was indexed by any rejected spelling.
    let (status, _) = send(
        &stack.state,
        public_get(&format!("/v1/findings/{}", web.second_finding_id))?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn oversized_publish_body_rejects() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let oversized = "x".repeat(FINDING_PUBLISH_MAX_BODY_BYTES + 1);
    let (status, _) = send(
        &stack.state,
        authed_post("/v1/findings/publish", oversized)?,
    )
    .await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}

#[tokio::test]
async fn future_issued_and_expired_findings_reject() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let web = &stack.web;
    stack.seed_market().await?;
    let issuer = keypair(3);
    let now = unix_timestamp_now();

    let mut future = web.finding.clone();
    future.descriptor.topic = "repo:backbay/chio#m2-exit-future".to_string();
    future.issued_at = now + 86_400;
    future.expires_at = now + 172_800;
    future.finding_id = compute_finding_id(&future)?;
    let future = sign_finding(future, &issuer)?;
    let (status, body) = send(
        &stack.state,
        authed_post("/v1/findings/publish", canonical_string(&future)?)?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("future-issued"));

    let mut expired = web.finding.clone();
    expired.descriptor.topic = "repo:backbay/chio#m2-exit-expired".to_string();
    expired.issued_at = ISSUED_AT;
    expired.expires_at = ISSUED_AT + 86_400;
    expired.finding_id = compute_finding_id(&expired)?;
    let expired = sign_finding(expired, &issuer)?;
    let (status, body) = send(
        &stack.state,
        authed_post("/v1/findings/publish", canonical_string(&expired)?)?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("expired"));
    Ok(())
}

#[tokio::test]
async fn price_hint_ref_and_unretained_recipe_reject() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let web = &stack.web;
    stack.seed_market().await?;
    let issuer = keypair(3);

    // A finding-scoped hint reference inside the finding is a hash cycle.
    let mut hinted = web.finding.clone();
    hinted.descriptor.topic = "repo:backbay/chio#m2-exit-hinted".to_string();
    hinted.price_hint_ref = Some("pricing-hint/finding".to_string());
    hinted.finding_id = compute_finding_id(&hinted)?;
    let hinted = sign_finding(hinted, &issuer)?;
    let (status, body) = send(
        &stack.state,
        authed_post("/v1/findings/publish", canonical_string(&hinted)?)?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("price_hint_ref"));

    // A deterministic-replay claim whose recipe preimage was never
    // retained cannot publish.
    let mut unretained = web.finding.clone();
    unretained.descriptor.topic = "repo:backbay/chio#m2-exit-unretained".to_string();
    unretained.replay_recipe_sha256 = Some(hex64('d'));
    unretained.finding_id = compute_finding_id(&unretained)?;
    let unretained = sign_finding(unretained, &issuer)?;
    let (status, body) = send(
        &stack.state,
        authed_post("/v1/findings/publish", canonical_string(&unretained)?)?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("not retained"));
    Ok(())
}

#[tokio::test]
async fn deterministic_publish_requires_every_retained_recipe_dependency_class() -> TestResult {
    for (omitted_index, expected_fragment) in [
        (0_usize, "phase input bundle 0"),
        (2_usize, "parameter bundle"),
        (3_usize, "pre-run template"),
        (4_usize, "runner manifest"),
        (5_usize, "runtime image"),
    ] {
        let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
        let web = &stack.web;

        let (status, body) = send(
            &stack.state,
            authed_post("/v1/findings/profiles", web.profile_raw.clone())?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

        let (status, body) = send(
            &stack.state,
            authed_post("/v1/findings/recipes", web.recipe_bytes.clone())?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

        for (index, dependency) in web.recipe_dependencies.iter().enumerate() {
            if index == omitted_index {
                continue;
            }
            let (status, body) = send(
                &stack.state,
                authed_post("/v1/findings/recipes", dependency.clone())?,
            )
            .await?;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        }

        let (status, body) = send(
            &stack.state,
            authed_post("/v1/findings/publish", web.raw_finding.clone())?,
        )
        .await?;
        let text = String::from_utf8_lossy(&body);
        assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
        assert!(
            text.contains(expected_fragment),
            "expected {expected_fragment:?} in {text:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn wrong_issuer_signature_rejects() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let web = &stack.web;
    stack.seed_market().await?;

    // The body names the real issuer but an interloper produced the
    // signature: strict verification against the embedded issuer denies.
    let mut forged = web.finding.clone();
    forged.descriptor.topic = "repo:backbay/chio#m2-exit-forged".to_string();
    forged.finding_id = compute_finding_id(&forged)?;
    forged.signature.clear();
    let interloper = keypair(9);
    let (signature, _) = interloper.sign_canonical(&forged)?;
    forged.signature = signature.to_hex();
    let (status, body) = send(
        &stack.state,
        authed_post("/v1/findings/publish", canonical_string(&forged)?)?,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let (status, _) = send(
        &stack.state,
        public_get(&format!("/v1/findings/{}", forged.finding_id))?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn search_requires_filters_and_a_canonical_cursor() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    stack.seed_market().await?;

    let (status, body) = send(&stack.state, public_get("/v1/findings/search")?).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("requires"));

    let (status, _) = send(
        &stack.state,
        public_get(&format!(
            "/v1/findings/search?contextSha256={HEX64}&cursor=ZZ"
        ))?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn profile_not_signed_by_governance_rejects() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let interloper = keypair(9);
    let checkpoint_id = checkpoint_log_id(&stack.web.checkpoint);
    let forged_profile = build_profile(
        &interloper,
        checkpoint_id,
        &recipe_dependencies().runner_manifest_sha256,
    )?;
    let (status, body) = send(
        &stack.state,
        authed_post("/v1/findings/profiles", canonical_string(&forged_profile)?)?,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&body)
    );
    Ok(())
}

#[test]
fn activation_reverifies_profile_and_report_authority_lifecycle() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let governance = keypair(1);
    let profile = build_profile(
        &governance,
        checkpoint_log_id(&stack.web.checkpoint),
        &recipe_dependencies().runner_manifest_sha256,
    )?;
    let config = market_config();
    let profile_sha256 = digest_of(&profile)?;
    let now = stack.web.report.body.evaluation_time;
    verify_profile_for_activation(&profile, &profile_sha256, &config, now)
        .map_err(std::io::Error::other)?;
    verify_report_authority_lifecycle(&stack.web.report, &profile, &config)
        .map_err(std::io::Error::other)?;

    let forged = build_profile(
        &keypair(9),
        checkpoint_log_id(&stack.web.checkpoint),
        &recipe_dependencies().runner_manifest_sha256,
    )?;
    assert!(verify_profile_for_activation(&forged, &digest_of(&forged)?, &config, now).is_err());

    let mut expired_body = profile.body.clone();
    expired_body.expires_at = now;
    expired_body.profile_id = compute_profile_id(&expired_body)?;
    let expired = SignedExportEnvelope::sign(expired_body, &governance)?;
    assert!(verify_profile_for_activation(&expired, &digest_of(&expired)?, &config, now).is_err());

    let mut stale_pin = config.clone();
    stale_pin.verifier_report.valid_until = stack.web.report.body.evaluation_time;
    assert!(verify_report_authority_lifecycle(&stack.web.report, &profile, &stale_pin).is_err());

    let mut wrong_epoch = config;
    wrong_epoch.verifier_report.key_epoch += 1;
    assert!(verify_report_authority_lifecycle(&stack.web.report, &profile, &wrong_epoch).is_err());
    Ok(())
}

#[tokio::test]
async fn profile_body_authority_must_match_governance() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let governance = keypair(1);
    let interloper = keypair(9);
    let checkpoint_id = checkpoint_log_id(&stack.web.checkpoint);
    let profile = build_profile(
        &interloper,
        checkpoint_id,
        &recipe_dependencies().runner_manifest_sha256,
    )?;
    let mismatched_profile = SignedExportEnvelope::sign(profile.body, &governance)?;
    let (status, body) = send(
        &stack.state,
        authed_post(
            "/v1/findings/profiles",
            canonical_string(&mismatched_profile)?,
        )?,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&body)
    );
    Ok(())
}

#[tokio::test]
async fn unpaid_epoch_drops_the_marker_until_renewal() -> TestResult {
    // One-second audit epochs: the epoch lapses on the wall clock right
    // after activation, so the unpaid-epoch read-time filter is
    // observable without touching the stored envelope.
    let stack = provision_stack(1, ADMISSION_EXPIRES_AT)?;
    stack.seed_market().await?;
    let (status, body) = stack.activate().await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    assert!(
        stack.admission_marker().await?.is_none(),
        "an unpaid epoch must clear the qualified-profile marker"
    );
    let (status, _) = send(
        &stack.state,
        public_get(&format!("/v1/findings/{}/admission", stack.web.finding_id))?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Renewal restores currency. Epochs advance one wall-clock second at
    // a time here, so a short bounded loop of renewals catches up.
    let renewal = serde_json::json!({
        "feeSchedule": serde_json::to_value(&stack.web.schedule)?,
    })
    .to_string();
    let mut restored = false;
    for _ in 0..8 {
        let (status, body) = send(
            &stack.state,
            authed_post(
                &format!("/v1/findings/{}/participation", stack.web.finding_id),
                renewal.clone(),
            )?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        if stack.admission_marker().await?.is_some() {
            restored = true;
            break;
        }
    }
    assert!(
        restored,
        "participation renewal must restore the qualified-profile marker"
    );
    let paid_through = stack
        .store
        .paid_through_epoch(&stack.web.finding_id, LISTING_ID)?
        .ok_or_else(|| missing("paid-through epoch after renewal"))?;
    assert!(paid_through >= 1);
    Ok(())
}

#[tokio::test]
async fn expired_admission_loses_the_marker() -> TestResult {
    let expires_at = unix_timestamp_now() + 6;
    let stack = provision_stack(LONG_EPOCH_SECS, expires_at)?;
    stack.seed_market().await?;
    let (status, body) = stack.activate().await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(stack.admission_marker().await?.is_some());

    let remaining = expires_at.saturating_sub(unix_timestamp_now()) + 1;
    tokio::time::sleep(std::time::Duration::from_secs(remaining)).await;
    assert!(
        stack.admission_marker().await?.is_none(),
        "an expired admission must clear the qualified-profile marker"
    );
    let (status, _) = send(
        &stack.state,
        public_get(&format!("/v1/findings/{}/admission", stack.web.finding_id))?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}
