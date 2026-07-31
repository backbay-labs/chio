//! End-to-end coverage for a purchased finding reveal: an admitted listing
//! is discovered through the serve router, bid on through the real
//! marketplace path, reserved by the authoritative purchase coordinator,
//! revealed through the mediating kernel under a delivery-committed grant,
//! settled into a signed purchase record, and recorded into buyer memory
//! with a signed lineage statement back to the delivery receipt. The
//! failure lanes cover every way the reveal must refuse.
//!
//! One sqlite authority store provisions both the kernel's durable
//! admission stores and the finding market and purchase stores, so a
//! simulated restart is a genuine re-open of the same database.

use super::super::super::*;
use super::build_router;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chio_core::canonical_json_bytes;
use chio_core::capability::governance::{GovernedTransactionIntent, GovernedTransactionIntentBody};
use chio_core::capability::scope::{
    ChioScope, Constraint, FindingRecoveryMarkerV1, MonetaryAmount, Operation, PromptGrant,
    ResourceGrant, ToolGrant,
};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::{Keypair, PublicKey};
use chio_core::merkle::MerkleTree;
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::receipt::kinds::TrustLevel;
use chio_core::receipt::lineage::{
    ReceiptLineageEndpoints, ReceiptLineageRelationKind, ReceiptLineageStatement,
    ReceiptLineageStatementBody, SignedExportEnvelope,
};
use chio_core::receipt::metadata::{
    DeliveryContract, DeliveryResult, FindingDelivery, FindingDeliverySettlementMode,
    FindingMediaTypeCheck, FindingTransformProfile, DELIVERY_CONTRACT_METADATA_KEY,
    DELIVERY_CONTRACT_SCHEMA, FINDING_DELIVERY_METADATA_KEY, FINDING_DELIVERY_SCHEMA,
};
use chio_core::session::{RequestId, SessionAnchorReference};
use chio_core::sha256_hex;
use chio_finding::{
    compute_admission_id, compute_allocation_id, compute_authorization_id, compute_finding_id,
    compute_profile_id, compute_terms_id, derive_finding_recovery_id, derive_purchase_key,
    sign_finding, verify_signed_failed_delivery, verify_signed_purchase_record, Finding,
    FindingAdmission, FindingAuthorityKeyPolicy, FindingBackingRequirement, FindingBbsIssuerPolicy,
    FindingBondBacking, FindingBondClass, FindingChallengeBondLimit,
    FindingChallengeVerifierProfile, FindingCheckpointLogPolicy, FindingClaimedVerdict,
    FindingCollateralVault, FindingDescriptor, FindingEvidenceClass, FindingFacetKind,
    FindingFeeEvent, FindingFeeTerminalBinding, FindingGuaranteeClass, FindingMarketTerms,
    FindingOutcomeClass, FindingPayee, FindingPoolBinding, FindingPredicate,
    FindingPurchaseContext, FindingReceiptRole, FindingReceiptSignerRole, FindingRecipeEnvironment,
    FindingRecipePhase, FindingRecipePhaseKind, FindingRecoveryContext, FindingReplayRecipeInput,
    FindingResourceCaps, FindingSellerAuthorization, SignedFindingAdmission,
    SignedFindingBondBacking, SignedFindingChallengeVerifierProfile, SignedFindingMarketTerms,
    SignedFindingSellerAuthorization, SignedFindingVerifierReport, FINDING_ADMISSION_SCHEMA_V1,
    FINDING_BOND_BACKING_SCHEMA_V1, FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1,
    FINDING_MARKET_TERMS_SCHEMA_V1, FINDING_RECOVERY_CONTEXT_SCHEMA_V1,
    FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, FINDING_SCHEMA_V1,
    FINDING_SELLER_AUTHORIZATION_SCHEMA_V1, PURCHASE_CONTEXT_SCHEMA,
};
use chio_finding_verifier::{
    sign_finding_verifier_report, verify_finding_evidence, FindingBondSnapshot,
    FindingEvidenceBundle, FindingVerifierTrustRoots, NoNonceEvidence, ResolvedReceiptEvidence,
};
use chio_http_serve::{apply_server_hygiene, ServeHygieneConfig};
use chio_kernel::checkpoint::{
    build_checkpoint, build_checkpoint_transparency, build_inclusion_proof, checkpoint_log_id,
    KernelCheckpoint, ReceiptInclusionProof,
};
use chio_kernel::finding_purchase::FINDING_PURCHASE_CONTEXT_KEY;
use chio_kernel::finding_recovery::FINDING_RECOVERY_CONTEXT_ARGUMENT;
use chio_kernel::{
    ChioKernel, DpopConfig, DpopNonceStore, DpopProof, DpopProofBody, KernelConfig, KernelError,
    NestedFlowBridge, PaymentAdapter, PaymentAuthorization, PaymentAuthorizationState,
    PaymentAuthorizeRequest, PaymentError, PaymentRailMode, PaymentResult, RailSettlementStatus,
    ToolCallOutput, ToolCallRequest, ToolCallResponse, ToolServerConnection, Verdict,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES, DPOP_SCHEMA,
};
use chio_open_market::bidding::{
    BidMintContext, BidRequest, RequestedScope, ReservationReceipt, SignedAcceptedBid,
    SignedAskResponse, SignedBidRequest, SignedReservationReceipt, VerifiedReservationReceipt,
    BID_REQUEST_SCHEMA, RESERVATION_RECEIPT_SCHEMA,
};
use chio_open_market::fee_schedule::{
    build_open_market_fee_schedule_artifact, OpenMarketBondClass, OpenMarketBondRequirement,
    OpenMarketCollateralReferenceKind, OpenMarketEconomicsScope, OpenMarketFeeScheduleIssueRequest,
    SignedOpenMarketFeeSchedule,
};
use chio_open_market::finding_admission::{
    accept_finding_purchase, bid_with_finding_purchase, verify_finding_admission,
    FindingAdmissionContext, FindingAllocationSnapshot as SeamAllocationSnapshot,
    FindingAdmissionPenaltyGate, FindingAllocationStatus, FindingConstituentExpiryBounds,
    FindingFeeScheduleGate,
    VerifiedFindingAdmission,
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
use chio_open_market::purchase_verification::{
    derive_payment_operation_id, derive_purchase_intent_id, PurchaseVerificationAuthorities,
};
use chio_open_market::recovery::{
    mint_verified_finding_recovery_grant, verify_finding_recovery_context,
    RecoveryVerificationAuthorities, RecoveryVerificationInputs,
};
use chio_store_sqlite::finding_market_store::FindingAllocationState;
use chio_store_sqlite::{
    FindingPurchaseEncumbranceState, FindingPurchaseReservationState, FindingPurchaseSlotState,
};
use tower::ServiceExt;

use crate::trust_control::finding_purchase_coordinator::{
    derive_reservation_id, CoordinatorReservationReader, FindingPurchaseCoordinator,
    PurchaseCoordinatorError,
};
use crate::trust_control::finding_purchase_routes::{
    FindingPurchaseExecutionError, FindingPurchaseExecutor, FindingPurchaseRequest,
    FindingPurchaseResult, FindingPurchaseSettlementTerminal, FindingPurchaseVerdict,
    FindingPurchasedOutput, FINDING_PURCHASE_MAX_BODY_BYTES, FINDING_PURCHASE_RESULT_SCHEMA,
};
use crate::trust_control::finding_purchase_verifier::MarketFindingPurchaseVerifier;
use crate::trust_control::finding_recovery_verifier::MarketFindingRecoveryVerifier;
use crate::trust_control::finding_reveal_server::{
    FindingRevealServer, SealedFindingPayload, READ_FINDING_TOOL,
};

type AnyError = Box<dyn std::error::Error>;
type TestResult = Result<(), AnyError>;

const SERVICE_TOKEN: &str = "service-secret";
const VENUE_ID: &str = "venue-wedge";
const LISTING_ID: &str = "listing-finding-purchase-0001";
const SERVER_ID: &str = "finding-server.seller.example";
const PUBLISHER_OPERATOR_ID: &str = "seller-operator";
const AUDIT_POOL_PRINCIPAL: &str = "pool:audit";
const AUDIT_POOL_DESTINATION: &str = "rail:venue-ledger:audit-pool";
const COMMUNITY_FUND_DESTINATION: &str = "rail:venue-ledger:community-fund";
const PAYOUT_DESTINATION: &str = "rail:venue-ledger:seller-42";
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
const PRICE_UNITS: u64 = 300;
const RESERVATION_TTL_SECS: u64 = 3_600;
const LIABILITY_RETENTION_SECS: u64 = 604_800 + 2_592_000 + 259_200 + 86_400;
const TOKEN_ID: &str = "finding-purchase-token-0001";
const REVEAL_MEDIA_TYPE: &str = "application/json";
const SEALED_PAYLOAD: &[u8] = br#"{"repro":"baseline fails, candidate passes"}"#;
const OTHER_PAYLOAD: &[u8] = br#"{"repro":"a different payload entirely"}"#;

// ---------------------------------------------------------------------------
// Shared artifact builders
// ---------------------------------------------------------------------------

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
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

/// The exact two-field envelope the reveal server returns.
fn reveal_envelope(media_type: &str, payload: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "media_type": media_type,
        "payload_b64": STANDARD.encode(payload),
    })
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
        settlement_finality_requirement: chio_settle::FindingFinalityRequirement::Confirmations {
            min_depth: 64,
        },
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
        community_fund_destination: COMMUNITY_FUND_DESTINATION.to_string(),
        status_feed_operator_ref: "status-feed/venue-wedge".to_string(),
        fee_schedule_operator_keys: vec![keypair(24).public_key().to_hex()],
    }
}

fn market_state(
    joint: Arc<SqliteAuthorityStore>,
    config: FindingMarketConfig,
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
        finding_rail: Some(Arc::new(VenueLedgerRailObserver)),
        finding_purchase_executor: None,
    }
}

fn secure_directory(path: &std::path::Path) -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn hygiene() -> ServeHygieneConfig {
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
fn evidence_receipt(kernel: &Keypair, index: u32) -> Result<ChioReceipt, AnyError> {
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

fn recipe_environment() -> FindingRecipeEnvironment {
    FindingRecipeEnvironment {
        runtime_image_sha256: HEX64.to_string(),
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
        b"wedge baseline input bundle".to_vec(),
        b"wedge candidate input bundle".to_vec(),
        b"wedge canonical parameter bundle".to_vec(),
        b"wedge cycle-free pre-run template".to_vec(),
        b"wedge pinned runner manifest".to_vec(),
        b"wedge immutable runtime image".to_vec(),
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
    payload_sha256: &str,
    dependencies: &RecipeDependencies,
) -> FindingReplayRecipeInput {
    FindingReplayRecipeInput {
        schema: FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1.to_string(),
        decision_rule_ref: "decision/replay-v1".to_string(),
        verifier_profile_envelope_sha256: profile_envelope_sha256.to_string(),
        context_sha256: HEX64.to_string(),
        payload_sha256: payload_sha256.to_string(),
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
        environment: FindingRecipeEnvironment {
            runtime_image_sha256: dependencies.runtime_image_sha256.clone(),
            ..recipe_environment()
        },
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

/// The signed finding, committed to the exact reveal-envelope digest the
/// seller will serve rather than to a placeholder.
fn build_finding(
    issuer: &Keypair,
    replay_recipe_sha256: &str,
    receipt_ids: &[String],
    evidence_checkpoint_ref: &str,
    payload_sha256: &str,
    payload_media_type: &str,
) -> Result<Finding, AnyError> {
    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "repo:backbay/chio#cognition-market-wedge".to_string(),
            context_sha256: HEX64.to_string(),
            outcome_class: FindingOutcomeClass::VerifiedFix,
        },
        guarantee_class: FindingGuaranteeClass::DeterministicReplay,
        payload_sha256: payload_sha256.to_string(),
        payload_media_type: payload_media_type.to_string(),
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

fn build_schedule(operator: &Keypair) -> Result<SignedOpenMarketFeeSchedule, AnyError> {
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
            required_amount: usd(REQUIREMENT_UNITS),
            collateral_reference_kind: OpenMarketCollateralReferenceKind::ExternalReference,
            slashable: true,
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
        audit_epoch_length_secs: LONG_EPOCH_SECS,
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
) -> Result<SignedFindingSellerAuthorization, AnyError> {
    let mut authorization = FindingSellerAuthorization {
        schema: FINDING_SELLER_AUTHORIZATION_SCHEMA_V1.to_string(),
        authorization_id: String::new(),
        finding_id: finding.finding_id.clone(),
        finding_artifact_sha256: artifact_sha256.to_string(),
        listing_id: LISTING_ID.to_string(),
        issuer: issuer.public_key(),
        seller: seller.public_key(),
        provider_server_id: SERVER_ID.to_string(),
        provider_tool: READ_FINDING_TOOL.to_string(),
        payee: FindingPayee::Beneficiary {
            destination: PAYOUT_DESTINATION.to_string(),
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
            price_per_call: usd(PRICE_UNITS),
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
        receipts: inputs
            .receipts
            .iter()
            .map(|evidence| ResolvedReceiptEvidence {
                receipt: evidence.receipt.clone(),
                canonical_receipt_bytes: evidence.canonical_receipt_bytes.clone(),
                inclusion_proof: evidence.inclusion_proof.clone(),
            })
            .collect(),
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
        return Err(missing(
            "draft does not satisfy the required profile facets",
        ));
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
    let idempotency_key = chio_store_sqlite::finding_market_store::finding_fee_idempotency_key(
        schedule_sha256,
        &event,
        finding_id,
        LISTING_ID,
    );
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

// ---------------------------------------------------------------------------
// The artifact web behind one admitted, purchasable finding listing
// ---------------------------------------------------------------------------

/// How the seller's sealed bytes relate to what the finding committed to.
#[derive(Clone, Copy)]
struct RevealCase {
    /// Media type the signed finding advertises.
    finding_media_type: &'static str,
    /// Media type inside the envelope the finding's digest commits to.
    committed_media_type: &'static str,
    /// Payload inside the envelope the finding's digest commits to.
    committed_payload: &'static [u8],
    /// Media type the seller actually seals.
    sealed_media_type: &'static str,
    /// Payload the seller actually seals.
    sealed_payload: &'static [u8],
}

impl RevealCase {
    /// The seller serves exactly the envelope the finding committed to.
    const fn honest() -> Self {
        Self {
            finding_media_type: REVEAL_MEDIA_TYPE,
            committed_media_type: REVEAL_MEDIA_TYPE,
            committed_payload: SEALED_PAYLOAD,
            sealed_media_type: REVEAL_MEDIA_TYPE,
            sealed_payload: SEALED_PAYLOAD,
        }
    }

    /// The seller seals different bytes than the finding committed to.
    const fn digest_mismatch() -> Self {
        Self {
            sealed_payload: OTHER_PAYLOAD,
            ..Self::honest()
        }
    }

    /// The digest matches but the envelope advertises a media type the
    /// finding does not.
    const fn media_mismatch() -> Self {
        Self {
            finding_media_type: REVEAL_MEDIA_TYPE,
            committed_media_type: "text/markdown",
            committed_payload: SEALED_PAYLOAD,
            sealed_media_type: "text/markdown",
            sealed_payload: SEALED_PAYLOAD,
        }
    }
}

struct MarketWeb {
    operator: Keypair,
    venue: Keypair,
    finding: Finding,
    finding_id: String,
    raw_finding: String,
    recipe_bytes: Vec<u8>,
    recipe_sha256: String,
    recipe_dependencies: Vec<Vec<u8>>,
    profile: SignedFindingChallengeVerifierProfile,
    profile_raw: String,
    receipts: Vec<ResolvedReceiptEvidence>,
    checkpoint: KernelCheckpoint,
    schedule: SignedOpenMarketFeeSchedule,
    terms: SignedFindingMarketTerms,
    backing: SignedFindingBondBacking,
    allocation_id: String,
    listing: SignedGenericListing,
    pricing_hint: SignedListingPricingHint,
    authorization: SignedFindingSellerAuthorization,
    report: SignedFindingVerifierReport,
    admission: SignedFindingAdmission,
    admission_json: String,
    admission_sha256: String,
    scope: String,
    case: RevealCase,
}

impl MarketWeb {
    fn build(case: RevealCase) -> Result<Self, AnyError> {
        // The listing operator is also the seller: the mint issuer that the
        // listing authorizes is the same principal the seller authorization
        // names, which is what the reveal-time verifier requires.
        let operator = keypair(24);
        let governance = keypair(1);
        let issuer = keypair(3);
        let collateral = keypair(4);
        let venue = keypair(6);
        let kernel = keypair(21);

        let first = evidence_receipt(&kernel, 0)?;
        let second = evidence_receipt(&kernel, 1)?;
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

        let recipe_dependencies = recipe_dependencies();
        let profile = build_profile(
            &governance,
            log_id,
            &recipe_dependencies.runner_manifest_sha256,
        )?;
        let profile_raw = canonical_string(&profile)?;
        let profile_sha256 = sha256_hex(profile_raw.as_bytes());
        // The finding commits to the digest of the whole reveal envelope,
        // which is what the kernel compares the delivered output against,
        // and the replay recipe commits to the same payload.
        let committed_digest = digest_of(&reveal_envelope(
            case.committed_media_type,
            case.committed_payload,
        ))?;
        let recipe = build_recipe(&profile_sha256, &committed_digest, &recipe_dependencies);
        let recipe_bytes = canonical_json_bytes(&recipe)?;
        let recipe_sha256 = sha256_hex(&recipe_bytes);
        let receipt_ids = vec![first.id.clone(), second.id.clone()];
        let finding = build_finding(
            &issuer,
            &recipe_sha256,
            &receipt_ids,
            &evidence_checkpoint_ref,
            &committed_digest,
            case.finding_media_type,
        )?;
        let raw_finding = canonical_string(&finding)?;
        let artifact_sha256 = sha256_hex(raw_finding.as_bytes());

        let schedule = build_schedule(&operator)?;
        let schedule_sha256 = signed_fee_schedule_digest(&schedule)?;
        let terms = build_terms(&operator, &finding, &artifact_sha256, &profile_sha256)?;
        let terms_sha256 = digest_of(&terms)?;
        let authorization = build_authorization(&issuer, &operator, &finding, &artifact_sha256)?;
        let authorization_sha256 = digest_of(&authorization)?;
        let backing = build_backing(
            &collateral,
            &operator,
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

        let report = make_signed_report(
            &ReportInputs {
                governance: &governance,
                kernel: &kernel,
                profile: &profile,
                raw_finding: &raw_finding,
                receipts: &receipts,
                checkpoint: &checkpoint,
                recipe_bytes: &recipe_bytes,
                backing: &backing,
                collateral: &collateral,
            },
            unix_timestamp_now().saturating_add(3_600),
        )?;

        let mut admission = FindingAdmission {
            schema: FINDING_ADMISSION_SCHEMA_V1.to_string(),
            admission_id: String::new(),
            venue: venue.public_key(),
            venue_id: VENUE_ID.to_string(),
            finding_id: finding.finding_id.clone(),
            finding_artifact_sha256: artifact_sha256.clone(),
            seller_authorization_envelope_sha256: authorization_sha256.clone(),
            listing_id: LISTING_ID.to_string(),
            listing_envelope_sha256: listing_sha256.clone(),
            server_id: SERVER_ID.to_string(),
            metadata_url: metadata_url(&finding.finding_id),
            pricing_hint_envelope_sha256: hint_sha256.clone(),
            capability_scope: scope.clone(),
            publisher_operator_id: PUBLISHER_OPERATOR_ID.to_string(),
            payee_destination: PAYOUT_DESTINATION.to_string(),
            fee_schedule_envelope_sha256: schedule_sha256.clone(),
            verifier_report_id: report.body.report_id.clone(),
            verifier_report_envelope_sha256: digest_of(&report)?,
            terms_envelope_sha256: terms_sha256.clone(),
            profile_envelope_sha256: profile_sha256.clone(),
            fee_terminals: vec![
                fee_terminal_binding(
                    &schedule_sha256,
                    FindingFeeEvent::Publication,
                    usd(PUBLICATION_FEE_UNITS),
                    &finding.finding_id,
                )?,
                fee_terminal_binding(
                    &schedule_sha256,
                    FindingFeeEvent::ParticipationEpoch { epoch_index: 0 },
                    usd(PARTICIPATION_FEE_UNITS),
                    &finding.finding_id,
                )?,
            ],
            backing_allocation_id: allocation_id.clone(),
            backing_envelope_sha256: backing_sha256.clone(),
            audit_pool: FindingPoolBinding {
                principal_id: AUDIT_POOL_PRINCIPAL.to_string(),
                rail_destination: AUDIT_POOL_DESTINATION.to_string(),
                currency: "USD".to_string(),
                authority_epoch: 1,
            },
            challenge_administration_pool: FindingPoolBinding {
                principal_id: "pool:challenge-admin".to_string(),
                rail_destination: "rail:venue-ledger:challenge-admin".to_string(),
                currency: "USD".to_string(),
                authority_epoch: 1,
            },
            community_fund_destination: COMMUNITY_FUND_DESTINATION.to_string(),
            status_feed_operator_ref: "status-feed/venue-wedge".to_string(),
            purchase_authority: key_policy(16, "purchase"),
            failed_delivery_authority: key_policy(17, "failed-delivery"),
            issued_at: ISSUED_AT,
            expires_at: ADMISSION_EXPIRES_AT,
        };
        admission.admission_id = compute_admission_id(&admission)?;
        let admission: SignedFindingAdmission = SignedExportEnvelope::sign(admission, &venue)?;
        let admission_json = canonical_string(&admission)?;
        let admission_sha256 = sha256_hex(admission_json.as_bytes());

        Ok(MarketWeb {
            operator,
            venue,
            finding_id: finding.finding_id.clone(),
            finding,
            raw_finding,
            recipe_bytes,
            recipe_sha256,
            recipe_dependencies: recipe_dependencies.blobs,
            profile,
            profile_raw,
            receipts,
            checkpoint,
            schedule,
            terms,
            backing,
            allocation_id,
            listing,
            pricing_hint,
            authorization,
            report,
            admission,
            admission_json,
            admission_sha256,
            scope,
            case,
        })
    }

    fn activate_request(&self) -> Result<String, AnyError> {
        Ok(serde_json::json!({
            "admission": serde_json::to_value(&self.admission)?,
            "sellerAuthorization": serde_json::to_value(&self.authorization)?,
            "terms": serde_json::to_value(&self.terms)?,
            "backing": serde_json::to_value(&self.backing)?,
            "feeSchedule": serde_json::to_value(&self.schedule)?,
            "verifierReport": serde_json::to_value(&self.report)?,
            "listing": serde_json::to_value(&self.listing)?,
            "pricingHint": serde_json::to_value(&self.pricing_hint)?,
        })
        .to_string())
    }

    fn listing_entry(&self) -> Listing {
        Listing {
            rank: 1,
            listing: self.listing.clone(),
            pricing: self.pricing_hint.clone(),
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
        }
    }

    fn sealed_payloads(&self) -> HashMap<String, SealedFindingPayload> {
        let mut sealed = HashMap::new();
        sealed.insert(
            self.finding_id.clone(),
            SealedFindingPayload {
                media_type: self.case.sealed_media_type.to_string(),
                payload: self.case.sealed_payload.to_vec(),
            },
        );
        sealed
    }
}

// ---------------------------------------------------------------------------
// Deployment: one sqlite authority store behind both halves
// ---------------------------------------------------------------------------

struct Deployment {
    _temp: tempfile::TempDir,
    database: PathBuf,
    lock_root: PathBuf,
    receipt_db: PathBuf,
    web: MarketWeb,
}

fn provision(case: RevealCase) -> Result<Deployment, AnyError> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    std::fs::create_dir(&lock_root)?;
    secure_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let receipt_db = temp.path().join("buyer-receipts.db");
    let web = MarketWeb::build(case)?;
    Ok(Deployment {
        _temp: temp,
        database,
        lock_root,
        receipt_db,
        web,
    })
}

impl Deployment {
    fn open(&self) -> Result<Arc<SqliteAuthorityStore>, AnyError> {
        Ok(Arc::new(SqliteAuthorityStore::open_serving(
            &self.database,
            &self.lock_root,
        )?))
    }

    /// Register the profile, retain the recipe, publish the finding,
    /// register the collateral allocation, then activate the admission.
    async fn seed_and_activate(&self, state: &TrustServiceState) -> TestResult {
        // Acyclic publication order: profile, then recipe, then finding.
        let web = &self.web;
        let (status, body) = send(
            state,
            authed_post("/v1/findings/profiles", web.profile_raw.clone())?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

        let (status, body) = send(
            state,
            authed_post("/v1/findings/recipes", web.recipe_bytes.clone())?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            json_body(&body)?["canonicalSha256"],
            serde_json::json!(web.recipe_sha256)
        );

        for dependency in &web.recipe_dependencies {
            let expected_digest = sha256_hex(dependency);
            let (status, body) = send(
                state,
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
            state,
            authed_post("/v1/findings/publish", web.raw_finding.clone())?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

        let (status, body) = send(
            state,
            authed_post(
                "/v1/findings/collateral",
                serde_json::to_string(&web.backing)?,
            )?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

        let (status, body) = send(
            state,
            authed_post(
                &format!("/v1/findings/{}/activate", web.finding_id),
                web.activate_request()?,
            )?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(json_body(&body)?["outcome"], serde_json::json!("Activated"));
        Ok(())
    }
}

/// The recipe is published before the finding, so the finding's
/// deterministic-replay claim resolves. Ordering is handled by
/// `seed_and_activate`; this recovers the admitted allocation snapshot the
/// pure admission verifier needs.
fn allocation_accepted_at(
    authority: &SqliteAuthorityStore,
    web: &MarketWeb,
) -> Result<u64, AnyError> {
    let allocation = authority
        .finding_market_store()
        .get_allocation(&web.allocation_id)?
        .ok_or_else(|| missing("allocation snapshot"))?;
    assert_eq!(allocation.state, FindingAllocationState::Consumed);
    Ok(allocation.accepted_at)
}

fn admission_witness(
    web: &MarketWeb,
    accepted_at: u64,
) -> Result<VerifiedFindingAdmission, AnyError> {
    let venue_key = web.venue.public_key();
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
            allocation_id: web.allocation_id.clone(),
            backing_envelope_sha256: web.admission.body.backing_envelope_sha256.clone(),
            expires_at: web.backing.body.expires_at,
            status: FindingAllocationStatus::Consumed,
            active_admission_id: Some(web.admission.body.admission_id.clone()),
            prepared_admission_id: None,
            accepted_at,
        },
        bond_backing_observed_at: None,
        penalty_gate: FindingAdmissionPenaltyGate::Ungoverned,
        collateral_authority: &collateral_key,
        constituent_expiry_bounds: FindingConstituentExpiryBounds {
            finding: web.finding.expires_at,
            listing: web.listing.body.expires_at.unwrap_or(u64::MAX),
            pricing_hint: web.pricing_hint.body.expires_at,
            seller_authorization: web.authorization.body.expires_at,
            profile: WINDOW_EXPIRES_AT,
        },
    };
    Ok(verify_finding_admission(&web.admission, &context)?)
}

// ---------------------------------------------------------------------------
// Kernel-side wiring
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PaymentCalls {
    authorizations: AtomicU64,
    captures: AtomicU64,
    releases: AtomicU64,
}

struct ReversibleHoldAdapter {
    calls: Arc<PaymentCalls>,
}

impl PaymentAdapter for ReversibleHoldAdapter {
    fn rail_id(&self) -> &'static str {
        "wedge-reversible-hold"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::ReversibleHold)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.calls.authorizations.fetch_add(1, Ordering::SeqCst);
        Ok(PaymentAuthorization {
            authorization_id: format!("authorization:{}", request.reference),
            state: PaymentAuthorizationState::Held,
            metadata: serde_json::json!({}),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls.captures.fetch_add(1, Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: authorization_id.to_owned(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({}),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls.releases.fetch_add(1, Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: format!("release:{authorization_id}"),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({}),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_owned(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({}),
        })
    }
}

/// A final-settlement rail: it prepays, so it cannot arbitrate a compare
/// that only runs after the tool returns.
struct PrepaidFinalAdapter {
    calls: Arc<PaymentCalls>,
}

impl PaymentAdapter for PrepaidFinalAdapter {
    fn rail_id(&self) -> &'static str {
        "wedge-prepaid-final"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::PrepaidFinal)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.calls.authorizations.fetch_add(1, Ordering::SeqCst);
        Ok(PaymentAuthorization {
            authorization_id: format!("prepaid:{}", request.reference),
            state: PaymentAuthorizationState::PrepaidFinal,
            metadata: serde_json::json!({}),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls.captures.fetch_add(1, Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: authorization_id.to_owned(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({}),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls.releases.fetch_add(1, Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: format!("release:{authorization_id}"),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({}),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_owned(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({}),
        })
    }
}

/// Counts dispatches into the buyer-blind reveal server without changing
/// what it serves.
struct CountingRevealServer {
    inner: FindingRevealServer,
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingRevealServer {
    fn server_id(&self) -> &str {
        self.inner.server_id()
    }

    fn tool_names(&self) -> Vec<String> {
        self.inner.tool_names()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        self.inner
            .invoke(tool_name, arguments, nested_flow_bridge)
            .await
    }
}

/// The buyer's own memory server: it acknowledges the write the buyer
/// records after a settled reveal.
struct BuyerMemoryServer;

#[async_trait::async_trait]
impl ToolServerConnection for BuyerMemoryServer {
    fn server_id(&self) -> &str {
        "buyer-memory"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["memory_write".to_owned()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({
            "written": true,
            "id": arguments.get("id").cloned().unwrap_or(serde_json::Value::Null),
        }))
    }
}

fn kernel_config(keypair: Keypair, trusted_issuers: Vec<PublicKey>) -> KernelConfig {
    KernelConfig {
        keypair,
        ca_public_keys: trusted_issuers,
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"cognition-market-wedge-purchase-policy"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}

/// Which settlement rail the reveal kernel is wired to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Rail {
    ReversibleHold,
    PrepaidFinal,
}

struct RevealKernelInputs<'a> {
    authority: &'a SqliteAuthorityStore,
    kernel_keypair: &'a Keypair,
    web: &'a MarketWeb,
    rail: Rail,
    calls: &'a Arc<PaymentCalls>,
    invocations: &'a Arc<AtomicU64>,
    install_verifier: bool,
}

fn purchase_authorities(web: &MarketWeb) -> PurchaseVerificationAuthorities {
    PurchaseVerificationAuthorities {
        venue_authority: web.venue.public_key(),
        venue_id: VENUE_ID.to_string(),
        reservation_authority: keypair(16).public_key(),
    }
}

fn recovery_authorities(
    web: &MarketWeb,
    kernel_keypair: &Keypair,
) -> RecoveryVerificationAuthorities {
    RecoveryVerificationAuthorities {
        purchase: purchase_authorities(web),
        purchase_authority: keypair(16).public_key(),
        kernel_receipt_authority: kernel_keypair.public_key(),
        recovery_authority: web.operator.public_key(),
    }
}

fn build_reveal_kernel(inputs: &RevealKernelInputs<'_>) -> Result<ChioKernel, AnyError> {
    let mut kernel = ChioKernel::new(kernel_config(
        inputs.kernel_keypair.clone(),
        vec![inputs.web.operator.public_key()],
    ));
    kernel.set_durable_admission_store(
        Arc::new(inputs.authority.admission_operation_store()),
        Arc::new(inputs.authority.tool_outcome_store()),
        inputs.authority.mutation_fence(),
    )?;
    kernel.set_budget_store_handle(Arc::new(inputs.authority.budget_store()));
    match inputs.rail {
        Rail::ReversibleHold => kernel.set_payment_adapter(Box::new(ReversibleHoldAdapter {
            calls: inputs.calls.clone(),
        })),
        Rail::PrepaidFinal => kernel.set_payment_adapter(Box::new(PrepaidFinalAdapter {
            calls: inputs.calls.clone(),
        })),
    }
    kernel.register_tool_server(Box::new(CountingRevealServer {
        inner: FindingRevealServer::new(SERVER_ID.to_string(), inputs.web.sealed_payloads()),
        invocations: inputs.invocations.clone(),
    }));
    let dpop_config = DpopConfig::default();
    kernel.set_dpop_store(
        DpopNonceStore::new(
            dpop_config.nonce_store_capacity,
            std::time::Duration::from_secs(dpop_config.proof_ttl_secs),
        ),
        dpop_config,
    );
    if inputs.install_verifier {
        kernel.set_finding_purchase_verifier(Arc::new(MarketFindingPurchaseVerifier::new(
            purchase_authorities(inputs.web),
            CoordinatorReservationReader::shared(
                inputs.authority.finding_purchase_store(),
                inputs.authority.finding_market_store(),
            ),
        )));
        kernel.set_finding_recovery_verifier(Arc::new(MarketFindingRecoveryVerifier::new(
            recovery_authorities(inputs.web, inputs.kernel_keypair),
            inputs.authority.finding_recovery_store(),
        )));
    }
    Ok(kernel)
}

fn coordinator(authority: &SqliteAuthorityStore) -> Result<FindingPurchaseCoordinator, AnyError> {
    Ok(FindingPurchaseCoordinator::new(
        authority.finding_purchase_store(),
        authority.finding_market_store(),
        authority.admission_operation_store(),
        authority.tool_outcome_store(),
        keypair(16),
        &keypair(16).public_key(),
        keypair(17),
        &keypair(17).public_key(),
        &keypair(6).public_key(),
        VENUE_ID,
    )?)
}

// ---------------------------------------------------------------------------
// The buyer's half of the handshake
// ---------------------------------------------------------------------------

struct Handshake {
    bid: SignedBidRequest,
    ask: SignedAskResponse,
    ask_digest: String,
    buyer_signature_hex: String,
    reservation_id: String,
}

fn handshake(
    web: &MarketWeb,
    witness: &VerifiedFindingAdmission,
    buyer: &Keypair,
    agent_id: &str,
    token_id: &str,
) -> Result<Handshake, AnyError> {
    let now = unix_timestamp_now();
    handshake_at(
        web,
        witness,
        buyer,
        agent_id,
        token_id,
        now,
        usd(PRICE_UNITS),
        3_600,
    )
}

#[allow(clippy::too_many_arguments)]
fn handshake_at(
    web: &MarketWeb,
    witness: &VerifiedFindingAdmission,
    buyer: &Keypair,
    agent_id: &str,
    token_id: &str,
    now: u64,
    max_price_per_call: MonetaryAmount,
    window_seconds: u64,
) -> Result<Handshake, AnyError> {
    let bid = SignedBidRequest::sign(
        BidRequest {
            schema: BID_REQUEST_SCHEMA.to_string(),
            agent_id: agent_id.to_string(),
            listing_id: LISTING_ID.to_string(),
            max_price_per_call,
            window_seconds,
            requested_scope: RequestedScope {
                server_id: SERVER_ID.to_string(),
                tool_name: READ_FINDING_TOOL.to_string(),
                max_invocations: Some(1),
                capability_scope_prefix: web.scope.clone(),
            },
            issued_at: now,
        },
        buyer,
    )?;
    let ask = bid_with_finding_purchase(
        &bid,
        BidMintContext {
            listing: &web.listing_entry(),
            issuer_keypair: &web.operator,
            agent_subject: buyer.public_key(),
            token_id: token_id.to_string(),
            now,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
        witness,
        &web.finding,
    )?;
    let ask_digest = digest_of(&ask.body)?;
    let buyer_signature_hex = buyer.sign(ask_digest.as_bytes()).to_hex();
    let reservation_id = derive_reservation_id(&ask_digest, &buyer.public_key().to_hex());
    Ok(Handshake {
        bid,
        ask,
        ask_digest,
        buyer_signature_hex,
        reservation_id,
    })
}

struct CarrierInputs<'a> {
    web: &'a MarketWeb,
    handshake: &'a Handshake,
    accepted: &'a SignedAcceptedBid,
    reservation_receipt: &'a SignedReservationReceipt,
}

fn purchase_context_b64(inputs: &CarrierInputs<'_>) -> Result<String, AnyError> {
    let web = inputs.web;
    let context = FindingPurchaseContext {
        schema: PURCHASE_CONTEXT_SCHEMA.to_string(),
        finding_json: web.raw_finding.clone(),
        listing_envelope_json: canonical_string(&web.listing)?,
        pricing_hint_envelope_json: canonical_string(&web.pricing_hint)?,
        venue_admission_envelope_json: web.admission_json.clone(),
        market_terms_envelope_json: canonical_string(&web.terms)?,
        seller_authorization_envelope_json: canonical_string(&web.authorization)?,
        verifier_profile_envelope_json: web.profile_raw.clone(),
        seller_backing_envelope_json: canonical_string(&web.backing)?,
        verifier_report_envelope_json: canonical_string(&web.report)?,
        bid_request_envelope_json: canonical_string(&inputs.handshake.bid)?,
        ask_response_envelope_json: canonical_string(&inputs.handshake.ask)?,
        accepted_bid_envelope_json: canonical_string(inputs.accepted)?,
        reservation_receipt_envelope_json: canonical_string(inputs.reservation_receipt)?,
        reservation_store_key: inputs.handshake.reservation_id.clone(),
        token_offer_json: canonical_string(&inputs.handshake.ask.body.token_offer)?,
    };
    context.validate()?;
    Ok(STANDARD.encode(canonical_json_bytes(&context)?))
}

fn dpop_proof(
    capability: &CapabilityToken,
    buyer: &Keypair,
    tool_name: &str,
    arguments: &serde_json::Value,
    nonce: &str,
) -> Result<DpopProof, AnyError> {
    dpop_proof_at(
        capability,
        buyer,
        tool_name,
        arguments,
        nonce,
        unix_timestamp_now(),
    )
}

fn dpop_proof_at(
    capability: &CapabilityToken,
    buyer: &Keypair,
    tool_name: &str,
    arguments: &serde_json::Value,
    nonce: &str,
    issued_at: u64,
) -> Result<DpopProof, AnyError> {
    Ok(DpopProof::sign(
        DpopProofBody {
            schema: DPOP_SCHEMA.to_string(),
            capability_id: capability.id.clone(),
            tool_server: SERVER_ID.to_string(),
            tool_name: tool_name.to_string(),
            action_hash: sha256_hex(&canonical_json_bytes(arguments)?),
            nonce: nonce.to_string(),
            issued_at,
            agent_key: buyer.public_key(),
        },
        buyer,
    )?)
}

fn governed_reveal_intent(request_id: &str, context_b64: &str) -> GovernedTransactionIntent {
    GovernedTransactionIntent {
        id: format!("intent-{request_id}"),
        server_id: SERVER_ID.to_string(),
        tool_name: READ_FINDING_TOOL.to_string(),
        purpose: "purchased finding reveal".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            FINDING_PURCHASE_CONTEXT_KEY: context_b64,
        })),
        body: GovernedTransactionIntentBody::ToolInvocation,
    }
}

struct RevealRequestInputs<'a> {
    request_id: &'a str,
    capability: &'a CapabilityToken,
    buyer: &'a Keypair,
    finding_id: &'a str,
    context_b64: Option<&'a str>,
    nonce: &'a str,
}

fn reveal_request(inputs: &RevealRequestInputs<'_>) -> Result<ToolCallRequest, AnyError> {
    reveal_request_at(inputs, unix_timestamp_now())
}

fn reveal_request_at(
    inputs: &RevealRequestInputs<'_>,
    issued_at: u64,
) -> Result<ToolCallRequest, AnyError> {
    let arguments = serde_json::json!({ "finding_id": inputs.finding_id });
    let proof = dpop_proof_at(
        inputs.capability,
        inputs.buyer,
        READ_FINDING_TOOL,
        &arguments,
        inputs.nonce,
        issued_at,
    )?;
    Ok(ToolCallRequest {
        request_id: inputs.request_id.to_string(),
        capability: inputs.capability.clone(),
        tool_name: READ_FINDING_TOOL.to_string(),
        server_id: SERVER_ID.to_string(),
        agent_id: inputs.capability.subject.to_hex(),
        arguments,
        dpop_proof: Some(proof),
        execution_nonce: None,
        governed_intent: inputs
            .context_b64
            .map(|context| governed_reveal_intent(inputs.request_id, context)),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    })
}

fn delivery_contract_block(response: &ToolCallResponse) -> Result<DeliveryContract, AnyError> {
    let value = response
        .receipt
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|metadata| metadata.get(DELIVERY_CONTRACT_METADATA_KEY))
        .cloned()
        .ok_or_else(|| missing("delivery contract block is absent"))?;
    let block: DeliveryContract = serde_json::from_value(value)?;
    block.validate()?;
    Ok(block)
}

fn finding_delivery_block(response: &ToolCallResponse) -> Result<FindingDelivery, AnyError> {
    let value = response
        .receipt
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|metadata| metadata.get(FINDING_DELIVERY_METADATA_KEY))
        .cloned()
        .ok_or_else(|| missing("finding delivery block is absent"))?;
    let block: FindingDelivery = serde_json::from_value(value)?;
    block.validate()?;
    Ok(block)
}

fn denial_checkpoint(
    receipt: &ChioReceipt,
) -> Result<(KernelCheckpoint, ReceiptInclusionProof), AnyError> {
    let receipt_bytes = canonical_json_bytes(receipt)?;
    let tree = MerkleTree::from_leaves(std::slice::from_ref(&receipt_bytes))?;
    let checkpoint = build_checkpoint(1, 1, 1, std::slice::from_ref(&receipt_bytes), &keypair(40))?;
    let proof = build_inclusion_proof(&tree, 0, checkpoint.body.checkpoint_seq, 1)?;
    Ok((checkpoint, proof))
}

/// The delivered value, once the response is known to carry a value rather
/// than a stream.
fn delivered_value(response: &ToolCallResponse) -> Result<serde_json::Value, AnyError> {
    match response.output.as_ref() {
        Some(ToolCallOutput::Value(value)) => Ok(value.clone()),
        _ => Err(missing("response did not carry a delivered value")),
    }
}

fn finding_delivery_block_absent(response: &ToolCallResponse) -> bool {
    response
        .receipt
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|metadata| metadata.get(FINDING_DELIVERY_METADATA_KEY))
        .is_none()
}

fn deny_reason(response: &ToolCallResponse) -> String {
    response.reason.clone().unwrap_or_default()
}

fn assert_denied_with(response: &ToolCallResponse, fragment: &str) {
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    let reason = deny_reason(response);
    assert!(
        reason.contains(fragment),
        "expected {fragment:?} in {reason:?}"
    );
}

/// One reserved, slot-held purchase ready for reveal.
struct ReadyPurchase {
    handshake: Handshake,
    accepted_bid_envelope_sha256: String,
    context_b64: String,
    capability: CapabilityToken,
    slot_ordinal: u64,
}

fn reserve_and_accept(
    web: &MarketWeb,
    witness: &VerifiedFindingAdmission,
    coordinator: &FindingPurchaseCoordinator,
    buyer: &Keypair,
    handshake: Handshake,
) -> Result<ReadyPurchase, AnyError> {
    let now = unix_timestamp_now();
    let reservation_receipt = coordinator.reserve(
        &handshake.bid,
        &handshake.ask,
        &handshake.buyer_signature_hex,
        &web.admission,
        &web.authorization,
        EXPOSURE_UNITS,
        RESERVATION_TTL_SECS,
        now,
    )?;
    let verified =
        VerifiedReservationReceipt::from_signed(&reservation_receipt, &keypair(16).public_key())?;
    assert_eq!(verified.receipt_id(), handshake.reservation_id);
    let accepted =
        accept_finding_purchase(&handshake.ask, &verified, buyer, now, witness, &web.finding)?;
    let accepted_bid_envelope_sha256 = digest_of(&accepted)?;
    let slot_ordinal = coordinator.reserve_slot(&handshake.reservation_id, now)?;
    let context_b64 = purchase_context_b64(&CarrierInputs {
        web,
        handshake: &handshake,
        accepted: &accepted,
        reservation_receipt: &reservation_receipt,
    })?;
    let capability = handshake.ask.body.token_offer.clone();
    Ok(ReadyPurchase {
        handshake,
        accepted_bid_envelope_sha256,
        context_b64,
        capability,
        slot_ordinal,
    })
}

/// Everything one failure lane needs: an activated market, a wired kernel,
/// and a reserved purchase whose carrier is genuine.
struct Lane {
    deployment: Deployment,
    authority: Arc<SqliteAuthorityStore>,
    state: TrustServiceState,
    coordinator: FindingPurchaseCoordinator,
    kernel: ChioKernel,
    calls: Arc<PaymentCalls>,
    invocations: Arc<AtomicU64>,
    witness: VerifiedFindingAdmission,
    purchase: ReadyPurchase,
    buyer: Keypair,
}

struct LaneOptions {
    case: RevealCase,
    rail: Rail,
    install_verifier: bool,
}

impl LaneOptions {
    fn standard() -> Self {
        Self {
            case: RevealCase::honest(),
            rail: Rail::ReversibleHold,
            install_verifier: true,
        }
    }
}

async fn open_lane(options: LaneOptions) -> Result<Lane, AnyError> {
    let deployment = provision(options.case)?;
    let authority = deployment.open()?;
    let state = market_state(authority.clone(), market_config());
    state
        .config
        .finding_market
        .as_ref()
        .ok_or_else(|| missing("finding market configuration"))?
        .validate()?;
    deployment.seed_and_activate(&state).await?;
    let accepted_at = allocation_accepted_at(&authority, &deployment.web)?;
    let witness = admission_witness(&deployment.web, accepted_at)?;

    let calls = Arc::new(PaymentCalls::default());
    let invocations = Arc::new(AtomicU64::new(0));
    let kernel = build_reveal_kernel(&RevealKernelInputs {
        authority: &authority,
        kernel_keypair: &keypair(40),
        web: &deployment.web,
        rail: options.rail,
        calls: &calls,
        invocations: &invocations,
        install_verifier: options.install_verifier,
    })?;

    let buyer = keypair(31);
    let coordinator = coordinator(&authority)?;
    let exchange = handshake(&deployment.web, &witness, &buyer, "buyer-agent-7", TOKEN_ID)?;
    let purchase = reserve_and_accept(&deployment.web, &witness, &coordinator, &buyer, exchange)?;
    Ok(Lane {
        deployment,
        authority,
        state,
        coordinator,
        kernel,
        calls,
        invocations,
        witness,
        purchase,
        buyer,
    })
}

impl Lane {
    fn reveal(&self, request_id: &str, nonce: &str) -> Result<ToolCallResponse, AnyError> {
        let request = reveal_request(&RevealRequestInputs {
            request_id,
            capability: &self.purchase.capability,
            buyer: &self.buyer,
            finding_id: &self.deployment.web.finding_id,
            context_b64: Some(&self.purchase.context_b64),
            nonce,
        })?;
        Ok(self.kernel.evaluate_tool_call_blocking(&request)?)
    }
}

/// Deployment adapter used by the public-route exit. It owns the seller web,
/// buyer mapping, coordinator keys, and kernel construction, so none of those
/// artifacts become caller-authoritative request fields.
struct RoutedPurchaseExecutor {
    authority: Arc<SqliteAuthorityStore>,
    web: MarketWeb,
    witness: VerifiedFindingAdmission,
    buyer: Keypair,
    kernel_keypair: Keypair,
    calls: Arc<PaymentCalls>,
    invocations: Arc<AtomicU64>,
    attempts: Arc<AtomicU64>,
    exchange_now: u64,
    now: Arc<AtomicU64>,
}

impl RoutedPurchaseExecutor {
    fn execution_error(error: impl std::fmt::Display) -> FindingPurchaseExecutionError {
        FindingPurchaseExecutionError::Internal(error.to_string())
    }
}

#[async_trait::async_trait]
impl FindingPurchaseExecutor for RoutedPurchaseExecutor {
    async fn execute(
        &self,
        request: FindingPurchaseRequest,
    ) -> Result<FindingPurchaseResult, FindingPurchaseExecutionError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let now = self.now.load(Ordering::SeqCst);
        if request.finding_id != self.web.finding_id
            || request.max_price.currency != "USD"
            || request.max_price.units < PRICE_UNITS
        {
            return Err(FindingPurchaseExecutionError::Rejected(
                "finding or price ceiling does not match the admitted offer".to_owned(),
            ));
        }
        let payer_key = self.buyer.public_key();
        let payer = request.payer.clone().unwrap_or_else(|| payer_key.to_hex());
        if payer != payer_key.to_hex() {
            return Err(FindingPurchaseExecutionError::Rejected(
                "payer is not mapped to the authenticated buyer key".to_owned(),
            ));
        }
        let deadline_secs = request.deadline_secs.unwrap_or(RESERVATION_TTL_SECS);
        let exchange = handshake_at(
            &self.web,
            &self.witness,
            &self.buyer,
            &payer,
            TOKEN_ID,
            self.exchange_now,
            request.max_price.clone(),
            deadline_secs,
        )
        .map_err(Self::execution_error)?;
        let coordinator = coordinator(&self.authority).map_err(Self::execution_error)?;
        let reservation_receipt = match coordinator.resolve(&exchange.reservation_id) {
            Ok(reservation) => {
                let bid_envelope_sha256 =
                    digest_of(&exchange.bid).map_err(Self::execution_error)?;
                let admission_envelope_sha256 =
                    digest_of(&self.web.admission).map_err(Self::execution_error)?;
                if reservation.state != FindingPurchaseReservationState::Consumed {
                    return Err(FindingPurchaseExecutionError::Pending(
                        "durable reservation has not reached a purchase terminal".to_owned(),
                    ));
                }
                if reservation.purchase_intent_id
                    != derive_purchase_intent_id(&exchange.reservation_id)
                    || reservation.authoritative_payment_operation_id
                        != derive_payment_operation_id(&exchange.reservation_id)
                    || reservation.payer_hex != payer_key.to_hex()
                    || reservation.agent_id != exchange.ask.body.agent_id
                    || reservation.finding_id != self.web.finding_id
                    || reservation.listing_id != exchange.ask.body.listing_id
                    || reservation.bid_envelope_sha256 != bid_envelope_sha256
                    || reservation.ask_digest != exchange.ask_digest
                    || reservation.admission_envelope_sha256 != admission_envelope_sha256
                    || reservation.amount_units != exchange.ask.body.quoted_price.units
                    || reservation.currency != exchange.ask.body.quoted_price.currency
                    || reservation.created_at != self.exchange_now
                    || reservation.expires_at != self.exchange_now.saturating_add(deadline_secs)
                {
                    return Err(FindingPurchaseExecutionError::Conflict(
                        "durable reservation does not bind the public replay".to_owned(),
                    ));
                }
                SignedReservationReceipt::sign(
                    ReservationReceipt {
                        schema: RESERVATION_RECEIPT_SCHEMA.to_owned(),
                        receipt_id: exchange.reservation_id.clone(),
                        agent_id: exchange.ask.body.agent_id.clone(),
                        listing_id: exchange.ask.body.listing_id.clone(),
                        ask_digest: exchange.ask_digest.clone(),
                        reserved_amount: exchange.ask.body.quoted_price.clone(),
                    },
                    &keypair(16),
                )
                .map_err(Self::execution_error)?
            }
            Err(PurchaseCoordinatorError::UnknownReservation) => coordinator
                .reserve(
                    &exchange.bid,
                    &exchange.ask,
                    &exchange.buyer_signature_hex,
                    &self.web.admission,
                    &self.web.authorization,
                    EXPOSURE_UNITS,
                    deadline_secs,
                    now,
                )
                .map_err(Self::execution_error)?,
            Err(error) => return Err(Self::execution_error(error)),
        };
        let verified = VerifiedReservationReceipt::from_signed(
            &reservation_receipt,
            &keypair(16).public_key(),
        )
        .map_err(Self::execution_error)?;
        let accepted = accept_finding_purchase(
            &exchange.ask,
            &verified,
            &self.buyer,
            self.exchange_now,
            &self.witness,
            &self.web.finding,
        )
        .map_err(Self::execution_error)?;
        let reservation = coordinator
            .resolve(&exchange.reservation_id)
            .map_err(Self::execution_error)?;
        match reservation.state {
            FindingPurchaseReservationState::Open => {
                coordinator
                    .reserve_slot(&exchange.reservation_id, now)
                    .map_err(Self::execution_error)?;
            }
            FindingPurchaseReservationState::SlotReserved
            | FindingPurchaseReservationState::Consumed => {}
            FindingPurchaseReservationState::Released
            | FindingPurchaseReservationState::Expired => {
                return Err(FindingPurchaseExecutionError::Conflict(
                    "reservation is already closed without a purchase record".to_owned(),
                ));
            }
        }
        let context_b64 = purchase_context_b64(&CarrierInputs {
            web: &self.web,
            handshake: &exchange,
            accepted: &accepted,
            reservation_receipt: &reservation_receipt,
        })
        .map_err(Self::execution_error)?;
        let capability = exchange.ask.body.token_offer.clone();
        let reveal = reveal_request_at(
            &RevealRequestInputs {
                request_id: &request.request_id,
                capability: &capability,
                buyer: &self.buyer,
                finding_id: &self.web.finding_id,
                context_b64: Some(&context_b64),
                nonce: &request.request_id,
            },
            self.exchange_now,
        )
        .map_err(Self::execution_error)?;
        let kernel = build_reveal_kernel(&RevealKernelInputs {
            authority: &self.authority,
            kernel_keypair: &self.kernel_keypair,
            web: &self.web,
            rail: Rail::ReversibleHold,
            calls: &self.calls,
            invocations: &self.invocations,
            install_verifier: true,
        })
        .map_err(Self::execution_error)?;
        let response = kernel
            .evaluate_tool_call_blocking(&reveal)
            .map_err(Self::execution_error)?;
        if response.verdict != Verdict::Allow {
            return Err(FindingPurchaseExecutionError::Pending(
                "test adapter received a denial requiring checkpointed finalization".to_owned(),
            ));
        }
        let output = delivered_value(&response).map_err(Self::execution_error)?;
        let media_type = output
            .get("media_type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Self::execution_error("reveal media type missing"))?
            .to_owned();
        let payload_b64 = output
            .get("payload_b64")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Self::execution_error("reveal payload missing"))?
            .to_owned();
        let record = coordinator
            .finalize_delivery(
                &exchange.reservation_id,
                &response.receipt,
                &self.web.admission,
                &self.web.backing,
                now,
            )
            .map_err(Self::execution_error)?;
        Ok(FindingPurchaseResult {
            schema: FINDING_PURCHASE_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id,
            finding_id: self.web.finding_id.clone(),
            payer,
            payer_key,
            reservation_id: exchange.reservation_id.clone(),
            purchase_intent_id: record.body.purchase_intent_id.clone(),
            authoritative_payment_operation_id: record
                .body
                .authoritative_payment_operation_id
                .clone(),
            verdict: FindingPurchaseVerdict::Allow,
            settlement: FindingPurchaseSettlementTerminal::Captured,
            accepted_price: record.body.accepted_price.clone(),
            realized_spend: record.body.realized_spend.clone(),
            delivery_receipt: response.receipt,
            purchase_record: Some(record),
            failed_delivery: None,
            output: Some(FindingPurchasedOutput {
                media_type,
                payload_b64,
            }),
        })
    }
}

// ---------------------------------------------------------------------------
// The end-to-end wedge purchase
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cognition_market_live_purchase_route_exit() -> TestResult {
    let deployment = provision(RevealCase::honest())?;
    let authority = deployment.open()?;
    let mut state = market_state(authority.clone(), market_config());
    deployment.seed_and_activate(&state).await?;
    let fixed_now = unix_timestamp_now();
    let replay_now = deployment
        .web
        .admission
        .body
        .expires_at
        .max(deployment.web.finding.expires_at)
        .max(deployment.web.admission.body.purchase_authority.valid_until)
        .max(fixed_now.saturating_add(901))
        .saturating_add(1);
    let accepted_at = allocation_accepted_at(&authority, &deployment.web)?;
    let witness = admission_witness(&deployment.web, accepted_at)?;
    let buyer = keypair(31);
    let payer = buyer.public_key().to_hex();
    let request = FindingPurchaseRequest::new(
        deployment.web.finding_id.clone(),
        PRICE_UNITS + 50,
        "USD".to_owned(),
        Some(payer.clone()),
        Some(900),
    )?;
    let request_body = canonical_json_bytes(&request)?;
    let path = format!("/v1/findings/{}/purchase", deployment.web.finding_id);
    let expected_finding_id = deployment.web.finding_id.clone();

    // Authentication is checked before any request body is consumed.
    let (status, body) = send(
        &state,
        Request::builder()
            .method("POST")
            .uri(&path)
            .header("content-type", "application/json")
            .body(Body::from(vec![b' '; FINDING_PURCHASE_MAX_BODY_BYTES + 1]))?,
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        json_body(&body)?["code"],
        serde_json::json!("purchase_unauthorized")
    );

    let mut noncanonical = request_body.clone();
    noncanonical.push(b'\n');
    let (status, body) = send(&state, authed_post(&path, noncanonical)?).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(&body)?["code"],
        serde_json::json!("purchase_request_not_canonical")
    );

    let (status, body) = send(
        &state,
        authed_post(&path, vec![b' '; FINDING_PURCHASE_MAX_BODY_BYTES + 1])?,
    )
    .await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        json_body(&body)?["code"],
        serde_json::json!("purchase_request_too_large")
    );

    // Ordinary service startup is deliberately inert: no coordinator or
    // seller adapter is inferred from the mere presence of market config.
    let (status, body) = send(&state, authed_post(&path, request_body.clone())?).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(&body)?["code"],
        serde_json::json!("purchase_executor_unavailable")
    );

    // A path/body disagreement is rejected before the adapter can reserve.
    let mismatched_path = format!("/v1/findings/{}/purchase", "f".repeat(64));
    let (status, body) = send(&state, authed_post(&mismatched_path, request_body.clone())?).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(&body)?["code"],
        serde_json::json!("purchase_path_mismatch")
    );

    let calls = Arc::new(PaymentCalls::default());
    let invocations = Arc::new(AtomicU64::new(0));
    let attempts = Arc::new(AtomicU64::new(0));
    let purchase_clock = Arc::new(AtomicU64::new(fixed_now));
    state.finding_purchase_executor = Some(Arc::new(RoutedPurchaseExecutor {
        authority: authority.clone(),
        web: deployment.web,
        witness,
        buyer,
        kernel_keypair: keypair(40),
        calls: calls.clone(),
        invocations: invocations.clone(),
        attempts: attempts.clone(),
        exchange_now: fixed_now,
        now: purchase_clock.clone(),
    }));

    let (status, first_body) = send(&state, authed_post(&path, request_body.clone())?).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&first_body)
    );
    let first: FindingPurchaseResult = serde_json::from_slice(&first_body)?;
    assert_eq!(first.request_id, request.request_id);
    assert_eq!(first.finding_id, expected_finding_id);
    assert_eq!(first.payer, payer);
    assert_eq!(first.verdict, FindingPurchaseVerdict::Allow);
    assert_eq!(
        first.settlement,
        FindingPurchaseSettlementTerminal::Captured
    );
    assert_eq!(first.accepted_price, usd(PRICE_UNITS));
    assert_eq!(first.realized_spend, usd(PRICE_UNITS));
    assert_eq!(
        first.output,
        Some(FindingPurchasedOutput {
            media_type: REVEAL_MEDIA_TYPE.to_owned(),
            payload_b64: STANDARD.encode(SEALED_PAYLOAD),
        })
    );
    let record = first
        .purchase_record
        .as_ref()
        .ok_or_else(|| missing("public purchase result omitted its record"))?;
    verify_signed_purchase_record(record, &keypair(16).public_key())?;
    assert_eq!(record.body.delivery_receipt_id, first.delivery_receipt.id);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
    assert_eq!(calls.releases.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);

    let stored = authority
        .finding_purchase_store()
        .get_reservation(&first.reservation_id)?
        .ok_or_else(|| missing("public purchase reservation missing"))?;
    assert_eq!(stored.state, FindingPurchaseReservationState::Consumed);
    let slot = authority
        .finding_purchase_store()
        .get_slot(&first.reservation_id)?
        .ok_or_else(|| missing("public purchase slot missing"))?;
    assert_eq!(slot.state, FindingPurchaseSlotState::ClosedRecord);

    // The identical public request rebuilds the same signed exchange, replays
    // the durable kernel terminal, and returns byte-identical result JSON even
    // after the ask, Finding, admission, and purchase authority have expired.
    purchase_clock.store(replay_now, Ordering::SeqCst);
    let (status, replay_body) = send(&state, authed_post(&path, request_body)?).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay_body, first_body);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
    assert_eq!(calls.releases.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cognition_market_wedge_purchase_e2e() -> TestResult {
    let deployment = provision(RevealCase::honest())?;
    let calls = Arc::new(PaymentCalls::default());
    let invocations = Arc::new(AtomicU64::new(0));
    let kernel_keypair = keypair(40);
    let buyer = keypair(31);

    // Epoch one: everything runs against one open serving store.
    let (reveal, delivery_receipt, purchase) = {
        let authority = deployment.open()?;
        let state = market_state(authority.clone(), market_config());
        deployment.seed_and_activate(&state).await?;

        // Discovery: the admitted listing carries the qualified-profile
        // marker over the exact admission envelope.
        let uri = format!("/v1/findings/search?contextSha256={HEX64}&limit=50");
        let (status, body) = send(&state, public_get(&uri)?).await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let rows = json_body(&body)?;
        let row = rows["results"]
            .as_array()
            .ok_or_else(|| missing("search results array"))?
            .iter()
            .find(|row| row["findingId"] == serde_json::json!(deployment.web.finding_id))
            .cloned()
            .ok_or_else(|| missing("admitted finding missing from search"))?;
        assert_eq!(
            row["admission"]["envelopeSha256"],
            serde_json::json!(deployment.web.admission_sha256)
        );

        // The admission witness gates the marketplace bid.
        let accepted_at = allocation_accepted_at(&authority, &deployment.web)?;
        let witness = admission_witness(&deployment.web, accepted_at)?;
        assert_eq!(witness.capability_scope(), deployment.web.scope);
        assert_eq!(witness.finding_id(), deployment.web.finding_id);
        assert_eq!(witness.listing_id(), LISTING_ID);

        let exchange = handshake(&deployment.web, &witness, &buyer, "buyer-agent-7", TOKEN_ID)?;

        // The provider, not the buyer, authored the delivery bindings.
        let grant = exchange
            .ask
            .body
            .token_offer
            .scope
            .grants
            .first()
            .ok_or_else(|| missing("minted grant"))?;
        assert_eq!(grant.server_id, SERVER_ID);
        assert_eq!(grant.tool_name, READ_FINDING_TOOL);
        assert_eq!(grant.max_invocations, Some(1));
        assert_eq!(grant.dpop_required, Some(true));
        assert_eq!(grant.max_cost_per_invocation, Some(usd(PRICE_UNITS)));
        assert_eq!(grant.max_total_cost, Some(usd(PRICE_UNITS)));
        assert!(grant.constraints.iter().any(|constraint| matches!(
            constraint,
            Constraint::OutputDigestSha256(digest)
                if digest == &deployment.web.finding.payload_sha256
        )));
        assert!(grant.constraints.iter().any(|constraint| matches!(
            constraint,
            Constraint::RequireFindingPurchase(marker)
                if marker.finding_id == deployment.web.finding_id
                    && marker.listing_id == LISTING_ID
        )));

        let purchase_store = authority.finding_purchase_store();
        let coordinator = coordinator(&authority)?;
        let purchase =
            reserve_and_accept(&deployment.web, &witness, &coordinator, &buyer, exchange)?;

        // The reservation is open and holds the first pending-purchase slot.
        assert_eq!(purchase.slot_ordinal, 1);
        let reservation = purchase_store
            .get_reservation(&purchase.handshake.reservation_id)?
            .ok_or_else(|| missing("reservation record"))?;
        assert_eq!(
            reservation.state,
            FindingPurchaseReservationState::SlotReserved
        );
        assert_eq!(reservation.amount_units, PRICE_UNITS);
        assert_eq!(reservation.payer_hex, buyer.public_key().to_hex());
        let encumbrance = purchase_store
            .get_encumbrance(&purchase.handshake.reservation_id)?
            .ok_or_else(|| missing("exposure encumbrance"))?;
        assert_eq!(encumbrance.state, FindingPurchaseEncumbranceState::Open);
        let slot = purchase_store
            .get_slot(&purchase.handshake.reservation_id)?
            .ok_or_else(|| missing("pending purchase slot"))?;
        assert_eq!(slot.state, FindingPurchaseSlotState::Reserved);
        assert_eq!(slot.slot_ordinal, 1);

        // The reveal itself.
        let kernel = build_reveal_kernel(&RevealKernelInputs {
            authority: &authority,
            kernel_keypair: &kernel_keypair,
            web: &deployment.web,
            rail: Rail::ReversibleHold,
            calls: &calls,
            invocations: &invocations,
            install_verifier: true,
        })?;
        let request = reveal_request(&RevealRequestInputs {
            request_id: "wedge-reveal-1",
            capability: &purchase.capability,
            buyer: &buyer,
            finding_id: &deployment.web.finding_id,
            context_b64: Some(&purchase.context_b64),
            nonce: "wedge-reveal-nonce-1",
        })?;
        let response = kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
        assert_eq!(calls.releases.load(Ordering::SeqCst), 0);

        // The buyer received exactly the envelope the finding committed to.
        assert_eq!(
            delivered_value(&response)?,
            reveal_envelope(REVEAL_MEDIA_TYPE, SEALED_PAYLOAD)
        );
        assert_eq!(
            response.receipt.content_hash,
            deployment.web.finding.payload_sha256
        );

        let contract = delivery_contract_block(&response)?;
        assert_eq!(contract.schema, DELIVERY_CONTRACT_SCHEMA);
        assert_eq!(contract.result, DeliveryResult::Matched);
        assert_eq!(
            contract.expected_digest,
            deployment.web.finding.payload_sha256
        );
        assert_eq!(contract.observed_digest, contract.expected_digest);

        let delivery = finding_delivery_block(&response)?;
        assert_eq!(delivery.schema, FINDING_DELIVERY_SCHEMA);
        assert_eq!(delivery.finding_id, deployment.web.finding_id);
        assert_eq!(delivery.listing_id, LISTING_ID);
        assert_eq!(
            delivery.transform_profile,
            FindingTransformProfile::Identity
        );
        assert_eq!(delivery.digest_check, DeliveryResult::Matched);
        assert_eq!(delivery.media_type_check, FindingMediaTypeCheck::Matched);
        assert_eq!(
            delivery.settlement_mode,
            FindingDeliverySettlementMode::LocalReversibleHold
        );
        assert_eq!(delivery.reservation_id, purchase.handshake.reservation_id);
        assert_eq!(
            delivery.purchase_intent_id,
            derive_purchase_intent_id(&purchase.handshake.reservation_id)
        );
        assert_eq!(
            delivery.authoritative_payment_operation_id,
            derive_payment_operation_id(&purchase.handshake.reservation_id)
        );
        assert_eq!(
            delivery.accepted_bid_envelope_sha256,
            purchase.accepted_bid_envelope_sha256
        );
        assert_eq!(
            delivery.venue_admission_envelope_sha256,
            deployment.web.admission_sha256
        );

        // The buyer records the payload it just bought, under a governed
        // memory write whose lineage names the delivery receipt.
        buyer_memory_write(&deployment, &response.receipt, &buyer)?;

        let delivery_receipt = response.receipt.clone();
        (response, delivery_receipt, purchase)
    };

    // Epoch two: a restart re-opens the same store, rebuilds the kernel
    // under the same key, and re-presents the identical request.
    let authority = deployment.open()?;
    let recovered = build_reveal_kernel(&RevealKernelInputs {
        authority: &authority,
        kernel_keypair: &kernel_keypair,
        web: &deployment.web,
        rail: Rail::ReversibleHold,
        calls: &calls,
        invocations: &invocations,
        install_verifier: true,
    })?;
    let request = reveal_request(&RevealRequestInputs {
        request_id: "wedge-reveal-1",
        capability: &purchase.capability,
        buyer: &buyer,
        finding_id: &deployment.web.finding_id,
        context_b64: Some(&purchase.context_b64),
        nonce: "wedge-reveal-nonce-2",
    })?;
    let replay = recovered.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(replay.receipt.id, delivery_receipt.id);
    assert_eq!(
        canonical_json_bytes(&replay.receipt)?,
        canonical_json_bytes(&delivery_receipt)?
    );
    assert_eq!(delivered_value(&replay)?, delivered_value(&reveal)?);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
    assert_eq!(
        authority
            .finding_purchase_store()
            .get_reservation(&purchase.handshake.reservation_id)?
            .ok_or_else(|| missing("reservation after the restart"))?
            .state,
        FindingPurchaseReservationState::SlotReserved
    );
    Ok(())
}

/// Settling a delivered purchase signs the authoritative record, retains
/// the seller exposure, admits the payout destination behind the community
/// fund, and closes the pending-purchase slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_settles_into_a_signed_record() -> TestResult {
    let lane = open_lane(LaneOptions::standard()).await?;
    let response = lane.reveal("wedge-settle-1", "nonce-settle-1")?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);

    let purchase_store = lane.authority.finding_purchase_store();
    let now = unix_timestamp_now();
    let record = lane.coordinator.finalize_delivery(
        &lane.purchase.handshake.reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &lane.deployment.web.backing,
        now,
    )?;
    verify_signed_purchase_record(&record, &keypair(16).public_key())?;
    assert_eq!(
        record.body.purchase_key,
        derive_purchase_key(
            &lane.purchase.accepted_bid_envelope_sha256,
            &derive_payment_operation_id(&lane.purchase.handshake.reservation_id),
        )
    );
    assert_eq!(
        record.body.accepted_bid_envelope_sha256,
        lane.purchase.accepted_bid_envelope_sha256
    );
    assert_eq!(record.body.buyer, lane.buyer.public_key());
    assert_eq!(record.body.accepted_price, usd(PRICE_UNITS));
    assert_eq!(record.body.realized_spend, usd(PRICE_UNITS));
    assert_eq!(record.body.delivery_receipt_id, response.receipt.id);
    assert_eq!(record.body.payout_destination, PAYOUT_DESTINATION);

    let reservation = purchase_store
        .get_reservation(&lane.purchase.handshake.reservation_id)?
        .ok_or_else(|| missing("settled reservation"))?;
    assert_eq!(reservation.state, FindingPurchaseReservationState::Consumed);
    assert_eq!(record.body.recorded_at, reservation.created_at);
    assert!(
        lane.deployment
            .web
            .admission
            .body
            .purchase_authority
            .valid_from
            <= record.body.recorded_at
    );
    assert!(
        record.body.recorded_at
            <= lane
                .deployment
                .web
                .admission
                .body
                .purchase_authority
                .valid_until
    );
    let slot = purchase_store
        .get_slot(&lane.purchase.handshake.reservation_id)?
        .ok_or_else(|| missing("settled slot"))?;
    assert_eq!(slot.state, FindingPurchaseSlotState::ClosedRecord);
    let encumbrance = purchase_store
        .get_encumbrance(&lane.purchase.handshake.reservation_id)?
        .ok_or_else(|| missing("retained encumbrance"))?;
    assert_eq!(encumbrance.state, FindingPurchaseEncumbranceState::Retained);
    assert_eq!(
        encumbrance.retention_expires_at,
        Some(reservation.created_at + LIABILITY_RETENTION_SECS)
    );
    assert_eq!(
        purchase_store.list_payout_destinations(&lane.deployment.web.allocation_id)?,
        vec![(1_u8, PAYOUT_DESTINATION.to_string())],
        "the community fund pays from configuration, never from an admitted slot"
    );
    assert!(purchase_store
        .get_purchase_record(&record.body.purchase_key)?
        .is_some());

    Ok(())
}

/// The buyer's own kernel writes the purchased payload into memory and
/// records a signed lineage statement whose parent is the delivery receipt.
fn buyer_memory_write(
    deployment: &Deployment,
    delivery_receipt: &ChioReceipt,
    buyer: &Keypair,
) -> TestResult {
    let receipts = Arc::new(chio_store_sqlite::SqliteReceiptStore::open(
        &deployment.receipt_db,
    )?);
    let buyer_kernel_keypair = keypair(41);
    let mut config = kernel_config(buyer_kernel_keypair.clone(), Vec::new());
    config.checkpoint_batch_size = 0;
    let mut kernel = ChioKernel::new(config);
    kernel.set_receipt_store_handle(receipts.clone())?;
    kernel.register_tool_server(Box::new(BuyerMemoryServer));
    let capability = kernel.issue_capability(
        &buyer.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "buyer-memory".to_string(),
                tool_name: "memory_write".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::GovernedIntentRequired],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        300,
    )?;
    let arguments = serde_json::json!({
        "collection": "purchased-findings",
        "id": deployment.web.finding_id,
        "content": STANDARD.encode(SEALED_PAYLOAD),
    });
    let request = ToolCallRequest {
        request_id: "wedge-memory-write-1".to_string(),
        capability: capability.clone(),
        tool_name: "memory_write".to_string(),
        server_id: "buyer-memory".to_string(),
        agent_id: capability.subject.to_hex(),
        arguments,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-wedge-memory-write-1".to_string(),
            server_id: "buyer-memory".to_string(),
            tool_name: "memory_write".to_string(),
            purpose: "retain the purchased finding payload".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
            body: GovernedTransactionIntentBody::ToolInvocation,
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let write = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(write.verdict, Verdict::Allow, "{:?}", write.reason);
    assert!(write
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .is_some());

    let statement = ReceiptLineageStatement::sign(
        ReceiptLineageStatementBody::new(
            format!("lineage-{}", write.receipt.id),
            ReceiptLineageEndpoints::new(
                delivery_receipt.id.clone(),
                write.receipt.id.clone(),
                RequestId::new("wedge-reveal-1"),
                RequestId::new("wedge-memory-write-1"),
                SessionAnchorReference::new("anchor-reveal", HEX64),
                SessionAnchorReference::new("anchor-memory", HEX64),
            ),
            ReceiptLineageRelationKind::LocalChild,
            unix_timestamp_now(),
            buyer_kernel_keypair.public_key(),
        ),
        &buyer_kernel_keypair,
    )?;
    assert!(statement.verify_signature()?);
    let store: &dyn ReceiptStore = receipts.as_ref();
    store.record_session_anchor(
        "wedge-buyer-session",
        "anchor-memory",
        &sha256_hex(b"wedge-buyer-auth-context"),
        unix_timestamp_now(),
        None,
        &serde_json::json!({
            "schema": "chio.session_anchor.v1",
            "id": "anchor-memory",
        }),
    )?;
    store.record_receipt_lineage_statement(
        &write.receipt.id,
        Some("wedge-memory-write-1"),
        Some("wedge-buyer-session"),
        Some("anchor-memory"),
        Some("wedge-reveal-1"),
        Some(&delivery_receipt.id),
        None,
        unix_timestamp_now(),
        &serde_json::to_value(&statement)?,
    )?;
    let links = store.list_receipt_lineage_statement_links(&write.receipt.id)?;
    let link = links
        .first()
        .ok_or_else(|| missing("persisted lineage statement link"))?;
    assert_eq!(link.child_receipt_id, write.receipt.id);
    assert_eq!(
        link.parent_receipt_id.as_deref(),
        Some(delivery_receipt.id.as_str())
    );
    assert_eq!(link.statement_id.as_deref(), Some(statement.id.as_str()));
    assert_eq!(
        statement.relation_kind,
        ReceiptLineageRelationKind::LocalChild
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Failure lanes
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_digest_mismatch_denies_and_releases() -> TestResult {
    let lane = open_lane(LaneOptions {
        case: RevealCase::digest_mismatch(),
        ..LaneOptions::standard()
    })
    .await?;

    let response = lane.reveal("wedge-digest-mismatch-1", "nonce-digest-1")?;
    assert_denied_with(&response, "committed output digest");
    let contract = delivery_contract_block(&response)?;
    assert_eq!(contract.result, DeliveryResult::Mismatched);
    let delivery = finding_delivery_block(&response)?;
    assert_eq!(delivery.digest_check, DeliveryResult::Mismatched);
    assert_eq!(
        delivery.media_type_check,
        FindingMediaTypeCheck::NotEvaluated
    );
    assert_eq!(lane.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(lane.calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.releases.load(Ordering::SeqCst), 1);

    // A durable Deny cannot be selected into a paid terminal.
    let now = unix_timestamp_now();
    assert!(matches!(
        lane.coordinator.finalize_delivery(
            &lane.purchase.handshake.reservation_id,
            &response.receipt,
            &lane.deployment.web.admission,
            &lane.deployment.web.backing,
            now,
        ),
        Err(PurchaseCoordinatorError::TerminalEvidence(_))
    ));

    // The coordinator closes the purchase to its checkpointed denial terminal.
    let (checkpoint, inclusion_proof) = denial_checkpoint(&response.receipt)?;
    let mut wrong_proof = inclusion_proof.clone();
    wrong_proof.receipt_seq = wrong_proof.receipt_seq.saturating_add(1);
    assert!(matches!(
        lane.coordinator.finalize_denial(
            &lane.purchase.handshake.reservation_id,
            &response.receipt,
            &lane.deployment.web.admission,
            &checkpoint,
            &wrong_proof,
            now,
        ),
        Err(PurchaseCoordinatorError::CheckpointEvidence(_))
    ));
    let failed = lane.coordinator.finalize_denial(
        &lane.purchase.handshake.reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &checkpoint,
        &inclusion_proof,
        now,
    )?;
    verify_signed_failed_delivery(&failed, &keypair(17).public_key())?;
    assert!(!failed.body.payout_eligible);
    assert_eq!(failed.body.realized_spend_units, 0);
    assert_eq!(
        failed.body.accepted_bid_envelope_sha256,
        lane.purchase.accepted_bid_envelope_sha256
    );

    {
        let purchase_store = lane.authority.finding_purchase_store();
        let reservation = purchase_store
            .get_reservation(&lane.purchase.handshake.reservation_id)?
            .ok_or_else(|| missing("denied reservation"))?;
        assert_eq!(reservation.state, FindingPurchaseReservationState::Released);
        assert_eq!(failed.body.recorded_at, reservation.created_at);
        assert!(
            lane.deployment
                .web
                .admission
                .body
                .failed_delivery_authority
                .valid_from
                <= failed.body.recorded_at
        );
        assert!(
            failed.body.recorded_at
                <= lane
                    .deployment
                    .web
                    .admission
                    .body
                    .failed_delivery_authority
                    .valid_until
        );
        let slot = purchase_store
            .get_slot(&lane.purchase.handshake.reservation_id)?
            .ok_or_else(|| missing("denied slot"))?;
        assert_eq!(slot.state, FindingPurchaseSlotState::ClosedDeny);
        let encumbrance = purchase_store
            .get_encumbrance(&lane.purchase.handshake.reservation_id)?
            .ok_or_else(|| missing("released encumbrance"))?;
        assert_eq!(encumbrance.state, FindingPurchaseEncumbranceState::Released);
    }

    // The persisted Deny replays byte-identically after a restart, which
    // first requires every handle on the serving store to be released.
    let Lane {
        deployment,
        authority,
        state,
        coordinator,
        kernel,
        calls,
        invocations,
        witness,
        purchase,
        buyer,
    } = lane;
    drop((state, coordinator, kernel, witness, authority));
    let authority = deployment.open()?;
    let recovered = build_reveal_kernel(&RevealKernelInputs {
        authority: &authority,
        kernel_keypair: &keypair(40),
        web: &deployment.web,
        rail: Rail::ReversibleHold,
        calls: &calls,
        invocations: &invocations,
        install_verifier: true,
    })?;
    let request = reveal_request(&RevealRequestInputs {
        request_id: "wedge-digest-mismatch-1",
        capability: &purchase.capability,
        buyer: &buyer,
        finding_id: &deployment.web.finding_id,
        context_b64: Some(&purchase.context_b64),
        nonce: "nonce-digest-2",
    })?;
    let replay = recovered.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.verdict, Verdict::Deny, "{:?}", replay.reason);
    assert_eq!(
        canonical_json_bytes(&replay.receipt)?,
        canonical_json_bytes(&response.receipt)?
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_media_type_mismatch_denies() -> TestResult {
    let lane = open_lane(LaneOptions {
        case: RevealCase::media_mismatch(),
        ..LaneOptions::standard()
    })
    .await?;
    let response = lane.reveal("wedge-media-mismatch-1", "nonce-media-1")?;
    assert_denied_with(&response, "media type");
    let delivery = finding_delivery_block(&response)?;
    assert_eq!(delivery.digest_check, DeliveryResult::Matched);
    assert_eq!(delivery.media_type_check, FindingMediaTypeCheck::Mismatched);
    assert_eq!(
        delivery_contract_block(&response)?.result,
        DeliveryResult::Matched
    );
    assert_eq!(lane.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(lane.calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.releases.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_without_governed_context_denies_before_dispatch() -> TestResult {
    let lane = open_lane(LaneOptions::standard()).await?;
    let request = reveal_request(&RevealRequestInputs {
        request_id: "wedge-no-context-1",
        capability: &lane.purchase.capability,
        buyer: &lane.buyer,
        finding_id: &lane.deployment.web.finding_id,
        context_b64: None,
        nonce: "nonce-no-context-1",
    })?;
    let response = lane.kernel.evaluate_tool_call_blocking(&request)?;
    assert_denied_with(&response, "governed purchase context");
    assert_eq!(lane.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.captures.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_wrong_finding_argument_is_out_of_scope() -> TestResult {
    let lane = open_lane(LaneOptions::standard()).await?;
    let request = reveal_request(&RevealRequestInputs {
        request_id: "wedge-wrong-argument-1",
        capability: &lane.purchase.capability,
        buyer: &lane.buyer,
        finding_id: &"f".repeat(64),
        context_b64: Some(&lane.purchase.context_b64),
        nonce: "nonce-wrong-argument-1",
    })?;
    let response = lane.kernel.evaluate_tool_call_blocking(&request)?;
    assert_denied_with(&response, "is not in capability scope");
    assert_eq!(lane.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.authorizations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_alternate_token_denies() -> TestResult {
    let lane = open_lane(LaneOptions::standard()).await?;

    // A second mint for the same subject and sale: same grant profile, a
    // different token identity, so the carrier's ask no longer names it.
    let alternate = handshake(
        &lane.deployment.web,
        &lane.witness,
        &lane.buyer,
        "buyer-agent-7",
        "finding-purchase-token-0002",
    )?;
    assert_ne!(
        alternate.ask.body.token_offer.id,
        lane.purchase.capability.id
    );
    let request = reveal_request(&RevealRequestInputs {
        request_id: "wedge-alternate-token-1",
        capability: &alternate.ask.body.token_offer,
        buyer: &lane.buyer,
        finding_id: &lane.deployment.web.finding_id,
        context_b64: Some(&lane.purchase.context_b64),
        nonce: "nonce-alternate-token-1",
    })?;
    let response = lane.kernel.evaluate_tool_call_blocking(&request)?;
    assert_denied_with(&response, "exact ask token offer");
    assert_eq!(lane.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.authorizations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_on_a_prepaid_final_rail_denies_before_dispatch() -> TestResult {
    let lane = open_lane(LaneOptions {
        rail: Rail::PrepaidFinal,
        ..LaneOptions::standard()
    })
    .await?;
    let response = lane.reveal("wedge-prepaid-1", "nonce-prepaid-1")?;
    assert_denied_with(&response, "reversible-hold");
    assert_eq!(lane.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.captures.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_without_a_verifier_denies() -> TestResult {
    let lane = open_lane(LaneOptions {
        install_verifier: false,
        ..LaneOptions::standard()
    })
    .await?;
    let response = lane.reveal("wedge-no-verifier-1", "nonce-no-verifier-1")?;
    assert_denied_with(&response, "configured purchase verifier");
    assert_eq!(lane.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.authorizations.load(Ordering::SeqCst), 0);
    Ok(())
}

fn finding_recovery_request(
    request_id: &str,
    capability: &CapabilityToken,
    buyer: &Keypair,
    finding_id: &str,
    context_b64: &str,
    nonce: &str,
) -> Result<ToolCallRequest, AnyError> {
    let arguments = serde_json::json!({
        "finding_id": finding_id,
        FINDING_RECOVERY_CONTEXT_ARGUMENT: context_b64,
    });
    let proof = dpop_proof(capability, buyer, READ_FINDING_TOOL, &arguments, nonce)?;
    Ok(ToolCallRequest {
        request_id: request_id.to_owned(),
        capability: capability.clone(),
        tool_name: READ_FINDING_TOOL.to_owned(),
        server_id: SERVER_ID.to_owned(),
        agent_id: capability.subject.to_hex(),
        arguments,
        dpop_proof: Some(proof),
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    })
}

fn legacy_custom_recovery_token(
    subject: PublicKey,
    issuer: &Keypair,
    token_id: &str,
    finding_id: &str,
    payload_sha256: &str,
    original_receipt_id: &str,
    original_capability_id: &str,
    now: u64,
) -> Result<CapabilityToken, AnyError> {
    Ok(CapabilityToken::sign(
        CapabilityTokenBody {
            id: token_id.to_owned(),
            issuer: issuer.public_key(),
            subject,
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: SERVER_ID.to_owned(),
                    tool_name: READ_FINDING_TOOL.to_owned(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![
                        Constraint::OutputDigestSha256(payload_sha256.to_owned()),
                        Constraint::Custom(
                            "recovery_of_receipt_id".to_owned(),
                            original_receipt_id.to_owned(),
                        ),
                        Constraint::Custom(
                            "recovery_of_capability_id".to_owned(),
                            original_capability_id.to_owned(),
                        ),
                        Constraint::Custom("finding_id".to_owned(), finding_id.to_owned()),
                    ],
                    max_invocations: Some(2),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: Some(true),
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at: now.saturating_sub(5),
            expires_at: now.saturating_add(600),
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        issuer,
    )?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_recovery_grant_redelivers_without_charging() -> TestResult {
    let lane = open_lane(LaneOptions::standard()).await?;
    let finding_id = lane.deployment.web.finding_id.clone();
    let payload_sha256 = lane.deployment.web.finding.payload_sha256.clone();

    // An out-of-scope request denies before any budget or payment
    // mutation, so it yields a Deny receipt without disturbing the
    // one-shot purchase grant under test.
    let denied =
        lane.kernel
            .evaluate_tool_call_blocking(&reveal_request(&RevealRequestInputs {
                request_id: "wedge-recovery-denied-1",
                capability: &lane.purchase.capability,
                buyer: &lane.buyer,
                finding_id: &"f".repeat(64),
                context_b64: Some(&lane.purchase.context_b64),
                nonce: "nonce-recovery-denied-1",
            })?)?;
    assert_eq!(denied.verdict, Verdict::Deny, "{:?}", denied.reason);

    let response = lane.reveal("wedge-recovery-origin-1", "nonce-recovery-1")?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(lane.calls.captures.load(Ordering::SeqCst), 1);

    let now = unix_timestamp_now();
    let purchase_record = lane.coordinator.finalize_delivery(
        &lane.purchase.handshake.reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &lane.deployment.web.backing,
        now,
    )?;
    let recovery_id = derive_finding_recovery_id(
        &lane.purchase.capability.id,
        &purchase_record.body.purchase_key,
        &response.receipt.id,
    );
    let context = FindingRecoveryContext {
        schema: FINDING_RECOVERY_CONTEXT_SCHEMA_V1.to_owned(),
        recovery_id: recovery_id.clone(),
        original_capability_json: String::from_utf8(canonical_json_bytes(
            &lane.purchase.capability,
        )?)?,
        purchase_context_json: String::from_utf8(STANDARD.decode(&lane.purchase.context_b64)?)?,
        purchase_record_envelope_json: String::from_utf8(canonical_json_bytes(&purchase_record)?)?,
        original_delivery_receipt_json: String::from_utf8(canonical_json_bytes(
            &response.receipt,
        )?)?,
    };
    let context_b64 = STANDARD.encode(canonical_json_bytes(&context)?);
    let marker = FindingRecoveryMarkerV1 {
        recovery_id,
        finding_id: finding_id.clone(),
        listing_id: LISTING_ID.to_owned(),
        original_capability_id: lane.purchase.capability.id.clone(),
        original_delivery_receipt_id: response.receipt.id.clone(),
        purchase_key: purchase_record.body.purchase_key.clone(),
        max_recoveries: 2,
    };
    let verification_arguments = serde_json::json!({
        "finding_id": finding_id,
        FINDING_RECOVERY_CONTEXT_ARGUMENT: context_b64,
    });
    let recovery_context_b64 = verification_arguments[FINDING_RECOVERY_CONTEXT_ARGUMENT]
        .as_str()
        .ok_or_else(|| missing("recovery context"))?;
    let authorities = recovery_authorities(&lane.deployment.web, &keypair(40));
    let recovery_subject = lane.buyer.public_key();
    let recovery_issuer = lane.deployment.web.operator.public_key();
    let verified = verify_finding_recovery_context(
        &RecoveryVerificationInputs {
            marker: &marker,
            context_b64: recovery_context_b64,
            recovery_subject: &recovery_subject,
            recovery_issuer: &recovery_issuer,
            server_id: SERVER_ID,
            tool_name: READ_FINDING_TOOL,
            arguments: &verification_arguments,
            expected_output_digest: &payload_sha256,
        },
        &authorities,
    )?;

    let mut substituted_marker = marker.clone();
    substituted_marker.original_delivery_receipt_id = denied.receipt.id.clone();
    assert!(verify_finding_recovery_context(
        &RecoveryVerificationInputs {
            marker: &substituted_marker,
            context_b64: recovery_context_b64,
            recovery_subject: &recovery_subject,
            recovery_issuer: &recovery_issuer,
            server_id: SERVER_ID,
            tool_name: READ_FINDING_TOOL,
            arguments: &verification_arguments,
            expected_output_digest: &payload_sha256,
        },
        &authorities,
    )
    .is_err());

    let recovery_service = MarketFindingRecoveryVerifier::new(
        authorities.clone(),
        lane.authority.finding_recovery_store(),
    );
    let recovery = recovery_service.issue_and_mint(
        &verified,
        &lane.deployment.web.operator,
        "recovery-token-0001".to_owned(),
        2,
        now.saturating_sub(5),
        now.saturating_add(600),
    )?;

    let legacy = legacy_custom_recovery_token(
        lane.buyer.public_key(),
        &lane.deployment.web.operator,
        "legacy-recovery-token-1",
        &finding_id,
        &payload_sha256,
        &response.receipt.id,
        &lane.purchase.capability.id,
        now,
    )?;
    let legacy_arguments = serde_json::json!({
        "finding_id": finding_id,
        "recovery_of_receipt_id": response.receipt.id,
        "recovery_of_capability_id": lane.purchase.capability.id,
    });
    let mut legacy_request = finding_recovery_request(
        "wedge-legacy-recovery-1",
        &legacy,
        &lane.buyer,
        &finding_id,
        recovery_context_b64,
        "nonce-unused-legacy",
    )?;
    legacy_request.dpop_proof = Some(dpop_proof(
        &legacy,
        &lane.buyer,
        READ_FINDING_TOOL,
        &legacy_arguments,
        "nonce-legacy-recovery-1",
    )?);
    legacy_request.arguments = legacy_arguments;
    assert_eq!(
        lane.kernel
            .evaluate_tool_call_blocking(&legacy_request)?
            .verdict,
        Verdict::Deny
    );

    let self_minted = mint_verified_finding_recovery_grant(
        &verified,
        &lane.buyer,
        "buyer-self-minted-recovery".to_owned(),
        2,
        now.saturating_sub(5),
        now.saturating_add(3_600),
    )?;
    assert_eq!(
        lane.kernel
            .evaluate_tool_call_blocking(&finding_recovery_request(
                "wedge-self-minted-recovery-1",
                &self_minted,
                &lane.buyer,
                &finding_id,
                recovery_context_b64,
                "nonce-self-minted-recovery-1",
            )?)?
            .verdict,
        Verdict::Deny,
    );

    let request = finding_recovery_request(
        "wedge-recovery-1",
        &recovery,
        &lane.buyer,
        &finding_id,
        recovery_context_b64,
        "nonce-recovery-grant-1",
    )?;
    let recovered = lane.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(recovered.verdict, Verdict::Allow, "{:?}", recovered.reason);
    assert_eq!(
        delivery_contract_block(&recovered)?.result,
        DeliveryResult::Matched
    );
    assert!(finding_delivery_block_absent(&recovered));
    assert_eq!(
        delivered_value(&recovered)?,
        reveal_envelope(REVEAL_MEDIA_TYPE, SEALED_PAYLOAD)
    );
    assert_eq!(lane.calls.captures.load(Ordering::SeqCst), 1);

    let restarted = build_reveal_kernel(&RevealKernelInputs {
        authority: &lane.authority,
        kernel_keypair: &keypair(40),
        web: &lane.deployment.web,
        rail: Rail::ReversibleHold,
        calls: &lane.calls,
        invocations: &lane.invocations,
        install_verifier: true,
    })?;
    let legacy_remint = legacy_custom_recovery_token(
        lane.buyer.public_key(),
        &lane.deployment.web.operator,
        "legacy-recovery-token-2",
        &finding_id,
        &payload_sha256,
        &response.receipt.id,
        &lane.purchase.capability.id,
        now,
    )?;
    let legacy_remint_arguments = serde_json::json!({
        "finding_id": finding_id,
        "recovery_of_receipt_id": response.receipt.id,
        "recovery_of_capability_id": lane.purchase.capability.id,
    });
    let mut legacy_remint_request = finding_recovery_request(
        "wedge-legacy-recovery-2",
        &legacy_remint,
        &lane.buyer,
        &finding_id,
        recovery_context_b64,
        "nonce-unused-legacy-remint",
    )?;
    legacy_remint_request.dpop_proof = Some(dpop_proof(
        &legacy_remint,
        &lane.buyer,
        READ_FINDING_TOOL,
        &legacy_remint_arguments,
        "nonce-legacy-recovery-2",
    )?);
    legacy_remint_request.arguments = legacy_remint_arguments;
    assert_eq!(
        restarted
            .evaluate_tool_call_blocking(&legacy_remint_request)?
            .verdict,
        Verdict::Deny
    );

    let remint = recovery_service.issue_and_mint(
        &verified,
        &lane.deployment.web.operator,
        "recovery-token-0002".to_owned(),
        2,
        now,
        now.saturating_add(600),
    )?;
    let second = restarted.evaluate_tool_call_blocking(&finding_recovery_request(
        "wedge-recovery-2",
        &remint,
        &lane.buyer,
        &finding_id,
        recovery_context_b64,
        "nonce-recovery-grant-2",
    )?)?;
    assert_eq!(second.verdict, Verdict::Allow, "{:?}", second.reason);
    let exhausted = restarted.evaluate_tool_call_blocking(&finding_recovery_request(
        "wedge-recovery-3",
        &remint,
        &lane.buyer,
        &finding_id,
        recovery_context_b64,
        "nonce-recovery-grant-3",
    )?)?;
    assert_denied_with(&exhausted, "quota");
    assert_eq!(lane.calls.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(lane.calls.captures.load(Ordering::SeqCst), 1);
    assert_eq!(lane.invocations.load(Ordering::SeqCst), 3);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_reservation_authenticates_the_buyer_and_replays() -> TestResult {
    let deployment = provision(RevealCase::honest())?;
    let authority = deployment.open()?;
    let state = market_state(authority.clone(), market_config());
    deployment.seed_and_activate(&state).await?;
    let accepted_at = allocation_accepted_at(&authority, &deployment.web)?;
    let witness = admission_witness(&deployment.web, accepted_at)?;
    let buyer = keypair(31);
    let coordinator = coordinator(&authority)?;
    let exchange = handshake(&deployment.web, &witness, &buyer, "buyer-agent-7", TOKEN_ID)?;

    // A signature by a key that is not the token subject never reserves.
    let interloper = keypair(9).sign(exchange.ask_digest.as_bytes()).to_hex();
    let rejected = coordinator.reserve(
        &exchange.bid,
        &exchange.ask,
        &interloper,
        &deployment.web.admission,
        &deployment.web.authorization,
        EXPOSURE_UNITS,
        RESERVATION_TTL_SECS,
        unix_timestamp_now(),
    );
    assert!(matches!(
        rejected,
        Err(PurchaseCoordinatorError::BuyerSignature)
    ));
    assert!(authority
        .finding_purchase_store()
        .get_reservation(&exchange.reservation_id)?
        .is_none());

    // Reserving the same ask for the same payer twice is idempotent.
    let now = unix_timestamp_now();
    let first = coordinator.reserve(
        &exchange.bid,
        &exchange.ask,
        &exchange.buyer_signature_hex,
        &deployment.web.admission,
        &deployment.web.authorization,
        EXPOSURE_UNITS,
        RESERVATION_TTL_SECS,
        now,
    )?;
    let second = coordinator.reserve(
        &exchange.bid,
        &exchange.ask,
        &exchange.buyer_signature_hex,
        &deployment.web.admission,
        &deployment.web.authorization,
        EXPOSURE_UNITS,
        RESERVATION_TTL_SECS,
        now,
    )?;
    assert_eq!(
        canonical_json_bytes(&first)?,
        canonical_json_bytes(&second)?
    );
    assert_eq!(first.body.receipt_id, exchange.reservation_id);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_second_reservation_overcommits_the_allocation() -> TestResult {
    let deployment = provision(RevealCase::honest())?;
    let authority = deployment.open()?;
    let state = market_state(authority.clone(), market_config());
    deployment.seed_and_activate(&state).await?;
    let accepted_at = allocation_accepted_at(&authority, &deployment.web)?;
    let witness = admission_witness(&deployment.web, accepted_at)?;
    let purchase_store = authority.finding_purchase_store();
    let coordinator = coordinator(&authority)?;

    let first_buyer = keypair(31);
    let first = handshake(
        &deployment.web,
        &witness,
        &first_buyer,
        "buyer-agent-7",
        TOKEN_ID,
    )?;
    coordinator.reserve(
        &first.bid,
        &first.ask,
        &first.buyer_signature_hex,
        &deployment.web.admission,
        &deployment.web.authorization,
        EXPOSURE_UNITS,
        RESERVATION_TTL_SECS,
        unix_timestamp_now(),
    )?;

    // Two sales at the quoted price exceed the allocation's exposure cap.
    let second_buyer = keypair(32);
    let second = handshake(
        &deployment.web,
        &witness,
        &second_buyer,
        "buyer-agent-8",
        "finding-purchase-token-0003",
    )?;
    let overcommitted = coordinator.reserve(
        &second.bid,
        &second.ask,
        &second.buyer_signature_hex,
        &deployment.web.admission,
        &deployment.web.authorization,
        EXPOSURE_UNITS,
        RESERVATION_TTL_SECS,
        unix_timestamp_now(),
    );
    let Err(PurchaseCoordinatorError::Store(reason)) = overcommitted else {
        return Err(missing("second reservation must overcommit the allocation"));
    };
    assert!(reason.contains("exposure"), "{reason}");
    assert!(purchase_store
        .get_reservation(&second.reservation_id)?
        .is_none());
    let surviving = purchase_store
        .get_reservation(&first.reservation_id)?
        .ok_or_else(|| missing("first reservation"))?;
    assert_eq!(surviving.state, FindingPurchaseReservationState::Open);
    assert_eq!(
        purchase_store
            .list_outstanding_exposure_total(&deployment.web.allocation_id, unix_timestamp_now())?,
        PRICE_UNITS
    );
    Ok(())
}

/// One activated market, one coordinator, and one genuine handshake: the
/// whole surface a reserve-time refusal needs.
struct ReserveFixture {
    deployment: Deployment,
    authority: Arc<SqliteAuthorityStore>,
    coordinator: FindingPurchaseCoordinator,
    exchange: Handshake,
}

async fn open_reserve_fixture() -> Result<ReserveFixture, AnyError> {
    let deployment = provision(RevealCase::honest())?;
    let authority = deployment.open()?;
    let state = market_state(authority.clone(), market_config());
    deployment.seed_and_activate(&state).await?;
    let accepted_at = allocation_accepted_at(&authority, &deployment.web)?;
    let witness = admission_witness(&deployment.web, accepted_at)?;
    let coordinator = coordinator(&authority)?;
    let exchange = handshake(
        &deployment.web,
        &witness,
        &keypair(31),
        "buyer-agent-7",
        TOKEN_ID,
    )?;
    Ok(ReserveFixture {
        deployment,
        authority,
        coordinator,
        exchange,
    })
}

impl ReserveFixture {
    fn reserve_with(
        &self,
        admission: &SignedFindingAdmission,
        now: u64,
    ) -> Result<SignedReservationReceipt, PurchaseCoordinatorError> {
        self.coordinator.reserve(
            &self.exchange.bid,
            &self.exchange.ask,
            &self.exchange.buyer_signature_hex,
            admission,
            &self.deployment.web.authorization,
            EXPOSURE_UNITS,
            RESERVATION_TTL_SECS,
            now,
        )
    }
}

/// The admission chooses the finding and the collateral allocation the
/// reservation binds, so an admission that does not verify under the
/// pinned venue authority, or that is outside its own window, opens
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_reserve_refuses_an_unverified_venue_admission() -> TestResult {
    let fixture = open_reserve_fixture().await?;
    let purchase_store = fixture.authority.finding_purchase_store();
    let now = unix_timestamp_now();

    // The same body, signed by a key that is not the venue authority.
    let forged: SignedFindingAdmission =
        SignedExportEnvelope::sign(fixture.deployment.web.admission.body.clone(), &keypair(9))?;
    assert!(matches!(
        fixture.reserve_with(&forged, now),
        Err(PurchaseCoordinatorError::AdmissionEnvelope(_))
    ));

    // The venue's signature, over a body that now names a different
    // collateral allocation.
    let mut redirected = fixture.deployment.web.admission.clone();
    redirected.body.backing_allocation_id = HEX64.to_string();
    assert!(matches!(
        fixture.reserve_with(&redirected, now),
        Err(PurchaseCoordinatorError::AdmissionEnvelope(_))
    ));

    // A genuinely venue-signed admission whose window has closed.
    let mut lapsed_body = fixture.deployment.web.admission.body.clone();
    lapsed_body.expires_at = now.saturating_sub(1);
    lapsed_body.admission_id = compute_admission_id(&lapsed_body)?;
    let lapsed: SignedFindingAdmission =
        SignedExportEnvelope::sign(lapsed_body, &fixture.deployment.web.venue)?;
    assert!(matches!(
        fixture.reserve_with(&lapsed, now),
        Err(PurchaseCoordinatorError::AdmissionWindow)
    ));

    assert!(purchase_store
        .get_reservation(&fixture.exchange.reservation_id)?
        .is_none());
    assert_eq!(
        purchase_store
            .list_outstanding_exposure_total(&fixture.deployment.web.allocation_id, now)?,
        0
    );

    // The admission the venue actually issued still reserves.
    let receipt = fixture.reserve_with(&fixture.deployment.web.admission, now)?;
    assert_eq!(receipt.body.receipt_id, fixture.exchange.reservation_id);
    let reservation = purchase_store
        .get_reservation(&fixture.exchange.reservation_id)?
        .ok_or_else(|| missing("reservation under the genuine admission"))?;
    assert_eq!(reservation.finding_id, fixture.deployment.web.finding_id);
    Ok(())
}

/// The admission declares which keys hold the purchase and failed-delivery
/// authorities and for what window, and downstream standing verification
/// accepts a settlement artifact only when the declared key signed it at an
/// instant the declared window covers. Reserve fixes that instant, so
/// reserve must refuse a coordinator signing under any other key and an
/// instant outside either declared window; otherwise the sale settles into
/// artifacts that grant the paying buyer no standing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_reserve_binds_the_declared_settlement_authorities() -> TestResult {
    let fixture = open_reserve_fixture().await?;
    let purchase_store = fixture.authority.finding_purchase_store();
    let now = unix_timestamp_now();

    // A coordinator holding a purchase key the admission never declared.
    let drifted_purchase = FindingPurchaseCoordinator::new(
        purchase_store.clone(),
        fixture.authority.finding_market_store(),
        fixture.authority.admission_operation_store(),
        fixture.authority.tool_outcome_store(),
        keypair(18),
        &keypair(18).public_key(),
        keypair(17),
        &keypair(17).public_key(),
        &keypair(6).public_key(),
        VENUE_ID,
    )?;
    assert!(matches!(
        drifted_purchase.reserve(
            &fixture.exchange.bid,
            &fixture.exchange.ask,
            &fixture.exchange.buyer_signature_hex,
            &fixture.deployment.web.admission,
            &fixture.deployment.web.authorization,
            EXPOSURE_UNITS,
            RESERVATION_TTL_SECS,
            now,
        ),
        Err(PurchaseCoordinatorError::DeclaredAuthorityMismatch(
            "purchase"
        ))
    ));

    // A coordinator holding a failed-delivery key the admission never
    // declared.
    let drifted_failed_delivery = FindingPurchaseCoordinator::new(
        purchase_store.clone(),
        fixture.authority.finding_market_store(),
        fixture.authority.admission_operation_store(),
        fixture.authority.tool_outcome_store(),
        keypair(16),
        &keypair(16).public_key(),
        keypair(19),
        &keypair(19).public_key(),
        &keypair(6).public_key(),
        VENUE_ID,
    )?;
    assert!(matches!(
        drifted_failed_delivery.reserve(
            &fixture.exchange.bid,
            &fixture.exchange.ask,
            &fixture.exchange.buyer_signature_hex,
            &fixture.deployment.web.admission,
            &fixture.deployment.web.authorization,
            EXPOSURE_UNITS,
            RESERVATION_TTL_SECS,
            now,
        ),
        Err(PurchaseCoordinatorError::DeclaredAuthorityMismatch(
            "failed-delivery"
        ))
    ));

    // A venue-signed admission whose declared purchase window has lapsed
    // by the reservation instant.
    let mut lapsed_body = fixture.deployment.web.admission.body.clone();
    lapsed_body.purchase_authority.valid_until = ISSUED_AT.saturating_add(1);
    lapsed_body.admission_id = compute_admission_id(&lapsed_body)?;
    let lapsed: SignedFindingAdmission =
        SignedExportEnvelope::sign(lapsed_body, &fixture.deployment.web.venue)?;
    assert!(matches!(
        fixture.reserve_with(&lapsed, now),
        Err(PurchaseCoordinatorError::DeclaredAuthorityWindow(
            "purchase"
        ))
    ));
    let mut future_body = fixture.deployment.web.admission.body.clone();
    future_body.purchase_authority.valid_from = now.saturating_add(1);
    future_body.admission_id = compute_admission_id(&future_body)?;
    let future: SignedFindingAdmission =
        SignedExportEnvelope::sign(future_body, &fixture.deployment.web.venue)?;
    assert!(matches!(
        fixture.reserve_with(&future, now),
        Err(PurchaseCoordinatorError::DeclaredAuthorityWindow(
            "purchase"
        ))
    ));
    let mut failed_lapsed_body = fixture.deployment.web.admission.body.clone();
    failed_lapsed_body.failed_delivery_authority.valid_until = ISSUED_AT.saturating_add(1);
    failed_lapsed_body.admission_id = compute_admission_id(&failed_lapsed_body)?;
    let failed_lapsed: SignedFindingAdmission =
        SignedExportEnvelope::sign(failed_lapsed_body, &fixture.deployment.web.venue)?;
    assert!(matches!(
        fixture.reserve_with(&failed_lapsed, now),
        Err(PurchaseCoordinatorError::DeclaredAuthorityWindow(
            "failed-delivery"
        ))
    ));

    // No refusal opened durable state; the declared coordinator still
    // reserves under the genuine admission.
    assert!(purchase_store
        .get_reservation(&fixture.exchange.reservation_id)?
        .is_none());
    fixture.reserve_with(&fixture.deployment.web.admission, now)?;
    assert!(purchase_store
        .get_reservation(&fixture.exchange.reservation_id)?
        .is_some());
    Ok(())
}

/// An ask outside its own window never opens a reservation: the seller's
/// collateral would be held for a full TTL against a quote that no longer
/// stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_reserve_refuses_an_ask_outside_its_window() -> TestResult {
    let fixture = open_reserve_fixture().await?;
    let purchase_store = fixture.authority.finding_purchase_store();
    let issued_at = fixture.exchange.ask.body.issued_at;
    let expires_at = fixture.exchange.ask.body.expires_at;
    for now in [
        issued_at.saturating_sub(1),
        expires_at,
        expires_at.saturating_add(LONG_EPOCH_SECS),
    ] {
        assert!(
            matches!(
                fixture.reserve_with(&fixture.deployment.web.admission, now),
                Err(PurchaseCoordinatorError::AskWindow)
            ),
            "ask must not reserve at {now}"
        );
    }
    assert!(purchase_store
        .get_reservation(&fixture.exchange.reservation_id)?
        .is_none());
    assert_eq!(
        purchase_store
            .list_outstanding_exposure_total(&fixture.deployment.web.allocation_id, issued_at)?,
        0
    );

    // The same ask inside its window reserves.
    fixture.reserve_with(&fixture.deployment.web.admission, issued_at)?;
    assert!(purchase_store
        .get_reservation(&fixture.exchange.reservation_id)?
        .is_some());
    Ok(())
}

/// Reserve must bind the ask to a minter the finding issuer authorized:
/// otherwise any holder of the live admission envelope can re-mint the
/// token under its own issuer key, to itself, at its own price, and book
/// exposure against the seller's collateral allocation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_reserve_refuses_a_self_minted_ask() -> TestResult {
    let fixture = open_reserve_fixture().await?;
    let purchase_store = fixture.authority.finding_purchase_store();
    let now = unix_timestamp_now();

    let interloper = keypair(9);
    let mut forged_body = fixture.exchange.ask.body.clone();
    let mut token = forged_body.token_offer.clone();
    token.issuer = interloper.public_key();
    token.subject = interloper.public_key();
    for grant in &mut token.scope.grants {
        grant.max_cost_per_invocation = Some(usd(1));
        grant.max_total_cost = Some(usd(1));
    }
    forged_body.token_offer = CapabilityToken::sign(token.body(), &interloper)?;
    forged_body.quoted_price = usd(1);
    let forged: SignedAskResponse = SignedExportEnvelope::sign(forged_body, &interloper)?;
    let forged_bid = SignedBidRequest::sign(fixture.exchange.bid.body.clone(), &interloper)?;
    let forged_digest = digest_of(&forged.body)?;
    let forged_signature = interloper.sign(forged_digest.as_bytes()).to_hex();

    assert!(matches!(
        fixture.coordinator.reserve(
            &forged_bid,
            &forged,
            &forged_signature,
            &fixture.deployment.web.admission,
            &fixture.deployment.web.authorization,
            EXPOSURE_UNITS,
            RESERVATION_TTL_SECS,
            now,
        ),
        Err(PurchaseCoordinatorError::AskMinterUnauthorized)
    ));
    let forged_reservation_id =
        derive_reservation_id(&forged_digest, &interloper.public_key().to_hex());
    assert!(purchase_store
        .get_reservation(&forged_reservation_id)?
        .is_none());
    assert_eq!(
        purchase_store
            .list_outstanding_exposure_total(&fixture.deployment.web.allocation_id, now)?,
        0
    );

    // A seller authorization that is not the admission-bound envelope
    // refuses even when internally valid.
    let unrelated = build_authorization(
        &keypair(3),
        &keypair(9),
        &fixture.deployment.web.finding,
        &sha256_hex(fixture.deployment.web.raw_finding.as_bytes()),
    )?;
    assert!(matches!(
        fixture.coordinator.reserve(
            &fixture.exchange.bid,
            &fixture.exchange.ask,
            &fixture.exchange.buyer_signature_hex,
            &fixture.deployment.web.admission,
            &unrelated,
            EXPOSURE_UNITS,
            RESERVATION_TTL_SECS,
            now,
        ),
        Err(PurchaseCoordinatorError::SellerAuthorizationBinding)
    ));

    // The authorized minter's genuine ask still reserves.
    fixture.reserve_with(&fixture.deployment.web.admission, now)?;
    assert!(purchase_store
        .get_reservation(&fixture.exchange.reservation_id)?
        .is_some());
    Ok(())
}

/// The reserved grant must be the one-shot, DPoP-bound, output-committed,
/// purchase-marked delivery grant: anything looser books seller exposure
/// for a sale the reveal gate would never admit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_reserve_refuses_a_malformed_purchase_grant() -> TestResult {
    let fixture = open_reserve_fixture().await?;
    let now = unix_timestamp_now();
    let buyer = keypair(31);
    let operator = fixture.deployment.web.operator.clone();

    let reissue = |mutate: fn(&mut ToolGrant)| -> Result<(SignedAskResponse, String), AnyError> {
        let mut body = fixture.exchange.ask.body.clone();
        let mut token = body.token_offer.clone();
        let grant = token
            .scope
            .grants
            .first_mut()
            .ok_or_else(|| missing("minted grant"))?;
        mutate(grant);
        body.token_offer = CapabilityToken::sign(token.body(), &operator)?;
        let signed: SignedAskResponse = SignedExportEnvelope::sign(body, &operator)?;
        let digest = digest_of(&signed.body)?;
        let signature = buyer.sign(digest.as_bytes()).to_hex();
        Ok((signed, signature))
    };

    type GrantMutationCase = (&'static str, &'static str, fn(&mut ToolGrant));
    let cases: [GrantMutationCase; 8] = [
        ("max_invocations", "max_invocations", |grant| {
            grant.max_invocations = Some(2);
        }),
        ("extra_operation", "operations", |grant| {
            grant.operations.push(Operation::Delegate);
        }),
        ("dpop_required", "dpop_required", |grant| {
            grant.dpop_required = None;
        }),
        ("missing_output_digest", "output_digest", |grant| {
            grant
                .constraints
                .retain(|constraint| !matches!(constraint, Constraint::OutputDigestSha256(_)));
        }),
        ("wrong_output_digest", "output_digest", |grant| {
            for constraint in &mut grant.constraints {
                if let Constraint::OutputDigestSha256(digest) = constraint {
                    *digest = HEX64.to_owned();
                }
            }
        }),
        ("duplicate_output_digest", "output_digest", |grant| {
            grant
                .constraints
                .push(Constraint::OutputDigestSha256(HEX64.to_owned()));
        }),
        ("missing_purchase_marker", "purchase_marker", |grant| {
            grant
                .constraints
                .retain(|constraint| !matches!(constraint, Constraint::RequireFindingPurchase(_)));
        }),
        ("duplicate_purchase_marker", "purchase_marker", |grant| {
            if let Some(marker) = grant.constraints.iter().find_map(|constraint| {
                if let Constraint::RequireFindingPurchase(marker) = constraint {
                    Some(marker.clone())
                } else {
                    None
                }
            }) {
                grant
                    .constraints
                    .push(Constraint::RequireFindingPurchase(marker));
            }
        }),
    ];
    for (label, expected_shape, mutate) in cases {
        let (ask, signature) = reissue(mutate)?;
        assert!(
            matches!(
                fixture.coordinator.reserve(
                    &fixture.exchange.bid,
                    &ask,
                    &signature,
                    &fixture.deployment.web.admission,
                    &fixture.deployment.web.authorization,
                    EXPOSURE_UNITS,
                    RESERVATION_TTL_SECS,
                    now,
                ),
                Err(PurchaseCoordinatorError::AskGrantShape(shape)) if shape == expected_shape
            ),
            "grant mutation {label} must refuse"
        );
    }
    let sign_ask_with_token =
        |token: CapabilityToken| -> Result<(SignedAskResponse, String), AnyError> {
            let mut body = fixture.exchange.ask.body.clone();
            body.token_offer = token;
            let ask: SignedAskResponse = SignedExportEnvelope::sign(body, &operator)?;
            let signature = buyer.sign(digest_of(&ask.body)?.as_bytes()).to_hex();
            Ok((ask, signature))
        };
    let mut resource_token = fixture.exchange.ask.body.token_offer.clone();
    resource_token.scope.resource_grants.push(ResourceGrant {
        uri_pattern: "resource://extra".to_owned(),
        operations: vec![Operation::Read],
    });
    let resource_token = CapabilityToken::sign(resource_token.body(), &operator)?;
    let mut prompt_token = fixture.exchange.ask.body.token_offer.clone();
    prompt_token.scope.prompt_grants.push(PromptGrant {
        prompt_name: "extra".to_owned(),
        operations: vec![Operation::Get],
    });
    let prompt_token = CapabilityToken::sign(prompt_token.body(), &operator)?;
    for (label, token) in [("resource", resource_token), ("prompt", prompt_token)] {
        let (ask, signature) = sign_ask_with_token(token)?;
        assert!(
            matches!(
                fixture.coordinator.reserve(
                    &fixture.exchange.bid,
                    &ask,
                    &signature,
                    &fixture.deployment.web.admission,
                    &fixture.deployment.web.authorization,
                    EXPOSURE_UNITS,
                    RESERVATION_TTL_SECS,
                    now,
                ),
                Err(PurchaseCoordinatorError::AskGrantShape("grant_families"))
            ),
            "extra {label} grant must refuse"
        );
    }

    let mut stale_signature_token = fixture.exchange.ask.body.token_offer.clone();
    stale_signature_token.scope.grants[0].max_invocations = Some(2);
    let (stale_signature_ask, stale_signature) = sign_ask_with_token(stale_signature_token)?;
    assert!(matches!(
        fixture.coordinator.reserve(
            &fixture.exchange.bid,
            &stale_signature_ask,
            &stale_signature,
            &fixture.deployment.web.admission,
            &fixture.deployment.web.authorization,
            EXPOSURE_UNITS,
            RESERVATION_TTL_SECS,
            now,
        ),
        Err(PurchaseCoordinatorError::TokenOffer)
    ));

    let mut window_body = fixture.exchange.ask.body.token_offer.body();
    window_body.issued_at = fixture.exchange.ask.body.issued_at.saturating_add(1);
    let window_token = CapabilityToken::sign(window_body, &operator)?;
    let (window_ask, window_signature) = sign_ask_with_token(window_token)?;
    assert!(matches!(
        fixture.coordinator.reserve(
            &fixture.exchange.bid,
            &window_ask,
            &window_signature,
            &fixture.deployment.web.admission,
            &fixture.deployment.web.authorization,
            EXPOSURE_UNITS,
            RESERVATION_TTL_SECS,
            now,
        ),
        Err(PurchaseCoordinatorError::TokenOffer)
    ));
    assert!(fixture
        .authority
        .finding_purchase_store()
        .get_reservation(&fixture.exchange.reservation_id)?
        .is_none());
    Ok(())
}

/// The reservation freezes the exact buyer-signed bid envelope, not only
/// its body digest. Re-signing the same body under another key must fail at
/// the admission-time reservation gate before payment or dispatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_rejects_a_resigned_bid_envelope() -> TestResult {
    let lane = open_lane(LaneOptions::standard()).await?;
    let resigned = SignedBidRequest::sign(lane.purchase.handshake.bid.body.clone(), &keypair(33))?;
    let context_bytes = STANDARD.decode(&lane.purchase.context_b64)?;
    let mut context: FindingPurchaseContext = serde_json::from_slice(&context_bytes)?;
    context.bid_request_envelope_json = canonical_string(&resigned)?;
    context.validate()?;
    let substituted_context = STANDARD.encode(canonical_json_bytes(&context)?);
    let request = reveal_request(&RevealRequestInputs {
        request_id: "wedge-resigned-bid-1",
        capability: &lane.purchase.capability,
        buyer: &lane.buyer,
        finding_id: &lane.deployment.web.finding_id,
        context_b64: Some(&substituted_context),
        nonce: "nonce-resigned-bid-1",
    })?;
    let response = lane.kernel.evaluate_tool_call_blocking(&request)?;
    assert_denied_with(&response, "reservation does not bind this purchase");
    assert_eq!(lane.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.captures.load(Ordering::SeqCst), 0);
    Ok(())
}

/// Activating a newer admission supersedes the one a purchase was
/// reserved under. A superseded admission carries retired terms, fees,
/// collateral bindings, and authority pins, so it must stop transacting
/// everywhere money could still move: a reveal reserved under it denies
/// before dispatch, and a new reserve presenting the retired envelope
/// refuses while the current one still reserves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_superseded_admission_stops_transacting() -> TestResult {
    let lane = open_lane(LaneOptions::standard()).await?;
    let web = &lane.deployment.web;

    // The seller re-collateralizes: a fresh allocation backs a newer
    // admission for the same finding and listing.
    let mut backing_body = web.backing.body.clone();
    backing_body.issued_at = backing_body.issued_at.saturating_add(1);
    backing_body.allocation_id = String::new();
    backing_body.allocation_id = compute_allocation_id(&backing_body)?;
    let second_backing: SignedFindingBondBacking =
        SignedExportEnvelope::sign(backing_body, &keypair(4))?;
    let (status, body) = send(
        &lane.state,
        authed_post(
            "/v1/findings/collateral",
            serde_json::to_string(&second_backing)?,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

    let second_report = make_signed_report(
        &ReportInputs {
            governance: &keypair(1),
            kernel: &keypair(21),
            profile: &web.profile,
            raw_finding: &web.raw_finding,
            receipts: &web.receipts,
            checkpoint: &web.checkpoint,
            recipe_bytes: &web.recipe_bytes,
            backing: &second_backing,
            collateral: &keypair(4),
        },
        unix_timestamp_now().saturating_add(3_600),
    )?;
    let mut admission_body = web.admission.body.clone();
    admission_body.backing_allocation_id = second_backing.body.allocation_id.clone();
    admission_body.backing_envelope_sha256 = digest_of(&second_backing)?;
    admission_body.verifier_report_id = second_report.body.report_id.clone();
    admission_body.verifier_report_envelope_sha256 = digest_of(&second_report)?;
    admission_body.admission_id = String::new();
    admission_body.admission_id = compute_admission_id(&admission_body)?;
    let second_admission: SignedFindingAdmission =
        SignedExportEnvelope::sign(admission_body, &web.venue)?;
    let activate = serde_json::json!({
        "admission": serde_json::to_value(&second_admission)?,
        "sellerAuthorization": serde_json::to_value(&web.authorization)?,
        "terms": serde_json::to_value(&web.terms)?,
        "backing": serde_json::to_value(&second_backing)?,
        "feeSchedule": serde_json::to_value(&web.schedule)?,
        "verifierReport": serde_json::to_value(&second_report)?,
        "listing": serde_json::to_value(&web.listing)?,
        "pricingHint": serde_json::to_value(&web.pricing_hint)?,
    })
    .to_string();
    let (status, body) = send(
        &lane.state,
        authed_post(
            &format!("/v1/findings/{}/activate", web.finding_id),
            activate,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

    // The reveal reserved under the first admission denies before
    // dispatch: no invocation and no payment authorization.
    let response = lane.reveal("wedge-superseded-1", "nonce-superseded-1")?;
    assert_denied_with(&response, "superseded");
    assert_eq!(lane.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.captures.load(Ordering::SeqCst), 0);
    let released_at = unix_timestamp_now();
    lane.coordinator
        .release(&lane.purchase.handshake.reservation_id, released_at)?;
    let purchase_store = lane.authority.finding_purchase_store();
    assert_eq!(
        purchase_store
            .get_reservation(&lane.purchase.handshake.reservation_id)?
            .ok_or_else(|| missing("released superseded reservation"))?
            .state,
        FindingPurchaseReservationState::Released
    );
    assert_eq!(
        purchase_store
            .get_slot(&lane.purchase.handshake.reservation_id)?
            .ok_or_else(|| missing("closed superseded slot"))?
            .state,
        FindingPurchaseSlotState::ClosedDeny
    );
    assert_eq!(
        purchase_store
            .get_encumbrance(&lane.purchase.handshake.reservation_id)?
            .ok_or_else(|| missing("released superseded encumbrance"))?
            .state,
        FindingPurchaseEncumbranceState::Released
    );

    // A new reservation presenting the retired envelope refuses; the same
    // handshake reserves under the current admission.
    let second_buyer = keypair(32);
    let exchange = handshake(
        web,
        &lane.witness,
        &second_buyer,
        "buyer-agent-8",
        "finding-purchase-token-0004",
    )?;
    let now = unix_timestamp_now();
    assert!(matches!(
        lane.coordinator.reserve(
            &exchange.bid,
            &exchange.ask,
            &exchange.buyer_signature_hex,
            &web.admission,
            &web.authorization,
            EXPOSURE_UNITS,
            RESERVATION_TTL_SECS,
            now,
        ),
        Err(PurchaseCoordinatorError::AdmissionNotCurrent)
    ));
    let reservation_receipt = lane.coordinator.reserve(
        &exchange.bid,
        &exchange.ask,
        &exchange.buyer_signature_hex,
        &second_admission,
        &web.authorization,
        EXPOSURE_UNITS,
        RESERVATION_TTL_SECS,
        now,
    )?;
    let verified =
        VerifiedReservationReceipt::from_signed(&reservation_receipt, &keypair(16).public_key())?;
    let accepted = accept_finding_purchase(
        &exchange.ask,
        &verified,
        &second_buyer,
        now,
        &lane.witness,
        &web.finding,
    )?;
    lane.coordinator
        .reserve_slot(&exchange.reservation_id, now)?;
    let stale_carrier = purchase_context_b64(&CarrierInputs {
        web,
        handshake: &exchange,
        accepted: &accepted,
        reservation_receipt: &reservation_receipt,
    })?;
    let request = reveal_request(&RevealRequestInputs {
        request_id: "wedge-superseded-substitution-1",
        capability: &exchange.ask.body.token_offer,
        buyer: &second_buyer,
        finding_id: &web.finding_id,
        context_b64: Some(&stale_carrier),
        nonce: "nonce-superseded-substitution-1",
    })?;
    let substituted = lane.kernel.evaluate_tool_call_blocking(&request)?;
    assert_denied_with(&substituted, "reservation does not bind this purchase");
    assert_eq!(lane.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.captures.load(Ordering::SeqCst), 0);
    Ok(())
}

/// Terminal selection and realized spend come from the durable kernel
/// verdict and outcome, never from coordinator-call parameters.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_finalization_uses_the_durable_verdict_and_capture() -> TestResult {
    let lane = open_lane(LaneOptions::standard()).await?;
    let response = lane.reveal("wedge-overspend-1", "nonce-overspend-1")?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);

    let purchase_store = lane.authority.finding_purchase_store();
    let allocation_id = lane.deployment.web.allocation_id.clone();
    let reservation_id = lane.purchase.handshake.reservation_id.clone();
    let now = unix_timestamp_now();

    let (checkpoint, inclusion_proof) = denial_checkpoint(&response.receipt)?;
    let refused = lane.coordinator.finalize_denial(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &checkpoint,
        &inclusion_proof,
        now,
    );
    assert!(matches!(
        refused,
        Err(PurchaseCoordinatorError::TerminalEvidence(_))
    ));

    // The refusal preceded every durable step: no destination took a slot,
    // the purchase slot is still reserved, and no record exists.
    assert!(purchase_store
        .list_payout_destinations(&allocation_id)?
        .is_empty());
    let slot = purchase_store
        .get_slot(&reservation_id)?
        .ok_or_else(|| missing("slot after the refused settlement"))?;
    assert_eq!(slot.state, FindingPurchaseSlotState::Reserved);
    let purchase_key = derive_purchase_key(
        &lane.purchase.accepted_bid_envelope_sha256,
        &derive_payment_operation_id(&reservation_id),
    );
    assert!(purchase_store.get_purchase_record(&purchase_key)?.is_none());

    let record = lane.coordinator.finalize_delivery(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &lane.deployment.web.backing,
        now,
    )?;
    verify_signed_purchase_record(&record, &keypair(16).public_key())?;
    assert_eq!(record.body.accepted_price, usd(PRICE_UNITS));
    assert_eq!(record.body.realized_spend, usd(PRICE_UNITS));
    assert!(purchase_store
        .get_purchase_record(&record.body.purchase_key)?
        .is_some());
    Ok(())
}

/// A settlement retried after a crash arrives with a later clock. The
/// terminal artifacts must not embed that clock: the store compares the
/// retained bytes against the retry's bytes, so a clock-dependent artifact
/// would turn an honest retry into an unresolvable conflict. Both closes
/// must therefore replay byte-identically whatever `now` the retry carries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_settlement_replays_byte_identically_across_clocks() -> TestResult {
    let lane = open_lane(LaneOptions::standard()).await?;
    let response = lane.reveal("wedge-clock-replay-1", "nonce-clock-replay-1")?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);

    let reservation_id = lane.purchase.handshake.reservation_id.clone();
    let now = unix_timestamp_now();
    let first = lane.coordinator.finalize_delivery(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &lane.deployment.web.backing,
        now,
    )?;
    let retry = lane.coordinator.finalize_delivery(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &lane.deployment.web.backing,
        now.saturating_add(41),
    )?;
    assert_eq!(canonical_json_bytes(&first)?, canonical_json_bytes(&retry)?);
    Ok(())
}

/// The denial close must replay across clocks the same way: the terminal id
/// is content-addressed over the artifact body, so a clock inside the body
/// would give every retry a different identity for the same denial.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_denial_replays_byte_identically_across_clocks() -> TestResult {
    let lane = open_lane(LaneOptions {
        case: RevealCase::digest_mismatch(),
        ..LaneOptions::standard()
    })
    .await?;
    let response = lane.reveal("wedge-clock-deny-1", "nonce-clock-deny-1")?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);

    let reservation_id = lane.purchase.handshake.reservation_id.clone();
    let now = unix_timestamp_now();
    let (checkpoint, inclusion_proof) = denial_checkpoint(&response.receipt)?;
    let first = lane.coordinator.finalize_denial(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &checkpoint,
        &inclusion_proof,
        now,
    )?;
    let retry = lane.coordinator.finalize_denial(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &checkpoint,
        &inclusion_proof,
        now.saturating_add(41),
    )?;
    assert_eq!(first.body.failed_delivery_id, retry.body.failed_delivery_id);
    assert_eq!(canonical_json_bytes(&first)?, canonical_json_bytes(&retry)?);
    Ok(())
}

/// Invalid admission-bound backing and a terminal-selection mismatch are
/// refused before either immutable payout admission or slot close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_refuses_to_persist_an_unvalidatable_artifact() -> TestResult {
    let lane = open_lane(LaneOptions::standard()).await?;
    let response = lane.reveal("wedge-invalid-artifact-1", "nonce-invalid-artifact-1")?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);

    let purchase_store = lane.authority.finding_purchase_store();
    let allocation_id = lane.deployment.web.allocation_id.clone();
    let reservation_id = lane.purchase.handshake.reservation_id.clone();
    let now = unix_timestamp_now();

    let mut tampered_backing = lane.deployment.web.backing.clone();
    tampered_backing.body.maximum_sale_exposure.units = tampered_backing
        .body
        .maximum_sale_exposure
        .units
        .saturating_sub(1);
    let refused = lane.coordinator.finalize_delivery(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &tampered_backing,
        now,
    );
    assert!(matches!(
        refused,
        Err(PurchaseCoordinatorError::SellerBacking(_))
    ));

    let (checkpoint, inclusion_proof) = denial_checkpoint(&response.receipt)?;
    let refused_denial = lane.coordinator.finalize_denial(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &checkpoint,
        &inclusion_proof,
        now,
    );
    assert!(matches!(
        refused_denial,
        Err(PurchaseCoordinatorError::TerminalEvidence(_))
    ));

    // Neither refusal moved the purchase or admitted a destination.
    assert!(purchase_store
        .list_payout_destinations(&allocation_id)?
        .is_empty());
    let slot = purchase_store
        .get_slot(&reservation_id)?
        .ok_or_else(|| missing("slot after the refused artifacts"))?;
    assert_eq!(slot.state, FindingPurchaseSlotState::Reserved);
    let reservation = purchase_store
        .get_reservation(&reservation_id)?
        .ok_or_else(|| missing("reservation after the refused artifacts"))?;
    assert_eq!(
        reservation.state,
        FindingPurchaseReservationState::SlotReserved
    );
    let purchase_key = derive_purchase_key(
        &lane.purchase.accepted_bid_envelope_sha256,
        &derive_payment_operation_id(&reservation_id),
    );
    assert!(purchase_store.get_purchase_record(&purchase_key)?.is_none());

    // The purchase is still settleable under a valid record.
    let record = lane.coordinator.finalize_delivery(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &lane.deployment.web.backing,
        now,
    )?;
    verify_signed_purchase_record(&record, &keypair(16).public_key())?;
    assert!(purchase_store
        .get_purchase_record(&record.body.purchase_key)?
        .is_some());
    Ok(())
}
