//! Chio federated trust, quorum, and shared reputation contracts.
//!
//! These contracts extend Chio's local listing, governance, and open-market
//! surfaces into one bounded cross-operator federation lane. Federation stays
//! evidence-referential and fail-closed: visibility may flow across operators,
//! but runtime trust still requires explicit local activation and review.

pub use chio_core_types::{capability, receipt};
pub use chio_listing as listing;
pub use chio_open_market as open_market;

pub mod bilateral;
pub mod bilateral_dsse;
pub mod bilateral_verifier;
pub mod metrics;
pub mod revocation_gossip;
// spec/CHIODOS_SELECTIVE_DISCLOSURE.md §6 BBS+ projection. Default-off
// behind the honestly-named `bbs-stub` feature: the implementation is a
// STUB BBS+ that captures the deterministic projection and
// disclose/withhold semantics but offers no privacy-preserving cryptographic property.
// Real BLS12-381 BBS+ signing is deferred.
#[cfg(feature = "bbs-stub")]
pub mod selective_disclosure;
pub mod trust_establishment;

pub use metrics::{
    federation_hop_latency_count, federation_hop_total, observe_federation_hop_latency_nanos,
    record_federation_hop, render_federation_metrics_prometheus,
    CHIO_FEDERATION_HOP_LATENCY_SECONDS, CHIO_FEDERATION_HOP_TOTAL, HOP_RESULT_ERROR,
    HOP_RESULT_OK,
};

pub use bilateral::{
    co_sign_with_origin, co_sign_with_origin_full, execute_bilateral_invocation,
    BilateralCoSignArtifacts, BilateralCoSigningError, BilateralCoSigningProtocol,
    BilateralInvocationError, BilateralInvocationOutcome, BilateralInvocationRequest,
    CoSigningBody, CoSigningRequest, CoSigningResponse, DualSignedReceipt, InProcessCoSigner,
    BILATERAL_COSIGNING_SCHEMA, BILATERAL_DUAL_RECEIPT_SCHEMA,
};
pub use bilateral_dsse::{
    build_predicate, build_predicate_full, build_statement, pae, receipt_subject_name,
    sign_dsse_envelope, sign_dsse_envelope_full, verify_dsse_envelope, BilateralPredicate,
    BilateralPredicateExtensions, CapabilityLeaseRef, DsseEnvelope, DsseSignature, DsseStatement,
    GovernanceReceiptRef, HashRecord, KernelIdentity, Keyid, PolicyEvaluationSummary,
    PolicyVerdict, StatementSubject, SubjectDigest, BILATERAL_DSSE_ENVELOPE_SCHEMA,
    DEFAULT_CONSISTENCY_MODEL, DEFAULT_COSIGN_MODE, DEFAULT_CROSS_ORG_VISIBILITY,
    PAYLOAD_TYPE_IN_TOTO, PREDICATE_BODY_SCHEMA, PREDICATE_TYPE_BILATERAL, STATEMENT_TYPE_V1,
};
pub use bilateral_verifier::{
    verify_bilateral_cosign_invocation, ActionClassKind, AllowAllRevocationOracle,
    CapabilityLeaseRegistry, DenyListRevocationOracle, GovernanceReceiptStore,
    InMemoryGovernanceReceiptStore, InMemoryLeaseRegistry, InMemoryReceiptStore, PeerPinSet,
    PinnedEpoch, PinnedPeer, ReceiptStore, ResolvedGovernanceReceipt, ResolvedLease,
    RevocationOracle, UnknownActionClassPolicy, VerifiedBilateralCoSignInvocation, VerifierConfig,
    VerifierError,
};
pub use revocation_gossip::{
    respond_to_catchup, RevocationCatchupHistory, RevocationCatchupRequest,
    RevocationCatchupResponse, RevocationGossipBatch, RevocationGossipError,
    RevocationGossipPushQueue, RevocationRootGossip, REVOCATION_CATCHUP_MAX_EPOCHS,
    REVOCATION_CATCHUP_REQUEST_SCHEMA, REVOCATION_CATCHUP_RESPONSE_SCHEMA,
    REVOCATION_ROOT_GOSSIP_BATCH_SCHEMA, REVOCATION_ROOT_GOSSIP_SCHEMA,
};
#[cfg(feature = "bbs-stub")]
pub use selective_disclosure::{
    project_audit_view, verify_audit_view, BbsAuditView, BbsMessage, DisclosedFields,
    DisclosedMessage, DisclosureSet, SelectiveDisclosureError, AUDIT_VIEW_SCHEMA_STUB,
    PROJECTION_VERSION_RECEIPT_V1,
};
pub use trust_establishment::{
    ConformanceEvidence, ConformanceTier, FederationPeer, FederationPeerStore, HandshakeChallenge,
    InMemoryPeerStore, KernelTrustExchange, KernelTrustExchangeConfig, PeerHandshakeEnvelope,
    PeerHandshakeError, QuorumPolicy, CONFORMANCE_BPS_DENOMINATOR, DEFAULT_HANDSHAKE_MAX_SKEW_SECS,
    DEFAULT_ROTATION_WINDOW_SECS, FEDERATION_HANDSHAKE_SCHEMA, GOLD_MIN_KANI_TRUST_BOUNDARY_CRATES,
    GOLD_MIN_MUTATION_KILL_BPS, GOLD_MIN_THREAT_COVERAGE_BPS,
    SILVER_MIN_KANI_TRUST_BOUNDARY_CRATES, SILVER_MIN_MUTATION_KILL_BPS,
    SILVER_MIN_THREAT_COVERAGE_BPS,
};

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::capability::MonetaryAmount;
use crate::listing::{
    GenericListingActorKind, GenericListingFreshnessState, GenericListingReplicaFreshness,
    GenericRegistryPublisher, GenericRegistryPublisherRole, GenericTrustAdmissionClass,
};
use crate::open_market::OpenMarketBondClass;
use crate::receipt::SignedExportEnvelope;

pub const CHIO_FEDERATION_ACTIVATION_EXCHANGE_SCHEMA: &str =
    "chio.federation-activation-exchange.v1";
pub const CHIO_FEDERATION_QUORUM_REPORT_SCHEMA: &str = "chio.federation-quorum-report.v1";
pub const CHIO_FEDERATION_OPEN_ADMISSION_POLICY_SCHEMA: &str =
    "chio.federation-open-admission-policy.v1";
pub const CHIO_FEDERATION_REPUTATION_CLEARING_SCHEMA: &str =
    "chio.federation-reputation-clearing.v1";
pub const CHIO_FEDERATION_QUALIFICATION_MATRIX_SCHEMA: &str =
    "chio.federation-qualification-matrix.v1";

const FEDERATION_REQUIRED_REQUIREMENTS: [&str; 5] = [
    "TRUSTMAX-01",
    "TRUSTMAX-02",
    "TRUSTMAX-03",
    "TRUSTMAX-04",
    "TRUSTMAX-05",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationArtifactKind {
    TrustActivation,
    Listing,
    ListingReport,
    GovernanceCharter,
    GovernanceCase,
    OpenMarketFeeSchedule,
    OpenMarketPenalty,
    PortableReputationSummary,
    PortableNegativeEvent,
    CrossIssuerTrustPack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationQuorumState {
    Converged,
    Stale,
    Conflicting,
    InsufficientQuorum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederatedReputationInputKind {
    ReputationSummary,
    NegativeEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationScenarioKind {
    HostilePublisher,
    ConflictingActivation,
    InsufficientQuorum,
    EclipseAttempt,
    ReputationSybil,
    GovernanceInterop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationQualificationOutcome {
    Pass,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationArtifactReference {
    pub kind: FederationArtifactKind,
    pub schema: String,
    pub artifact_id: String,
    pub operator_id: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationTrustScope {
    pub namespace: String,
    pub subject_operator_id: String,
    pub allowed_actor_kinds: Vec<GenericListingActorKind>,
    pub allowed_admission_classes: Vec<GenericTrustAdmissionClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationDelegationControl {
    pub delegator_operator_id: String,
    pub delegate_operator_id: String,
    pub max_hops: u32,
    pub attenuation_required: bool,
    pub visibility_only_until_local_activation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationImportControl {
    pub explicit_local_activation_required: bool,
    pub manual_review_required: bool,
    pub reject_stale_inputs: bool,
    pub allow_visibility_without_runtime_trust: bool,
    pub prohibit_ambient_runtime_admission: bool,
}

impl Default for FederationImportControl {
    fn default() -> Self {
        Self {
            explicit_local_activation_required: true,
            manual_review_required: true,
            reject_stale_inputs: true,
            allow_visibility_without_runtime_trust: true,
            prohibit_ambient_runtime_admission: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationActivationExchangeArtifact {
    pub schema: String,
    pub exchange_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub source_operator_id: String,
    pub target_operator_id: String,
    pub listing_id: String,
    pub activation_ref: FederationArtifactReference,
    pub listing_ref: FederationArtifactReference,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governing_charter_ref: Option<FederationArtifactReference>,
    pub scope: FederationTrustScope,
    pub delegation_control: FederationDelegationControl,
    pub import_control: FederationImportControl,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedFederationActivationExchange =
    SignedExportEnvelope<FederationActivationExchangeArtifact>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationPublisherObservation {
    pub publisher: GenericRegistryPublisher,
    pub report_ref: FederationArtifactReference,
    pub observed_listing_sha256: String,
    pub freshness: GenericListingReplicaFreshness,
    pub observed_at: u64,
    pub upstream_hop_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationConflictEvidence {
    pub divergence_key: String,
    pub publisher_operator_ids: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationAntiEclipsePolicy {
    pub minimum_distinct_operators: u32,
    pub require_origin_publisher: bool,
    pub require_indexer_observation: bool,
    pub max_upstream_hops: u32,
}

impl Default for FederationAntiEclipsePolicy {
    fn default() -> Self {
        Self {
            minimum_distinct_operators: 2,
            require_origin_publisher: true,
            require_indexer_observation: true,
            max_upstream_hops: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationQuorumReport {
    pub schema: String,
    pub report_id: String,
    pub generated_at: u64,
    pub namespace: String,
    pub listing_id: String,
    pub origin_operator_id: String,
    pub quorum_threshold: u32,
    pub max_replica_age_secs: u64,
    pub publishers: Vec<FederationPublisherObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<FederationConflictEvidence>,
    pub anti_eclipse_policy: FederationAntiEclipsePolicy,
    pub final_state: FederationQuorumState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedFederationQuorumReport = SignedExportEnvelope<FederationQuorumReport>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedStakeRequirement {
    pub admission_class: GenericTrustAdmissionClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_bond_class: Option<OpenMarketBondClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_bond_amount: Option<MonetaryAmount>,
    pub slashable: bool,
    pub governance_case_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedOpenAdmissionPolicyArtifact {
    pub schema: String,
    pub policy_id: String,
    pub issued_at: u64,
    pub namespace: String,
    pub governing_operator_id: String,
    pub allowed_admission_classes: Vec<GenericTrustAdmissionClass>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stake_requirements: Vec<FederatedStakeRequirement>,
    pub governing_charter_ref: FederationArtifactReference,
    pub fee_schedule_ref: FederationArtifactReference,
    pub explicit_local_review_required: bool,
    pub visibility_only_without_activation: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedFederatedOpenAdmissionPolicy =
    SignedExportEnvelope<FederatedOpenAdmissionPolicyArtifact>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedReputationInputReference {
    pub kind: FederatedReputationInputKind,
    pub artifact_ref: FederationArtifactReference,
    pub subject_key: String,
    pub issuer_operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_independence_group_id: Option<String>,
    pub weight_bps: u32,
    pub blocking: bool,
    pub published_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedSybilControl {
    pub minimum_independent_issuers: u32,
    pub maximum_inputs_per_issuer: u32,
    pub oracle_cap_bps: u32,
    pub local_weighting_required: bool,
    pub negative_event_corroboration_required: bool,
}

impl Default for FederatedSybilControl {
    fn default() -> Self {
        Self {
            minimum_independent_issuers: 2,
            maximum_inputs_per_issuer: 2,
            oracle_cap_bps: 4_000,
            local_weighting_required: true,
            negative_event_corroboration_required: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedReputationClearingContinuity {
    pub continuity_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_clearing_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedReputationClearingArtifact {
    pub schema: String,
    pub clearing_id: String,
    pub generated_at: u64,
    pub subject_key: String,
    pub namespace: String,
    pub participating_operator_ids: Vec<String>,
    pub local_weighting_policy_ref: String,
    pub admission_policy_ref: String,
    pub inputs: Vec<FederatedReputationInputReference>,
    pub sybil_control: FederatedSybilControl,
    pub accepted_input_ids: Vec<String>,
    pub rejected_input_ids: Vec<String>,
    pub effective_admission_class: GenericTrustAdmissionClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity: Option<FederatedReputationClearingContinuity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedFederatedReputationClearing =
    SignedExportEnvelope<FederatedReputationClearingArtifact>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationQualificationCase {
    pub id: String,
    pub name: String,
    pub requirement_ids: Vec<String>,
    pub scenario: FederationScenarioKind,
    pub expected_outcome: FederationQualificationOutcome,
    pub observed_outcome: FederationQualificationOutcome,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationQualificationMatrix {
    pub schema: String,
    pub profile_id: String,
    pub exchange_ref: String,
    pub quorum_report_ref: String,
    pub reputation_clearing_ref: String,
    pub cases: Vec<FederationQualificationCase>,
}

pub type SignedFederationQualificationMatrix = SignedExportEnvelope<FederationQualificationMatrix>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FederationContractError {
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    #[error("duplicate value: {0}")]
    DuplicateValue(String),

    #[error("invalid reference: {0}")]
    InvalidReference(String),

    #[error("invalid exchange: {0}")]
    InvalidExchange(String),

    #[error("invalid quorum: {0}")]
    InvalidQuorum(String),

    #[error("invalid admission: {0}")]
    InvalidAdmission(String),

    #[error("invalid clearing: {0}")]
    InvalidClearing(String),

    #[error("invalid qualification case: {0}")]
    InvalidQualificationCase(String),
}

pub fn validate_federation_activation_exchange(
    exchange: &FederationActivationExchangeArtifact,
) -> Result<(), FederationContractError> {
    if exchange.schema != CHIO_FEDERATION_ACTIVATION_EXCHANGE_SCHEMA {
        return Err(FederationContractError::UnsupportedSchema(
            exchange.schema.clone(),
        ));
    }
    ensure_non_empty(&exchange.exchange_id, "federation_exchange.exchange_id")?;
    ensure_non_empty(
        &exchange.source_operator_id,
        "federation_exchange.source_operator_id",
    )?;
    ensure_non_empty(
        &exchange.target_operator_id,
        "federation_exchange.target_operator_id",
    )?;
    ensure_non_empty(&exchange.listing_id, "federation_exchange.listing_id")?;
    if exchange.source_operator_id == exchange.target_operator_id {
        return Err(FederationContractError::InvalidExchange(
            "source_operator_id and target_operator_id must differ".to_string(),
        ));
    }
    if exchange.expires_at <= exchange.issued_at {
        return Err(FederationContractError::InvalidExchange(
            "expires_at must be greater than issued_at".to_string(),
        ));
    }
    validate_federation_artifact_reference(
        &exchange.activation_ref,
        "federation_exchange.activation_ref",
    )?;
    validate_federation_artifact_reference(
        &exchange.listing_ref,
        "federation_exchange.listing_ref",
    )?;
    if exchange.activation_ref.kind != FederationArtifactKind::TrustActivation {
        return Err(FederationContractError::InvalidExchange(
            "activation_ref must reference a trust activation artifact".to_string(),
        ));
    }
    if exchange.listing_ref.kind != FederationArtifactKind::Listing {
        return Err(FederationContractError::InvalidExchange(
            "listing_ref must reference a listing artifact".to_string(),
        ));
    }
    if let Some(charter_ref) = exchange.governing_charter_ref.as_ref() {
        validate_federation_artifact_reference(
            charter_ref,
            "federation_exchange.governing_charter_ref",
        )?;
        if charter_ref.kind != FederationArtifactKind::GovernanceCharter {
            return Err(FederationContractError::InvalidExchange(
                "governing_charter_ref must reference a governance charter".to_string(),
            ));
        }
    }
    validate_federation_scope(&exchange.scope)?;
    validate_delegation_control(&exchange.delegation_control)?;
    validate_import_control(&exchange.import_control)?;
    if exchange.delegation_control.delegator_operator_id != exchange.source_operator_id {
        return Err(FederationContractError::InvalidExchange(
            "delegation_control.delegator_operator_id must match source_operator_id".to_string(),
        ));
    }
    if exchange.delegation_control.delegate_operator_id != exchange.target_operator_id {
        return Err(FederationContractError::InvalidExchange(
            "delegation_control.delegate_operator_id must match target_operator_id".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_federation_quorum_report(
    report: &FederationQuorumReport,
) -> Result<(), FederationContractError> {
    if report.schema != CHIO_FEDERATION_QUORUM_REPORT_SCHEMA {
        return Err(FederationContractError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    ensure_non_empty(&report.report_id, "federation_quorum.report_id")?;
    ensure_non_empty(&report.namespace, "federation_quorum.namespace")?;
    ensure_non_empty(&report.listing_id, "federation_quorum.listing_id")?;
    ensure_non_empty(
        &report.origin_operator_id,
        "federation_quorum.origin_operator_id",
    )?;
    if report.quorum_threshold == 0 {
        return Err(FederationContractError::InvalidQuorum(
            "quorum_threshold must be non-zero".to_string(),
        ));
    }
    if report.max_replica_age_secs == 0 {
        return Err(FederationContractError::InvalidQuorum(
            "max_replica_age_secs must be non-zero".to_string(),
        ));
    }
    if report.publishers.is_empty() {
        return Err(FederationContractError::MissingField(
            "federation_quorum.publishers",
        ));
    }
    validate_anti_eclipse_policy(&report.anti_eclipse_policy)?;

    let mut publisher_ids = HashSet::new();
    let mut fresh_count = 0_u32;
    let mut stale_count = 0_u32;
    let mut has_origin = false;
    let mut has_indexer = false;
    for publisher in &report.publishers {
        publisher
            .publisher
            .validate()
            .map_err(FederationContractError::InvalidQuorum)?;
        validate_federation_artifact_reference(
            &publisher.report_ref,
            "federation_quorum.publishers.report_ref",
        )?;
        if publisher.report_ref.kind != FederationArtifactKind::ListingReport {
            return Err(FederationContractError::InvalidQuorum(
                "publisher report_ref must reference a listing report".to_string(),
            ));
        }
        if publisher.report_ref.operator_id != publisher.publisher.operator_id {
            return Err(FederationContractError::InvalidQuorum(
                "publisher report_ref operator_id must match publisher.operator_id".to_string(),
            ));
        }
        validate_hex_digest(
            &publisher.observed_listing_sha256,
            "federation_quorum.publishers.observed_listing_sha256",
        )?;
        publisher
            .freshness
            .validate()
            .map_err(FederationContractError::InvalidQuorum)?;
        if publisher.freshness.age_secs > report.max_replica_age_secs
            || publisher.freshness.state == GenericListingFreshnessState::Stale
        {
            stale_count += 1;
        } else {
            fresh_count += 1;
        }
        if publisher.upstream_hop_count > report.anti_eclipse_policy.max_upstream_hops {
            return Err(FederationContractError::InvalidQuorum(
                "publisher upstream_hop_count exceeds anti-eclipse policy".to_string(),
            ));
        }
        if !publisher_ids.insert(publisher.publisher.operator_id.as_str()) {
            return Err(FederationContractError::DuplicateValue(
                publisher.publisher.operator_id.clone(),
            ));
        }
        if publisher.publisher.role == GenericRegistryPublisherRole::Origin
            && publisher.publisher.operator_id == report.origin_operator_id
        {
            has_origin = true;
        }
        if publisher.publisher.role == GenericRegistryPublisherRole::Indexer {
            has_indexer = true;
        }
    }

    if report.anti_eclipse_policy.require_origin_publisher && !has_origin {
        return Err(FederationContractError::InvalidQuorum(
            "anti-eclipse policy requires an origin publisher observation".to_string(),
        ));
    }
    if report.anti_eclipse_policy.require_indexer_observation && !has_indexer {
        return Err(FederationContractError::InvalidQuorum(
            "anti-eclipse policy requires an indexer observation".to_string(),
        ));
    }
    if publisher_ids.len() < report.anti_eclipse_policy.minimum_distinct_operators as usize {
        return Err(FederationContractError::InvalidQuorum(
            "insufficient distinct operators for anti-eclipse policy".to_string(),
        ));
    }

    let mut divergence_keys = HashSet::new();
    for conflict in &report.conflicts {
        ensure_non_empty(
            &conflict.divergence_key,
            "federation_quorum.conflicts.divergence_key",
        )?;
        ensure_non_empty(&conflict.reason, "federation_quorum.conflicts.reason")?;
        ensure_unique_strings(
            &conflict.publisher_operator_ids,
            "federation_quorum.conflicts.publisher_operator_ids",
        )?;
        if !divergence_keys.insert(conflict.divergence_key.as_str()) {
            return Err(FederationContractError::DuplicateValue(
                conflict.divergence_key.clone(),
            ));
        }
    }

    match report.final_state {
        FederationQuorumState::Converged => {
            if !report.conflicts.is_empty() {
                return Err(FederationContractError::InvalidQuorum(
                    "converged quorum reports cannot include conflicts".to_string(),
                ));
            }
            if fresh_count < report.quorum_threshold {
                return Err(FederationContractError::InvalidQuorum(
                    "converged quorum reports require fresh observations meeting the quorum threshold"
                        .to_string(),
                ));
            }
        }
        FederationQuorumState::Conflicting => {
            if report.conflicts.is_empty() {
                return Err(FederationContractError::InvalidQuorum(
                    "conflicting quorum reports require conflict evidence".to_string(),
                ));
            }
        }
        FederationQuorumState::InsufficientQuorum => {
            if fresh_count >= report.quorum_threshold
                && publisher_ids.len()
                    >= report.anti_eclipse_policy.minimum_distinct_operators as usize
                && (!report.anti_eclipse_policy.require_origin_publisher || has_origin)
                && (!report.anti_eclipse_policy.require_indexer_observation || has_indexer)
            {
                return Err(FederationContractError::InvalidQuorum(
                    "insufficient_quorum requires a real quorum shortfall".to_string(),
                ));
            }
        }
        FederationQuorumState::Stale => {
            if stale_count != report.publishers.len() as u32 {
                return Err(FederationContractError::InvalidQuorum(
                    "stale quorum reports require all observations to be stale".to_string(),
                ));
            }
        }
    }

    Ok(())
}

pub fn validate_federated_open_admission_policy(
    policy: &FederatedOpenAdmissionPolicyArtifact,
) -> Result<(), FederationContractError> {
    if policy.schema != CHIO_FEDERATION_OPEN_ADMISSION_POLICY_SCHEMA {
        return Err(FederationContractError::UnsupportedSchema(
            policy.schema.clone(),
        ));
    }
    ensure_non_empty(&policy.policy_id, "federated_admission.policy_id")?;
    ensure_non_empty(&policy.namespace, "federated_admission.namespace")?;
    ensure_non_empty(
        &policy.governing_operator_id,
        "federated_admission.governing_operator_id",
    )?;
    if policy.allowed_admission_classes.is_empty() {
        return Err(FederationContractError::MissingField(
            "federated_admission.allowed_admission_classes",
        ));
    }
    ensure_unique_copy_values(
        &policy.allowed_admission_classes,
        "federated_admission.allowed_admission_classes",
    )?;
    validate_federation_artifact_reference(
        &policy.governing_charter_ref,
        "federated_admission.governing_charter_ref",
    )?;
    if policy.governing_charter_ref.kind != FederationArtifactKind::GovernanceCharter {
        return Err(FederationContractError::InvalidAdmission(
            "governing_charter_ref must reference a governance charter".to_string(),
        ));
    }
    validate_federation_artifact_reference(
        &policy.fee_schedule_ref,
        "federated_admission.fee_schedule_ref",
    )?;
    if policy.fee_schedule_ref.kind != FederationArtifactKind::OpenMarketFeeSchedule {
        return Err(FederationContractError::InvalidAdmission(
            "fee_schedule_ref must reference an open-market fee schedule".to_string(),
        ));
    }
    if !policy.explicit_local_review_required {
        return Err(FederationContractError::InvalidAdmission(
            "open admission must still require explicit local review".to_string(),
        ));
    }
    if !policy.visibility_only_without_activation {
        return Err(FederationContractError::InvalidAdmission(
            "open admission must remain visibility-only without activation".to_string(),
        ));
    }

    let mut requirement_classes = HashSet::new();
    for requirement in &policy.stake_requirements {
        validate_stake_requirement(requirement)?;
        if !policy
            .allowed_admission_classes
            .contains(&requirement.admission_class)
        {
            return Err(FederationContractError::InvalidAdmission(
                "stake requirement admission_class must be allowed by the policy".to_string(),
            ));
        }
        if !requirement_classes.insert(requirement.admission_class) {
            return Err(FederationContractError::DuplicateValue(format!(
                "{:?}",
                requirement.admission_class
            )));
        }
    }

    if policy
        .allowed_admission_classes
        .contains(&GenericTrustAdmissionClass::BondBacked)
        && !requirement_classes.contains(&GenericTrustAdmissionClass::BondBacked)
    {
        return Err(FederationContractError::InvalidAdmission(
            "bond_backed admission requires an explicit stake requirement".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_federated_reputation_clearing(
    clearing: &FederatedReputationClearingArtifact,
) -> Result<(), FederationContractError> {
    if clearing.schema != CHIO_FEDERATION_REPUTATION_CLEARING_SCHEMA {
        return Err(FederationContractError::UnsupportedSchema(
            clearing.schema.clone(),
        ));
    }
    ensure_non_empty(&clearing.clearing_id, "federated_clearing.clearing_id")?;
    ensure_non_empty(&clearing.subject_key, "federated_clearing.subject_key")?;
    ensure_non_empty(&clearing.namespace, "federated_clearing.namespace")?;
    ensure_non_empty(
        &clearing.local_weighting_policy_ref,
        "federated_clearing.local_weighting_policy_ref",
    )?;
    ensure_non_empty(
        &clearing.admission_policy_ref,
        "federated_clearing.admission_policy_ref",
    )?;
    if clearing.participating_operator_ids.is_empty() {
        return Err(FederationContractError::MissingField(
            "federated_clearing.participating_operator_ids",
        ));
    }
    ensure_unique_strings(
        &clearing.participating_operator_ids,
        "federated_clearing.participating_operator_ids",
    )?;
    validate_sybil_control(&clearing.sybil_control)?;
    if let Some(continuity) = clearing.continuity.as_ref() {
        validate_reputation_clearing_continuity(continuity, &clearing.clearing_id)?;
    }
    if clearing.inputs.is_empty() {
        return Err(FederationContractError::MissingField(
            "federated_clearing.inputs",
        ));
    }

    let participating_operators = clearing
        .participating_operator_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut input_ids = HashSet::new();
    let mut accepted_ids = HashSet::new();
    let mut rejected_ids = HashSet::new();
    let mut issuer_counts = std::collections::BTreeMap::<String, u32>::new();
    let mut accepted_summary_issuers = HashSet::new();
    let mut accepted_independence_groups = HashSet::new();
    let mut accepted_negative_event_groups = HashSet::new();

    for id in &clearing.accepted_input_ids {
        ensure_non_empty(id, "federated_clearing.accepted_input_ids")?;
        if !accepted_ids.insert(id.as_str()) {
            return Err(FederationContractError::DuplicateValue(id.clone()));
        }
    }
    for id in &clearing.rejected_input_ids {
        ensure_non_empty(id, "federated_clearing.rejected_input_ids")?;
        if !rejected_ids.insert(id.as_str()) {
            return Err(FederationContractError::DuplicateValue(id.clone()));
        }
    }
    if accepted_ids.iter().any(|id| rejected_ids.contains(id)) {
        return Err(FederationContractError::InvalidClearing(
            "an input cannot be both accepted and rejected".to_string(),
        ));
    }

    for input in &clearing.inputs {
        validate_reputation_input_reference(input, clearing.generated_at, &clearing.subject_key)?;
        if input.artifact_ref.operator_id != input.issuer_operator_id {
            return Err(FederationContractError::InvalidClearing(
                "input artifact_ref operator_id must match issuer_operator_id".to_string(),
            ));
        }
        if !participating_operators.contains(input.issuer_operator_id.as_str()) {
            return Err(FederationContractError::InvalidClearing(
                "input issuer_operator_id must appear in participating_operator_ids".to_string(),
            ));
        }
        let input_id = input.artifact_ref.artifact_id.as_str();
        if !input_ids.insert(input_id) {
            return Err(FederationContractError::DuplicateValue(
                input.artifact_ref.artifact_id.clone(),
            ));
        }
        *issuer_counts
            .entry(input.issuer_operator_id.clone())
            .or_insert(0) += 1;
        if issuer_counts[&input.issuer_operator_id]
            > clearing.sybil_control.maximum_inputs_per_issuer
        {
            return Err(FederationContractError::InvalidClearing(
                "issuer exceeds maximum_inputs_per_issuer".to_string(),
            ));
        }
        if input.weight_bps > clearing.sybil_control.oracle_cap_bps {
            return Err(FederationContractError::InvalidClearing(
                "input weight_bps exceeds oracle_cap_bps".to_string(),
            ));
        }
        if accepted_ids.contains(input_id) {
            let independence_group = input
                .issuer_independence_group_id
                .as_deref()
                .unwrap_or(input.issuer_operator_id.as_str());
            accepted_independence_groups.insert(independence_group);
            match input.kind {
                FederatedReputationInputKind::ReputationSummary => {
                    if !accepted_summary_issuers.insert(input.issuer_operator_id.as_str()) {
                        return Err(FederationContractError::InvalidClearing(
                            "accepted reputation summaries must come from distinct issuers"
                                .to_string(),
                        ));
                    }
                }
                FederatedReputationInputKind::NegativeEvent => {
                    if input.blocking {
                        accepted_negative_event_groups.insert(independence_group);
                    }
                }
            }
        }
    }

    if input_ids.len() != clearing.accepted_input_ids.len() + clearing.rejected_input_ids.len() {
        return Err(FederationContractError::InvalidClearing(
            "each input must be classified as accepted or rejected".to_string(),
        ));
    }
    if accepted_independence_groups.len()
        < clearing.sybil_control.minimum_independent_issuers as usize
    {
        return Err(FederationContractError::InvalidClearing(
            "accepted inputs must meet the minimum_independent_issuers threshold".to_string(),
        ));
    }
    if clearing.sybil_control.negative_event_corroboration_required
        && accepted_negative_event_groups.len() == 1
    {
        return Err(FederationContractError::InvalidClearing(
            "blocking negative events require corroboration from independent issuers".to_string(),
        ));
    }
    if clearing.effective_admission_class != GenericTrustAdmissionClass::PublicUntrusted
        && clearing.accepted_input_ids.is_empty()
    {
        return Err(FederationContractError::InvalidClearing(
            "non-public admission classes require accepted inputs".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_federation_qualification_matrix(
    matrix: &FederationQualificationMatrix,
) -> Result<(), FederationContractError> {
    if matrix.schema != CHIO_FEDERATION_QUALIFICATION_MATRIX_SCHEMA {
        return Err(FederationContractError::UnsupportedSchema(
            matrix.schema.clone(),
        ));
    }
    ensure_non_empty(&matrix.profile_id, "federation_qualification.profile_id")?;
    ensure_non_empty(
        &matrix.exchange_ref,
        "federation_qualification.exchange_ref",
    )?;
    ensure_non_empty(
        &matrix.quorum_report_ref,
        "federation_qualification.quorum_report_ref",
    )?;
    ensure_non_empty(
        &matrix.reputation_clearing_ref,
        "federation_qualification.reputation_clearing_ref",
    )?;
    if matrix.cases.is_empty() {
        return Err(FederationContractError::MissingField(
            "federation_qualification.cases",
        ));
    }

    let mut case_ids = HashSet::new();
    let mut covered_requirements = HashSet::new();
    for case in &matrix.cases {
        ensure_non_empty(&case.id, "federation_qualification.cases.id")?;
        ensure_non_empty(&case.name, "federation_qualification.cases.name")?;
        ensure_non_empty(&case.notes, "federation_qualification.cases.notes")?;
        if case.requirement_ids.is_empty() {
            return Err(FederationContractError::InvalidQualificationCase(format!(
                "qualification case `{}` requires at least one requirement id",
                case.id
            )));
        }
        ensure_unique_strings(
            &case.requirement_ids,
            "federation_qualification.cases.requirement_ids",
        )?;
        if !case_ids.insert(case.id.as_str()) {
            return Err(FederationContractError::DuplicateValue(case.id.clone()));
        }
        for requirement in &case.requirement_ids {
            covered_requirements.insert(requirement.as_str());
        }
    }

    for requirement in FEDERATION_REQUIRED_REQUIREMENTS {
        if !covered_requirements.contains(requirement) {
            return Err(FederationContractError::InvalidQualificationCase(format!(
                "qualification matrix is missing coverage for {requirement}"
            )));
        }
    }

    Ok(())
}

fn validate_federation_artifact_reference(
    reference: &FederationArtifactReference,
    field: &'static str,
) -> Result<(), FederationContractError> {
    ensure_non_empty(&reference.schema, field)?;
    ensure_non_empty(&reference.artifact_id, field)?;
    ensure_non_empty(&reference.operator_id, field)?;
    validate_hex_digest(&reference.sha256, field)
}

fn validate_federation_scope(scope: &FederationTrustScope) -> Result<(), FederationContractError> {
    ensure_non_empty(&scope.namespace, "federation_scope.namespace")?;
    ensure_non_empty(
        &scope.subject_operator_id,
        "federation_scope.subject_operator_id",
    )?;
    if scope.allowed_actor_kinds.is_empty() {
        return Err(FederationContractError::MissingField(
            "federation_scope.allowed_actor_kinds",
        ));
    }
    if scope.allowed_admission_classes.is_empty() {
        return Err(FederationContractError::MissingField(
            "federation_scope.allowed_admission_classes",
        ));
    }
    ensure_unique_copy_values(
        &scope.allowed_actor_kinds,
        "federation_scope.allowed_actor_kinds",
    )?;
    ensure_unique_copy_values(
        &scope.allowed_admission_classes,
        "federation_scope.allowed_admission_classes",
    )?;
    if let Some(policy_reference) = scope.policy_reference.as_deref() {
        ensure_non_empty(policy_reference, "federation_scope.policy_reference")?;
    }
    Ok(())
}

fn validate_delegation_control(
    control: &FederationDelegationControl,
) -> Result<(), FederationContractError> {
    ensure_non_empty(
        &control.delegator_operator_id,
        "federation_delegation.delegator_operator_id",
    )?;
    ensure_non_empty(
        &control.delegate_operator_id,
        "federation_delegation.delegate_operator_id",
    )?;
    if control.delegator_operator_id == control.delegate_operator_id {
        return Err(FederationContractError::InvalidExchange(
            "delegator and delegate operators must differ".to_string(),
        ));
    }
    if control.max_hops == 0 {
        return Err(FederationContractError::InvalidExchange(
            "delegation max_hops must be non-zero".to_string(),
        ));
    }
    if !control.attenuation_required {
        return Err(FederationContractError::InvalidExchange(
            "federation delegation must require attenuation".to_string(),
        ));
    }
    if !control.visibility_only_until_local_activation {
        return Err(FederationContractError::InvalidExchange(
            "federation delegation must remain visibility-only until local activation".to_string(),
        ));
    }
    Ok(())
}

fn validate_import_control(
    control: &FederationImportControl,
) -> Result<(), FederationContractError> {
    if !control.explicit_local_activation_required {
        return Err(FederationContractError::InvalidExchange(
            "federation imports must require explicit local activation".to_string(),
        ));
    }
    if !control.manual_review_required {
        return Err(FederationContractError::InvalidExchange(
            "federation imports must require manual review".to_string(),
        ));
    }
    if !control.reject_stale_inputs {
        return Err(FederationContractError::InvalidExchange(
            "federation imports must reject stale inputs".to_string(),
        ));
    }
    if !control.allow_visibility_without_runtime_trust {
        return Err(FederationContractError::InvalidExchange(
            "federation imports must preserve visibility without runtime trust".to_string(),
        ));
    }
    if !control.prohibit_ambient_runtime_admission {
        return Err(FederationContractError::InvalidExchange(
            "federation imports must prohibit ambient runtime admission".to_string(),
        ));
    }
    Ok(())
}

fn validate_anti_eclipse_policy(
    policy: &FederationAntiEclipsePolicy,
) -> Result<(), FederationContractError> {
    if policy.minimum_distinct_operators == 0 {
        return Err(FederationContractError::InvalidQuorum(
            "minimum_distinct_operators must be non-zero".to_string(),
        ));
    }
    Ok(())
}

fn validate_stake_requirement(
    requirement: &FederatedStakeRequirement,
) -> Result<(), FederationContractError> {
    match requirement.admission_class {
        GenericTrustAdmissionClass::PublicUntrusted | GenericTrustAdmissionClass::Reviewable => {
            if requirement.required_bond_class.is_some()
                || requirement.minimum_bond_amount.is_some()
            {
                return Err(FederationContractError::InvalidAdmission(
                    "public_untrusted and reviewable admission cannot require bond collateral"
                        .to_string(),
                ));
            }
        }
        GenericTrustAdmissionClass::BondBacked => {
            let amount = requirement.minimum_bond_amount.as_ref().ok_or_else(|| {
                FederationContractError::InvalidAdmission(
                    "bond_backed admission requires minimum_bond_amount".to_string(),
                )
            })?;
            if requirement.required_bond_class.is_none() {
                return Err(FederationContractError::InvalidAdmission(
                    "bond_backed admission requires required_bond_class".to_string(),
                ));
            }
            if !requirement.slashable {
                return Err(FederationContractError::InvalidAdmission(
                    "bond_backed admission requires slashable collateral".to_string(),
                ));
            }
            validate_positive_money(amount, "federated_admission.minimum_bond_amount")?;
        }
        GenericTrustAdmissionClass::RoleGated => {
            if !requirement.governance_case_required {
                return Err(FederationContractError::InvalidAdmission(
                    "role_gated admission requires governance_case_required".to_string(),
                ));
            }
            if requirement.required_bond_class.is_some()
                || requirement.minimum_bond_amount.is_some()
            {
                return Err(FederationContractError::InvalidAdmission(
                    "role_gated admission should not infer a bond requirement".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_reputation_input_reference(
    input: &FederatedReputationInputReference,
    generated_at: u64,
    subject_key: &str,
) -> Result<(), FederationContractError> {
    validate_federation_artifact_reference(&input.artifact_ref, "federated_clearing.inputs")?;
    ensure_non_empty(&input.subject_key, "federated_clearing.inputs.subject_key")?;
    ensure_non_empty(
        &input.issuer_operator_id,
        "federated_clearing.inputs.issuer_operator_id",
    )?;
    if let Some(group_id) = input.issuer_independence_group_id.as_deref() {
        ensure_non_empty(
            group_id,
            "federated_clearing.inputs.issuer_independence_group_id",
        )?;
    }
    if input.subject_key != subject_key {
        return Err(FederationContractError::InvalidClearing(
            "reputation clearing inputs must target the same subject_key".to_string(),
        ));
    }
    if input.weight_bps == 0 || input.weight_bps > 10_000 {
        return Err(FederationContractError::InvalidClearing(
            "reputation clearing weight_bps must be between 1 and 10000".to_string(),
        ));
    }
    if input.published_at > generated_at {
        return Err(FederationContractError::InvalidClearing(
            "reputation clearing inputs cannot be published in the future".to_string(),
        ));
    }
    if let Some(expires_at) = input.expires_at {
        if expires_at <= input.published_at {
            return Err(FederationContractError::InvalidClearing(
                "reputation clearing input expires_at must be greater than published_at"
                    .to_string(),
            ));
        }
        if expires_at <= generated_at {
            return Err(FederationContractError::InvalidClearing(
                "reputation clearing inputs cannot be expired at generated_at".to_string(),
            ));
        }
    }
    match input.kind {
        FederatedReputationInputKind::ReputationSummary => {
            if input.blocking {
                return Err(FederationContractError::InvalidClearing(
                    "reputation summaries cannot be marked blocking".to_string(),
                ));
            }
            if input.artifact_ref.kind != FederationArtifactKind::PortableReputationSummary {
                return Err(FederationContractError::InvalidClearing(
                    "reputation summary inputs must reference portable reputation summaries"
                        .to_string(),
                ));
            }
        }
        FederatedReputationInputKind::NegativeEvent => {
            if input.artifact_ref.kind != FederationArtifactKind::PortableNegativeEvent {
                return Err(FederationContractError::InvalidClearing(
                    "negative event inputs must reference portable negative events".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_reputation_clearing_continuity(
    continuity: &FederatedReputationClearingContinuity,
    clearing_id: &str,
) -> Result<(), FederationContractError> {
    ensure_non_empty(
        &continuity.continuity_id,
        "federated_clearing.continuity.continuity_id",
    )?;
    if let Some(previous_clearing_id) = continuity.previous_clearing_id.as_deref() {
        ensure_non_empty(
            previous_clearing_id,
            "federated_clearing.continuity.previous_clearing_id",
        )?;
        if previous_clearing_id == clearing_id {
            return Err(FederationContractError::InvalidClearing(
                "continuity previous_clearing_id must differ from clearing_id".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_sybil_control(control: &FederatedSybilControl) -> Result<(), FederationContractError> {
    if control.minimum_independent_issuers == 0 {
        return Err(FederationContractError::InvalidClearing(
            "minimum_independent_issuers must be non-zero".to_string(),
        ));
    }
    if control.maximum_inputs_per_issuer == 0 {
        return Err(FederationContractError::InvalidClearing(
            "maximum_inputs_per_issuer must be non-zero".to_string(),
        ));
    }
    if control.oracle_cap_bps == 0 || control.oracle_cap_bps > 10_000 {
        return Err(FederationContractError::InvalidClearing(
            "oracle_cap_bps must be between 1 and 10000".to_string(),
        ));
    }
    if !control.local_weighting_required {
        return Err(FederationContractError::InvalidClearing(
            "federated reputation clearing must require local weighting".to_string(),
        ));
    }
    Ok(())
}

fn validate_positive_money(
    amount: &MonetaryAmount,
    field: &'static str,
) -> Result<(), FederationContractError> {
    if amount.units == 0 {
        return Err(FederationContractError::InvalidAdmission(format!(
            "{field} must be greater than zero"
        )));
    }
    let normalized = amount.currency.trim().to_ascii_uppercase();
    if normalized.len() != 3
        || !normalized
            .chars()
            .all(|character| character.is_ascii_uppercase())
    {
        return Err(FederationContractError::InvalidAdmission(format!(
            "{field} currency must be a 3-letter uppercase currency code"
        )));
    }
    Ok(())
}

fn validate_hex_digest(value: &str, field: &'static str) -> Result<(), FederationContractError> {
    ensure_non_empty(value, field)?;
    let trimmed = value.trim();
    if trimmed.len() != 64
        || !trimmed
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(FederationContractError::InvalidReference(format!(
            "{field} must be a 64-character lowercase-compatible hex digest"
        )));
    }
    Ok(())
}

fn ensure_non_empty(value: &str, field: &'static str) -> Result<(), FederationContractError> {
    if value.trim().is_empty() {
        return Err(FederationContractError::MissingField(field));
    }
    Ok(())
}

fn ensure_unique_strings(
    values: &[String],
    field: &'static str,
) -> Result<(), FederationContractError> {
    let mut seen = HashSet::new();
    for value in values {
        if value.trim().is_empty() {
            return Err(FederationContractError::MissingField(field));
        }
        if !seen.insert(value.as_str()) {
            return Err(FederationContractError::DuplicateValue(format!(
                "{field}:{value}"
            )));
        }
    }
    Ok(())
}

fn ensure_unique_copy_values<T>(
    values: &[T],
    field: &'static str,
) -> Result<(), FederationContractError>
where
    T: Copy + Eq + std::hash::Hash + std::fmt::Debug,
{
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(FederationContractError::DuplicateValue(format!(
                "{field}:{value:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn must<T, E: core::fmt::Debug>(result: std::result::Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{context}: {err:?}"),
        }
    }

    fn must_some<T>(option: Option<T>, context: &str) -> T {
        match option {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }

    fn hex(seed: char) -> String {
        std::iter::repeat_n(seed, 64).collect()
    }

    fn sample_reference(
        kind: FederationArtifactKind,
        schema: &str,
        artifact_id: &str,
        operator_id: &str,
        seed: char,
    ) -> FederationArtifactReference {
        FederationArtifactReference {
            kind,
            schema: schema.to_string(),
            artifact_id: artifact_id.to_string(),
            operator_id: operator_id.to_string(),
            sha256: hex(seed),
            uri: Some(format!(
                "https://{operator_id}.chio.example/artifacts/{artifact_id}"
            )),
        }
    }

    fn sample_activation_exchange() -> FederationActivationExchangeArtifact {
        FederationActivationExchangeArtifact {
            schema: CHIO_FEDERATION_ACTIVATION_EXCHANGE_SCHEMA.to_string(),
            exchange_id: "fex-1".to_string(),
            issued_at: 1_743_552_000,
            expires_at: 1_743_638_400,
            source_operator_id: "origin-operator".to_string(),
            target_operator_id: "consumer-operator".to_string(),
            listing_id: "listing-liability-provider-1".to_string(),
            activation_ref: sample_reference(
                FederationArtifactKind::TrustActivation,
                "chio.registry.trust-activation.v1",
                "activation-1",
                "origin-operator",
                'a',
            ),
            listing_ref: sample_reference(
                FederationArtifactKind::Listing,
                "chio.registry.listing.v1",
                "listing-liability-provider-1",
                "origin-operator",
                'b',
            ),
            governing_charter_ref: Some(sample_reference(
                FederationArtifactKind::GovernanceCharter,
                "chio.registry.governance-charter.v1",
                "charter-1",
                "origin-operator",
                'c',
            )),
            scope: FederationTrustScope {
                namespace: "registry.chio.example/liability".to_string(),
                subject_operator_id: "origin-operator".to_string(),
                allowed_actor_kinds: vec![GenericListingActorKind::LiabilityProvider],
                allowed_admission_classes: vec![
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustAdmissionClass::BondBacked,
                ],
                policy_reference: Some("policy/federation/default".to_string()),
            },
            delegation_control: FederationDelegationControl {
                delegator_operator_id: "origin-operator".to_string(),
                delegate_operator_id: "consumer-operator".to_string(),
                max_hops: 2,
                attenuation_required: true,
                visibility_only_until_local_activation: true,
            },
            import_control: FederationImportControl::default(),
            note: Some(
                "Shares one reviewed trust activation without widening runtime trust.".to_string(),
            ),
        }
    }

    fn sample_quorum_report() -> FederationQuorumReport {
        FederationQuorumReport {
            schema: CHIO_FEDERATION_QUORUM_REPORT_SCHEMA.to_string(),
            report_id: "fqr-1".to_string(),
            generated_at: 1_743_552_060,
            namespace: "registry.chio.example/liability".to_string(),
            listing_id: "listing-liability-provider-1".to_string(),
            origin_operator_id: "origin-operator".to_string(),
            quorum_threshold: 2,
            max_replica_age_secs: 300,
            publishers: vec![
                FederationPublisherObservation {
                    publisher: GenericRegistryPublisher {
                        role: GenericRegistryPublisherRole::Origin,
                        operator_id: "origin-operator".to_string(),
                        operator_name: Some("Origin Operator".to_string()),
                        registry_url: "https://origin.chio.example/registry".to_string(),
                        upstream_registry_urls: vec![],
                    },
                    report_ref: sample_reference(
                        FederationArtifactKind::ListingReport,
                        "chio.registry.listing-report.v1",
                        "report-origin-1",
                        "origin-operator",
                        'd',
                    ),
                    observed_listing_sha256: hex('1'),
                    freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Fresh,
                        age_secs: 30,
                        max_age_secs: 300,
                        valid_until: 1_743_552_360,
                        generated_at: 1_743_552_030,
                    },
                    observed_at: 1_743_552_030,
                    upstream_hop_count: 0,
                },
                FederationPublisherObservation {
                    publisher: GenericRegistryPublisher {
                        role: GenericRegistryPublisherRole::Mirror,
                        operator_id: "mirror-operator-a".to_string(),
                        operator_name: Some("Mirror Operator A".to_string()),
                        registry_url: "https://mirror-a.chio.example/registry".to_string(),
                        upstream_registry_urls: vec![
                            "https://origin.chio.example/registry".to_string(),
                        ],
                    },
                    report_ref: sample_reference(
                        FederationArtifactKind::ListingReport,
                        "chio.registry.listing-report.v1",
                        "report-mirror-a-1",
                        "mirror-operator-a",
                        'e',
                    ),
                    observed_listing_sha256: hex('1'),
                    freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Fresh,
                        age_secs: 40,
                        max_age_secs: 300,
                        valid_until: 1_743_552_360,
                        generated_at: 1_743_552_020,
                    },
                    observed_at: 1_743_552_020,
                    upstream_hop_count: 1,
                },
                FederationPublisherObservation {
                    publisher: GenericRegistryPublisher {
                        role: GenericRegistryPublisherRole::Indexer,
                        operator_id: "indexer-operator-a".to_string(),
                        operator_name: Some("Indexer Operator A".to_string()),
                        registry_url: "https://indexer-a.chio.example/registry".to_string(),
                        upstream_registry_urls: vec![
                            "https://origin.chio.example/registry".to_string(),
                        ],
                    },
                    report_ref: sample_reference(
                        FederationArtifactKind::ListingReport,
                        "chio.registry.listing-report.v1",
                        "report-indexer-a-1",
                        "indexer-operator-a",
                        'f',
                    ),
                    observed_listing_sha256: hex('1'),
                    freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Fresh,
                        age_secs: 45,
                        max_age_secs: 300,
                        valid_until: 1_743_552_360,
                        generated_at: 1_743_552_015,
                    },
                    observed_at: 1_743_552_015,
                    upstream_hop_count: 1,
                },
            ],
            conflicts: vec![],
            anti_eclipse_policy: FederationAntiEclipsePolicy::default(),
            final_state: FederationQuorumState::Converged,
            note: Some("Requires origin plus independent mirror/indexer observation before a remote listing is treated as converged."
                .to_string()),
        }
    }

    fn sample_open_admission_policy() -> FederatedOpenAdmissionPolicyArtifact {
        FederatedOpenAdmissionPolicyArtifact {
            schema: CHIO_FEDERATION_OPEN_ADMISSION_POLICY_SCHEMA.to_string(),
            policy_id: "foap-1".to_string(),
            issued_at: 1_743_552_120,
            namespace: "registry.chio.example/liability".to_string(),
            governing_operator_id: "origin-operator".to_string(),
            allowed_admission_classes: vec![
                GenericTrustAdmissionClass::PublicUntrusted,
                GenericTrustAdmissionClass::Reviewable,
                GenericTrustAdmissionClass::BondBacked,
            ],
            stake_requirements: vec![FederatedStakeRequirement {
                admission_class: GenericTrustAdmissionClass::BondBacked,
                required_bond_class: Some(OpenMarketBondClass::Listing),
                minimum_bond_amount: Some(MonetaryAmount {
                    units: 10_000,
                    currency: "USD".to_string(),
                }),
                slashable: true,
                governance_case_required: false,
            }],
            governing_charter_ref: sample_reference(
                FederationArtifactKind::GovernanceCharter,
                "chio.registry.governance-charter.v1",
                "charter-1",
                "origin-operator",
                '2',
            ),
            fee_schedule_ref: sample_reference(
                FederationArtifactKind::OpenMarketFeeSchedule,
                "chio.registry.market-fee-schedule.v1",
                "fee-schedule-1",
                "origin-operator",
                '3',
            ),
            explicit_local_review_required: true,
            visibility_only_without_activation: true,
            note: Some("Allows public visibility, but runtime trust still requires explicit local review or bond-backed admission."
                .to_string()),
        }
    }

    fn sample_reputation_clearing() -> FederatedReputationClearingArtifact {
        FederatedReputationClearingArtifact {
            schema: CHIO_FEDERATION_REPUTATION_CLEARING_SCHEMA.to_string(),
            clearing_id: "frc-1".to_string(),
            generated_at: 1_743_552_180,
            subject_key: "subject-1".to_string(),
            namespace: "registry.chio.example/liability".to_string(),
            participating_operator_ids: vec![
                "origin-operator".to_string(),
                "mirror-operator-a".to_string(),
                "indexer-operator-a".to_string(),
                "consumer-operator".to_string(),
            ],
            local_weighting_policy_ref: "policy/reputation/federated-default".to_string(),
            admission_policy_ref: "foap-1".to_string(),
            inputs: vec![
                FederatedReputationInputReference {
                    kind: FederatedReputationInputKind::ReputationSummary,
                    artifact_ref: sample_reference(
                        FederationArtifactKind::PortableReputationSummary,
                        "chio.portable-reputation-summary.v1",
                        "summary-origin-1",
                        "origin-operator",
                        '4',
                    ),
                    subject_key: "subject-1".to_string(),
                    issuer_operator_id: "origin-operator".to_string(),
                    issuer_independence_group_id: Some("operator-group-origin".to_string()),
                    weight_bps: 3_000,
                    blocking: false,
                    published_at: 1_743_552_000,
                    expires_at: Some(1_743_638_400),
                    note: Some("Origin-issued portable reputation summary.".to_string()),
                },
                FederatedReputationInputReference {
                    kind: FederatedReputationInputKind::ReputationSummary,
                    artifact_ref: sample_reference(
                        FederationArtifactKind::PortableReputationSummary,
                        "chio.portable-reputation-summary.v1",
                        "summary-mirror-a-1",
                        "mirror-operator-a",
                        '5',
                    ),
                    subject_key: "subject-1".to_string(),
                    issuer_operator_id: "mirror-operator-a".to_string(),
                    issuer_independence_group_id: Some("operator-group-mirror".to_string()),
                    weight_bps: 2_500,
                    blocking: false,
                    published_at: 1_743_552_010,
                    expires_at: Some(1_743_638_400),
                    note: Some("Mirror-issued portable reputation summary.".to_string()),
                },
                FederatedReputationInputReference {
                    kind: FederatedReputationInputKind::NegativeEvent,
                    artifact_ref: sample_reference(
                        FederationArtifactKind::PortableNegativeEvent,
                        "chio.portable-negative-event.v1",
                        "negative-indexer-a-1",
                        "indexer-operator-a",
                        '6',
                    ),
                    subject_key: "subject-1".to_string(),
                    issuer_operator_id: "indexer-operator-a".to_string(),
                    issuer_independence_group_id: Some("operator-group-indexer".to_string()),
                    weight_bps: 2_000,
                    blocking: true,
                    published_at: 1_743_552_020,
                    expires_at: Some(1_743_595_200),
                    note: Some("Indexers contribute corroborated negative-event evidence."
                        .to_string()),
                },
                FederatedReputationInputReference {
                    kind: FederatedReputationInputKind::NegativeEvent,
                    artifact_ref: sample_reference(
                        FederationArtifactKind::PortableNegativeEvent,
                        "chio.portable-negative-event.v1",
                        "negative-origin-1",
                        "origin-operator",
                        '7',
                    ),
                    subject_key: "subject-1".to_string(),
                    issuer_operator_id: "origin-operator".to_string(),
                    issuer_independence_group_id: Some("operator-group-origin".to_string()),
                    weight_bps: 1_500,
                    blocking: true,
                    published_at: 1_743_552_025,
                    expires_at: Some(1_743_595_200),
                    note: Some("Independent corroboration keeps a single issuer from becoming a universal oracle."
                        .to_string()),
                },
            ],
            sybil_control: FederatedSybilControl::default(),
            accepted_input_ids: vec![
                "summary-origin-1".to_string(),
                "summary-mirror-a-1".to_string(),
                "negative-indexer-a-1".to_string(),
                "negative-origin-1".to_string(),
            ],
            rejected_input_ids: vec![],
            effective_admission_class: GenericTrustAdmissionClass::Reviewable,
            continuity: Some(FederatedReputationClearingContinuity {
                continuity_id: "registry.chio.example/liability:subject-1".to_string(),
                previous_clearing_id: None,
            }),
            note: Some("Shared reputation clearing preserves local weighting and requires corroborated negative-event inputs."
                .to_string()),
        }
    }

    fn sample_qualification_matrix() -> FederationQualificationMatrix {
        FederationQualificationMatrix {
            schema: CHIO_FEDERATION_QUALIFICATION_MATRIX_SCHEMA.to_string(),
            profile_id: "chio.federation.profile".to_string(),
            exchange_ref: "fex-1".to_string(),
            quorum_report_ref: "fqr-1".to_string(),
            reputation_clearing_ref: "frc-1".to_string(),
            cases: vec![
                FederationQualificationCase {
                    id: "activation-exchange".to_string(),
                    name: "Federated activation exchange stays visibility-first and locally reviewable"
                        .to_string(),
                    requirement_ids: vec!["TRUSTMAX-01".to_string()],
                    scenario: FederationScenarioKind::ConflictingActivation,
                    expected_outcome: FederationQualificationOutcome::Pass,
                    observed_outcome: FederationQualificationOutcome::Pass,
                    notes: "Remote trust activation remains an explicit exchange contract and never becomes ambient runtime trust."
                        .to_string(),
                },
                FederationQualificationCase {
                    id: "quorum-conflict".to_string(),
                    name: "Quorum, freshness, and anti-eclipse posture remain machine-reviewable"
                        .to_string(),
                    requirement_ids: vec!["TRUSTMAX-02".to_string()],
                    scenario: FederationScenarioKind::InsufficientQuorum,
                    expected_outcome: FederationQualificationOutcome::Pass,
                    observed_outcome: FederationQualificationOutcome::Pass,
                    notes: "Conflicting or stale publisher state fails closed instead of silently rewriting trust."
                        .to_string(),
                },
                FederationQualificationCase {
                    id: "open-admission-boundary".to_string(),
                    name: "Open admission stays bounded by explicit stake and review policy"
                        .to_string(),
                    requirement_ids: vec!["TRUSTMAX-03".to_string()],
                    scenario: FederationScenarioKind::GovernanceInterop,
                    expected_outcome: FederationQualificationOutcome::Pass,
                    observed_outcome: FederationQualificationOutcome::Pass,
                    notes: "Visibility and participation stay distinct from runtime trust, even when bond-backed admission is allowed."
                        .to_string(),
                },
                FederationQualificationCase {
                    id: "shared-reputation-sybil".to_string(),
                    name: "Shared reputation clearing resists duplicate-issuer and oracle collapse"
                        .to_string(),
                    requirement_ids: vec!["TRUSTMAX-04".to_string()],
                    scenario: FederationScenarioKind::ReputationSybil,
                    expected_outcome: FederationQualificationOutcome::Pass,
                    observed_outcome: FederationQualificationOutcome::Pass,
                    notes: "Accepted summaries come from distinct issuers and blocking negative events require corroboration."
                        .to_string(),
                },
                FederationQualificationCase {
                    id: "adversarial-federation".to_string(),
                    name: "Hostile publisher and eclipse attempts fail closed under the federation boundary"
                        .to_string(),
                    requirement_ids: vec!["TRUSTMAX-05".to_string()],
                    scenario: FederationScenarioKind::EclipseAttempt,
                    expected_outcome: FederationQualificationOutcome::Pass,
                    observed_outcome: FederationQualificationOutcome::Pass,
                    notes: "Hostile federation inputs remain visible but do not collapse governance or admission into ambient trust."
                        .to_string(),
                },
            ],
        }
    }

    fn sample_conflict() -> FederationConflictEvidence {
        FederationConflictEvidence {
            divergence_key: "listing-liability-provider-1:hash-mismatch".to_string(),
            publisher_operator_ids: vec![
                "origin-operator".to_string(),
                "mirror-operator-a".to_string(),
            ],
            reason: "origin and mirror observed different listing bodies".to_string(),
        }
    }

    #[test]
    fn activation_exchange_requires_local_policy_import() {
        let mut exchange = sample_activation_exchange();
        exchange.import_control.explicit_local_activation_required = false;
        assert!(matches!(
            validate_federation_activation_exchange(&exchange),
            Err(FederationContractError::InvalidExchange(_))
        ));
    }

    #[test]
    fn quorum_report_requires_origin_publisher() {
        let mut report = sample_quorum_report();
        report.publishers.remove(0);
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::InvalidQuorum(_))
        ));
    }

    #[test]
    fn open_admission_policy_requires_bond_requirement() {
        let mut policy = sample_open_admission_policy();
        policy.stake_requirements.clear();
        assert!(matches!(
            validate_federated_open_admission_policy(&policy),
            Err(FederationContractError::InvalidAdmission(_))
        ));
    }

    #[test]
    fn reputation_clearing_rejects_duplicate_summary_issuer() {
        let mut clearing = sample_reputation_clearing();
        clearing.inputs[1].issuer_operator_id = "origin-operator".to_string();
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::InvalidClearing(_))
        ));
    }

    #[test]
    fn reference_artifacts_parse_and_validate() {
        let exchange: FederationActivationExchangeArtifact = must(
            serde_json::from_str(include_str!(
                "../../../docs/standards/CHIO_FEDERATION_ACTIVATION_EXCHANGE_EXAMPLE.json"
            )),
            "parse activation exchange reference",
        );
        let quorum: FederationQuorumReport = must(
            serde_json::from_str(include_str!(
                "../../../docs/standards/CHIO_FEDERATION_QUORUM_REPORT_EXAMPLE.json"
            )),
            "parse quorum report reference",
        );
        let admission: FederatedOpenAdmissionPolicyArtifact = must(
            serde_json::from_str(include_str!(
                "../../../docs/standards/CHIO_FEDERATION_OPEN_ADMISSION_POLICY_EXAMPLE.json"
            )),
            "parse admission policy reference",
        );
        let clearing: FederatedReputationClearingArtifact = must(
            serde_json::from_str(include_str!(
                "../../../docs/standards/CHIO_FEDERATION_REPUTATION_CLEARING_EXAMPLE.json"
            )),
            "parse reputation clearing reference",
        );
        let matrix: FederationQualificationMatrix = must(
            serde_json::from_str(include_str!(
                "../../../docs/standards/CHIO_FEDERATION_QUALIFICATION_MATRIX.json"
            )),
            "parse qualification matrix reference",
        );

        must(
            validate_federation_activation_exchange(&exchange),
            "validate activation exchange reference",
        );
        must(
            validate_federation_quorum_report(&quorum),
            "validate quorum report reference",
        );
        must(
            validate_federated_open_admission_policy(&admission),
            "validate admission policy reference",
        );
        must(
            validate_federated_reputation_clearing(&clearing),
            "validate reputation clearing reference",
        );
        must(
            validate_federation_qualification_matrix(&matrix),
            "validate qualification matrix reference",
        );
    }

    #[test]
    fn qualification_matrix_requires_requirement_coverage() {
        let mut matrix = sample_qualification_matrix();
        matrix.cases.pop();
        assert!(matches!(
            validate_federation_qualification_matrix(&matrix),
            Err(FederationContractError::InvalidQualificationCase(_))
        ));
    }

    #[test]
    fn activation_exchange_rejects_schema_reference_and_operator_mismatches() {
        let mut exchange = sample_activation_exchange();
        exchange.schema = "chio.federation-activation-exchange.v0".to_string();
        assert!(matches!(
            validate_federation_activation_exchange(&exchange),
            Err(FederationContractError::UnsupportedSchema(_))
        ));

        let mut exchange = sample_activation_exchange();
        exchange.target_operator_id = exchange.source_operator_id.clone();
        assert!(matches!(
            validate_federation_activation_exchange(&exchange),
            Err(FederationContractError::InvalidExchange(_))
        ));

        let mut exchange = sample_activation_exchange();
        exchange.expires_at = exchange.issued_at;
        assert!(matches!(
            validate_federation_activation_exchange(&exchange),
            Err(FederationContractError::InvalidExchange(_))
        ));

        let mut exchange = sample_activation_exchange();
        exchange.activation_ref.kind = FederationArtifactKind::Listing;
        assert!(matches!(
            validate_federation_activation_exchange(&exchange),
            Err(FederationContractError::InvalidExchange(_))
        ));

        let mut exchange = sample_activation_exchange();
        exchange.listing_ref.kind = FederationArtifactKind::TrustActivation;
        assert!(matches!(
            validate_federation_activation_exchange(&exchange),
            Err(FederationContractError::InvalidExchange(_))
        ));

        let mut exchange = sample_activation_exchange();
        must_some(
            exchange.governing_charter_ref.as_mut(),
            "activation exchange should include governing charter",
        )
        .kind = FederationArtifactKind::Listing;
        assert!(matches!(
            validate_federation_activation_exchange(&exchange),
            Err(FederationContractError::InvalidExchange(_))
        ));

        let mut exchange = sample_activation_exchange();
        exchange.delegation_control.delegator_operator_id = "other-operator".to_string();
        assert!(matches!(
            validate_federation_activation_exchange(&exchange),
            Err(FederationContractError::InvalidExchange(_))
        ));

        let mut exchange = sample_activation_exchange();
        exchange.delegation_control.delegate_operator_id = "other-operator".to_string();
        assert!(matches!(
            validate_federation_activation_exchange(&exchange),
            Err(FederationContractError::InvalidExchange(_))
        ));
    }

    #[test]
    fn federation_helper_validators_reject_invalid_boundary_inputs() {
        let mut reference = sample_reference(
            FederationArtifactKind::Listing,
            "chio.registry.listing.v1",
            "listing-1",
            "origin-operator",
            'a',
        );
        reference.sha256 = "deadbeef".to_string();
        assert!(matches!(
            validate_federation_artifact_reference(&reference, "reference"),
            Err(FederationContractError::InvalidReference(_))
        ));

        let mut scope = sample_activation_exchange().scope;
        scope.allowed_actor_kinds.clear();
        assert!(matches!(
            validate_federation_scope(&scope),
            Err(FederationContractError::MissingField(_))
        ));

        let mut scope = sample_activation_exchange().scope;
        scope.allowed_admission_classes.clear();
        assert!(matches!(
            validate_federation_scope(&scope),
            Err(FederationContractError::MissingField(_))
        ));

        let mut scope = sample_activation_exchange().scope;
        scope.policy_reference = Some("   ".to_string());
        assert!(matches!(
            validate_federation_scope(&scope),
            Err(FederationContractError::MissingField(_))
        ));

        let mut control = sample_activation_exchange().delegation_control;
        control.delegate_operator_id = control.delegator_operator_id.clone();
        assert!(matches!(
            validate_delegation_control(&control),
            Err(FederationContractError::InvalidExchange(_))
        ));

        let mut control = sample_activation_exchange().delegation_control;
        control.max_hops = 0;
        assert!(matches!(
            validate_delegation_control(&control),
            Err(FederationContractError::InvalidExchange(_))
        ));

        let mut control = sample_activation_exchange().delegation_control;
        control.attenuation_required = false;
        assert!(matches!(
            validate_delegation_control(&control),
            Err(FederationContractError::InvalidExchange(_))
        ));

        let mut control = sample_activation_exchange().delegation_control;
        control.visibility_only_until_local_activation = false;
        assert!(matches!(
            validate_delegation_control(&control),
            Err(FederationContractError::InvalidExchange(_))
        ));

        let import = FederationImportControl {
            manual_review_required: false,
            ..Default::default()
        };
        assert!(matches!(
            validate_import_control(&import),
            Err(FederationContractError::InvalidExchange(_))
        ));

        let import = FederationImportControl {
            reject_stale_inputs: false,
            ..Default::default()
        };
        assert!(matches!(
            validate_import_control(&import),
            Err(FederationContractError::InvalidExchange(_))
        ));

        let import = FederationImportControl {
            allow_visibility_without_runtime_trust: false,
            ..Default::default()
        };
        assert!(matches!(
            validate_import_control(&import),
            Err(FederationContractError::InvalidExchange(_))
        ));

        let import = FederationImportControl {
            prohibit_ambient_runtime_admission: false,
            ..Default::default()
        };
        assert!(matches!(
            validate_import_control(&import),
            Err(FederationContractError::InvalidExchange(_))
        ));

        let anti_eclipse = FederationAntiEclipsePolicy {
            minimum_distinct_operators: 0,
            ..Default::default()
        };
        assert!(matches!(
            validate_anti_eclipse_policy(&anti_eclipse),
            Err(FederationContractError::InvalidQuorum(_))
        ));

        assert!(matches!(
            validate_positive_money(
                &MonetaryAmount {
                    units: 0,
                    currency: "USD".to_string(),
                },
                "bond"
            ),
            Err(FederationContractError::InvalidAdmission(_))
        ));

        assert!(matches!(
            validate_positive_money(
                &MonetaryAmount {
                    units: 10,
                    currency: "US".to_string(),
                },
                "bond"
            ),
            Err(FederationContractError::InvalidAdmission(_))
        ));

        assert!(matches!(
            validate_hex_digest("", "digest"),
            Err(FederationContractError::MissingField(_))
        ));

        assert!(matches!(
            validate_hex_digest("xyz", "digest"),
            Err(FederationContractError::InvalidReference(_))
        ));

        assert!(matches!(
            ensure_unique_strings(&["origin".to_string(), "origin".to_string()], "operators"),
            Err(FederationContractError::DuplicateValue(_))
        ));

        assert!(matches!(
            ensure_unique_copy_values(
                &[
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustAdmissionClass::Reviewable,
                ],
                "classes"
            ),
            Err(FederationContractError::DuplicateValue(_))
        ));
    }

    #[test]
    fn quorum_report_rejects_invalid_observations_and_policy_failures() {
        let mut report = sample_quorum_report();
        report.schema = "chio.federation-quorum-report.v0".to_string();
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::UnsupportedSchema(_))
        ));

        let mut report = sample_quorum_report();
        report.quorum_threshold = 0;
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::InvalidQuorum(_))
        ));

        let mut report = sample_quorum_report();
        report.max_replica_age_secs = 0;
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::InvalidQuorum(_))
        ));

        let mut report = sample_quorum_report();
        report.publishers.clear();
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::MissingField(_))
        ));

        let mut report = sample_quorum_report();
        report.publishers[0].report_ref.kind = FederationArtifactKind::Listing;
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::InvalidQuorum(_))
        ));

        let mut report = sample_quorum_report();
        report.publishers[0].report_ref.operator_id = "other-operator".to_string();
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::InvalidQuorum(_))
        ));

        let mut report = sample_quorum_report();
        report.publishers[0].observed_listing_sha256 = "bad-digest".to_string();
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::InvalidReference(_))
        ));

        let mut report = sample_quorum_report();
        report.publishers[1].upstream_hop_count = 2;
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::InvalidQuorum(_))
        ));

        let mut report = sample_quorum_report();
        report.publishers[1].publisher.operator_id =
            report.publishers[0].publisher.operator_id.clone();
        report.publishers[1].report_ref.operator_id =
            report.publishers[0].publisher.operator_id.clone();
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::DuplicateValue(_))
        ));

        let mut report = sample_quorum_report();
        report
            .publishers
            .retain(|publisher| publisher.publisher.role != GenericRegistryPublisherRole::Indexer);
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::InvalidQuorum(_))
        ));

        let mut report = sample_quorum_report();
        report.anti_eclipse_policy.minimum_distinct_operators = 4;
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::InvalidQuorum(_))
        ));
    }

    #[test]
    fn quorum_report_rejects_invalid_conflict_and_state_combinations() {
        let mut report = sample_quorum_report();
        report.conflicts = vec![sample_conflict(), sample_conflict()];
        report.final_state = FederationQuorumState::Conflicting;
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::DuplicateValue(_))
        ));

        let mut report = sample_quorum_report();
        report.conflicts.push(sample_conflict());
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::InvalidQuorum(_))
        ));

        let mut report = sample_quorum_report();
        report.publishers[0].freshness.state = GenericListingFreshnessState::Stale;
        report.publishers[0].freshness.age_secs = 400;
        report.publishers[1].freshness.state = GenericListingFreshnessState::Stale;
        report.publishers[1].freshness.age_secs = 400;
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::InvalidQuorum(_))
        ));

        let mut report = sample_quorum_report();
        report.final_state = FederationQuorumState::Conflicting;
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::InvalidQuorum(_))
        ));

        let mut report = sample_quorum_report();
        report.final_state = FederationQuorumState::InsufficientQuorum;
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::InvalidQuorum(_))
        ));

        let mut report = sample_quorum_report();
        report.final_state = FederationQuorumState::Stale;
        report.publishers[0].freshness.state = GenericListingFreshnessState::Fresh;
        assert!(matches!(
            validate_federation_quorum_report(&report),
            Err(FederationContractError::InvalidQuorum(_))
        ));
    }

    #[test]
    fn open_admission_policy_and_stake_rules_reject_invalid_configurations() {
        let mut policy = sample_open_admission_policy();
        policy.schema = "chio.federation-open-admission-policy.v0".to_string();
        assert!(matches!(
            validate_federated_open_admission_policy(&policy),
            Err(FederationContractError::UnsupportedSchema(_))
        ));

        let mut policy = sample_open_admission_policy();
        policy.allowed_admission_classes.clear();
        assert!(matches!(
            validate_federated_open_admission_policy(&policy),
            Err(FederationContractError::MissingField(_))
        ));

        let mut policy = sample_open_admission_policy();
        policy
            .allowed_admission_classes
            .push(GenericTrustAdmissionClass::Reviewable);
        assert!(matches!(
            validate_federated_open_admission_policy(&policy),
            Err(FederationContractError::DuplicateValue(_))
        ));

        let mut policy = sample_open_admission_policy();
        policy.governing_charter_ref.kind = FederationArtifactKind::Listing;
        assert!(matches!(
            validate_federated_open_admission_policy(&policy),
            Err(FederationContractError::InvalidAdmission(_))
        ));

        let mut policy = sample_open_admission_policy();
        policy.fee_schedule_ref.kind = FederationArtifactKind::GovernanceCharter;
        assert!(matches!(
            validate_federated_open_admission_policy(&policy),
            Err(FederationContractError::InvalidAdmission(_))
        ));

        let mut policy = sample_open_admission_policy();
        policy.explicit_local_review_required = false;
        assert!(matches!(
            validate_federated_open_admission_policy(&policy),
            Err(FederationContractError::InvalidAdmission(_))
        ));

        let mut policy = sample_open_admission_policy();
        policy.visibility_only_without_activation = false;
        assert!(matches!(
            validate_federated_open_admission_policy(&policy),
            Err(FederationContractError::InvalidAdmission(_))
        ));

        let mut policy = sample_open_admission_policy();
        policy.stake_requirements[0].admission_class = GenericTrustAdmissionClass::RoleGated;
        assert!(matches!(
            validate_federated_open_admission_policy(&policy),
            Err(FederationContractError::InvalidAdmission(_))
        ));

        let mut policy = sample_open_admission_policy();
        let duplicate = policy.stake_requirements[0].clone();
        policy.stake_requirements.push(duplicate);
        assert!(matches!(
            validate_federated_open_admission_policy(&policy),
            Err(FederationContractError::DuplicateValue(_))
        ));

        let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
        requirement.minimum_bond_amount = None;
        assert!(matches!(
            validate_stake_requirement(&requirement),
            Err(FederationContractError::InvalidAdmission(_))
        ));

        let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
        requirement.required_bond_class = None;
        assert!(matches!(
            validate_stake_requirement(&requirement),
            Err(FederationContractError::InvalidAdmission(_))
        ));

        let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
        requirement.slashable = false;
        assert!(matches!(
            validate_stake_requirement(&requirement),
            Err(FederationContractError::InvalidAdmission(_))
        ));

        let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
        requirement.minimum_bond_amount = Some(MonetaryAmount {
            units: 0,
            currency: "USD".to_string(),
        });
        assert!(matches!(
            validate_stake_requirement(&requirement),
            Err(FederationContractError::InvalidAdmission(_))
        ));

        let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
        requirement.minimum_bond_amount = Some(MonetaryAmount {
            units: 10,
            currency: "US".to_string(),
        });
        assert!(matches!(
            validate_stake_requirement(&requirement),
            Err(FederationContractError::InvalidAdmission(_))
        ));

        let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
        requirement.admission_class = GenericTrustAdmissionClass::PublicUntrusted;
        assert!(matches!(
            validate_stake_requirement(&requirement),
            Err(FederationContractError::InvalidAdmission(_))
        ));

        let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
        requirement.admission_class = GenericTrustAdmissionClass::RoleGated;
        requirement.required_bond_class = None;
        requirement.minimum_bond_amount = None;
        requirement.governance_case_required = false;
        assert!(matches!(
            validate_stake_requirement(&requirement),
            Err(FederationContractError::InvalidAdmission(_))
        ));

        let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
        requirement.admission_class = GenericTrustAdmissionClass::RoleGated;
        requirement.governance_case_required = true;
        assert!(matches!(
            validate_stake_requirement(&requirement),
            Err(FederationContractError::InvalidAdmission(_))
        ));
    }

    #[test]
    fn reputation_input_and_sybil_helpers_reject_invalid_values() {
        let clearing = sample_reputation_clearing();

        let mut input = clearing.inputs[0].clone();
        input.subject_key = "someone-else".to_string();
        assert!(matches!(
            validate_reputation_input_reference(
                &input,
                clearing.generated_at,
                &clearing.subject_key
            ),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut input = clearing.inputs[0].clone();
        input.weight_bps = 0;
        assert!(matches!(
            validate_reputation_input_reference(
                &input,
                clearing.generated_at,
                &clearing.subject_key
            ),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut input = clearing.inputs[0].clone();
        input.published_at = clearing.generated_at + 1;
        assert!(matches!(
            validate_reputation_input_reference(
                &input,
                clearing.generated_at,
                &clearing.subject_key
            ),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut input = clearing.inputs[0].clone();
        input.expires_at = Some(input.published_at);
        assert!(matches!(
            validate_reputation_input_reference(
                &input,
                clearing.generated_at,
                &clearing.subject_key
            ),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut input = clearing.inputs[0].clone();
        input.expires_at = Some(clearing.generated_at);
        assert!(matches!(
            validate_reputation_input_reference(
                &input,
                clearing.generated_at,
                &clearing.subject_key
            ),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut input = clearing.inputs[0].clone();
        input.issuer_independence_group_id = Some("   ".to_string());
        assert!(matches!(
            validate_reputation_input_reference(
                &input,
                clearing.generated_at,
                &clearing.subject_key
            ),
            Err(FederationContractError::MissingField(_))
        ));

        let mut input = clearing.inputs[0].clone();
        input.blocking = true;
        assert!(matches!(
            validate_reputation_input_reference(
                &input,
                clearing.generated_at,
                &clearing.subject_key
            ),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut input = clearing.inputs[0].clone();
        input.artifact_ref.kind = FederationArtifactKind::PortableNegativeEvent;
        assert!(matches!(
            validate_reputation_input_reference(
                &input,
                clearing.generated_at,
                &clearing.subject_key
            ),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut input = clearing.inputs[2].clone();
        input.artifact_ref.kind = FederationArtifactKind::PortableReputationSummary;
        assert!(matches!(
            validate_reputation_input_reference(
                &input,
                clearing.generated_at,
                &clearing.subject_key
            ),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let sybil = FederatedSybilControl {
            minimum_independent_issuers: 0,
            ..Default::default()
        };
        assert!(matches!(
            validate_sybil_control(&sybil),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let sybil = FederatedSybilControl {
            maximum_inputs_per_issuer: 0,
            ..Default::default()
        };
        assert!(matches!(
            validate_sybil_control(&sybil),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let sybil = FederatedSybilControl {
            oracle_cap_bps: 10_001,
            ..Default::default()
        };
        assert!(matches!(
            validate_sybil_control(&sybil),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let sybil = FederatedSybilControl {
            local_weighting_required: false,
            ..Default::default()
        };
        assert!(matches!(
            validate_sybil_control(&sybil),
            Err(FederationContractError::InvalidClearing(_))
        ));
    }

    #[test]
    fn reputation_clearing_rejects_invalid_classification_and_sybil_outcomes() {
        let mut clearing = sample_reputation_clearing();
        clearing.schema = "chio.federation-reputation-clearing.v0".to_string();
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::UnsupportedSchema(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing.participating_operator_ids.clear();
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::MissingField(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing.participating_operator_ids[1] = clearing.participating_operator_ids[0].clone();
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::DuplicateValue(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing.inputs.clear();
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::MissingField(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing
            .accepted_input_ids
            .push("summary-origin-1".to_string());
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::DuplicateValue(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing.rejected_input_ids = vec![
            "negative-origin-1".to_string(),
            "negative-origin-1".to_string(),
        ];
        clearing
            .accepted_input_ids
            .retain(|id| id != "negative-origin-1");
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::DuplicateValue(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing
            .rejected_input_ids
            .push("summary-origin-1".to_string());
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing.accepted_input_ids.pop();
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing.inputs[1].issuer_operator_id = "origin-operator".to_string();
        clearing.inputs[1].artifact_ref.operator_id = "origin-operator".to_string();
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing.inputs[0].artifact_ref.operator_id = "other-operator".to_string();
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing.inputs[0].issuer_operator_id = "other-operator".to_string();
        clearing.inputs[0].artifact_ref.operator_id = "other-operator".to_string();
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing.inputs[0].weight_bps = 4_001;
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing.accepted_input_ids = vec![
            "summary-origin-1".to_string(),
            "negative-origin-1".to_string(),
        ];
        clearing.rejected_input_ids = vec![
            "summary-mirror-a-1".to_string(),
            "negative-indexer-a-1".to_string(),
        ];
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing.accepted_input_ids = vec![
            "summary-origin-1".to_string(),
            "summary-mirror-a-1".to_string(),
            "negative-indexer-a-1".to_string(),
        ];
        clearing.rejected_input_ids = vec!["negative-origin-1".to_string()];
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing.sybil_control.minimum_independent_issuers = 3;
        clearing.inputs[1].issuer_independence_group_id =
            clearing.inputs[0].issuer_independence_group_id.clone();
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut clearing = sample_reputation_clearing();
        clearing.accepted_input_ids.clear();
        clearing.rejected_input_ids = clearing
            .inputs
            .iter()
            .map(|input| input.artifact_ref.artifact_id.clone())
            .collect();
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::InvalidClearing(_))
        ));

        let mut clearing = sample_reputation_clearing();
        let clearing_id = clearing.clearing_id.clone();
        must_some(
            clearing.continuity.as_mut(),
            "reputation clearing should include continuity",
        )
        .previous_clearing_id = Some(clearing_id);
        assert!(matches!(
            validate_federated_reputation_clearing(&clearing),
            Err(FederationContractError::InvalidClearing(_))
        ));
    }

    #[test]
    fn qualification_matrix_rejects_case_level_misconfigurations() {
        let mut matrix = sample_qualification_matrix();
        matrix.schema = "chio.federation-qualification-matrix.v0".to_string();
        assert!(matches!(
            validate_federation_qualification_matrix(&matrix),
            Err(FederationContractError::UnsupportedSchema(_))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases.clear();
        assert!(matches!(
            validate_federation_qualification_matrix(&matrix),
            Err(FederationContractError::MissingField(_))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases[0].requirement_ids.clear();
        assert!(matches!(
            validate_federation_qualification_matrix(&matrix),
            Err(FederationContractError::InvalidQualificationCase(_))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases[0]
            .requirement_ids
            .push("TRUSTMAX-01".to_string());
        assert!(matches!(
            validate_federation_qualification_matrix(&matrix),
            Err(FederationContractError::DuplicateValue(_))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases[1].id = matrix.cases[0].id.clone();
        assert!(matches!(
            validate_federation_qualification_matrix(&matrix),
            Err(FederationContractError::DuplicateValue(_))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases[0].notes.clear();
        assert!(matches!(
            validate_federation_qualification_matrix(&matrix),
            Err(FederationContractError::MissingField(_))
        ));
    }
}
