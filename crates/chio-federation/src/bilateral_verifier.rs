//! Implements a partial local verifier for the bilateral DSSE
//! signature-slice profile produced by
//! [`crate::bilateral_dsse::sign_dsse_envelope_full`].
//!
//! ## Partial-verifier scope
//!
//! The implementation does not yet cover the full predicate schema:
//!
//!   - `BilateralPredicate` is intentionally not the strict Chio
//!     predicate: it is missing required fields the spec
//!     enumerates (for example, `tool_args_hash` per the Chio bilateral
//!     invocation spec) and accepts
//!     internal non-schema fields that the spec does not define.
//!   - The error mapping conflates parseable-but-schema-malformed
//!     Statement JSON with `dsse.malformed` rather than the spec's
//!     `statement.malformed`.
//!
//! This verifier is labeled as a **partial local verifier**: it
//! implements the structural / cryptographic core
//! plus a meaningful subset of the §7 step list against the local
//! signature-slice profile. Strict Chio predicate completion belongs
//! in a separate predicate-profile implementation.
//!
//! Receipts that surface verifier output should NOT advertise full
//! §7 conformance based on this implementation alone.
//!
//! ## Public API summary
//!
//! * [`PeerPinSet`], [`PinnedPeer`] - verifier pin set: which kernels
//!   are trusted at which passport keys.
//! * [`ReceiptStore`] / [`InMemoryReceiptStore`] - step 7 lookup.
//! * [`CapabilityLeaseRegistry`] / [`InMemoryLeaseRegistry`] - step 14.
//! * [`GovernanceReceiptStore`] / [`InMemoryGovernanceReceiptStore`] - step 15.
//! * [`RevocationOracle`] / [`DemoAllowAllRevocationOracle`] - step 9.
//! * [`PinnedEpoch`] - verifier's wall clock + epoch height.
//! * [`VerifierConfig`] - bundles the trait objects + epoch.
//! * [`verify_bilateral_cosign_invocation`] - the canonical verifier for
//!   the local bilateral DSSE signature-slice profile. This is not full
//!   §7 conformance pending strict predicate-profile completion.
//! * [`VerifiedBilateralCoSignInvocation`] - successful verifier output
//!   (mirrors §7 step 17 for the steps this implementation covers).
//! * [`VerifierError`] - fail-closed error codes for the spec §7.1-compatible
//!   subset this partial verifier can reach (e.g. `subject.digest_mismatch`,
//!   `peer.unpinned_or_keyid_mismatch`).
//!
//! ## Usage from the local fixture helper
//!
//! [`crate::bilateral::execute_local_bilateral_invocation_fixture`] is the
//! local fixture helper that drives [`sign_dsse_envelope_full`] and
//! immediately runs this partial local verifier before returning the
//! [`crate::bilateral::BilateralCoSignArtifacts`]. Callers that want to
//! verify externally produced envelopes call
//! [`verify_bilateral_cosign_invocation`] directly.

use std::collections::{BTreeMap, HashMap, HashSet};

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::ChioReceipt;
use sha2::{Digest, Sha256};

use crate::bilateral::BilateralCoSigningError;
use crate::bilateral_dsse::{
    receipt_subject_name, require_policy_evaluation_allow_admission,
    verify_chio_bilateral_dsse_envelope, verify_dsse_envelope, BilateralPredicate,
    CapabilityLeaseRef, DsseEnvelope, DsseStatement, GovernanceReceiptRef, Keyid, TreatyBindingRef,
    PAYLOAD_TYPE_IN_TOTO, PREDICATE_BODY_SCHEMA, PREDICATE_TYPE_BILATERAL,
    PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION, STATEMENT_TYPE_V1, VALID_CROSS_ORG_VISIBILITY,
};
use crate::trust_establishment::LadderManifestRef;

// ---------------------------------------------------------------------------
// Spec §7.1 error codes
// ---------------------------------------------------------------------------

/// Fail-closed error codes returned by [`verify_bilateral_cosign_invocation`].
/// Each exposed variant maps verbatim to a spec §7.1 code (the `Display`
/// impl emits the code itself); kernels that surface verifier output in
/// receipts SHOULD log the code as the canonical value. Strict Chio
/// ordered and quorum consistency claims are accepted only by strict
/// treaty-bound Chio predicates that carry matching treaty refs and an
/// explicit consistency anchor.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum VerifierError {
    /// `dsse.malformed` - envelope JSON is not parseable, payloadType
    /// mismatched, or signatures count != expected for the cosign mode.
    #[error("dsse.malformed: {0}")]
    DsseMalformed(String),
    /// `statement.malformed` - Statement payload is not parseable JSON.
    #[error("statement.malformed: {0}")]
    StatementMalformed(String),
    /// `statement.schema_invalid` - Statement does not satisfy in-toto v1 schema.
    #[error("statement.schema_invalid: {0}")]
    StatementSchemaInvalid(String),
    /// `predicate.type_unrecognised` - predicateType is neither the proposed
    /// in-toto URI nor the chio-namespaced fallback.
    #[error("predicate.type_unrecognised: {0}")]
    PredicateTypeUnrecognised(String),
    #[error("predicate.schema_invalid: {0}")]
    PredicateSchemaInvalid(String),
    /// `subject.digest_mismatch` - subject SHA-256 does not match the
    /// resolved receipt body's canonical-JSON.
    #[error("subject.digest_mismatch: {0}")]
    SubjectDigestMismatch(String),
    /// `peer.unpinned_or_keyid_mismatch` - either kernel identity is not
    /// pinned in the verifier's peer set, or its declared fingerprint
    /// disagrees with the pinned passport.
    #[error("peer.unpinned_or_keyid_mismatch: {0}")]
    PeerUnpinnedOrKeyidMismatch(String),
    /// `peer.revoked_at_epoch` - a participating kernel's passport is
    /// revoked at the pinned epoch.
    #[error("peer.revoked_at_epoch: {0}")]
    PeerRevokedAtEpoch(String),
    /// `signature.server_a_invalid` - tool_server_a's signature does not
    /// verify under its passport key.
    #[error("signature.server_a_invalid: {0}")]
    SignatureServerAInvalid(String),
    /// `signature.server_b_invalid` - tool_server_b's signature does not
    /// verify under its passport key.
    #[error("signature.server_b_invalid: {0}")]
    SignatureServerBInvalid(String),
    /// `policy.verdict_disagreement` - verdicts disagree, or
    /// joint_disposition is inconsistent.
    #[error("policy.verdict_disagreement: {0}")]
    PolicyVerdictDisagreement(String),
    /// `capability.lease_expired_or_unknown` - the named capability lease
    /// cannot be resolved or is past its `expires_at_unix_ms`.
    #[error("capability.lease_expired_or_unknown: {0}")]
    CapabilityLeaseExpiredOrUnknown(String),
    /// `governance.receipt_required_missing` - a receipt-backed class
    /// lacks a `governance_receipt_ref`.
    #[error("governance.receipt_required_missing: {0}")]
    GovernanceReceiptRequiredMissing(String),
    /// `ladder.manifest_missing` - strict Chio verification requires
    /// a signed ladder manifest reference for every participating peer.
    #[error("ladder.manifest_missing: {0}")]
    LadderManifestMissing(String),
    /// `ladder.manifest_stale` - the pinned ladder manifest reference
    /// is not live at the verifier's pinned epoch.
    #[error("ladder.manifest_stale: {0}")]
    LadderManifestStale(String),
    /// Fail-closed action-class invariant: `governance.unknown_action_class`.
    /// The predicate's `tool_name` is not registered in the verifier's
    /// `action_classes` table. Strict mode requires explicit registration:
    /// falling back to `Routine` (no governance receipt required) for an
    /// unregistered tool is fail-OPEN for receipt-backed classes that were
    /// misspelled or omitted from the registry.
    #[error("governance.unknown_action_class: {tool_name:?}")]
    UnknownActionClass { tool_name: String },
}

impl VerifierError {
    /// The bare spec code (e.g. `"subject.digest_mismatch"`), without
    /// the trailing context. Stable across releases.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::DsseMalformed(_) => "dsse.malformed",
            Self::StatementMalformed(_) => "statement.malformed",
            Self::StatementSchemaInvalid(_) => "statement.schema_invalid",
            Self::PredicateTypeUnrecognised(_) => "predicate.type_unrecognised",
            Self::PredicateSchemaInvalid(_) => "predicate.schema_invalid",
            Self::SubjectDigestMismatch(_) => "subject.digest_mismatch",
            Self::PeerUnpinnedOrKeyidMismatch(_) => "peer.unpinned_or_keyid_mismatch",
            Self::PeerRevokedAtEpoch(_) => "peer.revoked_at_epoch",
            Self::SignatureServerAInvalid(_) => "signature.server_a_invalid",
            Self::SignatureServerBInvalid(_) => "signature.server_b_invalid",
            Self::PolicyVerdictDisagreement(_) => "policy.verdict_disagreement",
            Self::CapabilityLeaseExpiredOrUnknown(_) => "capability.lease_expired_or_unknown",
            Self::GovernanceReceiptRequiredMissing(_) => "governance.receipt_required_missing",
            Self::LadderManifestMissing(_) => "ladder.manifest_missing",
            Self::LadderManifestStale(_) => "ladder.manifest_stale",
            Self::UnknownActionClass { .. } => "governance.unknown_action_class",
        }
    }
}

impl From<BilateralCoSigningError> for VerifierError {
    fn from(e: BilateralCoSigningError) -> Self {
        map_bilateral_error(e)
    }
}

// ---------------------------------------------------------------------------
// Pinned epoch + peer set (steps 8, 9)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedEpoch {
    /// Verifier wall-clock at the moment of verification, in Unix ms.
    pub now_unix_ms: u64,
    pub epoch_height: u64,
}

/// One pinned peer in the verifier's trust store.
#[derive(Debug, Clone)]
pub struct PinnedPeer {
    /// `did:chio` identifier of the kernel.
    pub kernel_id: String,
    /// Pinned passport public key.
    pub public_key: PublicKey,
    /// Signed ladder manifest reference accepted during trust establishment.
    pub ladder_manifest_ref: Option<LadderManifestRef>,
}

impl PinnedPeer {
    /// SHA-256 fingerprint of the pinned passport public key, hex-lowercase.
    /// MUST match `KernelIdentity::passport_key_fingerprint` from the
    /// envelope predicate (spec §7 step 8).
    #[must_use]
    pub fn fingerprint(&self) -> Keyid {
        Keyid::from_public_key(&self.public_key)
    }
}

/// Verifier's pin set: which kernels (by `did:chio`) are trusted at
/// which passport keys.
#[derive(Debug, Clone, Default)]
pub struct PeerPinSet {
    by_kernel_id: HashMap<String, PinnedPeer>,
}

impl PeerPinSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, peer: PinnedPeer) {
        self.by_kernel_id.insert(peer.kernel_id.clone(), peer);
    }

    pub fn lookup(&self, kernel_id: &str) -> Option<&PinnedPeer> {
        self.by_kernel_id.get(kernel_id)
    }
}

// ---------------------------------------------------------------------------
// Step 7: ReceiptStore
// ---------------------------------------------------------------------------

/// Returning `None` is fail-closed (mapped to
/// `VerifierError::SubjectDigestMismatch`).
pub trait ReceiptStore: Send + Sync {
    /// Resolve a receipt by `invocation_id` (spec calls this the
    /// invocation id; chio uses `ChioReceipt::id` interchangeably).
    fn resolve(&self, invocation_id: &str) -> Option<ChioReceipt>;
}

#[derive(Debug, Default)]
pub struct InMemoryReceiptStore {
    receipts: HashMap<String, ChioReceipt>,
}

impl InMemoryReceiptStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, receipt: ChioReceipt) {
        self.receipts.insert(receipt.id.clone(), receipt);
    }
}

impl ReceiptStore for InMemoryReceiptStore {
    fn resolve(&self, invocation_id: &str) -> Option<ChioReceipt> {
        self.receipts.get(invocation_id).cloned()
    }
}

// ---------------------------------------------------------------------------
// Step 9: RevocationOracle
// ---------------------------------------------------------------------------

/// Step 9 surface: is a passport key revoked at the pinned epoch?
/// `true` means non-revoked (allowed); `false` triggers
/// `peer.revoked_at_epoch`.
pub trait RevocationOracle: Send + Sync {
    fn is_active_at_epoch(&self, fingerprint: &Keyid, epoch_height: u64) -> bool;
}

/// Demo-only revocation oracle that treats every passport key as active.
/// Production verifiers must provide a real revocation source.
#[derive(Debug, Clone, Default)]
pub struct DemoAllowAllRevocationOracle;

impl RevocationOracle for DemoAllowAllRevocationOracle {
    fn is_active_at_epoch(&self, _fingerprint: &Keyid, _epoch_height: u64) -> bool {
        true
    }
}

/// Test-only revocation oracle that lets fixtures explicitly mark a
/// fingerprint revoked. Used by the conformance test for step 9.
#[derive(Debug, Clone, Default)]
pub struct DenyListRevocationOracle {
    revoked: HashSet<String>,
}

impl DenyListRevocationOracle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&mut self, fingerprint: &Keyid) {
        self.revoked.insert(fingerprint.0.clone());
    }
}

impl RevocationOracle for DenyListRevocationOracle {
    fn is_active_at_epoch(&self, fingerprint: &Keyid, _epoch_height: u64) -> bool {
        !self.revoked.contains(&fingerprint.0)
    }
}

// ---------------------------------------------------------------------------
// Step 14: CapabilityLeaseRegistry
// ---------------------------------------------------------------------------

/// Resolved capability lease record returned by the registry. The
/// verifier (step 14) compares this against the predicate's
/// `capability_lease_ref` (issuer match, expires_at > now).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLease {
    pub lease_id: String,
    pub issuer: String,
    pub expires_at_unix_ms: u64,
    pub scope_digest_hex: Option<String>,
}

/// Step 14 surface: resolve a capability lease id. Returning `None`
/// fails-closed with `VerifierError::CapabilityLeaseExpiredOrUnknown`.
pub trait CapabilityLeaseRegistry: Send + Sync {
    fn resolve(&self, lease_id: &str) -> Option<ResolvedLease>;
}

#[derive(Debug, Default)]
pub struct InMemoryLeaseRegistry {
    leases: HashMap<String, ResolvedLease>,
}

impl InMemoryLeaseRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, lease: ResolvedLease) {
        self.leases.insert(lease.lease_id.clone(), lease);
    }
}

impl CapabilityLeaseRegistry for InMemoryLeaseRegistry {
    fn resolve(&self, lease_id: &str) -> Option<ResolvedLease> {
        self.leases.get(lease_id).cloned()
    }
}

// ---------------------------------------------------------------------------
// Step 15: GovernanceReceiptStore
// ---------------------------------------------------------------------------

/// Resolved governance receipt record returned by the store. The
/// verifier (step 15) compares this against the predicate's
/// `governance_receipt_ref` (kernel_id match, digest match).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGovernanceReceipt {
    pub receipt_id: String,
    pub kernel_id: String,
    pub canonical_json: String,
}

/// Step 15 surface. Returning `None` fails-closed with
/// `VerifierError::GovernanceReceiptRequiredMissing` when the action
/// class is `receipt-backed`.
pub trait GovernanceReceiptStore: Send + Sync {
    fn resolve(&self, receipt_id: &str) -> Option<ResolvedGovernanceReceipt>;
}

#[derive(Debug, Default)]
pub struct InMemoryGovernanceReceiptStore {
    receipts: HashMap<String, ResolvedGovernanceReceipt>,
}

impl InMemoryGovernanceReceiptStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, r: ResolvedGovernanceReceipt) {
        self.receipts.insert(r.receipt_id.clone(), r);
    }
}

impl GovernanceReceiptStore for InMemoryGovernanceReceiptStore {
    fn resolve(&self, receipt_id: &str) -> Option<ResolvedGovernanceReceipt> {
        self.receipts.get(receipt_id).cloned()
    }
}

// ---------------------------------------------------------------------------
// Verifier configuration + output
// ---------------------------------------------------------------------------

/// Action-class declaration looked up by `tool_name` in the verifier's
/// local ladder manifest. Spec §7 step 15 requires
/// `governance_receipt_ref` only when the class is `receipt-backed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionClassKind {
    /// Self-evident, low-stakes class. No governance receipt required.
    Routine,
    /// Receipt-backed class - requires `governance_receipt_ref` in the
    /// predicate body (§7 step 15).
    ReceiptBacked,
}

/// Fail-closed action-class invariant: policy controlling step 15's
/// reaction to an unknown `tool_name`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnknownActionClassPolicy {
    /// Default. An unknown tool name is rejected with
    /// [`VerifierError::UnknownActionClass`]. Prevents a misspelled
    /// or missing registration from silently downgrading a
    /// receipt-backed class to `Routine` (fail-open).
    #[default]
    Reject,
}

/// Verifier configuration: the trait objects + pinned epoch +
/// per-tool action class. Constructed by the kernel at the boundary;
/// passed by reference to [`verify_bilateral_cosign_invocation`].
pub struct VerifierConfig<'a> {
    pub peer_pin_set: &'a PeerPinSet,
    pub receipt_store: &'a dyn ReceiptStore,
    pub lease_registry: &'a dyn CapabilityLeaseRegistry,
    pub governance_receipt_store: &'a dyn GovernanceReceiptStore,
    pub revocation_oracle: &'a dyn RevocationOracle,
    pub pinned_epoch: PinnedEpoch,
    /// Per-tool action-class table. The verifier (step 15) consults
    /// this with the predicate's `tool_name` to decide whether
    /// `governance_receipt_ref` is required.
    pub action_classes: BTreeMap<String, ActionClassKind>,
    /// Fail-closed action-class invariant: controls how step 15 reacts
    /// to a `tool_name` that is not present in `action_classes`.
    ///
    /// The only supported value is [`UnknownActionClassPolicy::Reject`]
    /// (default): the verifier returns [`VerifierError::UnknownActionClass`]
    /// so a misspelled or missing registration cannot silently downgrade
    /// a receipt-backed class to `Routine`.
    pub unknown_action_class_policy: UnknownActionClassPolicy,
}

/// Successful output of [`verify_bilateral_cosign_invocation`]
/// (mirrors §7 step 17).
#[derive(Debug, Clone)]
pub struct VerifiedBilateralCoSignInvocation {
    /// The parsed Statement (subject + predicate).
    pub statement: DsseStatement,
    /// The resolved receipt the subject digest pointed at.
    pub resolved_receipt: ChioReceipt,
    /// The resolved capability lease (step 14 always runs).
    pub resolved_lease: ResolvedLease,
    /// The resolved governance receipt, when the class is
    /// `ReceiptBacked` (step 15).
    pub resolved_governance_receipt: Option<ResolvedGovernanceReceipt>,
    /// The verdict both kernels agreed on (step 13).
    pub joint_verdict: String,
}

/// Strict Chio verifier wrapper over the local bilateral DSSE verifier.
///
/// The base verifier authenticates the DSSE envelope, receipt subject, lease,
/// governance receipt, and policy agreement. Strict Chio mode adds the
/// workflow-ladder requirement: both pinned peers must carry fresh signed
/// ladder manifest references at the pinned epoch.
pub struct ChioBilateralVerifierConfig<'a, 'b> {
    pub base: &'a VerifierConfig<'b>,
}

/// Inputs for strict buyer-review verification of a treaty-bound Chio
/// bilateral DSSE envelope.
pub struct TreatyBoundBilateralDsseReview<'a> {
    pub expected_treaty_binding: &'a TreatyBindingRef,
    pub expected_subject_name: &'a str,
    pub expected_subject_sha256: &'a str,
    pub expected_capability_lease_ref: &'a CapabilityLeaseRef,
    pub expected_governance_receipt_ref: &'a GovernanceReceiptRef,
    pub expected_consistency_anchor: &'a str,
    pub signer_public_keys: &'a BTreeMap<String, PublicKey>,
}

// ---------------------------------------------------------------------------
// Partial local verifier (subset of spec §7 step list)
// ---------------------------------------------------------------------------

pub fn verify_treaty_bound_chio_bilateral_invocation(
    envelope: &DsseEnvelope,
    review: &TreatyBoundBilateralDsseReview<'_>,
) -> Result<DsseStatement, VerifierError> {
    if envelope.payload_type != PAYLOAD_TYPE_IN_TOTO {
        return Err(VerifierError::DsseMalformed(format!(
            "payloadType {:?} is not application/vnd.in-toto+json",
            envelope.payload_type
        )));
    }
    if envelope.signatures.len() != 2 {
        return Err(VerifierError::DsseMalformed(format!(
            "strict treaty DSSE expected exactly 2 signatures, got {}",
            envelope.signatures.len()
        )));
    }
    require_unique_review_signature_keyids(envelope)?;

    validate_treaty_binding_ref_for_review(review.expected_treaty_binding, "expected", true)?;

    let (statement, statement_bytes) = envelope.decode_statement().map_err(map_bilateral_error)?;
    let canonical_statement_bytes = statement.canonical_bytes().map_err(map_bilateral_error)?;
    if canonical_statement_bytes != statement_bytes {
        return Err(VerifierError::StatementMalformed(
            "strict treaty DSSE payload is not canonical JSON".to_string(),
        ));
    }
    if statement.statement_type != STATEMENT_TYPE_V1 {
        return Err(VerifierError::StatementSchemaInvalid(format!(
            "_type {:?} is not {:?}",
            statement.statement_type, STATEMENT_TYPE_V1
        )));
    }
    if statement.predicate_type != PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION {
        return Err(VerifierError::PredicateTypeUnrecognised(format!(
            "predicateType {:?} is not strict Chio {:?}",
            statement.predicate_type, PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION
        )));
    }
    if statement.subject.len() != 1 {
        return Err(VerifierError::StatementSchemaInvalid(format!(
            "strict treaty DSSE must carry exactly 1 subject, got {}",
            statement.subject.len()
        )));
    }
    let pred = &statement.predicate;
    let Some(treaty_binding) = pred.treaty_binding_ref.as_ref() else {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE missing treaty_binding_ref".to_string(),
        ));
    };
    validate_treaty_binding_ref_for_review(treaty_binding, "predicate", true)?;
    if !treaty_binding_refs_equal(treaty_binding, review.expected_treaty_binding) {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE treaty_binding_ref does not match expected buyer review binding"
                .to_string(),
        ));
    }
    validate_predicate_operational_refs_match_treaty(pred, treaty_binding)?;
    if pred.tool_server_a.kernel_id != review.expected_treaty_binding.signer_kernel_ids[0]
        || pred.tool_server_b.kernel_id != review.expected_treaty_binding.signer_kernel_ids[1]
    {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(
            "strict treaty DSSE predicate signer kernels do not match treaty binding".to_string(),
        ));
    }
    if pred.consistency_model != review.expected_treaty_binding.consistency_model {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE consistency model does not match treaty binding".to_string(),
        ));
    }
    if !is_sha256_hex(review.expected_subject_sha256) {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE expected subject digest is not a lowercase SHA-256".to_string(),
        ));
    }
    let subject = &statement.subject[0];
    if subject.name != review.expected_subject_name {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "strict treaty DSSE subject name {} != expected {}",
            subject.name, review.expected_subject_name
        )));
    }
    if subject.digest.sha256 != review.expected_subject_sha256 {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "strict treaty DSSE subject digest {} != expected {}",
            subject.digest.sha256, review.expected_subject_sha256
        )));
    }
    let lease_ref = pred.capability_lease_ref.as_ref().ok_or_else(|| {
        VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE missing capability_lease_ref".to_string(),
        )
    })?;
    if lease_ref != review.expected_capability_lease_ref {
        return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(
            "strict treaty DSSE capability_lease_ref does not match package lease".to_string(),
        ));
    }
    let governance_ref = pred.governance_receipt_ref.as_ref().ok_or_else(|| {
        VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE missing governance_receipt_ref".to_string(),
        )
    })?;
    if governance_ref != review.expected_governance_receipt_ref {
        return Err(VerifierError::GovernanceReceiptRequiredMissing(
            "strict treaty DSSE governance_receipt_ref does not match package governance receipt"
                .to_string(),
        ));
    }
    if review.expected_consistency_anchor.trim().is_empty() {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE expected consistency anchor is empty".to_string(),
        ));
    }
    if pred.consistency_anchor.as_deref() != Some(review.expected_consistency_anchor) {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE consistency_anchor does not match runtime step evidence"
                .to_string(),
        ));
    }
    if matches!(
        pred.consistency_model.as_str(),
        "totally_ordered" | "quorum_required"
    ) && pred.consistency_anchor.as_deref().is_none_or(str::is_empty)
    {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE ordered consistency requires consistency_anchor".to_string(),
        ));
    }
    let summary = pred.policy_evaluation_summary.as_ref().ok_or_else(|| {
        VerifierError::PolicyVerdictDisagreement(
            "strict treaty DSSE missing policy_evaluation_summary".to_string(),
        )
    })?;
    require_policy_evaluation_allow_admission(summary).map_err(map_bilateral_error)?;

    let signer_a_id = &review.expected_treaty_binding.signer_kernel_ids[0];
    let signer_b_id = &review.expected_treaty_binding.signer_kernel_ids[1];
    let signer_a_public_key = review.signer_public_keys.get(signer_a_id).ok_or_else(|| {
        VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
            "strict treaty DSSE missing public key for signer {signer_a_id:?}"
        ))
    })?;
    let signer_b_public_key = review.signer_public_keys.get(signer_b_id).ok_or_else(|| {
        VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
            "strict treaty DSSE missing public key for signer {signer_b_id:?}"
        ))
    })?;
    if signer_a_public_key == signer_b_public_key {
        return Err(VerifierError::DsseMalformed(
            "strict treaty DSSE signer keys must represent independent Org A and Org B passports"
                .to_string(),
        ));
    }
    verify_chio_bilateral_dsse_envelope(envelope, signer_a_public_key, signer_b_public_key)
        .map_err(map_bilateral_error)?;

    Ok(statement)
}

fn require_unique_review_signature_keyids(envelope: &DsseEnvelope) -> Result<(), VerifierError> {
    let mut seen = HashSet::new();
    for signature in &envelope.signatures {
        if signature.keyid.is_empty() {
            return Err(VerifierError::DsseMalformed(
                "strict treaty DSSE signature keyid must be non-empty".to_string(),
            ));
        }
        if !seen.insert(signature.keyid.as_str()) {
            return Err(VerifierError::DsseMalformed(format!(
                "strict treaty DSSE duplicate signature keyid {}",
                signature.keyid
            )));
        }
    }
    Ok(())
}

fn validate_treaty_binding_ref_for_review(
    treaty: &TreatyBindingRef,
    label: &str,
    require_operational_refs: bool,
) -> Result<(), VerifierError> {
    if treaty.treaty_id.is_empty()
        || treaty.action_class_id.is_empty()
        || treaty.consistency_model.is_empty()
    {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "{label} treaty_binding_ref treaty_id, action_class_id, and consistency_model must be non-empty"
        )));
    }
    for (field, value) in [
        ("treaty_scope_sha256", &treaty.treaty_scope_sha256),
        (
            "ladder_intersection_sha256",
            &treaty.ladder_intersection_sha256,
        ),
        ("admission_report_sha256", &treaty.admission_report_sha256),
        ("continuation_sha256", &treaty.continuation_sha256),
        ("lineage_bundle_sha256", &treaty.lineage_bundle_sha256),
        ("request_sha256", &treaty.request_sha256),
        ("outcome_sha256", &treaty.outcome_sha256),
        ("local_receipt_sha256", &treaty.local_receipt_sha256),
        ("remote_receipt_sha256", &treaty.remote_receipt_sha256),
    ] {
        if !is_sha256_hex(value) {
            return Err(VerifierError::PredicateSchemaInvalid(format!(
                "{label} treaty_binding_ref.{field} must be 64 lowercase hex"
            )));
        }
    }
    if treaty.signer_kernel_ids.len() != 2 {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "{label} treaty_binding_ref.signer_kernel_ids must contain exactly 2 signers"
        )));
    }
    if treaty
        .signer_kernel_ids
        .iter()
        .any(|signer| signer.is_empty())
    {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "{label} treaty_binding_ref.signer_kernel_ids must be non-empty"
        )));
    }
    if treaty.signer_kernel_ids[0] == treaty.signer_kernel_ids[1] {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "{label} treaty_binding_ref.signer_kernel_ids must be distinct"
        )));
    }
    if require_operational_refs && treaty.lease_refs.is_empty() {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "{label} treaty_binding_ref lease_refs must be non-empty"
        )));
    }
    Ok(())
}

fn treaty_binding_refs_equal(left: &TreatyBindingRef, right: &TreatyBindingRef) -> bool {
    left.treaty_id == right.treaty_id
        && left.treaty_scope_sha256 == right.treaty_scope_sha256
        && left.ladder_intersection_sha256 == right.ladder_intersection_sha256
        && left.admission_report_sha256 == right.admission_report_sha256
        && left.continuation_sha256 == right.continuation_sha256
        && left.lineage_bundle_sha256 == right.lineage_bundle_sha256
        && left.action_class_id == right.action_class_id
        && left.consistency_model == right.consistency_model
        && left.request_sha256 == right.request_sha256
        && left.outcome_sha256 == right.outcome_sha256
        && left.local_receipt_sha256 == right.local_receipt_sha256
        && left.remote_receipt_sha256 == right.remote_receipt_sha256
        && left.lease_refs == right.lease_refs
        && left.governance_refs == right.governance_refs
        && left.signer_kernel_ids == right.signer_kernel_ids
}

fn validate_predicate_operational_refs_match_treaty(
    pred: &BilateralPredicate,
    treaty: &TreatyBindingRef,
) -> Result<(), VerifierError> {
    let tool_args_hash = pred.tool_args_hash.as_ref().ok_or_else(|| {
        VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE missing tool_args_hash".to_string(),
        )
    })?;
    if treaty.request_sha256 != tool_args_hash.value {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE request_sha256 does not match tool_args_hash".to_string(),
        ));
    }
    if treaty.signer_kernel_ids
        != [
            pred.tool_server_a.kernel_id.clone(),
            pred.tool_server_b.kernel_id.clone(),
        ]
    {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE signer_kernel_ids do not match authenticated predicate kernels"
                .to_string(),
        ));
    }
    let lease_ref = pred.capability_lease_ref.as_ref().ok_or_else(|| {
        VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE missing capability_lease_ref".to_string(),
        )
    })?;
    if treaty.lease_refs != [lease_ref.lease_id.clone()] {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE lease_refs do not match capability_lease_ref".to_string(),
        ));
    }
    match pred.governance_receipt_ref.as_ref() {
        Some(governance_ref) => {
            if treaty.governance_refs != [governance_ref.receipt_id.clone()] {
                return Err(VerifierError::PredicateSchemaInvalid(
                    "strict treaty DSSE governance_refs do not match governance_receipt_ref"
                        .to_string(),
                ));
            }
        }
        None => {
            if !treaty.governance_refs.is_empty() {
                return Err(VerifierError::PredicateSchemaInvalid(
                    "strict treaty DSSE governance_refs must be empty when governance_receipt_ref is absent"
                        .to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn resolve_governance_receipt_ref(
    store: &dyn GovernanceReceiptStore,
    governance_ref: &GovernanceReceiptRef,
) -> Result<ResolvedGovernanceReceipt, VerifierError> {
    validate_hash_record(&governance_ref.digest, "governance_receipt_ref.digest")
        .map_err(VerifierError::GovernanceReceiptRequiredMissing)?;
    let resolved = store.resolve(&governance_ref.receipt_id).ok_or_else(|| {
        VerifierError::GovernanceReceiptRequiredMissing(format!(
            "receipt_id {:?} not resolvable in GovernanceReceiptStore",
            governance_ref.receipt_id
        ))
    })?;
    if resolved.kernel_id != governance_ref.kernel_id {
        return Err(VerifierError::GovernanceReceiptRequiredMissing(format!(
            "governance receipt kernel_id mismatch: store={:?} predicate={:?}",
            resolved.kernel_id, governance_ref.kernel_id
        )));
    }
    let mut hasher = Sha256::new();
    hasher.update(resolved.canonical_json.as_bytes());
    let want = hex::encode(hasher.finalize());
    if want != governance_ref.digest.value {
        return Err(VerifierError::GovernanceReceiptRequiredMissing(format!(
            "governance receipt digest mismatch: computed={} predicate={}",
            want, governance_ref.digest.value
        )));
    }
    Ok(resolved)
}

fn validate_treaty_receipt_refs_match_resolved_receipt(
    treaty: &TreatyBindingRef,
    receipt: &ChioReceipt,
    receipt_sha256: &str,
) -> Result<(), VerifierError> {
    if treaty.outcome_sha256 != receipt.content_hash {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE outcome_sha256 does not match resolved receipt content_hash"
                .to_string(),
        ));
    }
    if treaty.remote_receipt_sha256 != receipt_sha256 {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE remote_receipt_sha256 does not match resolved receipt hash"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn verify_chio_bilateral_invocation(
    envelope: &DsseEnvelope,
    config: &ChioBilateralVerifierConfig<'_, '_>,
) -> Result<VerifiedBilateralCoSignInvocation, VerifierError> {
    if envelope.payload_type != crate::bilateral_dsse::PAYLOAD_TYPE_IN_TOTO {
        return Err(VerifierError::DsseMalformed(format!(
            "payloadType {:?} is not application/vnd.in-toto+json",
            envelope.payload_type
        )));
    }
    if envelope.signatures.is_empty() {
        return Err(VerifierError::DsseMalformed(
            "signatures array is empty".to_string(),
        ));
    }

    let (statement, _) = envelope.decode_statement().map_err(map_bilateral_error)?;
    if statement.predicate_type != PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION {
        return Err(VerifierError::PredicateTypeUnrecognised(format!(
            "signature-slice profile {:?} is not strict Chio {:?}",
            statement.predicate_type, PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION
        )));
    }
    if statement.statement_type != STATEMENT_TYPE_V1 {
        return Err(VerifierError::StatementSchemaInvalid(format!(
            "_type {:?} is not {:?}",
            statement.statement_type, STATEMENT_TYPE_V1
        )));
    }
    if statement.subject.len() != 1 {
        return Err(VerifierError::StatementSchemaInvalid(format!(
            "statement.malformed: bilateral envelope must carry exactly 1 subject, got {}",
            statement.subject.len()
        )));
    }

    let pred = &statement.predicate;
    let pinned_a = config
        .base
        .peer_pin_set
        .lookup(&pred.tool_server_a.kernel_id)
        .ok_or_else(|| {
            VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
                "tool_server_a kernel_id {:?} not pinned",
                pred.tool_server_a.kernel_id
            ))
        })?;
    if pinned_a.fingerprint().0 != pred.tool_server_a.passport_key_fingerprint.0 {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
            "tool_server_a fingerprint mismatch: pinned={} predicate={}",
            pinned_a.fingerprint().0,
            pred.tool_server_a.passport_key_fingerprint.0
        )));
    }
    let pinned_b = config
        .base
        .peer_pin_set
        .lookup(&pred.tool_server_b.kernel_id)
        .ok_or_else(|| {
            VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
                "tool_server_b kernel_id {:?} not pinned",
                pred.tool_server_b.kernel_id
            ))
        })?;
    if pinned_b.fingerprint().0 != pred.tool_server_b.passport_key_fingerprint.0 {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
            "tool_server_b fingerprint mismatch: pinned={} predicate={}",
            pinned_b.fingerprint().0,
            pred.tool_server_b.passport_key_fingerprint.0
        )));
    }

    let statement =
        verify_chio_bilateral_dsse_envelope(envelope, &pinned_a.public_key, &pinned_b.public_key)
            .map_err(map_bilateral_error)?;
    let pred = &statement.predicate;

    require_fresh_ladder_manifest(config.base, &pred.tool_server_a.kernel_id, "tool_server_a")?;
    require_fresh_ladder_manifest(config.base, &pred.tool_server_b.kernel_id, "tool_server_b")?;

    if !config.base.revocation_oracle.is_active_at_epoch(
        &pinned_a.fingerprint(),
        config.base.pinned_epoch.epoch_height,
    ) {
        return Err(VerifierError::PeerRevokedAtEpoch(format!(
            "tool_server_a {} revoked at epoch {}",
            pred.tool_server_a.kernel_id, config.base.pinned_epoch.epoch_height
        )));
    }
    if !config.base.revocation_oracle.is_active_at_epoch(
        &pinned_b.fingerprint(),
        config.base.pinned_epoch.epoch_height,
    ) {
        return Err(VerifierError::PeerRevokedAtEpoch(format!(
            "tool_server_b {} revoked at epoch {}",
            pred.tool_server_b.kernel_id, config.base.pinned_epoch.epoch_height
        )));
    }

    let resolved_receipt = config
        .base
        .receipt_store
        .resolve(&pred.invocation_id)
        .ok_or_else(|| {
            VerifierError::SubjectDigestMismatch(format!(
                "invocation_id {:?} not resolvable in ReceiptStore",
                pred.invocation_id
            ))
        })?;
    let resolved_receipt_signature_valid = resolved_receipt
        .verify_signature()
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("receipt signature: {e}")))?;
    if !resolved_receipt_signature_valid {
        return Err(VerifierError::SubjectDigestMismatch(
            "resolved receipt signature is invalid".to_string(),
        ));
    }
    if pred.tool_name != resolved_receipt.tool_name {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "predicate tool_name {:?} != resolved receipt tool_name {:?}",
            pred.tool_name, resolved_receipt.tool_name
        )));
    }
    if resolved_receipt.kernel_key != pinned_b.public_key {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(
            "resolved receipt kernel_key does not match pinned tool_server_b key".to_string(),
        ));
    }
    if pred.receipt_canonical_json.is_some() {
        return Err(VerifierError::PredicateSchemaInvalid(
            "receipt_canonical_json must be absent from strict Chio predicates".to_string(),
        ));
    }
    let tool_args_hash = pred.tool_args_hash.as_ref().ok_or_else(|| {
        VerifierError::PredicateSchemaInvalid("tool_args_hash is required".to_string())
    })?;
    validate_hash_record(tool_args_hash, "tool_args_hash")
        .map_err(VerifierError::PredicateSchemaInvalid)?;
    if !resolved_receipt
        .action
        .verify_hash()
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("tool args hash: {e}")))?
    {
        return Err(VerifierError::SubjectDigestMismatch(
            "resolved receipt action parameter_hash does not match parameters".to_string(),
        ));
    }
    if tool_args_hash.value != resolved_receipt.action.parameter_hash {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "predicate tool_args_hash {} != resolved receipt parameter_hash {}",
            tool_args_hash.value, resolved_receipt.action.parameter_hash
        )));
    }

    let resolved_body = resolved_receipt.body();
    let canonical = canonical_json_bytes(&resolved_body)
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("canonical-json: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    let want_hex = hex::encode(hasher.finalize());

    let subject = &statement.subject[0];
    let expected_subject_name = receipt_subject_name(&resolved_receipt.id);
    if subject.name != expected_subject_name {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "subject name {} != canonical receipt subject {}",
            subject.name, expected_subject_name
        )));
    }
    if subject.digest.sha256 != want_hex {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "subject digest {} != sha256(canonical_json(resolved_receipt.body())) {}",
            subject.digest.sha256, want_hex
        )));
    }
    let resolved_receipt_sha256 = receipt_canonical_digest_hex(&resolved_receipt)?;

    let summary = pred.policy_evaluation_summary.as_ref().ok_or_else(|| {
        VerifierError::PolicyVerdictDisagreement(
            "predicate is missing policy_evaluation_summary".to_string(),
        )
    })?;
    validate_policy_verdict(&summary.server_a_verdict, "server_a_verdict")?;
    validate_policy_verdict(&summary.server_b_verdict, "server_b_verdict")?;
    if summary.server_a_verdict.verdict != summary.server_b_verdict.verdict {
        return Err(VerifierError::PolicyVerdictDisagreement(format!(
            "server_a={} server_b={}",
            summary.server_a_verdict.verdict, summary.server_b_verdict.verdict
        )));
    }
    if let Some(joint) = &summary.joint_disposition {
        validate_verdict_string(joint)?;
        if joint != &summary.server_a_verdict.verdict {
            return Err(VerifierError::PolicyVerdictDisagreement(format!(
                "joint_disposition={} disagrees with server_a/b verdict={}",
                joint, summary.server_a_verdict.verdict
            )));
        }
    }
    let joint_verdict = summary.server_a_verdict.verdict.clone();

    let lease_ref = pred.capability_lease_ref.as_ref().ok_or_else(|| {
        VerifierError::CapabilityLeaseExpiredOrUnknown(
            "predicate is missing capability_lease_ref".to_string(),
        )
    })?;
    let resolved_lease = config
        .base
        .lease_registry
        .resolve(&lease_ref.lease_id)
        .ok_or_else(|| {
            VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                "lease_id {:?} not resolvable in CapabilityLeaseRegistry",
                lease_ref.lease_id
            ))
        })?;
    if resolved_lease.issuer != lease_ref.issuer {
        return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
            "lease issuer mismatch: registry={:?} predicate={:?}",
            resolved_lease.issuer, lease_ref.issuer
        )));
    }
    if resolved_lease.expires_at_unix_ms != lease_ref.expires_at_unix_ms {
        return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
            "lease expiry mismatch: registry={} predicate={}",
            resolved_lease.expires_at_unix_ms, lease_ref.expires_at_unix_ms
        )));
    }
    if resolved_lease.expires_at_unix_ms <= config.base.pinned_epoch.now_unix_ms {
        return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
            "lease expired: expires_at={} <= pinned_epoch.now={}",
            resolved_lease.expires_at_unix_ms, config.base.pinned_epoch.now_unix_ms
        )));
    }
    match (&lease_ref.scope_digest, &resolved_lease.scope_digest_hex) {
        (Some(predicate_scope), Some(registry_scope)) => {
            validate_hash_record(predicate_scope, "capability_lease_ref.scope_digest")
                .map_err(VerifierError::CapabilityLeaseExpiredOrUnknown)?;
            if &predicate_scope.value != registry_scope {
                return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                    "lease scope_digest mismatch: registry={:?} predicate={:?}",
                    registry_scope, predicate_scope.value
                )));
            }
        }
        (Some(predicate_scope), None) => {
            validate_hash_record(predicate_scope, "capability_lease_ref.scope_digest")
                .map_err(VerifierError::CapabilityLeaseExpiredOrUnknown)?;
            return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                "predicate names scope_digest={:?} but registry record has no scope_digest_hex",
                predicate_scope.value
            )));
        }
        (None, Some(registry_scope)) => {
            return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                "registry record carries scope_digest_hex={:?} but predicate omitted scope_digest",
                registry_scope
            )));
        }
        (None, None) => {}
    }

    let class = match config.base.action_classes.get(&pred.tool_name).copied() {
        Some(known) => known,
        None => match config.base.unknown_action_class_policy {
            UnknownActionClassPolicy::Reject => {
                return Err(VerifierError::UnknownActionClass {
                    tool_name: pred.tool_name.clone(),
                });
            }
        },
    };
    let mut resolved_governance_receipt = match class {
        ActionClassKind::Routine => None,
        ActionClassKind::ReceiptBacked => {
            let governance_ref = pred.governance_receipt_ref.as_ref().ok_or_else(|| {
                VerifierError::GovernanceReceiptRequiredMissing(format!(
                    "tool_name {:?} is receipt-backed but predicate omits governance_receipt_ref",
                    pred.tool_name
                ))
            })?;
            Some(resolve_governance_receipt_ref(
                config.base.governance_receipt_store,
                governance_ref,
            )?)
        }
    };

    if let Some(treaty) = pred.treaty_binding_ref.as_ref() {
        validate_treaty_binding_ref_for_review(treaty, "predicate", true)?;
        validate_predicate_operational_refs_match_treaty(pred, treaty)?;
        validate_treaty_receipt_refs_match_resolved_receipt(
            treaty,
            &resolved_receipt,
            &resolved_receipt_sha256,
        )?;
        if resolved_governance_receipt.is_none() {
            if let Some(governance_ref) = pred.governance_receipt_ref.as_ref() {
                resolved_governance_receipt = Some(resolve_governance_receipt_ref(
                    config.base.governance_receipt_store,
                    governance_ref,
                )?);
            }
        }
        if let Some(resolved_governance_receipt) = resolved_governance_receipt.as_ref() {
            if treaty.governance_refs != [resolved_governance_receipt.receipt_id.clone()] {
                return Err(VerifierError::PredicateSchemaInvalid(
                    "strict treaty DSSE governance_refs do not match resolved governance receipt"
                        .to_string(),
                ));
            }
        }
        if treaty.lease_refs != [resolved_lease.lease_id.clone()] {
            return Err(VerifierError::PredicateSchemaInvalid(
                "strict treaty DSSE lease_refs do not match resolved lease".to_string(),
            ));
        }
    }

    if pred.consistency_model != crate::bilateral_dsse::DEFAULT_CONSISTENCY_MODEL {
        let Some(treaty) = pred.treaty_binding_ref.as_ref() else {
            return Err(VerifierError::PredicateSchemaInvalid(format!(
                "consistency_model {:?} is not supported",
                pred.consistency_model
            )));
        };
        if treaty.consistency_model != pred.consistency_model {
            return Err(VerifierError::PredicateSchemaInvalid(
                "strict treaty DSSE consistency_model does not match treaty_binding_ref"
                    .to_string(),
            ));
        }
        if !matches!(
            pred.consistency_model.as_str(),
            "crdt_commutative" | "totally_ordered" | "single_kernel" | "quorum_required"
        ) {
            return Err(VerifierError::PredicateSchemaInvalid(format!(
                "consistency_model {:?} is not supported",
                pred.consistency_model
            )));
        }
        if matches!(
            pred.consistency_model.as_str(),
            "totally_ordered" | "quorum_required"
        ) && pred.consistency_anchor.as_deref().is_none_or(str::is_empty)
        {
            return Err(VerifierError::PredicateSchemaInvalid(
                "strict treaty DSSE ordered consistency requires consistency_anchor".to_string(),
            ));
        }
    }
    Ok(VerifiedBilateralCoSignInvocation {
        statement,
        resolved_receipt,
        resolved_lease,
        resolved_governance_receipt,
        joint_verdict,
    })
}

fn require_fresh_ladder_manifest(
    config: &VerifierConfig<'_>,
    kernel_id: &str,
    role: &str,
) -> Result<(), VerifierError> {
    let peer = config
        .peer_pin_set
        .lookup(kernel_id)
        .ok_or_else(|| VerifierError::PeerUnpinnedOrKeyidMismatch(kernel_id.to_string()))?;
    let ladder_manifest_ref = peer.ladder_manifest_ref.as_ref().ok_or_else(|| {
        VerifierError::LadderManifestMissing(format!(
            "{role} {kernel_id} has no pinned ladder manifest reference"
        ))
    })?;
    if !ladder_manifest_ref.is_fresh(config.pinned_epoch.now_unix_ms) {
        return Err(VerifierError::LadderManifestStale(format!(
            "{role} {kernel_id} ladder manifest {:?} is stale at {}",
            ladder_manifest_ref.manifest_id, config.pinned_epoch.now_unix_ms
        )));
    }
    Ok(())
}

/// Fail-closed: any error short-circuits and returns the corresponding
/// `VerifierError` variant whose `.code()` matches the spec §7.1
/// canonical string verbatim.
///
/// **Partial-verifier scope**: this is a partial
/// local verifier. It implements the structural / cryptographic core
/// plus a meaningful subset of the §7 step list but is not full §7
/// conformance: predicate schema fields are missing (e.g.
/// `tool_args_hash`) and the `statement.malformed` vs
/// `dsse.malformed` mapping is approximate. Full schema completion
/// belongs in a separate strict predicate-profile implementation.
pub fn verify_bilateral_cosign_invocation(
    envelope: &DsseEnvelope,
    config: &VerifierConfig<'_>,
) -> Result<VerifiedBilateralCoSignInvocation, VerifierError> {
    // ---- Steps 1-2: parse envelope; base64-decode payload --------------
    if envelope.payload_type != crate::bilateral_dsse::PAYLOAD_TYPE_IN_TOTO {
        return Err(VerifierError::DsseMalformed(format!(
            "payloadType {:?} is not application/vnd.in-toto+json",
            envelope.payload_type
        )));
    }
    if envelope.signatures.is_empty() {
        return Err(VerifierError::DsseMalformed(
            "signatures array is empty".to_string(),
        ));
    }

    let (statement, _) = envelope.decode_statement().map_err(map_bilateral_error)?;

    // ---- Step 3: in-toto v1 schema -------------------------------------
    if statement.statement_type != STATEMENT_TYPE_V1 {
        return Err(VerifierError::StatementSchemaInvalid(format!(
            "_type {:?} is not {:?}",
            statement.statement_type, STATEMENT_TYPE_V1
        )));
    }
    // Single-subject invariant: the bilateral envelope profile
    // binds exactly ONE subject (the receipt body). Rejecting only the
    // empty-list case is fail-OPEN: a signer could insert an arbitrary
    // second subject digest and verifiers that walked the full subject
    // list (the in-toto convention for subject membership) would resolve
    // a different receipt than the producer signed. Mirror the
    // `bilateral_dsse::verify_dsse_envelope` check at this layer so
    // the §7 verifier path also fails closed.
    if statement.subject.len() != 1 {
        return Err(VerifierError::StatementSchemaInvalid(format!(
            "statement.malformed: bilateral envelope must carry exactly 1 subject, got {}",
            statement.subject.len()
        )));
    }

    // ---- Step 4: predicateType is recognised ---------------------------
    if statement.predicate_type != PREDICATE_TYPE_BILATERAL {
        return Err(VerifierError::PredicateTypeUnrecognised(
            statement.predicate_type.clone(),
        ));
    }

    // ---- Step 5: predicate body schema (subset of §5) ------------------
    validate_predicate_required_fields(&statement.predicate)?;

    // ---- Step 6: bind pred ---------------------------------------------
    let pred = &statement.predicate;

    // ---- Step 8: peer pinning ------------------------------------------
    // Peer-pin lookup is the minimum local lookup needed before signature
    // authentication: it provides the trusted public keys for DSSE
    // verification. Receipt, revocation, lease, and governance stores are
    // intentionally queried only after the signatures authenticate.
    let pinned_a = config
        .peer_pin_set
        .lookup(&pred.tool_server_a.kernel_id)
        .ok_or_else(|| {
            VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
                "tool_server_a kernel_id {:?} not pinned",
                pred.tool_server_a.kernel_id
            ))
        })?;
    if pinned_a.fingerprint().0 != pred.tool_server_a.passport_key_fingerprint.0 {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
            "tool_server_a fingerprint mismatch: pinned={} predicate={}",
            pinned_a.fingerprint().0,
            pred.tool_server_a.passport_key_fingerprint.0
        )));
    }
    let pinned_b = config
        .peer_pin_set
        .lookup(&pred.tool_server_b.kernel_id)
        .ok_or_else(|| {
            VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
                "tool_server_b kernel_id {:?} not pinned",
                pred.tool_server_b.kernel_id
            ))
        })?;
    if pinned_b.fingerprint().0 != pred.tool_server_b.passport_key_fingerprint.0 {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
            "tool_server_b fingerprint mismatch: pinned={} predicate={}",
            pinned_b.fingerprint().0,
            pred.tool_server_b.passport_key_fingerprint.0
        )));
    }

    // ---- Steps 10-12: DSSE signature authentication -------------------
    verify_dsse_envelope(envelope, &pinned_a.public_key, &pinned_b.public_key)
        .map_err(map_bilateral_error)?;

    // ---- Step 9: revocation at pinned epoch ----------------------------
    if !config
        .revocation_oracle
        .is_active_at_epoch(&pinned_a.fingerprint(), config.pinned_epoch.epoch_height)
    {
        return Err(VerifierError::PeerRevokedAtEpoch(format!(
            "tool_server_a {} revoked at epoch {}",
            pred.tool_server_a.kernel_id, config.pinned_epoch.epoch_height
        )));
    }
    if !config
        .revocation_oracle
        .is_active_at_epoch(&pinned_b.fingerprint(), config.pinned_epoch.epoch_height)
    {
        return Err(VerifierError::PeerRevokedAtEpoch(format!(
            "tool_server_b {} revoked at epoch {}",
            pred.tool_server_b.kernel_id, config.pinned_epoch.epoch_height
        )));
    }

    // ---- Step 7: subject digest = sha256(canonical_json(resolve_receipt.body()))
    // Subject-digest store work is deferred until after DSSE authentication
    // so invalid signatures cannot force receipt-store reads.
    let resolved_receipt = config
        .receipt_store
        .resolve(&pred.invocation_id)
        .ok_or_else(|| {
            VerifierError::SubjectDigestMismatch(format!(
                "invocation_id {:?} not resolvable in ReceiptStore (fail-closed per §7 step 7)",
                pred.invocation_id
            ))
        })?;
    let resolved_receipt_signature_valid = resolved_receipt
        .verify_signature()
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("receipt signature: {e}")))?;
    if !resolved_receipt_signature_valid {
        return Err(VerifierError::SubjectDigestMismatch(
            "resolved receipt signature is invalid".to_string(),
        ));
    }
    if pred.tool_name != resolved_receipt.tool_name {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "predicate tool_name {:?} != resolved receipt tool_name {:?}",
            pred.tool_name, resolved_receipt.tool_name
        )));
    }
    if resolved_receipt.kernel_key != pinned_b.public_key {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(
            "resolved receipt kernel_key does not match pinned tool_server_b key".to_string(),
        ));
    }
    let resolved_receipt_canonical = canonical_json_string(&resolved_receipt)
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("canonical-json: {e}")))?;
    let receipt_canonical_json = pred.receipt_canonical_json.as_ref().ok_or_else(|| {
        VerifierError::PredicateSchemaInvalid(
            "receipt_canonical_json is required for the signature-slice profile".to_string(),
        )
    })?;
    if receipt_canonical_json != &resolved_receipt_canonical {
        return Err(VerifierError::SubjectDigestMismatch(
            "predicate embedded receipt JSON does not match resolved signed receipt".to_string(),
        ));
    }

    let resolved_body = resolved_receipt.body();
    let canonical = canonical_json_bytes(&resolved_body)
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("canonical-json: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    let want_hex = hex::encode(hasher.finalize());

    let subject = &statement.subject[0];
    let expected_subject_name = receipt_subject_name(&resolved_receipt.id);
    if subject.name != expected_subject_name {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "subject name {} != canonical receipt subject {}",
            subject.name, expected_subject_name
        )));
    }
    if subject.digest.sha256 != want_hex {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "subject digest {} != sha256(canonical_json(resolved_receipt.body())) {}",
            subject.digest.sha256, want_hex
        )));
    }

    // ---- Step 13: verdict agreement ------------------------------------
    let summary = pred.policy_evaluation_summary.as_ref().ok_or_else(|| {
        VerifierError::PolicyVerdictDisagreement(
            "predicate is missing policy_evaluation_summary (required for §7 step 13)".to_string(),
        )
    })?;
    validate_policy_verdict(&summary.server_a_verdict, "server_a_verdict")?;
    validate_policy_verdict(&summary.server_b_verdict, "server_b_verdict")?;
    if summary.server_a_verdict.verdict != summary.server_b_verdict.verdict {
        return Err(VerifierError::PolicyVerdictDisagreement(format!(
            "server_a={} server_b={}",
            summary.server_a_verdict.verdict, summary.server_b_verdict.verdict
        )));
    }
    if let Some(joint) = &summary.joint_disposition {
        validate_verdict_string(joint)?;
        if joint != &summary.server_a_verdict.verdict {
            return Err(VerifierError::PolicyVerdictDisagreement(format!(
                "joint_disposition={} disagrees with server_a/b verdict={}",
                joint, summary.server_a_verdict.verdict
            )));
        }
    }
    let joint_verdict = summary.server_a_verdict.verdict.clone();

    // ---- Step 14: capability lease resolution + expiry -----------------
    let lease_ref = pred.capability_lease_ref.as_ref().ok_or_else(|| {
        VerifierError::CapabilityLeaseExpiredOrUnknown(
            "predicate is missing capability_lease_ref (required for §7 step 14)".to_string(),
        )
    })?;
    let resolved_lease = config
        .lease_registry
        .resolve(&lease_ref.lease_id)
        .ok_or_else(|| {
            VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                "lease_id {:?} not resolvable in CapabilityLeaseRegistry (fail-closed)",
                lease_ref.lease_id
            ))
        })?;
    if resolved_lease.issuer != lease_ref.issuer {
        return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
            "lease issuer mismatch: registry={:?} predicate={:?}",
            resolved_lease.issuer, lease_ref.issuer
        )));
    }
    if resolved_lease.expires_at_unix_ms != lease_ref.expires_at_unix_ms {
        return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
            "lease expiry mismatch: registry={} predicate={}",
            resolved_lease.expires_at_unix_ms, lease_ref.expires_at_unix_ms
        )));
    }
    // Strict-greater per spec line 401: `expires_at_unix_ms > pinned_epoch.now`.
    if resolved_lease.expires_at_unix_ms <= config.pinned_epoch.now_unix_ms {
        return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
            "lease expired: expires_at={} <= pinned_epoch.now={}",
            resolved_lease.expires_at_unix_ms, config.pinned_epoch.now_unix_ms
        )));
    }
    // Scope-digest binding: for a
    // scoped capability lease the predicate's `scope_digest` and the
    // registry record's `scope_digest_hex` must BOTH be present and
    // agree. Treating one-sided presence as "skip validation" lets an
    // envelope claim a specific scope digest while the trusted
    // registry never confirms that scope (or vice versa); step 14
    // would silently accept an unbound or differently-scoped lease.
    // Fail-closed on any mismatch in presence or value.
    match (&lease_ref.scope_digest, &resolved_lease.scope_digest_hex) {
        (Some(predicate_scope), Some(registry_scope)) => {
            validate_hash_record(predicate_scope, "capability_lease_ref.scope_digest")
                .map_err(VerifierError::CapabilityLeaseExpiredOrUnknown)?;
            if &predicate_scope.value != registry_scope {
                return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                    "lease scope_digest mismatch: registry={:?} predicate={:?}",
                    registry_scope, predicate_scope.value
                )));
            }
        }
        (Some(predicate_scope), None) => {
            validate_hash_record(predicate_scope, "capability_lease_ref.scope_digest")
                .map_err(VerifierError::CapabilityLeaseExpiredOrUnknown)?;
            return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                "predicate names scope_digest={:?} but registry record has no scope_digest_hex; \
                 cannot confirm lease scope",
                predicate_scope.value
            )));
        }
        (None, Some(registry_scope)) => {
            return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                "registry record carries scope_digest_hex={:?} but predicate omitted scope_digest; \
                 cannot confirm lease scope",
                registry_scope
            )));
        }
        (None, None) => {
            // Both sides explicitly omit scope-digest binding; the
            // lease is unscoped on both ends and step 14 accepts it
            // on id+issuer+expiry alone. Unscoped leases are a valid
            // current configuration permitted by the spec.
        }
    }

    // ---- Step 15: governance receipt for receipt-backed classes -------
    //
    // Fail-closed action-class invariant: an unknown `tool_name` is
    // rejected with `governance.unknown_action_class` so a misspelled
    // or missing registration cannot silently downgrade a receipt-backed
    // class to `Routine` (fail-open).
    let class = match config.action_classes.get(&pred.tool_name).copied() {
        Some(known) => known,
        None => match config.unknown_action_class_policy {
            UnknownActionClassPolicy::Reject => {
                return Err(VerifierError::UnknownActionClass {
                    tool_name: pred.tool_name.clone(),
                });
            }
        },
    };
    let resolved_governance_receipt = match class {
        ActionClassKind::Routine => None,
        ActionClassKind::ReceiptBacked => {
            let g = pred.governance_receipt_ref.as_ref().ok_or_else(|| {
                VerifierError::GovernanceReceiptRequiredMissing(format!(
                    "tool_name {:?} is receipt-backed but predicate omits governance_receipt_ref",
                    pred.tool_name
                ))
            })?;
            validate_hash_record(&g.digest, "governance_receipt_ref.digest")
                .map_err(VerifierError::GovernanceReceiptRequiredMissing)?;
            let resolved = config
                .governance_receipt_store
                .resolve(&g.receipt_id)
                .ok_or_else(|| {
                    VerifierError::GovernanceReceiptRequiredMissing(format!(
                        "receipt_id {:?} not resolvable in GovernanceReceiptStore",
                        g.receipt_id
                    ))
                })?;
            if resolved.kernel_id != g.kernel_id {
                return Err(VerifierError::GovernanceReceiptRequiredMissing(format!(
                    "governance receipt kernel_id mismatch: store={:?} predicate={:?}",
                    resolved.kernel_id, g.kernel_id
                )));
            }
            // Recompute the digest of the resolved canonical JSON and
            // compare against the predicate's claimed digest.
            let mut hasher = Sha256::new();
            hasher.update(resolved.canonical_json.as_bytes());
            let want = hex::encode(hasher.finalize());
            if want != g.digest.value {
                return Err(VerifierError::GovernanceReceiptRequiredMissing(format!(
                    "governance receipt digest mismatch: computed={} predicate={}",
                    want, g.digest.value
                )));
            }
            Some(resolved)
        }
    };

    // ---- Step 16: consistency anchor reconciliation -------------------
    //
    // The signature-slice profile deliberately supports only
    // `crdt-commutative`. `verify_dsse_envelope` rejects
    // `totally-ordered` and `quorum-required` before this point with
    // `predicate.schema_invalid`, so this verifier does not expose
    // unreachable `consistency.*` error codes.
    if pred.consistency_model != crate::bilateral_dsse::DEFAULT_CONSISTENCY_MODEL {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "consistency_model {:?} is not supported by the signature-slice profile",
            pred.consistency_model
        )));
    }

    // ---- Step 17: success ---------------------------------------------
    Ok(VerifiedBilateralCoSignInvocation {
        statement,
        resolved_receipt,
        resolved_lease,
        resolved_governance_receipt,
        joint_verdict,
    })
}

fn validate_predicate_required_fields(pred: &BilateralPredicate) -> Result<(), VerifierError> {
    if pred.schema.as_deref() != Some(PREDICATE_BODY_SCHEMA) {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "schema {:?} is not {:?}",
            pred.schema, PREDICATE_BODY_SCHEMA
        )));
    }
    if pred.receipt_canonical_json.is_none() {
        return Err(VerifierError::PredicateSchemaInvalid(
            "receipt_canonical_json is required".to_string(),
        ));
    }
    if pred.tool_args_hash.is_some() {
        return Err(VerifierError::PredicateSchemaInvalid(
            "tool_args_hash is not part of the signature-slice profile".to_string(),
        ));
    }
    if pred.invocation_id.is_empty() {
        return Err(VerifierError::PredicateSchemaInvalid(
            "invocation_id is empty".to_string(),
        ));
    }
    if pred.tool_name.is_empty() {
        return Err(VerifierError::PredicateSchemaInvalid(
            "tool_name is empty".to_string(),
        ));
    }
    if pred.tool_server_a.kernel_id.is_empty() || pred.tool_server_b.kernel_id.is_empty() {
        return Err(VerifierError::PredicateSchemaInvalid(
            "tool_server_*.kernel_id is empty".to_string(),
        ));
    }
    if pred.tool_server_a.alg != "ed25519" || pred.tool_server_b.alg != "ed25519" {
        return Err(VerifierError::PredicateSchemaInvalid(
            "tool_server_*.alg must be ed25519".to_string(),
        ));
    }
    if !is_sha256_hex(&pred.tool_server_a.passport_key_fingerprint.0)
        || !is_sha256_hex(&pred.tool_server_b.passport_key_fingerprint.0)
    {
        return Err(VerifierError::PredicateSchemaInvalid(
            "tool_server_*.passport_key_fingerprint is not 64 lowercase hex".to_string(),
        ));
    }
    if !VALID_CROSS_ORG_VISIBILITY.contains(&pred.cross_org_visibility.as_str()) {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "cross_org_visibility {:?} is unsupported",
            pred.cross_org_visibility
        )));
    }
    match pred.co_sign.as_str() {
        "bilateral_required" | "bilateral_if_cross_org" => {}
        "n_of_m" => {
            return Err(VerifierError::PredicateSchemaInvalid(
                "co_sign \"n_of_m\" is rejected until quorum metadata and signature-set verification are implemented".to_string(),
            ))
        }
        other => {
            return Err(VerifierError::PredicateSchemaInvalid(format!(
                "co_sign {:?} is not in {{bilateral_required, bilateral_if_cross_org}}",
                other
            )))
        }
    }
    Ok(())
}

fn map_bilateral_error(error: BilateralCoSigningError) -> VerifierError {
    match error {
        BilateralCoSigningError::OrgASignatureInvalid => VerifierError::SignatureServerAInvalid(
            "PAE re-derivation under tool_server_a passport key failed".to_string(),
        ),
        BilateralCoSigningError::OrgBSignatureInvalid => VerifierError::SignatureServerBInvalid(
            "PAE re-derivation under tool_server_b passport key failed".to_string(),
        ),
        BilateralCoSigningError::ReceiptMismatch => VerifierError::SubjectDigestMismatch(
            "embedded receipt does not match the signed subject or resolved receipt".to_string(),
        ),
        BilateralCoSigningError::CanonicalJson(message) => {
            if message.starts_with("statement.malformed: subject name") {
                VerifierError::SubjectDigestMismatch(message)
            } else if message.starts_with("predicate.schema_invalid: server_a=")
                || message.starts_with("predicate.schema_invalid: unsupported verdict")
                || message.contains("requires allow verdict for admission")
                || message.contains("policy_id must be non-empty")
                || message.contains("policy_version must be non-empty")
                || message.contains("joint_disposition=")
            {
                VerifierError::PolicyVerdictDisagreement(message)
            } else if message.starts_with("payload json:")
                || message.starts_with("statement.malformed")
                || message.contains("not canonical JSON")
            {
                VerifierError::StatementMalformed(message)
            } else if message.starts_with("statement.schema_invalid") {
                VerifierError::StatementSchemaInvalid(message)
            } else if message.starts_with("predicate.type_unrecognised") {
                VerifierError::PredicateTypeUnrecognised(message)
            } else if message.starts_with("predicate.schema_invalid") {
                VerifierError::PredicateSchemaInvalid(message)
            } else if message.starts_with("subject.digest_mismatch") {
                VerifierError::SubjectDigestMismatch(message)
            } else {
                VerifierError::DsseMalformed(message)
            }
        }
        other => VerifierError::DsseMalformed(other.to_string()),
    }
}

fn canonical_json_string<T: serde::Serialize>(value: &T) -> Result<String, String> {
    let bytes = canonical_json_bytes(value).map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

fn validate_verdict_string(verdict: &str) -> Result<(), VerifierError> {
    match verdict {
        "allow" | "deny" => Ok(()),
        other => Err(VerifierError::PolicyVerdictDisagreement(format!(
            "unsupported verdict {other:?}; expected allow or deny"
        ))),
    }
}

fn validate_policy_verdict(
    verdict: &crate::bilateral_dsse::PolicyVerdict,
    field: &str,
) -> Result<(), VerifierError> {
    validate_verdict_string(&verdict.verdict)?;
    validate_non_empty_policy_field(&verdict.policy_id, field, "policy_id")?;
    validate_non_empty_policy_field(&verdict.policy_version, field, "policy_version")?;
    Ok(())
}

fn validate_non_empty_policy_field(
    value: &str,
    parent: &str,
    field: &str,
) -> Result<(), VerifierError> {
    if value.is_empty() {
        return Err(VerifierError::PolicyVerdictDisagreement(format!(
            "{parent}.{field} must be non-empty"
        )));
    }
    Ok(())
}

fn validate_hash_record(
    record: &crate::bilateral_dsse::HashRecord,
    field: &str,
) -> Result<(), String> {
    if record.alg != "sha256" {
        return Err(format!("{field}.alg must be sha256"));
    }
    if !is_sha256_hex(&record.value) {
        return Err(format!("{field}.value must be 64 lowercase hex"));
    }
    Ok(())
}

fn receipt_canonical_digest_hex(receipt: &ChioReceipt) -> Result<String, VerifierError> {
    let canonical = canonical_json_bytes(receipt)
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("canonical-json: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(hex::encode(hasher.finalize()))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

// ---------------------------------------------------------------------------
// Tests (happy path + a couple of fast negatives; full negative-conformance
// coverage lives in chio-conformance/tests/c2_bilateral_invocation_partial_verifier.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::bilateral_dsse::{
        pae, receipt_subject_name, sign_chio_bilateral_dsse_envelope, sign_dsse_envelope_full,
        BilateralPredicateExtensions, CapabilityLeaseRef, GovernanceReceiptRef, HashRecord,
        PolicyEvaluationSummary, PolicyVerdict, PAYLOAD_TYPE_IN_TOTO,
    };
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;
    use chio_core_types::crypto::{sha256_hex, Ed25519Backend, Keypair, SigningBackend};
    use chio_core_types::receipt::{
        ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel,
    };

    fn sample_receipt(kp_b: &Keypair) -> ChioReceipt {
        let body = ChioReceiptBody {
            id: "rcpt-bilateral-c2-sample".to_string(),
            timestamp: 1_734_000_000,
            capability_id: "cap-bilateral-c2".to_string(),
            tool_server: "srv-orgb-files".to_string(),
            tool_name: "file_read".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"k":"v"})).unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: sha256_hex(b"{}"),
            policy_hash: "pol".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp_b.public_key(),
        };
        ChioReceipt::sign(body, kp_b).unwrap()
    }

    fn happy_path_extensions(now_ms: u64) -> BilateralPredicateExtensions {
        BilateralPredicateExtensions {
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: "lease-c2-happy".to_string(),
                issuer: "did:chio:org-a".to_string(),
                expires_at_unix_ms: now_ms + 60_000,
                scope_digest: None,
            }),
            policy_evaluation_summary: Some(PolicyEvaluationSummary {
                server_a_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy.org-a".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                server_b_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy.org-b".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                joint_disposition: Some("allow".to_string()),
            }),
            governance_receipt_ref: None,
            consistency_anchor: None,
            consistency_model: None,
            cross_org_visibility: None,
            treaty_binding_ref: None,
        }
    }

    fn treaty_bound_extensions(
        receipt: &ChioReceipt,
        now_ms: u64,
        governance_digest: String,
    ) -> BilateralPredicateExtensions {
        BilateralPredicateExtensions {
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: "lease-c2-happy".to_string(),
                issuer: "did:chio:org-a".to_string(),
                expires_at_unix_ms: now_ms + 60_000,
                scope_digest: None,
            }),
            policy_evaluation_summary: Some(PolicyEvaluationSummary {
                server_a_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy.org-a".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                server_b_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy.org-b".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                joint_disposition: Some("allow".to_string()),
            }),
            governance_receipt_ref: Some(GovernanceReceiptRef {
                receipt_id: "gov-1".to_string(),
                kernel_id: "did:chio:governance".to_string(),
                digest: HashRecord {
                    alg: "sha256".to_string(),
                    value: governance_digest,
                },
            }),
            consistency_anchor: Some("anchor-live".to_string()),
            consistency_model: Some("totally_ordered".to_string()),
            cross_org_visibility: Some("treaty_only".to_string()),
            treaty_binding_ref: Some(TreatyBindingRef {
                treaty_id: "treaty-buyer-vendor".to_string(),
                treaty_scope_sha256: "1".repeat(64),
                ladder_intersection_sha256: "2".repeat(64),
                admission_report_sha256: "3".repeat(64),
                continuation_sha256: "4".repeat(64),
                lineage_bundle_sha256: "5".repeat(64),
                action_class_id: "workflow.destructive.vendor_call".to_string(),
                consistency_model: "totally_ordered".to_string(),
                request_sha256: receipt.action.parameter_hash.clone(),
                outcome_sha256: receipt.content_hash.clone(),
                local_receipt_sha256: "8".repeat(64),
                remote_receipt_sha256: receipt_canonical_digest_hex(receipt).unwrap(),
                lease_refs: vec!["lease-c2-happy".to_string()],
                governance_refs: vec!["gov-1".to_string()],
                signer_kernel_ids: vec!["did:chio:org-a".to_string(), "did:chio:org-b".to_string()],
            }),
        }
    }

    fn insert_fresh_ladder_peers(
        peers: &mut PeerPinSet,
        kp_a: &Keypair,
        kp_b: &Keypair,
        now_ms: u64,
    ) {
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-a".to_string(),
            public_key: kp_a.public_key(),
            ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
                manifest_id: "ladder:org-a:v1".to_string(),
                sha256: "a".repeat(64),
                issued_at_unix_ms: now_ms - 60_000,
                expires_at_unix_ms: now_ms + 60_000,
            }),
        });
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
            ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
                manifest_id: "ladder:org-b:v1".to_string(),
                sha256: "b".repeat(64),
                issued_at_unix_ms: now_ms - 60_000,
                expires_at_unix_ms: now_ms + 60_000,
            }),
        });
    }

    fn fixture(
        kp_a: &Keypair,
        kp_b: &Keypair,
        receipt: &ChioReceipt,
        now_ms: u64,
    ) -> (
        DsseEnvelope,
        InMemoryReceiptStore,
        InMemoryLeaseRegistry,
        InMemoryGovernanceReceiptStore,
        DemoAllowAllRevocationOracle,
        PeerPinSet,
    ) {
        let envelope = sign_dsse_envelope_full(
            receipt,
            kp_a,
            kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            happy_path_extensions(now_ms),
        )
        .unwrap();

        let mut receipt_store = InMemoryReceiptStore::new();
        receipt_store.insert(receipt.clone());

        let mut lease_registry = InMemoryLeaseRegistry::new();
        lease_registry.insert(ResolvedLease {
            lease_id: "lease-c2-happy".to_string(),
            issuer: "did:chio:org-a".to_string(),
            expires_at_unix_ms: now_ms + 60_000,
            scope_digest_hex: None,
        });

        let governance_store = InMemoryGovernanceReceiptStore::new();
        let revocation_oracle = DemoAllowAllRevocationOracle;

        let mut peer_pin_set = PeerPinSet::new();
        peer_pin_set.insert(PinnedPeer {
            kernel_id: "did:chio:org-a".to_string(),
            public_key: kp_a.public_key(),
            ladder_manifest_ref: None,
        });
        peer_pin_set.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
            ladder_manifest_ref: None,
        });

        (
            envelope,
            receipt_store,
            lease_registry,
            governance_store,
            revocation_oracle,
            peer_pin_set,
        )
    }

    fn config<'a>(
        peer_pin_set: &'a PeerPinSet,
        receipt_store: &'a dyn ReceiptStore,
        lease_registry: &'a dyn CapabilityLeaseRegistry,
        governance_store: &'a dyn GovernanceReceiptStore,
        revocation_oracle: &'a dyn RevocationOracle,
        now_ms: u64,
    ) -> VerifierConfig<'a> {
        // The happy-path test uses UnknownActionClassPolicy::Reject (the production default)
        // with `file_read` pre-registered as Routine. Negative tests that exercise
        // strict-mode rejection or receipt-backed classes mutate `action_classes` /
        // `unknown_action_class_policy` explicitly.
        let mut action_classes = BTreeMap::new();
        action_classes.insert("file_read".to_string(), ActionClassKind::Routine);
        VerifierConfig {
            peer_pin_set,
            receipt_store,
            lease_registry,
            governance_receipt_store: governance_store,
            revocation_oracle,
            pinned_epoch: PinnedEpoch {
                now_unix_ms: now_ms,
                epoch_height: 0,
            },
            action_classes,
            unknown_action_class_policy: UnknownActionClassPolicy::Reject,
        }
    }

    fn resign_envelope(
        envelope: &mut DsseEnvelope,
        kp_a: &Keypair,
        kp_b: &Keypair,
        statement_bytes: &[u8],
    ) {
        envelope.payload = BASE64_STANDARD.encode(statement_bytes);
        let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, statement_bytes);
        let sig_a = Ed25519Backend::new(kp_a.clone())
            .sign_bytes(&pae_bytes)
            .unwrap();
        let sig_b = Ed25519Backend::new(kp_b.clone())
            .sign_bytes(&pae_bytes)
            .unwrap();
        envelope.signatures[0].sig = BASE64_STANDARD.encode(sig_a.to_bytes());
        envelope.signatures[1].sig = BASE64_STANDARD.encode(sig_b.to_bytes());
    }

    fn strict_chio_verifier_rejects_treaty_mutation(
        mutate: impl FnOnce(&mut DsseStatement),
    ) -> VerifierError {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;
        let governance_json = r#"{"governance":"receipt"}"#.to_string();
        let governance_digest = sha256_hex(governance_json.as_bytes());
        let (
            _slice_envelope,
            receipt_store,
            lease_registry,
            mut governance_store,
            oracle,
            mut peers,
        ) = fixture(&kp_a, &kp_b, &receipt, now_ms);
        governance_store.insert(ResolvedGovernanceReceipt {
            receipt_id: "gov-1".to_string(),
            kernel_id: "did:chio:governance".to_string(),
            canonical_json: governance_json,
        });
        insert_fresh_ladder_peers(&mut peers, &kp_a, &kp_b, now_ms);
        let mut envelope = sign_chio_bilateral_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            treaty_bound_extensions(&receipt, now_ms, governance_digest),
        )
        .unwrap();
        let (mut statement, _) = envelope.decode_statement().unwrap();
        mutate(&mut statement);
        let statement_bytes = statement.canonical_bytes().unwrap();
        resign_envelope(&mut envelope, &kp_a, &kp_b, &statement_bytes);
        let mut base = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );
        base.action_classes
            .insert("file_read".to_string(), ActionClassKind::ReceiptBacked);

        verify_chio_bilateral_invocation(&envelope, &ChioBilateralVerifierConfig { base: &base })
            .unwrap_err()
    }

    #[test]
    fn happy_path_passes_partial_local_verifier() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (envelope, receipt_store, lease_registry, governance_store, oracle, peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        let config = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let verified = verify_bilateral_cosign_invocation(&envelope, &config).unwrap();
        assert_eq!(verified.joint_verdict, "allow");
        assert_eq!(verified.resolved_receipt.id, receipt.id);
    }

    #[test]
    fn verify_chio_bilateral_invocation_accepts_unanimous_deny_for_audit() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (_slice_envelope, receipt_store, lease_registry, governance_store, oracle, mut peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        let mut envelope = sign_chio_bilateral_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            happy_path_extensions(now_ms),
        )
        .unwrap();
        insert_fresh_ladder_peers(&mut peers, &kp_a, &kp_b, now_ms);
        let (mut statement, _) = envelope.decode_statement().unwrap();
        let summary = statement
            .predicate
            .policy_evaluation_summary
            .as_mut()
            .unwrap();
        summary.server_a_verdict.verdict = "deny".to_string();
        summary.server_b_verdict.verdict = "deny".to_string();
        summary.joint_disposition = Some("deny".to_string());
        let statement_bytes = statement.canonical_bytes().unwrap();
        resign_envelope(&mut envelope, &kp_a, &kp_b, &statement_bytes);

        let config = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );
        let verified = verify_chio_bilateral_invocation(
            &envelope,
            &ChioBilateralVerifierConfig { base: &config },
        )
        .unwrap();
        assert_eq!(verified.joint_verdict, "deny");
    }

    #[test]
    fn strict_chio_verifier_requires_fresh_ladder_refs() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (_slice_envelope, receipt_store, lease_registry, governance_store, oracle, mut peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        let envelope = sign_chio_bilateral_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            happy_path_extensions(now_ms),
        )
        .unwrap();
        let base = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );
        assert!(matches!(
            verify_chio_bilateral_invocation(
                &envelope,
                &ChioBilateralVerifierConfig { base: &base }
            ),
            Err(VerifierError::LadderManifestMissing(_))
        ));

        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-a".to_string(),
            public_key: kp_a.public_key(),
            ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
                manifest_id: "ladder:org-a:v1".to_string(),
                sha256: "a".repeat(64),
                issued_at_unix_ms: now_ms - 60_000,
                expires_at_unix_ms: now_ms + 60_000,
            }),
        });
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
            ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
                manifest_id: "ladder:org-b:v1".to_string(),
                sha256: "b".repeat(64),
                issued_at_unix_ms: now_ms - 60_000,
                expires_at_unix_ms: now_ms + 60_000,
            }),
        });
        let base = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );
        let verified = verify_chio_bilateral_invocation(
            &envelope,
            &ChioBilateralVerifierConfig { base: &base },
        )
        .unwrap();
        assert_eq!(verified.resolved_receipt.id, receipt.id);
    }

    #[test]
    fn strict_chio_verifier_rejects_signature_slice_profile() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (envelope, receipt_store, lease_registry, governance_store, oracle, mut peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-a".to_string(),
            public_key: kp_a.public_key(),
            ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
                manifest_id: "ladder:org-a:v1".to_string(),
                sha256: "a".repeat(64),
                issued_at_unix_ms: now_ms - 60_000,
                expires_at_unix_ms: now_ms + 60_000,
            }),
        });
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
            ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
                manifest_id: "ladder:org-b:v1".to_string(),
                sha256: "b".repeat(64),
                issued_at_unix_ms: now_ms - 60_000,
                expires_at_unix_ms: now_ms + 60_000,
            }),
        });
        let base = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let err = verify_chio_bilateral_invocation(
            &envelope,
            &ChioBilateralVerifierConfig { base: &base },
        )
        .unwrap_err();
        assert_eq!(err.code(), "predicate.type_unrecognised");
        assert!(err.to_string().contains("signature-slice"));
    }

    #[test]
    fn strict_chio_verifier_accepts_strict_predicate_profile() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let envelope = sign_chio_bilateral_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            happy_path_extensions(now_ms),
        )
        .unwrap();
        let mut receipt_store = InMemoryReceiptStore::new();
        receipt_store.insert(receipt.clone());
        let mut lease_registry = InMemoryLeaseRegistry::new();
        lease_registry.insert(ResolvedLease {
            lease_id: "lease-c2-happy".to_string(),
            issuer: "did:chio:org-a".to_string(),
            expires_at_unix_ms: now_ms + 60_000,
            scope_digest_hex: None,
        });
        let governance_store = InMemoryGovernanceReceiptStore::new();
        let oracle = DemoAllowAllRevocationOracle;
        let mut peers = PeerPinSet::new();
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-a".to_string(),
            public_key: kp_a.public_key(),
            ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
                manifest_id: "ladder:org-a:v1".to_string(),
                sha256: "a".repeat(64),
                issued_at_unix_ms: now_ms - 60_000,
                expires_at_unix_ms: now_ms + 60_000,
            }),
        });
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
            ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
                manifest_id: "ladder:org-b:v1".to_string(),
                sha256: "b".repeat(64),
                issued_at_unix_ms: now_ms - 60_000,
                expires_at_unix_ms: now_ms + 60_000,
            }),
        });
        let base = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let verified = verify_chio_bilateral_invocation(
            &envelope,
            &ChioBilateralVerifierConfig { base: &base },
        )
        .unwrap();
        assert_eq!(verified.resolved_receipt.id, receipt.id);
        assert_eq!(
            verified
                .statement
                .predicate
                .tool_args_hash
                .as_ref()
                .unwrap()
                .value,
            receipt.action.parameter_hash
        );
        assert!(verified
            .statement
            .predicate
            .receipt_canonical_json
            .is_none());
    }

    #[test]
    fn strict_chio_verifier_requires_tool_args_hash() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (_slice_envelope, receipt_store, lease_registry, governance_store, oracle, mut peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        let mut envelope = sign_chio_bilateral_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            happy_path_extensions(now_ms),
        )
        .unwrap();
        let (mut statement, _) = envelope.decode_statement().unwrap();
        statement.predicate.tool_args_hash = None;
        let statement_bytes = statement.canonical_bytes().unwrap();
        resign_envelope(&mut envelope, &kp_a, &kp_b, &statement_bytes);

        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-a".to_string(),
            public_key: kp_a.public_key(),
            ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
                manifest_id: "ladder:org-a:v1".to_string(),
                sha256: "a".repeat(64),
                issued_at_unix_ms: now_ms - 60_000,
                expires_at_unix_ms: now_ms + 60_000,
            }),
        });
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
            ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
                manifest_id: "ladder:org-b:v1".to_string(),
                sha256: "b".repeat(64),
                issued_at_unix_ms: now_ms - 60_000,
                expires_at_unix_ms: now_ms + 60_000,
            }),
        });
        let base = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let err = verify_chio_bilateral_invocation(
            &envelope,
            &ChioBilateralVerifierConfig { base: &base },
        )
        .unwrap_err();
        assert_eq!(err.code(), "predicate.schema_invalid");
        assert!(err.to_string().contains("tool_args_hash"));
    }

    #[test]
    fn strict_chio_verifier_binds_treaty_request_hash_to_tool_args() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;
        let governance_json = r#"{"governance":"receipt"}"#.to_string();
        let governance_digest = sha256_hex(governance_json.as_bytes());
        let (
            _slice_envelope,
            receipt_store,
            lease_registry,
            mut governance_store,
            oracle,
            mut peers,
        ) = fixture(&kp_a, &kp_b, &receipt, now_ms);
        governance_store.insert(ResolvedGovernanceReceipt {
            receipt_id: "gov-1".to_string(),
            kernel_id: "did:chio:governance".to_string(),
            canonical_json: governance_json,
        });
        insert_fresh_ladder_peers(&mut peers, &kp_a, &kp_b, now_ms);
        let mut envelope = sign_chio_bilateral_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            treaty_bound_extensions(&receipt, now_ms, governance_digest),
        )
        .unwrap();
        let (mut statement, _) = envelope.decode_statement().unwrap();
        statement
            .predicate
            .treaty_binding_ref
            .as_mut()
            .unwrap()
            .request_sha256 = "6".repeat(64);
        let statement_bytes = statement.canonical_bytes().unwrap();
        resign_envelope(&mut envelope, &kp_a, &kp_b, &statement_bytes);
        let mut base = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );
        base.action_classes
            .insert("file_read".to_string(), ActionClassKind::ReceiptBacked);

        let err = verify_chio_bilateral_invocation(
            &envelope,
            &ChioBilateralVerifierConfig { base: &base },
        )
        .unwrap_err();
        assert_eq!(err.code(), "predicate.schema_invalid");
        assert!(err.to_string().contains("request_sha256"));
    }

    #[test]
    fn strict_chio_verifier_binds_treaty_outcome_hash_to_resolved_receipt() {
        let err = strict_chio_verifier_rejects_treaty_mutation(|statement| {
            statement
                .predicate
                .treaty_binding_ref
                .as_mut()
                .unwrap()
                .outcome_sha256 = "7".repeat(64);
        });
        assert_eq!(err.code(), "predicate.schema_invalid");
        assert!(err.to_string().contains("outcome_sha256"));
    }

    #[test]
    fn strict_chio_verifier_binds_treaty_remote_receipt_hash_to_resolved_receipt() {
        let err = strict_chio_verifier_rejects_treaty_mutation(|statement| {
            statement
                .predicate
                .treaty_binding_ref
                .as_mut()
                .unwrap()
                .remote_receipt_sha256 = "9".repeat(64);
        });
        assert_eq!(err.code(), "predicate.schema_invalid");
        assert!(err.to_string().contains("remote_receipt_sha256"));
    }

    #[test]
    fn strict_chio_verifier_accepts_treaty_ordered_consistency() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;
        let governance_json = r#"{"governance":"receipt"}"#.to_string();
        let governance_digest = sha256_hex(governance_json.as_bytes());
        let (
            _slice_envelope,
            receipt_store,
            lease_registry,
            mut governance_store,
            oracle,
            mut peers,
        ) = fixture(&kp_a, &kp_b, &receipt, now_ms);
        governance_store.insert(ResolvedGovernanceReceipt {
            receipt_id: "gov-1".to_string(),
            kernel_id: "did:chio:governance".to_string(),
            canonical_json: governance_json,
        });
        insert_fresh_ladder_peers(&mut peers, &kp_a, &kp_b, now_ms);
        let envelope = sign_chio_bilateral_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            treaty_bound_extensions(&receipt, now_ms, governance_digest),
        )
        .unwrap();
        let mut base = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );
        base.action_classes
            .insert("file_read".to_string(), ActionClassKind::ReceiptBacked);

        let verified = verify_chio_bilateral_invocation(
            &envelope,
            &ChioBilateralVerifierConfig { base: &base },
        )
        .unwrap();

        assert_eq!(verified.resolved_receipt.id, receipt.id);
        assert_eq!(
            verified.statement.predicate.consistency_model,
            "totally_ordered"
        );
        assert!(verified.statement.predicate.treaty_binding_ref.is_some());
    }

    #[test]
    fn strict_chio_verifier_resolves_treaty_governance_refs_for_routine_class() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;
        let governance_digest = sha256_hex(br#"{"governance":"receipt"}"#);
        let (_slice_envelope, receipt_store, lease_registry, governance_store, oracle, mut peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        insert_fresh_ladder_peers(&mut peers, &kp_a, &kp_b, now_ms);
        let envelope = sign_chio_bilateral_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            treaty_bound_extensions(&receipt, now_ms, governance_digest),
        )
        .unwrap();
        let base = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let err = verify_chio_bilateral_invocation(
            &envelope,
            &ChioBilateralVerifierConfig { base: &base },
        )
        .unwrap_err();

        assert_eq!(err.code(), "governance.receipt_required_missing");
        assert!(err.to_string().contains("not resolvable"));
    }

    #[test]
    fn strict_chio_treaty_review_binds_live_material() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;
        let governance_digest = sha256_hex(br#"{"governance":"receipt"}"#);
        let envelope = sign_chio_bilateral_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            treaty_bound_extensions(&receipt, now_ms, governance_digest),
        )
        .unwrap();
        let (statement, _) = envelope.decode_statement().unwrap();
        let expected_treaty_binding = statement.predicate.treaty_binding_ref.clone().unwrap();
        let expected_subject_name = receipt_subject_name(&receipt.id);
        let expected_subject_sha256 = chio_core_types::crypto::sha256_hex(
            &chio_core_types::crypto::canonical_json_bytes(&receipt.body()).unwrap(),
        );
        let expected_capability_lease_ref =
            statement.predicate.capability_lease_ref.clone().unwrap();
        let expected_governance_receipt_ref =
            statement.predicate.governance_receipt_ref.clone().unwrap();
        let mut signer_public_keys = BTreeMap::new();
        signer_public_keys.insert("did:chio:org-a".to_string(), kp_a.public_key());
        signer_public_keys.insert("did:chio:org-b".to_string(), kp_b.public_key());

        let accepted = TreatyBoundBilateralDsseReview {
            expected_treaty_binding: &expected_treaty_binding,
            expected_subject_name: &expected_subject_name,
            expected_subject_sha256: &expected_subject_sha256,
            expected_capability_lease_ref: &expected_capability_lease_ref,
            expected_governance_receipt_ref: &expected_governance_receipt_ref,
            expected_consistency_anchor: "anchor-live",
            signer_public_keys: &signer_public_keys,
        };
        verify_treaty_bound_chio_bilateral_invocation(&envelope, &accepted).unwrap();

        let mut bad_statement = statement.clone();
        bad_statement
            .predicate
            .policy_evaluation_summary
            .as_mut()
            .unwrap()
            .server_b_verdict
            .verdict = "deny".to_string();
        bad_statement
            .predicate
            .policy_evaluation_summary
            .as_mut()
            .unwrap()
            .joint_disposition = Some("deny".to_string());
        let bad_payload = BASE64_STANDARD.encode(bad_statement.canonical_bytes().unwrap());
        let bad_envelope = DsseEnvelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
            payload: bad_payload,
            signatures: envelope.signatures.clone(),
        };
        assert_eq!(
            verify_treaty_bound_chio_bilateral_invocation(&bad_envelope, &accepted)
                .unwrap_err()
                .code(),
            "policy.verdict_disagreement"
        );
        let mut deny_statement = statement.clone();
        let deny_summary = deny_statement
            .predicate
            .policy_evaluation_summary
            .as_mut()
            .unwrap();
        deny_summary.server_a_verdict.verdict = "deny".to_string();
        deny_summary.server_b_verdict.verdict = "deny".to_string();
        deny_summary.joint_disposition = Some("deny".to_string());
        let deny_payload = BASE64_STANDARD.encode(deny_statement.canonical_bytes().unwrap());
        let deny_envelope = DsseEnvelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
            payload: deny_payload,
            signatures: envelope.signatures.clone(),
        };
        let deny_error =
            verify_treaty_bound_chio_bilateral_invocation(&deny_envelope, &accepted).unwrap_err();
        assert_eq!(deny_error.code(), "policy.verdict_disagreement");
        assert!(deny_error
            .to_string()
            .contains("requires allow verdict for admission"));

        let wrong_anchor = TreatyBoundBilateralDsseReview {
            expected_treaty_binding: &expected_treaty_binding,
            expected_subject_name: &expected_subject_name,
            expected_subject_sha256: &expected_subject_sha256,
            expected_capability_lease_ref: &expected_capability_lease_ref,
            expected_governance_receipt_ref: &expected_governance_receipt_ref,
            expected_consistency_anchor: "anchor-other",
            signer_public_keys: &signer_public_keys,
        };
        assert_eq!(
            verify_treaty_bound_chio_bilateral_invocation(&envelope, &wrong_anchor)
                .unwrap_err()
                .code(),
            "predicate.schema_invalid"
        );

        let mut wrong_lease = expected_capability_lease_ref.clone();
        wrong_lease.issuer = "did:chio:attacker".to_string();
        let wrong_lease_review = TreatyBoundBilateralDsseReview {
            expected_treaty_binding: &expected_treaty_binding,
            expected_subject_name: &expected_subject_name,
            expected_subject_sha256: &expected_subject_sha256,
            expected_capability_lease_ref: &wrong_lease,
            expected_governance_receipt_ref: &expected_governance_receipt_ref,
            expected_consistency_anchor: "anchor-live",
            signer_public_keys: &signer_public_keys,
        };
        assert_eq!(
            verify_treaty_bound_chio_bilateral_invocation(&envelope, &wrong_lease_review)
                .unwrap_err()
                .code(),
            "capability.lease_expired_or_unknown"
        );

        let mut wrong_governance = expected_governance_receipt_ref.clone();
        wrong_governance.digest.value = "0".repeat(64);
        let wrong_governance_review = TreatyBoundBilateralDsseReview {
            expected_treaty_binding: &expected_treaty_binding,
            expected_subject_name: &expected_subject_name,
            expected_subject_sha256: &expected_subject_sha256,
            expected_capability_lease_ref: &expected_capability_lease_ref,
            expected_governance_receipt_ref: &wrong_governance,
            expected_consistency_anchor: "anchor-live",
            signer_public_keys: &signer_public_keys,
        };
        assert_eq!(
            verify_treaty_bound_chio_bilateral_invocation(&envelope, &wrong_governance_review)
                .unwrap_err()
                .code(),
            "governance.receipt_required_missing"
        );

        let wrong_subject_sha256 = "0".repeat(64);
        let wrong_subject_review = TreatyBoundBilateralDsseReview {
            expected_treaty_binding: &expected_treaty_binding,
            expected_subject_name: &expected_subject_name,
            expected_subject_sha256: &wrong_subject_sha256,
            expected_capability_lease_ref: &expected_capability_lease_ref,
            expected_governance_receipt_ref: &expected_governance_receipt_ref,
            expected_consistency_anchor: "anchor-live",
            signer_public_keys: &signer_public_keys,
        };
        assert_eq!(
            verify_treaty_bound_chio_bilateral_invocation(&envelope, &wrong_subject_review)
                .unwrap_err()
                .code(),
            "subject.digest_mismatch"
        );
    }

    #[test]
    fn strict_chio_verifier_binds_treaty_signers_to_authenticated_peers() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;
        let governance_json = r#"{"governance":"receipt"}"#.to_string();
        let governance_digest = sha256_hex(governance_json.as_bytes());
        let (
            _slice_envelope,
            receipt_store,
            lease_registry,
            mut governance_store,
            oracle,
            mut peers,
        ) = fixture(&kp_a, &kp_b, &receipt, now_ms);
        governance_store.insert(ResolvedGovernanceReceipt {
            receipt_id: "gov-1".to_string(),
            kernel_id: "did:chio:governance".to_string(),
            canonical_json: governance_json,
        });
        insert_fresh_ladder_peers(&mut peers, &kp_a, &kp_b, now_ms);
        let mut envelope = sign_chio_bilateral_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            treaty_bound_extensions(&receipt, now_ms, governance_digest),
        )
        .unwrap();
        let (mut statement, _) = envelope.decode_statement().unwrap();
        statement
            .predicate
            .treaty_binding_ref
            .as_mut()
            .unwrap()
            .signer_kernel_ids[0] = "did:chio:attacker".to_string();
        let statement_bytes = statement.canonical_bytes().unwrap();
        resign_envelope(&mut envelope, &kp_a, &kp_b, &statement_bytes);
        let mut base = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );
        base.action_classes
            .insert("file_read".to_string(), ActionClassKind::ReceiptBacked);

        let err = verify_chio_bilateral_invocation(
            &envelope,
            &ChioBilateralVerifierConfig { base: &base },
        )
        .unwrap_err();
        assert_eq!(err.code(), "predicate.schema_invalid");
        assert!(err.to_string().contains("signer_kernel_ids"));
    }

    #[test]
    fn strict_chio_verifier_rejects_treaty_without_ordered_anchor() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;
        let governance_json = r#"{"governance":"receipt"}"#.to_string();
        let governance_digest = sha256_hex(governance_json.as_bytes());
        let (
            _slice_envelope,
            receipt_store,
            lease_registry,
            mut governance_store,
            oracle,
            mut peers,
        ) = fixture(&kp_a, &kp_b, &receipt, now_ms);
        governance_store.insert(ResolvedGovernanceReceipt {
            receipt_id: "gov-1".to_string(),
            kernel_id: "did:chio:governance".to_string(),
            canonical_json: governance_json,
        });
        insert_fresh_ladder_peers(&mut peers, &kp_a, &kp_b, now_ms);
        let mut ext = treaty_bound_extensions(&receipt, now_ms, governance_digest);
        ext.consistency_anchor = None;
        let envelope = sign_chio_bilateral_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            ext,
        )
        .unwrap();
        let mut base = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );
        base.action_classes
            .insert("file_read".to_string(), ActionClassKind::ReceiptBacked);

        let err = verify_chio_bilateral_invocation(
            &envelope,
            &ChioBilateralVerifierConfig { base: &base },
        )
        .unwrap_err();
        assert_eq!(err.code(), "predicate.schema_invalid");
        assert!(err.to_string().contains("consistency_anchor"));
    }

    #[test]
    fn step_7_missing_receipt_fails_closed_with_subject_digest_mismatch() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (envelope, _store, lease_registry, governance_store, oracle, peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        let empty_store = InMemoryReceiptStore::new();
        let config = config(
            &peers,
            &empty_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let err = verify_bilateral_cosign_invocation(&envelope, &config).unwrap_err();
        assert_eq!(err.code(), "subject.digest_mismatch");
    }

    #[test]
    fn parseable_dsse_with_bad_statement_json_reports_statement_malformed() {
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use base64::Engine as _;

        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (mut envelope, receipt_store, lease_registry, governance_store, oracle, peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        envelope.payload = BASE64_STANDARD.encode(b"{not-json");
        let config = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let err = verify_bilateral_cosign_invocation(&envelope, &config).unwrap_err();
        assert_eq!(err.code(), "statement.malformed");
    }

    /// Single-subject invariant: the §7 verifier must reject a multi-subject
    /// envelope structurally (mirror of the
    /// `bilateral_dsse::verify_dsse_envelope` check). Splices a second
    /// subject digest into a freshly-signed envelope and asserts the
    /// verifier returns `statement.schema_invalid` BEFORE any per-subject
    /// digest comparison.
    #[test]
    fn multi_subject_envelope_is_rejected_at_verifier_step_3() {
        use crate::bilateral_dsse::{StatementSubject, SubjectDigest};
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use base64::Engine as _;

        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (mut envelope, receipt_store, lease_registry, governance_store, oracle, peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);

        // Decode, splice a second subject, re-canonicalise, re-encode payload.
        let (mut statement, _bytes) = envelope.decode_statement().unwrap();
        statement.subject.push(StatementSubject {
            name: "rcpt-injected".to_string(),
            digest: SubjectDigest {
                sha256: "0".repeat(64),
            },
        });
        let new_statement_bytes = canonical_json_bytes(&statement).unwrap();
        envelope.payload = BASE64_STANDARD.encode(&new_statement_bytes);

        let config = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let err = verify_bilateral_cosign_invocation(&envelope, &config).unwrap_err();
        assert_eq!(err.code(), "statement.schema_invalid");
        let msg = err.to_string();
        assert!(
            msg.contains("statement.malformed") || msg.contains("exactly 1 subject"),
            "expected multi-subject diagnostic, got: {msg}"
        );
    }

    #[test]
    fn step_14_expired_lease_fails_closed() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (envelope, store, lease_registry, governance_store, oracle, peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);

        // Verifier wall clock advanced past the lease expiry.
        let expired_now = now_ms + 60_000 + 1;
        let config = config(
            &peers,
            &store,
            &lease_registry,
            &governance_store,
            &oracle,
            expired_now,
        );

        let err = verify_bilateral_cosign_invocation(&envelope, &config).unwrap_err();
        assert_eq!(err.code(), "capability.lease_expired_or_unknown");
    }

    #[test]
    fn step_13_verdict_disagreement_fails_closed() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        // Build extensions where the verdicts disagree.
        let mut ext = happy_path_extensions(now_ms);
        if let Some(s) = ext.policy_evaluation_summary.as_mut() {
            s.server_b_verdict.verdict = "deny".to_string();
            s.joint_disposition = Some("deny".to_string());
        }
        let envelope = sign_dsse_envelope_full(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            ext,
        )
        .unwrap();

        let mut peer_pin_set = PeerPinSet::new();
        peer_pin_set.insert(PinnedPeer {
            kernel_id: "did:chio:org-a".to_string(),
            public_key: kp_a.public_key(),
            ladder_manifest_ref: None,
        });
        peer_pin_set.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
            ladder_manifest_ref: None,
        });
        let mut receipt_store = InMemoryReceiptStore::new();
        receipt_store.insert(receipt.clone());
        let mut lease_registry = InMemoryLeaseRegistry::new();
        lease_registry.insert(ResolvedLease {
            lease_id: "lease-c2-happy".to_string(),
            issuer: "did:chio:org-a".to_string(),
            expires_at_unix_ms: now_ms + 60_000,
            scope_digest_hex: None,
        });
        let governance_store = InMemoryGovernanceReceiptStore::new();
        let oracle = DemoAllowAllRevocationOracle;

        let config = config(
            &peer_pin_set,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let err = verify_bilateral_cosign_invocation(&envelope, &config).unwrap_err();
        assert_eq!(err.code(), "policy.verdict_disagreement");
    }

    #[test]
    fn step_15_receipt_backed_class_requires_governance_receipt() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (envelope, store, lease_registry, governance_store, oracle, peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        let mut cfg = config(
            &peers,
            &store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );
        // Mark this tool as receipt-backed in the verifier's local
        // ladder manifest.
        cfg.action_classes
            .insert("file_read".to_string(), ActionClassKind::ReceiptBacked);

        let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
        assert_eq!(err.code(), "governance.receipt_required_missing");
    }

    #[test]
    fn step_8_unpinned_peer_fails_closed() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (envelope, store, lease_registry, governance_store, oracle, _peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);

        // Empty pin set.
        let peers = PeerPinSet::new();
        let cfg = config(
            &peers,
            &store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
        assert_eq!(err.code(), "peer.unpinned_or_keyid_mismatch");
    }

    #[test]
    fn step_15_unknown_action_class_rejected_under_strict_policy() {
        // Fail-closed action-class invariant: a tool name not present in
        // `action_classes` must not fall back to `Routine` (fail-OPEN for
        // receipt-backed classes misspelled or omitted from the registry).
        // The strict default (Reject) returns the typed
        // `governance.unknown_action_class` diagnostic.
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (envelope, store, lease_registry, governance_store, oracle, peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        let mut cfg = config(
            &peers,
            &store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );
        // Strict policy: any unregistered tool is rejected. The
        // `action_classes` table is intentionally cleared so the
        // predicate's `tool_name` cannot resolve. (The shared helper
        // pre-registers `file_read` for the happy path; this negative
        // test removes that registration.)
        cfg.unknown_action_class_policy = UnknownActionClassPolicy::Reject;
        cfg.action_classes.clear();

        let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
        assert_eq!(err.code(), "governance.unknown_action_class");
        match err {
            VerifierError::UnknownActionClass { tool_name } => {
                assert_eq!(tool_name, "file_read");
            }
            other => panic!("expected UnknownActionClass, got {other:?}"),
        }
    }

    #[test]
    fn resolved_receipt_signature_must_verify() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (envelope, _store, lease_registry, governance_store, oracle, peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        let mut tampered_receipt = receipt.clone();
        tampered_receipt.content_hash = sha256_hex(b"tampered");
        let mut receipt_store = InMemoryReceiptStore::new();
        receipt_store.insert(tampered_receipt);
        let cfg = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
        assert_eq!(err.code(), "subject.digest_mismatch");
        assert!(err.to_string().contains("signature"));
    }

    #[test]
    fn predicate_tool_name_must_match_resolved_receipt() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (mut envelope, store, lease_registry, governance_store, oracle, peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        let (mut statement, _) = envelope.decode_statement().unwrap();
        statement.predicate.tool_name = "file_write".to_string();
        resign_envelope(
            &mut envelope,
            &kp_a,
            &kp_b,
            &statement.canonical_bytes().unwrap(),
        );
        let cfg = config(
            &peers,
            &store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
        assert_eq!(err.code(), "predicate.schema_invalid");
        assert!(err.to_string().contains("tool_name"));
    }

    #[test]
    fn predicate_embedded_receipt_json_must_match_resolved_receipt() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (mut envelope, store, lease_registry, governance_store, oracle, peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        let (mut statement, _) = envelope.decode_statement().unwrap();
        let mut embedded: ChioReceipt =
            serde_json::from_str(statement.predicate.receipt_canonical_json.as_ref().unwrap())
                .unwrap();
        embedded.capability_id = "different-capability".to_string();
        statement.predicate.receipt_canonical_json =
            Some(canonical_json_string(&embedded).unwrap());
        resign_envelope(
            &mut envelope,
            &kp_a,
            &kp_b,
            &statement.canonical_bytes().unwrap(),
        );
        let cfg = config(
            &peers,
            &store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
        assert_eq!(err.code(), "subject.digest_mismatch");
        assert!(err.to_string().contains("embedded receipt"));
    }

    #[test]
    fn unsupported_policy_verdict_is_rejected() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let mut ext = happy_path_extensions(now_ms);
        if let Some(summary) = ext.policy_evaluation_summary.as_mut() {
            summary.server_a_verdict.verdict = "observe".to_string();
            summary.server_b_verdict.verdict = "observe".to_string();
            summary.joint_disposition = Some("observe".to_string());
        }
        let envelope = sign_dsse_envelope_full(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            ext,
        )
        .unwrap();
        let mut receipt_store = InMemoryReceiptStore::new();
        receipt_store.insert(receipt.clone());
        let mut lease_registry = InMemoryLeaseRegistry::new();
        lease_registry.insert(ResolvedLease {
            lease_id: "lease-c2-happy".to_string(),
            issuer: "did:chio:org-a".to_string(),
            expires_at_unix_ms: now_ms + 60_000,
            scope_digest_hex: None,
        });
        let governance_store = InMemoryGovernanceReceiptStore::new();
        let oracle = DemoAllowAllRevocationOracle;
        let mut peers = PeerPinSet::new();
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-a".to_string(),
            public_key: kp_a.public_key(),
            ladder_manifest_ref: None,
        });
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
            ladder_manifest_ref: None,
        });
        let cfg = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
        assert_eq!(err.code(), "policy.verdict_disagreement");
        assert!(err.to_string().contains("unsupported verdict"));
    }

    #[test]
    fn policy_provenance_fields_must_be_non_empty() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let mut ext = happy_path_extensions(now_ms);
        if let Some(summary) = ext.policy_evaluation_summary.as_mut() {
            summary.server_a_verdict.policy_id.clear();
        }
        let envelope = sign_dsse_envelope_full(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            ext,
        )
        .unwrap();

        let (_unused, store, lease_registry, governance_store, oracle, peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        let cfg = config(
            &peers,
            &store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
        assert_eq!(err.code(), "policy.verdict_disagreement");
        assert!(err.to_string().contains("policy_id must be non-empty"));
    }

    #[test]
    fn scope_digest_hash_record_must_be_sha256() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;
        let scope_value = "a".repeat(64);

        let mut ext = happy_path_extensions(now_ms);
        if let Some(lease) = ext.capability_lease_ref.as_mut() {
            lease.scope_digest = Some(HashRecord {
                alg: "sha512".to_string(),
                value: scope_value.clone(),
            });
        }
        let envelope = sign_dsse_envelope_full(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            ext,
        )
        .unwrap();
        let mut receipt_store = InMemoryReceiptStore::new();
        receipt_store.insert(receipt.clone());
        let mut lease_registry = InMemoryLeaseRegistry::new();
        lease_registry.insert(ResolvedLease {
            lease_id: "lease-c2-happy".to_string(),
            issuer: "did:chio:org-a".to_string(),
            expires_at_unix_ms: now_ms + 60_000,
            scope_digest_hex: Some(scope_value),
        });
        let governance_store = InMemoryGovernanceReceiptStore::new();
        let oracle = DemoAllowAllRevocationOracle;
        let mut peers = PeerPinSet::new();
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-a".to_string(),
            public_key: kp_a.public_key(),
            ladder_manifest_ref: None,
        });
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
            ladder_manifest_ref: None,
        });
        let cfg = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );

        let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
        assert_eq!(err.code(), "capability.lease_expired_or_unknown");
        assert!(err.to_string().contains("sha256"));
    }

    #[test]
    fn governance_digest_hash_record_must_be_sha256() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let governance_json = r#"{"governance":"receipt"}"#.to_string();
        let governance_digest = sha256_hex(governance_json.as_bytes());
        let mut ext = happy_path_extensions(now_ms);
        ext.governance_receipt_ref = Some(GovernanceReceiptRef {
            receipt_id: "gov-1".to_string(),
            kernel_id: "did:chio:governance".to_string(),
            digest: HashRecord {
                alg: "blake3".to_string(),
                value: governance_digest,
            },
        });
        let envelope = sign_dsse_envelope_full(
            &receipt,
            &kp_a,
            &kp_b,
            "did:chio:org-a",
            "did:chio:org-b",
            "file_read",
            now_ms,
            ext,
        )
        .unwrap();
        let mut receipt_store = InMemoryReceiptStore::new();
        receipt_store.insert(receipt.clone());
        let mut lease_registry = InMemoryLeaseRegistry::new();
        lease_registry.insert(ResolvedLease {
            lease_id: "lease-c2-happy".to_string(),
            issuer: "did:chio:org-a".to_string(),
            expires_at_unix_ms: now_ms + 60_000,
            scope_digest_hex: None,
        });
        let mut governance_store = InMemoryGovernanceReceiptStore::new();
        governance_store.insert(ResolvedGovernanceReceipt {
            receipt_id: "gov-1".to_string(),
            kernel_id: "did:chio:governance".to_string(),
            canonical_json: governance_json,
        });
        let oracle = DemoAllowAllRevocationOracle;
        let mut peers = PeerPinSet::new();
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-a".to_string(),
            public_key: kp_a.public_key(),
            ladder_manifest_ref: None,
        });
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
            ladder_manifest_ref: None,
        });
        let mut cfg = config(
            &peers,
            &receipt_store,
            &lease_registry,
            &governance_store,
            &oracle,
            now_ms,
        );
        cfg.action_classes
            .insert("file_read".to_string(), ActionClassKind::ReceiptBacked);

        let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
        assert_eq!(err.code(), "governance.receipt_required_missing");
        assert!(err.to_string().contains("sha256"));
    }
}
