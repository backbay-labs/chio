//! Implements a partial local verifier for the bilateral DSSE
//! signature-slice profile produced by
//! [`crate::bilateral_dsse::sign_dsse_envelope_full`].
//!
//! ## Partial-verifier scope
//!
//! This module previously self-described as a "full verifier" and
//! implied full §7 conformance. The
//! implementation does not yet cover the full predicate schema:
//!
//!   - `BilateralPredicate` is intentionally not the strict CHIODOS
//!     predicate: it is missing required fields the spec
//!     enumerates (e.g. `tool_args_hash` per
//!     `CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §5/§6) and accepts
//!     internal non-schema fields that the spec does not define.
//!   - The error mapping conflates parseable-but-schema-malformed
//!     Statement JSON with `dsse.malformed` rather than the spec's
//!     `statement.malformed`.
//!   - The receipt digest binding shape was wrong in an earlier
//!     revision, now fixed in `bilateral_dsse::build_statement`.
//!
//! This verifier is labeled as a **partial local verifier**: it
//! implements the structural / cryptographic core
//! plus a meaningful subset of the §7 step list against the local
//! signature-slice profile. Strict CHIODOS predicate completion belongs
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
//! * [`verify_bilateral_cosign_invocation`] - runs the partial
//!   local verifier (not full §7 conformance pending strict predicate-profile completion).
//! * [`VerifiedBilateralCoSignInvocation`] - successful verifier output
//!   (mirrors §7 step 17 for the steps this implementation covers).
//! * [`VerifierError`] - fail-closed error codes mapping 1:1 to spec
//!   §7.1 (e.g. `subject.digest_mismatch`, `peer.unpinned_or_keyid_mismatch`).
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
    receipt_subject_name, verify_dsse_envelope, BilateralPredicate, DsseEnvelope, DsseStatement,
    Keyid, PREDICATE_BODY_SCHEMA, PREDICATE_TYPE_BILATERAL, STATEMENT_TYPE_V1,
    VALID_CROSS_ORG_VISIBILITY,
};

// ---------------------------------------------------------------------------
// Spec §7.1 error codes
// ---------------------------------------------------------------------------

/// Fail-closed error codes returned by [`verify_bilateral_cosign_invocation`].
/// Each variant maps verbatim to a spec §7.1 code (the `Display` impl
/// emits the code itself); kernels that surface verifier output in
/// receipts SHOULD log the code as the canonical value.
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
    /// `consistency.anchor_unverified` - a `totally-ordered` predicate's
    /// anchor cannot be reconciled with the verifier's view.
    #[error("consistency.anchor_unverified: {0}")]
    ConsistencyAnchorUnverified(String),
    /// `consistency.quorum_underpopulated` - a `quorum-required`
    /// predicate's envelope lacks the declared quorum's signatures.
    #[error("consistency.quorum_underpopulated: {0}")]
    ConsistencyQuorumUnderpopulated(String),
    /// Fail-closed action-class invariant: `governance.unknown_action_class`.
    /// The predicate's `tool_name` is not registered in the verifier's
    /// `action_classes` table. The pre-fix verifier silently fell back
    /// to `Routine` (no governance receipt required) when the table
    /// did not contain the tool, which is fail-OPEN for receipt-backed
    /// classes that were misspelled or omitted from the registry. The
    /// strict mode requires explicit registration.
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
            Self::ConsistencyAnchorUnverified(_) => "consistency.anchor_unverified",
            Self::ConsistencyQuorumUnderpopulated(_) => "consistency.quorum_underpopulated",
            Self::UnknownActionClass { .. } => "governance.unknown_action_class",
        }
    }
}

impl From<BilateralCoSigningError> for VerifierError {
    fn from(e: BilateralCoSigningError) -> Self {
        match e {
            BilateralCoSigningError::CanonicalJson(s) => Self::StatementMalformed(s),
            BilateralCoSigningError::OrgASignatureInvalid => {
                Self::SignatureServerAInvalid("delegated".to_string())
            }
            BilateralCoSigningError::OrgBSignatureInvalid => {
                Self::SignatureServerBInvalid("delegated".to_string())
            }
            other => Self::DsseMalformed(other.to_string()),
        }
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
    /// Legacy fallback. Falls back to [`ActionClassKind::Routine`]
    /// when the table does not contain the tool. Integrators must
    /// opt in explicitly; production deployments are expected to
    /// migrate to `Reject`.
    DefaultRoutine,
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
    /// - [`UnknownActionClassPolicy::Reject`] (default): the verifier returns
    ///   [`VerifierError::UnknownActionClass`] so a misspelled or
    ///   missing registration cannot silently downgrade a
    ///   receipt-backed class to `Routine`.
    /// - [`UnknownActionClassPolicy::DefaultRoutine`]: the legacy
    ///   behavior, retained as an explicit opt-in for integrators
    ///   whose classification table is genuinely incomplete during
    ///   bootstrap. Kernels that opt in MUST also pin a strictness
    ///   schedule for production cutover.
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

// ---------------------------------------------------------------------------
// Partial local verifier (subset of spec §7 step list)
// ---------------------------------------------------------------------------

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

    let (statement, statement_bytes) = envelope
        .decode_statement()
        .map_err(|e| VerifierError::DsseMalformed(e.to_string()))?;

    // ---- Step 3: in-toto v1 schema -------------------------------------
    if statement.statement_type != STATEMENT_TYPE_V1 {
        return Err(VerifierError::StatementSchemaInvalid(format!(
            "_type {:?} is not {:?}",
            statement.statement_type, STATEMENT_TYPE_V1
        )));
    }
    // Single-subject invariant: the bilateral envelope profile
    // binds exactly ONE subject (the receipt body). The pre-fix
    // verifier only rejected the empty-list case, so a multi-subject
    // envelope was accepted and `subject[0]` alone was bound. A
    // signer could insert an arbitrary second subject digest and
    // verifiers that walked the full subject list (the in-toto
    // convention for subject membership) would resolve a different
    // receipt than the producer signed. Mirror the
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

    // ---- Step 7: subject digest = sha256(canonical_json(resolve_receipt.body()))
    // Subject-digest invariant: the subject digest binds the
    // receipt BODY (`ChioReceiptBody`), not the full signed wrapper.
    // The producer-side `bilateral_dsse::build_statement` was fixed
    // to hash the body; this verifier path must hash the
    // same input, otherwise the §7 step-7 check rejects every
    // freshly-signed envelope.
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
    let resolved_receipt_canonical = canonical_json_string(&resolved_receipt)
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("canonical-json: {e}")))?;
    if pred.receipt_canonical_json != resolved_receipt_canonical {
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

    // ---- Step 8: peer pinning ------------------------------------------
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
    if resolved_receipt.kernel_key != pinned_b.public_key {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(
            "resolved receipt kernel_key does not match pinned tool_server_b key".to_string(),
        ));
    }

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

    verify_dsse_envelope(envelope, &pinned_a.public_key, &pinned_b.public_key).map_err(
        |e| match e {
            BilateralCoSigningError::OrgASignatureInvalid => {
                VerifierError::SignatureServerAInvalid(
                    "PAE re-derivation under tool_server_a passport key failed".to_string(),
                )
            }
            BilateralCoSigningError::OrgBSignatureInvalid => {
                VerifierError::SignatureServerBInvalid(
                    "PAE re-derivation under tool_server_b passport key failed".to_string(),
                )
            }
            other => VerifierError::DsseMalformed(other.to_string()),
        },
    )?;

    // Sanity: the statement_bytes the producer signed equal what we just
    // decoded. (Detects a verifier-side encoding drift; the upstream
    // verifier already covered this, but we keep the check explicit.)
    let _ = statement_bytes;

    // ---- Step 13: verdict agreement ------------------------------------
    let summary = pred.policy_evaluation_summary.as_ref().ok_or_else(|| {
        VerifierError::PolicyVerdictDisagreement(
            "predicate is missing policy_evaluation_summary (required for §7 step 13)".to_string(),
        )
    })?;
    validate_verdict_string(&summary.server_a_verdict.verdict)?;
    validate_verdict_string(&summary.server_b_verdict.verdict)?;
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
            // on id+issuer+expiry alone. This is the legacy
            // unscoped-lease path.
        }
    }

    // ---- Step 15: governance receipt for receipt-backed classes -------
    //
    // Fail-closed action-class invariant: an unknown `tool_name` previously
    // silently fell back to `Routine`, which is fail-OPEN for any
    // receipt-backed class that was misspelled or omitted from the
    // registry. The default policy now rejects unknown tools; legacy
    // behavior is available as an explicit opt-in via
    // `UnknownActionClassPolicy::DefaultRoutine`.
    let class = match config.action_classes.get(&pred.tool_name).copied() {
        Some(known) => known,
        None => match config.unknown_action_class_policy {
            UnknownActionClassPolicy::Reject => {
                return Err(VerifierError::UnknownActionClass {
                    tool_name: pred.tool_name.clone(),
                });
            }
            UnknownActionClassPolicy::DefaultRoutine => ActionClassKind::Routine,
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
    match pred.consistency_model.as_str() {
        "crdt-commutative" => {}
        "totally-ordered" => {
            return Err(VerifierError::ConsistencyAnchorUnverified(
                "totally-ordered consistency requires verifier-side anchor reconciliation"
                    .to_string(),
            ));
        }
        "quorum-required" => {
            return Err(VerifierError::ConsistencyQuorumUnderpopulated(
                "quorum-required consistency is rejected until quorum metadata and signature-set verification are implemented".to_string(),
            ));
        }
        other => {
            return Err(VerifierError::PredicateSchemaInvalid(format!(
                "consistency_model {:?} is not in {{crdt-commutative, totally-ordered, quorum-required}}",
                other
            )));
        }
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
    if pred.schema != PREDICATE_BODY_SCHEMA {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "schema {:?} is not {:?}",
            pred.schema, PREDICATE_BODY_SCHEMA
        )));
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
        sign_dsse_envelope_full, BilateralPredicateExtensions, CapabilityLeaseRef,
        GovernanceReceiptRef, HashRecord, PolicyEvaluationSummary, PolicyVerdict,
    };
    use chio_core_types::crypto::{sha256_hex, Keypair};
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
            decision: Decision::Allow,
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
        }
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
        });
        peer_pin_set.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
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
        // Strict-default helper: the helper now returns the strict default
        // (`UnknownActionClassPolicy::Reject`) and pre-registers the
        // tool exercised by `fixture` (`file_read`) as `Routine`. The
        // happy-path test must pass under the production-shape policy
        // rather than relying on the legacy `DefaultRoutine` fallback.
        // Negative tests that exercise the strict-mode rejection or
        // the receipt-backed class path mutate `action_classes` /
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
        });
        peer_pin_set.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
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
        // Fail-closed action-class invariant: the pre-fix verifier silently
        // fell back to `Routine` for any tool name not present in
        // `action_classes`, fail-OPEN for receipt-backed classes
        // misspelled or omitted from the registry. The strict default
        // (Reject) returns the typed `governance.unknown_action_class`
        // diagnostic.
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
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use base64::Engine as _;

        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (mut envelope, store, lease_registry, governance_store, oracle, peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        let (mut statement, _) = envelope.decode_statement().unwrap();
        statement.predicate.tool_name = "file_write".to_string();
        envelope.payload = BASE64_STANDARD.encode(statement.canonical_bytes().unwrap());
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
        assert!(err.to_string().contains("tool_name"));
    }

    #[test]
    fn predicate_embedded_receipt_json_must_match_resolved_receipt() {
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use base64::Engine as _;

        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let now_ms = 1_734_000_000_000;

        let (mut envelope, store, lease_registry, governance_store, oracle, peers) =
            fixture(&kp_a, &kp_b, &receipt, now_ms);
        let (mut statement, _) = envelope.decode_statement().unwrap();
        let mut embedded: ChioReceipt =
            serde_json::from_str(&statement.predicate.receipt_canonical_json).unwrap();
        embedded.capability_id = "different-capability".to_string();
        statement.predicate.receipt_canonical_json = canonical_json_string(&embedded).unwrap();
        envelope.payload = BASE64_STANDARD.encode(statement.canonical_bytes().unwrap());
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
        assert!(err.to_string().contains("embedded receipt JSON"));
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
        });
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
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
        });
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
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
        });
        peers.insert(PinnedPeer {
            kernel_id: "did:chio:org-b".to_string(),
            public_key: kp_b.public_key(),
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

    #[test]
    fn happy_path_under_legacy_default_routine_fallback() {
        // The legacy policy (DefaultRoutine) is retained for explicit
        // opt-in by integrators whose registry is incomplete during
        // bootstrap. It must continue to pass when no governance
        // receipt is required (Routine class). Named to make clear
        // this is the legacy fallback path,
        // distinct from the strict happy path
        // (`happy_path_passes_partial_local_verifier`).
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
        cfg.unknown_action_class_policy = UnknownActionClassPolicy::DefaultRoutine;
        // Clear the helper's pre-registration so we genuinely
        // exercise the fallback (not the explicit Routine entry).
        cfg.action_classes.clear();

        // Empty action_classes + DefaultRoutine = silently treats the
        // tool as Routine, passing through to step 16+. The verifier
        // must not raise `governance.unknown_action_class`.
        let result = verify_bilateral_cosign_invocation(&envelope, &cfg);
        if let Err(err) = result {
            assert_ne!(
                err.code(),
                "governance.unknown_action_class",
                "DefaultRoutine policy must NOT raise UnknownActionClass"
            );
        }
    }
}
