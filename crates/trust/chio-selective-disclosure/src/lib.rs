//! Selective disclosure projections and proof packages for Chio receipts.

#![forbid(unsafe_code)]

#[cfg(feature = "bbs")]
use chio_core_types::receipt::{
    body::prepare_receipt_body_for_signing, body::ChioReceipt, signing::BbsReceiptSignature,
    signing::ContentHashMismatch, signing::ReceiptSigningHandle,
    signing::CHIO_RECEIPT_BBS_SIGNATURE_ALGORITHM, signing::CHIO_RECEIPT_BBS_SIGNATURE_SCHEMA,
};
use chio_core_types::receipt::{body::ChioReceiptBody, kinds::TrustLevel};
use chio_workflow::receipt::{StepRecord, WorkflowReceiptBody};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(feature = "bbs")]
use std::collections::BTreeSet;
use std::collections::HashMap;

mod crypto_context;
mod encoding;
mod projection_manifest;

#[cfg(feature = "bbs")]
use encoding::decode_message_hex;
use encoding::{
    bool_byte, canonical_bytes, decode_hx_field, hash_canonical, opt_string_bytes, push_message,
    sha256_hex_bytes, subject_sha256_hex, u64_le,
};

pub use chio_disclosure_lineage::{
    compute_signed_lineage_subgraph_digest, sign_crypto_context_report, sign_lineage_subgraph,
    verify_crypto_context_report_signature_with_trust, verify_disclosure_lineage_bundle,
    verify_disclosure_lineage_bundle_with_trust, DisclosureCapsule, DisclosureHiddenPredicate,
    DisclosureLeakageLedger, DisclosureLeakageLedgerEntry, DisclosureLineageBundle,
    DisclosureLineageError, DisclosureLineageVerifierReport, DisclosureLineageVerifierTrust,
    DisclosureProfileLeakageBudget, DisclosureSensitivityClass, DisclosureSignedLineageEdge,
    DisclosureSignedLineageNode, DisclosureSignedLineageRedaction, SignedLineageSubgraph,
    DISCLOSURE_CAPSULE_SCHEMA_V1, DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1,
    DISCLOSURE_LINEAGE_VERIFIER_REPORT_SCHEMA_V1, LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1,
};
#[cfg(feature = "bbs")]
pub use crypto_context::verify_selective_disclosure_with_context;
pub use crypto_context::{
    CryptoVerificationContext, DisclosureContextCheck, DisclosureContextVerdict,
    DisclosureCryptoContextError, DisclosureCryptoContextReport, DisclosureKeyState,
    DisclosureRevocationSnapshot, DisclosureVerifierPrivacyProfile, HolderBindingStatus,
    KeyStateStatus, NonceReplayStatus, RevocationSnapshotStatus, TransparencyState,
    CRYPTO_VERIFICATION_CONTEXT_SCHEMA_V1, DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1,
    DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1, TRUST_KEY_STATE_SCHEMA_V1,
    TRUST_REVOCATION_SNAPSHOT_SCHEMA_V1,
};
pub use projection_manifest::{
    BbsProjectionDisclosure, BbsProjectionHiddenPredicate, BbsProjectionManifest,
    BbsProjectionMessageSlot, BBS_PROJECTION_MANIFEST_SCHEMA_V2,
};

/// Receipt-body projection version used for BBS message vectors.
pub const PROJECTION_VERSION_RECEIPT_V1: &str = "chio.bbs-projection.receipt.v1";
/// WorkflowReceipt projection version used for BBS message vectors.
pub const PROJECTION_VERSION_WORKFLOW_V1: &str = "chio.bbs-projection.workflow.v1";
/// StepRecord projection version used for BBS message vectors.
pub const PROJECTION_VERSION_STEP_V1: &str = "chio.bbs-projection.step.v1";
/// Real selective disclosure proof package schema.
pub const SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1: &str = "chio.attest.selective-disclosure-proof.v1";
/// Internal full-signature carrier for a projected message vector.
pub const SIGNED_PROJECTION_SCHEMA_V1: &str =
    "chio.attest.selective-disclosure-signed-projection.v1";
/// BBS ciphersuite used by the MSRV-compatible Affinidi implementation.
pub const BBS_CIPHERSUITE_SHA256: &str = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";

#[cfg(feature = "bbs")]
const MESSAGE_DOMAIN_V1: &[u8] = b"chio.bbs.message.v1";
#[cfg(feature = "bbs")]
const HEADER_DOMAIN_V1: &[u8] = b"chio.bbs.header.v1";
#[cfg(feature = "bbs")]
const BBS_SHA256_POINT_BYTES: usize = 48;
#[cfg(feature = "bbs")]
const BBS_SHA256_SCALAR_BYTES: usize = 32;
#[cfg(feature = "bbs")]
const BBS_SHA256_PROOF_FIXED_BYTES: usize =
    (3 * BBS_SHA256_POINT_BYTES) + (4 * BBS_SHA256_SCALAR_BYTES);

/// One projected message in a Chio BBS vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionMessage {
    pub index: u16,
    pub field: String,
    pub encoding: String,
    pub bytes_hex: String,
    pub wholesale_only: bool,
}

/// A typed BBS projection over a Chio receipt-like object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Projection {
    pub version: String,
    pub subject_sha256_hex: String,
    pub messages: Vec<ProjectionMessage>,
}

/// Schema for a transparency log inclusion proof over the disclosed artifact.
pub const TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V1: &str = "chio.transparency.inclusion-proof.v1";

/// Merkle inclusion proof binding a selective disclosure artifact to a log root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransparencyInclusionProof {
    pub schema: String,
    pub proof_id: String,
    pub log_id: String,
    pub artifact_ref: String,
    pub root_hash: String,
    pub leaf_hash: String,
    pub tree_size: u64,
    pub leaf_index: u64,
    pub checkpoint: String,
    pub inclusion_path: Vec<String>,
    pub verified_at: u64,
}

/// Message indices to disclose to a buyer or auditor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DisclosureSet(pub Vec<u16>);

/// Disclosed message in a proof package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosedMessage {
    pub index: u16,
    pub field: String,
    pub encoding: String,
    pub bytes_hex: String,
}

/// BBS issuer keypair used by fixture producers and test registries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BbsKeyPair {
    pub issuer_fingerprint: String,
    pub public_key_hex: String,
    secret_key_hex: String,
}

/// Full BBS signature over a projection. This is not the auditor package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedProjection {
    pub schema: String,
    pub projection_version: String,
    pub subject_sha256_hex: String,
    pub ciphersuite: String,
    pub issuer_fingerprint: String,
    pub issuer_public_key_hex: String,
    pub message_count: usize,
    pub signature_hex: String,
}

/// Buyer or auditor proof package carrying only disclosed fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectiveDisclosureProof {
    pub schema: String,
    pub projection_version: String,
    pub subject_sha256_hex: String,
    pub ciphersuite: String,
    pub issuer_fingerprint: String,
    pub issuer_public_key_hex: String,
    pub message_count: usize,
    pub disclosed_indices: Vec<u16>,
    pub disclosed: Vec<DisclosedMessage>,
    pub proof_nonce_hex: String,
    pub proof_bytes_hex: String,
}

/// Verified disclosure returned after a BBS proof accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDisclosure {
    pub subject_sha256_hex: String,
    pub issuer_fingerprint: String,
    pub disclosed: Vec<DisclosedMessage>,
}

/// In-memory issuer key registry for tests and local conformance fixtures.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InMemoryIssuerRegistry {
    public_keys: HashMap<String, String>,
}

impl InMemoryIssuerRegistry {
    /// Insert a public key by issuer fingerprint.
    pub fn insert(&mut self, issuer_fingerprint: String, public_key_hex: String) {
        self.public_keys.insert(issuer_fingerprint, public_key_hex);
    }

    #[cfg(feature = "bbs")]
    fn public_key_hex(&self, issuer_fingerprint: &str) -> Option<&str> {
        self.public_keys
            .get(issuer_fingerprint)
            .map(std::string::String::as_str)
    }
}

/// Errors returned by selective disclosure projection and verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SelectiveDisclosureError {
    #[error("canonical JSON encoding failed: {0}")]
    CanonicalJson(String),
    #[error("malformed Hx field {field}: {reason}")]
    MalformedHexField { field: String, reason: String },
    #[error("disclosure set carries duplicate index {0}")]
    DisclosureDuplicateIndex(u16),
    #[error("disclosure set carries an out-of-range index {0}")]
    DisclosureIndexOutOfRange(u16),
    #[error("schema {0} is not accepted by the real BBS verifier")]
    SchemaMismatch(String),
    #[error("projection version {0} is not supported by this verifier")]
    ProjectionVersionMismatch(String),
    #[error("signed projection does not match the supplied projection")]
    SignedProjectionMismatch,
    #[error("BBS signature verification failed")]
    SignatureVerificationFailed,
    #[error("BBS proof verification failed")]
    ProofVerificationFailed,
    #[error("receipt signature verification failed")]
    ReceiptSignatureInvalid,
    #[error("receipt does not carry BBS signature material")]
    ReceiptBbsSignatureMissing,
    #[error("receipt BBS binding is invalid: {0}")]
    ReceiptBbsBindingInvalid(String),
    #[error("BBS projection manifest {0}")]
    ProjectionManifestInvalid(String),
    #[error("transparency inclusion proof {0}")]
    TransparencyInclusionInvalid(String),
    #[error("receipt content_hash does not match the bound canonical content (WYSIWYS): {0}")]
    ContentHashMismatch(String),
    #[error("issuer {0} is not registered")]
    UnknownIssuer(String),
    #[error("issuer public key does not match registry")]
    IssuerKeyMismatch,
    #[error("key material must be at least 32 bytes")]
    KeySeedTooShort,
    #[error("hex decoding failed: {0}")]
    Hex(String),
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
}

/// Project a receipt body using the Chio receipt v1 BBS table.
pub fn project_receipt_body(
    body: &ChioReceiptBody,
) -> Result<Projection, SelectiveDisclosureError> {
    if let Some(version) = &body.bbs_projection_version {
        if version != PROJECTION_VERSION_RECEIPT_V1 {
            return Err(SelectiveDisclosureError::ProjectionVersionMismatch(
                version.clone(),
            ));
        }
    }
    let mut messages = Vec::with_capacity(14);
    push_message(
        &mut messages,
        "action",
        "H",
        hash_canonical(&body.action)?,
        true,
    );
    push_message(
        &mut messages,
        "capability_id",
        "S",
        body.capability_id.as_bytes().to_vec(),
        false,
    );
    push_message(
        &mut messages,
        "content_hash",
        "Hx",
        decode_hx_field("content_hash", &body.content_hash)?,
        false,
    );
    push_message(
        &mut messages,
        "decision",
        "H",
        hash_canonical(&body.decision)?,
        true,
    );
    push_message(
        &mut messages,
        "evidence",
        "H",
        hash_canonical(&body.evidence)?,
        true,
    );
    push_message(&mut messages, "id", "S", body.id.as_bytes().to_vec(), false);
    push_message(
        &mut messages,
        "kernel_key",
        "H",
        hash_canonical(&body.kernel_key)?,
        false,
    );
    push_message(
        &mut messages,
        "metadata",
        "H",
        hash_canonical(&body.metadata)?,
        true,
    );
    push_message(
        &mut messages,
        "policy_hash",
        "Hx",
        decode_hx_field("policy_hash", &body.policy_hash)?,
        false,
    );
    push_message(
        &mut messages,
        "tenant_id",
        "Opt<S>",
        opt_string_bytes(&body.tenant_id),
        false,
    );
    push_message(
        &mut messages,
        "timestamp",
        "U64",
        u64_le(body.timestamp),
        false,
    );
    push_message(
        &mut messages,
        "tool_name",
        "S",
        body.tool_name.as_bytes().to_vec(),
        false,
    );
    push_message(
        &mut messages,
        "tool_server",
        "S",
        body.tool_server.as_bytes().to_vec(),
        false,
    );
    push_message(
        &mut messages,
        "trust_level",
        "S",
        trust_level_bytes(body.trust_level),
        false,
    );
    Ok(Projection {
        version: PROJECTION_VERSION_RECEIPT_V1.to_string(),
        subject_sha256_hex: subject_sha256_hex(body)?,
        messages,
    })
}

fn trust_level_bytes(trust_level: TrustLevel) -> Vec<u8> {
    trust_level.as_str().as_bytes().to_vec()
}

/// Project a workflow receipt body using the Chio workflow v1 BBS table.
pub fn project_workflow_receipt_body(
    body: &WorkflowReceiptBody,
) -> Result<Projection, SelectiveDisclosureError> {
    let mut messages = Vec::with_capacity(14);
    push_message(
        &mut messages,
        "agent_id",
        "S",
        body.agent_id.as_bytes().to_vec(),
        false,
    );
    push_message(
        &mut messages,
        "capability_id",
        "S",
        body.capability_id.as_bytes().to_vec(),
        false,
    );
    push_message(
        &mut messages,
        "completed_at",
        "U64",
        u64_le(body.completed_at),
        false,
    );
    push_message(
        &mut messages,
        "duration_ms",
        "U64",
        u64_le(body.duration_ms),
        false,
    );
    push_message(&mut messages, "id", "S", body.id.as_bytes().to_vec(), false);
    push_message(
        &mut messages,
        "kernel_key",
        "H",
        hash_canonical(&body.kernel_key)?,
        false,
    );
    push_message(
        &mut messages,
        "outcome",
        "H",
        hash_canonical(&body.outcome)?,
        true,
    );
    push_message(
        &mut messages,
        "schema",
        "S",
        body.schema.as_bytes().to_vec(),
        false,
    );
    push_message(
        &mut messages,
        "session_id",
        "Opt<S>",
        opt_string_bytes(&body.session_id),
        false,
    );
    push_message(
        &mut messages,
        "skill_id",
        "S",
        body.skill_id.as_bytes().to_vec(),
        false,
    );
    push_message(
        &mut messages,
        "skill_version",
        "S",
        body.skill_version.as_bytes().to_vec(),
        false,
    );
    push_message(
        &mut messages,
        "started_at",
        "U64",
        u64_le(body.started_at),
        false,
    );
    push_message(
        &mut messages,
        "steps",
        "H",
        hash_canonical(&body.steps)?,
        true,
    );
    push_message(
        &mut messages,
        "total_cost",
        "H",
        hash_canonical(&body.total_cost)?,
        true,
    );
    Ok(Projection {
        version: PROJECTION_VERSION_WORKFLOW_V1.to_string(),
        subject_sha256_hex: subject_sha256_hex(body)?,
        messages,
    })
}

/// Project an individual step, including its parent workflow id as context.
pub fn project_step_record(
    workflow_id: &str,
    step: &StepRecord,
) -> Result<Projection, SelectiveDisclosureError> {
    let mut messages = Vec::with_capacity(10);
    push_message(
        &mut messages,
        "allowed",
        "Bool",
        bool_byte(step.allowed),
        false,
    );
    push_message(
        &mut messages,
        "cost",
        "H",
        hash_canonical(&step.cost)?,
        true,
    );
    push_message(
        &mut messages,
        "duration_ms",
        "U64",
        u64_le(step.duration_ms),
        false,
    );
    push_message(
        &mut messages,
        "outcome",
        "H",
        hash_canonical(&step.outcome)?,
        false,
    );
    push_message(
        &mut messages,
        "output_hash",
        "Opt<S>",
        opt_string_bytes(&step.output_hash),
        false,
    );
    push_message(
        &mut messages,
        "server_id",
        "S",
        step.server_id.as_bytes().to_vec(),
        false,
    );
    push_message(
        &mut messages,
        "step_index",
        "U64",
        u64_le(step.step_index as u64),
        false,
    );
    push_message(
        &mut messages,
        "tool_name",
        "S",
        step.tool_name.as_bytes().to_vec(),
        false,
    );
    push_message(
        &mut messages,
        "tool_receipt_id",
        "Opt<S>",
        opt_string_bytes(&step.tool_receipt_id),
        false,
    );
    push_message(
        &mut messages,
        "workflow_id",
        "S",
        workflow_id.as_bytes().to_vec(),
        false,
    );
    Ok(Projection {
        version: PROJECTION_VERSION_STEP_V1.to_string(),
        subject_sha256_hex: sha256_hex_bytes(&canonical_bytes(&(workflow_id, step))?),
        messages,
    })
}

#[cfg(feature = "bbs")]
fn ensure_supported_projection_version(version: &str) -> Result<(), SelectiveDisclosureError> {
    match version {
        PROJECTION_VERSION_RECEIPT_V1
        | PROJECTION_VERSION_WORKFLOW_V1
        | PROJECTION_VERSION_STEP_V1 => Ok(()),
        other => Err(SelectiveDisclosureError::ProjectionVersionMismatch(
            other.to_string(),
        )),
    }
}

#[cfg(feature = "bbs")]
fn validate_disclosure_set(
    disclosure: &DisclosureSet,
    message_count: usize,
) -> Result<BTreeSet<u16>, SelectiveDisclosureError> {
    let mut seen = BTreeSet::new();
    for index in &disclosure.0 {
        if usize::from(*index) >= message_count {
            return Err(SelectiveDisclosureError::DisclosureIndexOutOfRange(*index));
        }
        if !seen.insert(*index) {
            return Err(SelectiveDisclosureError::DisclosureDuplicateIndex(*index));
        }
    }
    Ok(seen)
}

pub fn bbs_projection_manifest_from_projection(projection: &Projection) -> BbsProjectionManifest {
    BbsProjectionManifest {
        schema: BBS_PROJECTION_MANIFEST_SCHEMA_V2.to_string(),
        manifest_id: projection.version.clone(),
        artifact_ref: projection.subject_sha256_hex.clone(),
        canonicalization: "jcs".to_string(),
        hash_algorithm: "sha-256".to_string(),
        message_slots: projection
            .messages
            .iter()
            .map(|message| BbsProjectionMessageSlot {
                slot: message.index,
                field: message.field.clone(),
                message_class: projection_message_class(message).to_string(),
                sensitivity_class: projection_sensitivity_class(message).to_string(),
                encoding: message.encoding.clone(),
                disclosure: if message.wholesale_only
                    || exact_timing_direct_disclosure_field(&message.field)
                {
                    BbsProjectionDisclosure::Hidden
                } else {
                    BbsProjectionDisclosure::Disclosed
                },
                wholesale_only: message.wholesale_only
                    || exact_timing_direct_disclosure_field(&message.field),
                value_sha256: None,
            })
            .collect(),
        hidden_predicates: Vec::new(),
        issuer_key_ref: None,
        signature_ref: None,
    }
}

fn projection_message_class(message: &ProjectionMessage) -> &'static str {
    match message.field.as_str() {
        "action" => "governed_action",
        "agent_id" => "agent_identity",
        "allowed" => "decision_state",
        "capability_id" => "capability_identifier",
        "completed_at" | "started_at" | "timestamp" => "timing",
        "content_hash" | "policy_hash" => "content_integrity",
        "decision" | "outcome" => "decision_state",
        "duration_ms" | "total_cost" => "measurement",
        "evidence" | "metadata" | "steps" => "evidence_digest",
        "id" | "workflow_id" => "artifact_identity",
        "kernel_key" => "runtime_assurance",
        "schema" => "schema_identity",
        "session_id" | "tenant_id" => "tenant_context",
        "skill_id" | "skill_version" => "skill_identity",
        "tool_name" | "tool_server" => "tool_identity",
        "trust_level" => "trust_state",
        _ if message.wholesale_only => "wholesale_field",
        _ => "public_field",
    }
}

fn projection_sensitivity_class(message: &ProjectionMessage) -> &'static str {
    match message.field.as_str() {
        "capability_id" => "capability_identifier",
        "tenant_id" | "session_id" => "tenant_context",
        "tool_name" | "tool_server" => "tool_identity",
        "completed_at" | "duration_ms" | "started_at" | "timestamp" => "timing",
        "kernel_key" | "trust_level" => "runtime_assurance",
        _ if message.wholesale_only => "wholesale_only",
        _ => "public",
    }
}

fn exact_timing_direct_disclosure_field(field: &str) -> bool {
    field == "duration_ms"
}

pub fn verify_bbs_projection_manifest(
    proof: &SelectiveDisclosureProof,
    manifest: &BbsProjectionManifest,
) -> Result<(), SelectiveDisclosureError> {
    if manifest.schema != BBS_PROJECTION_MANIFEST_SCHEMA_V2 {
        return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
            format!("schema expected {BBS_PROJECTION_MANIFEST_SCHEMA_V2}"),
        ));
    }
    if manifest.manifest_id != proof.projection_version {
        return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
            "manifest id does not match proof projection version".to_string(),
        ));
    }
    if manifest.artifact_ref != proof.subject_sha256_hex {
        return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
            "artifact ref does not match proof subject".to_string(),
        ));
    }
    if manifest.canonicalization != "jcs" {
        return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
            "canonicalization must be jcs".to_string(),
        ));
    }
    if manifest.hash_algorithm != "sha-256" {
        return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
            "hash algorithm must be sha-256".to_string(),
        ));
    }
    if manifest.message_slots.len() != proof.message_count {
        return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
            "message slot count does not match proof message count".to_string(),
        ));
    }
    let mut seen_slots = Vec::with_capacity(manifest.message_slots.len());
    for slot in &manifest.message_slots {
        if usize::from(slot.slot) >= proof.message_count {
            return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
                format!("slot {} is outside proof message count", slot.slot),
            ));
        }
        if seen_slots.contains(&slot.slot) {
            return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
                format!("duplicate slot {}", slot.slot),
            ));
        }
        seen_slots.push(slot.slot);
        if slot.field.trim().is_empty()
            || slot.message_class.trim().is_empty()
            || slot.sensitivity_class.trim().is_empty()
            || slot.encoding.trim().is_empty()
        {
            return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
                "message slot field, class, sensitivity, and encoding must not be empty"
                    .to_string(),
            ));
        }
        if exact_timing_direct_disclosure_field(&slot.field)
            && slot.disclosure == BbsProjectionDisclosure::Disclosed
        {
            return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
                format!(
                    "exact timing field {} cannot be directly disclosed",
                    slot.field
                ),
            ));
        }
    }

    let mut seen_predicates = Vec::with_capacity(manifest.hidden_predicates.len());
    for predicate in &manifest.hidden_predicates {
        if predicate.predicate_id.trim().is_empty()
            || predicate.field.trim().is_empty()
            || predicate.operator.trim().is_empty()
        {
            return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
                "hidden predicate id, field, and operator must not be empty".to_string(),
            ));
        }
        if seen_predicates.contains(&predicate.predicate_id) {
            return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
                format!("duplicate hidden predicate {}", predicate.predicate_id),
            ));
        }
        seen_predicates.push(predicate.predicate_id.clone());
    }

    for disclosed in &proof.disclosed {
        let slot = projection_manifest_slot(manifest, disclosed.index)?;
        if slot.wholesale_only {
            return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
                "wholesale-only slot disclosed".to_string(),
            ));
        }
        if slot.disclosure != BbsProjectionDisclosure::Disclosed {
            return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
                format!("slot {} is not marked disclosed", disclosed.index),
            ));
        }
        if slot.field != disclosed.field {
            return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
                format!("slot {} field does not match proof", disclosed.index),
            ));
        }
        if slot.encoding != disclosed.encoding {
            return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
                format!("slot {} encoding does not match proof", disclosed.index),
            ));
        }
    }
    for slot in manifest
        .message_slots
        .iter()
        .filter(|slot| slot.disclosure == BbsProjectionDisclosure::Disclosed)
    {
        if !proof
            .disclosed
            .iter()
            .any(|disclosed| disclosed.index == slot.slot)
        {
            return Err(SelectiveDisclosureError::ProjectionManifestInvalid(
                format!(
                    "slot {} is marked disclosed but missing from proof",
                    slot.slot
                ),
            ));
        }
    }
    Ok(())
}

pub fn verify_transparency_inclusion_proof(
    proof: &SelectiveDisclosureProof,
    inclusion: &TransparencyInclusionProof,
) -> Result<(), SelectiveDisclosureError> {
    if inclusion.schema != TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V1 {
        return Err(SelectiveDisclosureError::TransparencyInclusionInvalid(
            format!("schema expected {TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V1}"),
        ));
    }
    for (field, value) in [
        ("proof_id", inclusion.proof_id.as_str()),
        ("log_id", inclusion.log_id.as_str()),
        ("checkpoint", inclusion.checkpoint.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(SelectiveDisclosureError::TransparencyInclusionInvalid(
                format!("{field} must not be empty"),
            ));
        }
    }
    if inclusion.verified_at == 0 {
        return Err(SelectiveDisclosureError::TransparencyInclusionInvalid(
            "verified_at must be greater than zero".to_string(),
        ));
    }
    if inclusion.artifact_ref != proof.subject_sha256_hex {
        return Err(SelectiveDisclosureError::TransparencyInclusionInvalid(
            "artifact ref mismatch".to_string(),
        ));
    }
    let expected_leaf = sha256_hex_bytes(proof.subject_sha256_hex.as_bytes());
    if inclusion.leaf_hash != expected_leaf {
        return Err(SelectiveDisclosureError::TransparencyInclusionInvalid(
            "leaf hash mismatch".to_string(),
        ));
    }
    if inclusion.tree_size == 0 {
        return Err(SelectiveDisclosureError::TransparencyInclusionInvalid(
            "tree size must be greater than zero".to_string(),
        ));
    }
    if inclusion.leaf_index >= inclusion.tree_size {
        return Err(SelectiveDisclosureError::TransparencyInclusionInvalid(
            "leaf index outside tree size".to_string(),
        ));
    }

    let mut current = decode_hx_field("leaf_hash", &inclusion.leaf_hash)?;
    let mut index = inclusion.leaf_index;
    let mut width = inclusion.tree_size;
    for (level, sibling_hex) in inclusion.inclusion_path.iter().enumerate() {
        if width <= 1 {
            return Err(SelectiveDisclosureError::TransparencyInclusionInvalid(
                "inclusion path exceeds tree height".to_string(),
            ));
        }
        let sibling = decode_hx_field(&format!("inclusion_path[{level}]"), sibling_hex)?;
        current = merkle_parent_hash(index, &current, &sibling);
        index /= 2;
        width = width.div_ceil(2);
    }
    if index != 0 || width != 1 {
        return Err(SelectiveDisclosureError::TransparencyInclusionInvalid(
            "inclusion path did not reach the root".to_string(),
        ));
    }
    if hex::encode(&current) != inclusion.root_hash {
        return Err(SelectiveDisclosureError::TransparencyInclusionInvalid(
            "root mismatch".to_string(),
        ));
    }
    Ok(())
}

fn merkle_parent_hash(index: u64, current: &[u8], sibling: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    if index.is_multiple_of(2) {
        hasher.update(current);
        hasher.update(sibling);
    } else {
        hasher.update(sibling);
        hasher.update(current);
    }
    hasher.finalize().to_vec()
}

fn projection_manifest_slot(
    manifest: &BbsProjectionManifest,
    index: u16,
) -> Result<&BbsProjectionMessageSlot, SelectiveDisclosureError> {
    manifest
        .message_slots
        .iter()
        .find(|slot| slot.slot == index)
        .ok_or_else(|| {
            SelectiveDisclosureError::ProjectionManifestInvalid(format!("missing slot {index}"))
        })
}

#[cfg(feature = "bbs")]
fn message_count_from_bbs_sha256_proof(
    proof_bytes: &[u8],
    disclosed_count: usize,
) -> Result<usize, SelectiveDisclosureError> {
    if proof_bytes.len() < BBS_SHA256_PROOF_FIXED_BYTES {
        return Err(SelectiveDisclosureError::ProofVerificationFailed);
    }
    let undisclosed_bytes = proof_bytes.len() - BBS_SHA256_PROOF_FIXED_BYTES;
    if !undisclosed_bytes.is_multiple_of(BBS_SHA256_SCALAR_BYTES) {
        return Err(SelectiveDisclosureError::ProofVerificationFailed);
    }
    Ok(disclosed_count + (undisclosed_bytes / BBS_SHA256_SCALAR_BYTES))
}

#[cfg(feature = "bbs")]
fn disclosed_messages(
    projection: &Projection,
    disclosure: &DisclosureSet,
) -> Result<Vec<DisclosedMessage>, SelectiveDisclosureError> {
    let set = validate_disclosure_set(disclosure, projection.messages.len())?;
    Ok(projection
        .messages
        .iter()
        .filter(|message| set.contains(&message.index))
        .map(|message| DisclosedMessage {
            index: message.index,
            field: message.field.clone(),
            encoding: message.encoding.clone(),
            bytes_hex: message.bytes_hex.clone(),
        })
        .collect())
}

#[cfg(feature = "bbs")]
fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(feature = "bbs")]
fn bbs_message_bytes(message: &ProjectionMessage) -> Result<Vec<u8>, SelectiveDisclosureError> {
    let raw = decode_message_hex(&message.field, &message.bytes_hex)?;
    let mut out = Vec::new();
    out.extend_from_slice(MESSAGE_DOMAIN_V1);
    out.extend_from_slice(&message.index.to_le_bytes());
    append_len_prefixed(&mut out, message.field.as_bytes());
    append_len_prefixed(&mut out, message.encoding.as_bytes());
    append_len_prefixed(&mut out, &raw);
    Ok(out)
}

#[cfg(feature = "bbs")]
fn bbs_messages(projection: &Projection) -> Result<Vec<Vec<u8>>, SelectiveDisclosureError> {
    projection.messages.iter().map(bbs_message_bytes).collect()
}

#[cfg(feature = "bbs")]
fn bbs_disclosed_messages(
    disclosed: &[DisclosedMessage],
) -> Result<Vec<Vec<u8>>, SelectiveDisclosureError> {
    disclosed
        .iter()
        .map(|message| {
            bbs_message_bytes(&ProjectionMessage {
                index: message.index,
                field: message.field.clone(),
                encoding: message.encoding.clone(),
                bytes_hex: message.bytes_hex.clone(),
                wholesale_only: false,
            })
        })
        .collect()
}

#[cfg(feature = "bbs")]
fn proof_header(
    projection_version: &str,
    subject_sha256_hex: &str,
    issuer_fingerprint: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(HEADER_DOMAIN_V1);
    append_len_prefixed(&mut out, projection_version.as_bytes());
    append_len_prefixed(&mut out, subject_sha256_hex.as_bytes());
    append_len_prefixed(&mut out, issuer_fingerprint.as_bytes());
    append_len_prefixed(&mut out, BBS_CIPHERSUITE_SHA256.as_bytes());
    out
}

#[cfg(feature = "bbs")]
fn crypto_err(error: affinidi_bbs::BbsError) -> SelectiveDisclosureError {
    SelectiveDisclosureError::Crypto(error.to_string())
}

#[cfg(feature = "bbs")]
fn decode_fixed<const N: usize>(hex_value: &str) -> Result<[u8; N], SelectiveDisclosureError> {
    let bytes = hex::decode(hex_value).map_err(|e| SelectiveDisclosureError::Hex(e.to_string()))?;
    if bytes.len() != N {
        return Err(SelectiveDisclosureError::Hex(format!(
            "expected {N} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0_u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Generate a deterministic BBS issuer keypair for fixtures.
#[cfg(feature = "bbs")]
pub fn generate_bbs_keypair(
    key_material: &[u8],
    key_info: &[u8],
) -> Result<BbsKeyPair, SelectiveDisclosureError> {
    if key_material.len() < 32 {
        return Err(SelectiveDisclosureError::KeySeedTooShort);
    }
    let secret = affinidi_bbs::keygen(key_material, key_info).map_err(crypto_err)?;
    let public = affinidi_bbs::sk_to_pk(&secret);
    let public_key = public.to_bytes();
    Ok(BbsKeyPair {
        issuer_fingerprint: sha256_hex_bytes(&public_key),
        public_key_hex: hex::encode(public_key),
        secret_key_hex: hex::encode(secret.to_bytes()),
    })
}

#[cfg(feature = "bbs")]
fn secret_key(keypair: &BbsKeyPair) -> Result<affinidi_bbs::SecretKey, SelectiveDisclosureError> {
    let bytes = decode_fixed::<32>(&keypair.secret_key_hex)?;
    affinidi_bbs::SecretKey::from_bytes(&bytes).map_err(crypto_err)
}

#[cfg(feature = "bbs")]
fn public_key(hex_value: &str) -> Result<affinidi_bbs::PublicKey, SelectiveDisclosureError> {
    let bytes = decode_fixed::<96>(hex_value)?;
    affinidi_bbs::PublicKey::from_bytes(&bytes).map_err(crypto_err)
}

#[cfg(feature = "bbs")]
fn signature(hex_value: &str) -> Result<affinidi_bbs::Signature, SelectiveDisclosureError> {
    let bytes = hex::decode(hex_value).map_err(|e| SelectiveDisclosureError::Hex(e.to_string()))?;
    affinidi_bbs::Signature::from_bytes(&bytes).map_err(crypto_err)
}

/// Sign a full projected message vector with BBS.
#[cfg(feature = "bbs")]
pub fn sign_projection(
    projection: &Projection,
    keypair: &BbsKeyPair,
) -> Result<SignedProjection, SelectiveDisclosureError> {
    ensure_supported_projection_version(&projection.version)?;
    let secret = secret_key(keypair)?;
    let public = public_key(&keypair.public_key_hex)?;
    let messages = bbs_messages(projection)?;
    let refs = messages.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let header = proof_header(
        &projection.version,
        &projection.subject_sha256_hex,
        &keypair.issuer_fingerprint,
    );
    let sig = affinidi_bbs::sign(&secret, &public, &header, &refs).map_err(crypto_err)?;
    Ok(SignedProjection {
        schema: SIGNED_PROJECTION_SCHEMA_V1.to_string(),
        projection_version: projection.version.clone(),
        subject_sha256_hex: projection.subject_sha256_hex.clone(),
        ciphersuite: BBS_CIPHERSUITE_SHA256.to_string(),
        issuer_fingerprint: keypair.issuer_fingerprint.clone(),
        issuer_public_key_hex: keypair.public_key_hex.clone(),
        message_count: projection.messages.len(),
        signature_hex: hex::encode(sig.to_bytes()),
    })
}

#[cfg(feature = "bbs")]
fn signed_matches_projection(signed: &SignedProjection, projection: &Projection) -> bool {
    signed.schema == SIGNED_PROJECTION_SCHEMA_V1
        && signed.projection_version == projection.version
        && signed.subject_sha256_hex == projection.subject_sha256_hex
        && signed.ciphersuite == BBS_CIPHERSUITE_SHA256
        && signed.message_count == projection.messages.len()
}

/// Verify a full BBS signature over a projection.
#[cfg(feature = "bbs")]
pub fn verify_signed_projection(
    signed: &SignedProjection,
    projection: &Projection,
) -> Result<bool, SelectiveDisclosureError> {
    if !signed_matches_projection(signed, projection) {
        return Err(SelectiveDisclosureError::SignedProjectionMismatch);
    }
    let public = public_key(&signed.issuer_public_key_hex)?;
    let sig = signature(&signed.signature_hex)?;
    let messages = bbs_messages(projection)?;
    let refs = messages.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let header = proof_header(
        &signed.projection_version,
        &signed.subject_sha256_hex,
        &signed.issuer_fingerprint,
    );
    affinidi_bbs::verify(&public, &sig, &header, &refs)
        .map_err(crypto_err)
        .map_err(|_| SelectiveDisclosureError::SignatureVerificationFailed)
}

/// Convert a full signed projection into receipt-bound BBS material.
#[cfg(feature = "bbs")]
#[must_use]
pub fn receipt_bbs_signature_from_signed_projection(
    signed: &SignedProjection,
) -> BbsReceiptSignature {
    BbsReceiptSignature {
        schema: CHIO_RECEIPT_BBS_SIGNATURE_SCHEMA.to_string(),
        projection_version: signed.projection_version.clone(),
        algorithm: CHIO_RECEIPT_BBS_SIGNATURE_ALGORITHM.to_string(),
        ciphersuite: signed.ciphersuite.clone(),
        issuer_fingerprint: signed.issuer_fingerprint.clone(),
        issuer_public_key_hex: signed.issuer_public_key_hex.clone(),
        message_count: signed.message_count,
        signature_hex: signed.signature_hex.clone(),
    }
}

/// Sign a receipt body with Ed25519 and embed BBS material over its final
/// projected receipt body.
///
/// WYSIWYS: the `handle` is a one-time [`ReceiptSigningHandle`] bound to the
/// exact canonical content the producer evaluated. The signer recomputes
/// `content_hash` over that content and refuses to sign (fail-closed) when the
/// body's claimed `content_hash` differs, exactly like the classical
/// ([`ChioReceipt::sign_with_handle`]) and backend
/// ([`ChioReceipt::sign_with_backend_using_handle`]) signers. This closes the
/// render-A / sign-B forgery at the BBS / selective-disclosure boundary: a
/// body claiming the hash of content `B` while the producer rendered content
/// `A` is rejected before any BBS material is produced.
///
/// `prepare_receipt_body_for_signing` does not mutate `content_hash`, so the
/// gate is checked against the prepared body's `content_hash` and is equivalent
/// to checking the caller's input.
///
/// # Errors
///
/// Returns [`SelectiveDisclosureError::ContentHashMismatch`] when the body's
/// `content_hash` does not equal the hash recomputed over the handle's bound
/// canonical content; otherwise propagates preparation, projection, BBS, and
/// Ed25519 signing errors.
#[cfg(feature = "bbs")]
pub fn sign_chio_receipt_with_bbs(
    mut body: ChioReceiptBody,
    receipt_keypair: &chio_core_types::crypto::Keypair,
    bbs_keypair: &BbsKeyPair,
    handle: ReceiptSigningHandle,
) -> Result<ChioReceipt, SelectiveDisclosureError> {
    body.bbs_projection_version = Some(PROJECTION_VERSION_RECEIPT_V1.to_string());
    let prepared = prepare_receipt_body_for_signing(body)
        .map_err(|error| SelectiveDisclosureError::CanonicalJson(error.to_string()))?;
    // Recompute-and-refuse BEFORE producing any BBS material so a render-A /
    // sign-B body can never yield a BBS signature.
    handle
        .ensure_body_matches(&prepared)
        .map_err(|mismatch: ContentHashMismatch| {
            SelectiveDisclosureError::ContentHashMismatch(mismatch.message())
        })?;
    let projection = project_receipt_body(&prepared)?;
    let signed = sign_projection(&projection, bbs_keypair)?;
    let bbs_signature = receipt_bbs_signature_from_signed_projection(&signed);
    ChioReceipt::sign_prepared_with_bbs_using_handle(
        prepared,
        receipt_keypair,
        bbs_signature,
        handle,
    )
    .map_err(|error| SelectiveDisclosureError::CanonicalJson(error.to_string()))
}

/// Reconstruct the full signed projection carrier from a receipt-bound BBS
/// signature.
#[cfg(feature = "bbs")]
pub fn receipt_signed_projection(
    receipt: &ChioReceipt,
) -> Result<SignedProjection, SelectiveDisclosureError> {
    let signature_valid = receipt
        .verify_signature()
        .map_err(|error| SelectiveDisclosureError::CanonicalJson(error.to_string()))?;
    if !signature_valid {
        return Err(SelectiveDisclosureError::ReceiptSignatureInvalid);
    }
    let Some(bbs_signature) = receipt.bbs_signature.as_ref() else {
        return Err(SelectiveDisclosureError::ReceiptBbsSignatureMissing);
    };
    let body = receipt.body();
    let version = body.bbs_projection_version.as_deref().ok_or_else(|| {
        SelectiveDisclosureError::ReceiptBbsBindingInvalid(
            "receipt body is missing bbs_projection_version".to_string(),
        )
    })?;
    if version != bbs_signature.projection_version {
        return Err(SelectiveDisclosureError::ReceiptBbsBindingInvalid(
            "receipt BBS projection version mismatch".to_string(),
        ));
    }
    ensure_supported_projection_version(version)?;
    let projection = project_receipt_body(&body)?;
    if bbs_signature.message_count != projection.messages.len() {
        return Err(SelectiveDisclosureError::SignedProjectionMismatch);
    }
    Ok(SignedProjection {
        schema: SIGNED_PROJECTION_SCHEMA_V1.to_string(),
        projection_version: bbs_signature.projection_version.clone(),
        subject_sha256_hex: projection.subject_sha256_hex,
        ciphersuite: bbs_signature.ciphersuite.clone(),
        issuer_fingerprint: bbs_signature.issuer_fingerprint.clone(),
        issuer_public_key_hex: bbs_signature.issuer_public_key_hex.clone(),
        message_count: bbs_signature.message_count,
        signature_hex: bbs_signature.signature_hex.clone(),
    })
}

/// Derive a selective disclosure proof from a signed projection.
#[cfg(feature = "bbs")]
pub fn derive_selective_disclosure_proof(
    signed: &SignedProjection,
    projection: &Projection,
    keypair: &BbsKeyPair,
    disclosure: &DisclosureSet,
    nonce: &[u8],
) -> Result<SelectiveDisclosureProof, SelectiveDisclosureError> {
    if !signed_matches_projection(signed, projection) {
        return Err(SelectiveDisclosureError::SignedProjectionMismatch);
    }
    if !verify_signed_projection(signed, projection)? {
        return Err(SelectiveDisclosureError::SignatureVerificationFailed);
    }
    if signed.issuer_fingerprint != keypair.issuer_fingerprint
        || signed.issuer_public_key_hex != keypair.public_key_hex
    {
        return Err(SelectiveDisclosureError::IssuerKeyMismatch);
    }
    let disclosure_set = validate_disclosure_set(disclosure, projection.messages.len())?;
    let public = public_key(&signed.issuer_public_key_hex)?;
    let sig = signature(&signed.signature_hex)?;
    let messages = bbs_messages(projection)?;
    let refs = messages.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let disclosed_indices = disclosure_set
        .iter()
        .copied()
        .map(usize::from)
        .collect::<Vec<_>>();
    let header = proof_header(
        &signed.projection_version,
        &signed.subject_sha256_hex,
        &signed.issuer_fingerprint,
    );
    let proof = affinidi_bbs::proof_gen(&public, &sig, &header, nonce, &refs, &disclosed_indices)
        .map_err(crypto_err)?;
    Ok(SelectiveDisclosureProof {
        schema: SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1.to_string(),
        projection_version: signed.projection_version.clone(),
        subject_sha256_hex: signed.subject_sha256_hex.clone(),
        ciphersuite: signed.ciphersuite.clone(),
        issuer_fingerprint: signed.issuer_fingerprint.clone(),
        issuer_public_key_hex: signed.issuer_public_key_hex.clone(),
        message_count: signed.message_count,
        disclosed_indices: disclosure_set.iter().copied().collect(),
        disclosed: disclosed_messages(projection, disclosure)?,
        proof_nonce_hex: hex::encode(nonce),
        proof_bytes_hex: hex::encode(proof.to_bytes()),
    })
}

/// Derive a selective disclosure proof from BBS material embedded in a Chio
/// receipt.
#[cfg(feature = "bbs")]
pub fn derive_selective_disclosure_proof_from_receipt(
    receipt: &ChioReceipt,
    keypair: &BbsKeyPair,
    disclosure: &DisclosureSet,
    nonce: &[u8],
) -> Result<SelectiveDisclosureProof, SelectiveDisclosureError> {
    let signed = receipt_signed_projection(receipt)?;
    let projection = project_receipt_body(&receipt.body())?;
    derive_selective_disclosure_proof(&signed, &projection, keypair, disclosure, nonce)
}

/// Verify a selective disclosure proof against the issuer registry.
#[cfg(feature = "bbs")]
pub fn verify_selective_disclosure_proof(
    proof: &SelectiveDisclosureProof,
    registry: &InMemoryIssuerRegistry,
) -> Result<VerifiedDisclosure, SelectiveDisclosureError> {
    if proof.schema != SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1 {
        return Err(SelectiveDisclosureError::SchemaMismatch(
            proof.schema.clone(),
        ));
    }
    ensure_supported_projection_version(&proof.projection_version)?;
    if proof.ciphersuite != BBS_CIPHERSUITE_SHA256 {
        return Err(SelectiveDisclosureError::ProofVerificationFailed);
    }
    let Some(registered_key) = registry.public_key_hex(&proof.issuer_fingerprint) else {
        return Err(SelectiveDisclosureError::UnknownIssuer(
            proof.issuer_fingerprint.clone(),
        ));
    };
    if registered_key != proof.issuer_public_key_hex {
        return Err(SelectiveDisclosureError::IssuerKeyMismatch);
    }
    let raw_proof = hex::decode(&proof.proof_bytes_hex)
        .map_err(|e| SelectiveDisclosureError::Hex(e.to_string()))?;
    let implied_message_count =
        message_count_from_bbs_sha256_proof(&raw_proof, proof.disclosed_indices.len())?;
    if proof.message_count != implied_message_count {
        return Err(SelectiveDisclosureError::ProofVerificationFailed);
    }
    let disclosure = DisclosureSet(proof.disclosed_indices.clone());
    let disclosure_set = validate_disclosure_set(&disclosure, implied_message_count)?;
    if disclosure_set.len() != proof.disclosed.len() {
        return Err(SelectiveDisclosureError::ProofVerificationFailed);
    }
    if !proof
        .disclosed
        .iter()
        .zip(disclosure_set.iter())
        .all(|(message, expected_index)| message.index == *expected_index)
    {
        return Err(SelectiveDisclosureError::ProofVerificationFailed);
    }
    let public = public_key(&proof.issuer_public_key_hex)?;
    let bbs_proof = affinidi_bbs::Proof::from_bytes(&raw_proof);
    let nonce = hex::decode(&proof.proof_nonce_hex)
        .map_err(|e| SelectiveDisclosureError::Hex(e.to_string()))?;
    let disclosed_messages = bbs_disclosed_messages(&proof.disclosed)?;
    let refs = disclosed_messages
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let disclosed_indices = disclosure_set
        .iter()
        .copied()
        .map(usize::from)
        .collect::<Vec<_>>();
    let header = proof_header(
        &proof.projection_version,
        &proof.subject_sha256_hex,
        &proof.issuer_fingerprint,
    );
    let verified = affinidi_bbs::proof_verify(
        &public,
        &bbs_proof,
        &header,
        &nonce,
        &refs,
        &disclosed_indices,
    )
    .map_err(crypto_err)?;
    if !verified {
        return Err(SelectiveDisclosureError::ProofVerificationFailed);
    }
    Ok(VerifiedDisclosure {
        subject_sha256_hex: proof.subject_sha256_hex.clone(),
        issuer_fingerprint: proof.issuer_fingerprint.clone(),
        disclosed: proof.disclosed.clone(),
    })
}
