//! ## Why this module exists
//!
//! ## Stub status (HONEST)
//!
//! What this module DOES today (`bbs-stub` feature):
//!
//! 1. Implements the deterministic alphabetical-by-serde-field-name
//!    projection from `ChioReceiptBody` to a 14-message vector per
//!    spec §5.2.
//! 2. Encodes each message with the spec §5.2 shorthand (`S` UTF-8
//!    bytes, `Hx` hex-decoded SHA-256, `H` SHA-256 over canonical-JSON
//!    of a structured sub-body, `U64` little-endian, `Opt<S>` with
//!    `None` projected as `"\u{0000}"`).
//! 3. Emits a `BbsAuditView` that exposes a disclosed-message subset
//!    plus an opaque `proof_bytes` placeholder. The placeholder is a
//!    SHA-256 commitment to the *withheld* messages plus the disclosed
//!    indices; this is NOT a privacy-preserving cryptographic proof - a verifier with
//!    access to the full receipt body can reconstruct withheld
//!    messages and re-hash.
//! 4. `verify_audit_view` re-runs the projection against the pinned
//!    receipt, recomputes the commitment over the withheld messages,
//!    and asserts it matches `proof_bytes`. This delivers the auditor
//!    *workflow* (the auditor sees only disclosed fields plus a binding
//!    proof that ties them to a real receipt) without delivering
//!    zero-knowledge of the withheld content from a verifier that
//!    holds the full receipt.
//!
//! - Actual BLS12-381 BBS+ signing (no `bbs_plus` dep is pulled in).
//! - Predicate language v1 (`eq`, `cmp`, `member`) - those need real
//!   BBS+ commitments + Bulletproofs RangeStatements, not SHA-256.
//! - WorkflowReceipt projection (only `ChioReceiptBody` here, not
//!   `WorkflowReceiptBody` from chio-workflow).
//! - Issuer fingerprint binding to `chio-credentials` passport.
//! - Wholesale-vs-disclosable enforcement at projection time
//!   (wholesale-only fields are flagged in the message metadata but
//!   not refused at projection - that lives in the predicate layer
//!   per §5.6 and arrives with the predicate-language pass).
//!
//! ## Bounded-claim language (per selective-disclosure.md)
//!
//! ## Crate placement note

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::receipt::ChioReceiptBody;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema discriminator for the §5.2 receipt-body projection.
pub const PROJECTION_VERSION_RECEIPT_V1: &str = "chio.bbs-projection.receipt.v1";

pub const AUDIT_VIEW_SCHEMA_STUB: &str = "chio.federation-bbs-audit-view.v1.stub";

/// One message in the §5 projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BbsMessage {
    /// Position in the §5.2 alphabetical-by-serde-field-name table.
    pub index: u8,
    /// `serde` field name from `ChioReceiptBody` (alphabetised).
    pub field: String,
    /// Encoding tag from §5.2 (`S`, `Hx`, `H`, `U64`, `Opt<S>`).
    pub encoding: String,
    /// Encoded message bytes per §5.2. Hex-encoded for serde
    /// transport so the audit view round-trips through JSON cleanly.
    /// In a real BBS+ implementation these bytes feed `hash_to_scalar`.
    pub bytes_hex: String,
    /// True iff the §5.2 table marks this row as wholesale-only
    /// (i.e. predicates cannot reach inside the structured sub-body).
    pub wholesale_only: bool,
}

/// The set of message indices the auditor is allowed to learn.
/// Indices that are NOT in this set are withheld. Indices outside
/// `0..14` are rejected at projection time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DisclosureSet(pub Vec<u8>);

/// A disclosed message exposed to the auditor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosedMessage {
    pub index: u8,
    pub field: String,
    pub encoding: String,
    pub bytes_hex: String,
}

/// The auditor view: disclosed messages plus a SHA-256 commitment to
/// the withheld message vector. This is the §6-shape stand-in for the
/// real BBS+ proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BbsAuditView {
    /// `AUDIT_VIEW_SCHEMA_STUB` - note the `.stub` suffix.
    pub schema: String,
    /// `PROJECTION_VERSION_RECEIPT_V1` (the projection that produced
    /// the message vector).
    pub projection_version: String,
    /// `sha256(canonical_json(body))` of the receipt the projection
    /// was applied to. Verifiers pin this to verify the disclosure was
    /// produced from a real receipt.
    pub subject_receipt_sha256_hex: String,
    /// Disclosed messages (subset of the 14-message vector).
    pub disclosed: Vec<DisclosedMessage>,
    pub proof_bytes_hex: String,
}

/// Disclosed payload returned to the caller after `verify_audit_view`
/// accepts a view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosedFields {
    pub subject_receipt_sha256_hex: String,
    pub fields: Vec<DisclosedMessage>,
}

/// Errors surfaced by the selective-disclosure surface.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SelectiveDisclosureError {
    #[error("canonical JSON encoding failed: {0}")]
    CanonicalJson(String),
    #[error("disclosure set carries an out-of-range index {0} (valid: 0..14)")]
    DisclosureIndexOutOfRange(u8),
    #[error("disclosure set carries duplicate index {0}")]
    DisclosureDuplicateIndex(u8),
    #[error("audit view schema {0} does not match {AUDIT_VIEW_SCHEMA_STUB}")]
    SchemaMismatch(String),
    #[error("audit view projection_version {0} does not match {PROJECTION_VERSION_RECEIPT_V1}")]
    ProjectionVersionMismatch(String),
    #[error("audit view subject_receipt_sha256_hex does not match the pinned receipt body")]
    SubjectReceiptMismatch,
    #[error("audit view proof_bytes_hex does not bind to the projection of the pinned receipt")]
    ProofBindingFailed,
    #[error("audit view disclosed message at index {0} does not match the pinned projection")]
    DisclosedMessageMismatch(u8),
    /// An `Hx` field on the receipt body did not decode to the 32-byte
    /// SHA-256 the §5.2 projection requires. An earlier implementation
    /// silently re-hashed the malformed string, which labelled it `Hx`
    /// while feeding non-`Hx` bytes downstream. Fail closed instead.
    #[error("malformed Hx field {field}: {reason}")]
    MalformedHexField { field: String, reason: String },
    /// A disclosed message's `encoding` did not match the pinned
    /// projection's encoding for that index. Without this gate, the
    /// verifier accepts views that re-tag the same bytes (e.g. `utf-8`
    /// -> `hex`) and misleads downstream decoders.
    #[error("audit view disclosed message at index {0} carries an encoding that does not match the pinned projection")]
    DisclosedEncodingMismatch(u8),
}

// ---------------------------------------------------------------------------
// Projection (§5.2 alphabetical-by-serde-field-name table)
// ---------------------------------------------------------------------------

/// Decode an `Hx` field per spec §5.2: the input MUST be a hex string
/// that decodes to exactly 32 bytes (a SHA-256 digest). Malformed input
/// (non-hex, wrong length, empty) returns `MalformedHexField` so the
/// projection fails closed rather than silently re-hashing the raw
/// string under an `Hx` encoding label.
fn decode_hx_field(field: &str, raw: &str) -> Result<Vec<u8>, SelectiveDisclosureError> {
    if raw.is_empty() {
        return Err(SelectiveDisclosureError::MalformedHexField {
            field: field.to_string(),
            reason: "empty string is not a valid 32-byte SHA-256 hex digest".to_string(),
        });
    }
    let bytes = hex::decode(raw).map_err(|e| SelectiveDisclosureError::MalformedHexField {
        field: field.to_string(),
        reason: format!("not valid hex: {e}"),
    })?;
    if bytes.len() != 32 {
        return Err(SelectiveDisclosureError::MalformedHexField {
            field: field.to_string(),
            reason: format!(
                "decoded length {} bytes does not equal the required 32 bytes",
                bytes.len()
            ),
        });
    }
    Ok(bytes)
}

/// Hash a structured sub-body (canonical JSON) per `H` encoding (§5.2).
fn hash_canonical<T: Serialize>(value: &T) -> Result<[u8; 32], SelectiveDisclosureError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|e| SelectiveDisclosureError::CanonicalJson(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Ok(arr)
}

fn project_receipt_body(
    body: &ChioReceiptBody,
) -> Result<Vec<BbsMessage>, SelectiveDisclosureError> {
    // Per §5.2 (alphabetical-by-serde-field-name):
    // 0  action          H        wholesale-only
    // 1  capability_id   S        disclosable
    // 2  content_hash    Hx       disclosable
    // 3  decision        H        wholesale-only
    // 4  evidence        H        wholesale-only
    // 5  id              S        disclosable
    // 6  kernel_key      H        disclosable
    // 7  metadata        H        wholesale-only ("None" -> "null")
    // 8  policy_hash     Hx       disclosable
    // 9  tenant_id       Opt<S>   disclosable
    // 10 timestamp       U64      cmp-able
    // 11 tool_name       S        disclosable
    // 12 tool_server     S        disclosable
    // 13 trust_level     S(as_str) disclosable
    let mut out = Vec::with_capacity(14);

    // 0 action (H over canonical JSON of ToolCallAction)
    let action_h = hash_canonical(&body.action)?;
    out.push(BbsMessage {
        index: 0,
        field: "action".to_string(),
        encoding: "H".to_string(),
        bytes_hex: hex::encode(action_h),
        wholesale_only: true,
    });

    // 1 capability_id (S)
    out.push(BbsMessage {
        index: 1,
        field: "capability_id".to_string(),
        encoding: "S".to_string(),
        bytes_hex: hex::encode(body.capability_id.as_bytes()),
        wholesale_only: false,
    });

    // 2 content_hash (Hx - already a 32-byte hex string; we MUST decode
    // per spec §5.2 "hex-decoded 32-byte SHA-256". Reject malformed
    // input rather than silently re-hashing the raw string; the
    // previous fallback fed non-Hx bytes through under an `Hx` label.)
    let content_hash_bytes = decode_hx_field("content_hash", &body.content_hash)?;
    out.push(BbsMessage {
        index: 2,
        field: "content_hash".to_string(),
        encoding: "Hx".to_string(),
        bytes_hex: hex::encode(content_hash_bytes),
        wholesale_only: false,
    });

    // 3 decision (H)
    let decision_h = hash_canonical(&body.decision)?;
    out.push(BbsMessage {
        index: 3,
        field: "decision".to_string(),
        encoding: "H".to_string(),
        bytes_hex: hex::encode(decision_h),
        wholesale_only: true,
    });

    // 4 evidence (H over canonical JSON of the Vec<GuardEvidence>)
    let evidence_h = hash_canonical(&body.evidence)?;
    out.push(BbsMessage {
        index: 4,
        field: "evidence".to_string(),
        encoding: "H".to_string(),
        bytes_hex: hex::encode(evidence_h),
        wholesale_only: true,
    });

    // 5 id (S)
    out.push(BbsMessage {
        index: 5,
        field: "id".to_string(),
        encoding: "S".to_string(),
        bytes_hex: hex::encode(body.id.as_bytes()),
        wholesale_only: false,
    });

    // 6 kernel_key (H over canonical JSON of the PublicKey)
    let kernel_key_h = hash_canonical(&body.kernel_key)?;
    out.push(BbsMessage {
        index: 6,
        field: "kernel_key".to_string(),
        encoding: "H".to_string(),
        bytes_hex: hex::encode(kernel_key_h),
        wholesale_only: false,
    });

    // 7 metadata (H over canonical JSON; None -> "null" per §5.2)
    let metadata_h = match &body.metadata {
        Some(v) => hash_canonical(v)?,
        None => {
            let mut h = Sha256::new();
            h.update(b"null");
            let out = h.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&out);
            arr
        }
    };
    out.push(BbsMessage {
        index: 7,
        field: "metadata".to_string(),
        encoding: "H".to_string(),
        bytes_hex: hex::encode(metadata_h),
        wholesale_only: true,
    });

    // 8 policy_hash (Hx; same strict-decode rule as content_hash).
    let policy_hash_bytes = decode_hx_field("policy_hash", &body.policy_hash)?;
    out.push(BbsMessage {
        index: 8,
        field: "policy_hash".to_string(),
        encoding: "Hx".to_string(),
        bytes_hex: hex::encode(policy_hash_bytes),
        wholesale_only: false,
    });

    // 9 tenant_id (Opt<S>; None -> "\u{0000}" per §5.2)
    let tenant_bytes = match &body.tenant_id {
        Some(s) => s.as_bytes().to_vec(),
        None => "\u{0000}".as_bytes().to_vec(),
    };
    out.push(BbsMessage {
        index: 9,
        field: "tenant_id".to_string(),
        encoding: "Opt<S>".to_string(),
        bytes_hex: hex::encode(tenant_bytes),
        wholesale_only: false,
    });

    // 10 timestamp (U64 little-endian)
    out.push(BbsMessage {
        index: 10,
        field: "timestamp".to_string(),
        encoding: "U64".to_string(),
        bytes_hex: hex::encode(body.timestamp.to_le_bytes()),
        wholesale_only: false,
    });

    // 11 tool_name (S)
    out.push(BbsMessage {
        index: 11,
        field: "tool_name".to_string(),
        encoding: "S".to_string(),
        bytes_hex: hex::encode(body.tool_name.as_bytes()),
        wholesale_only: false,
    });

    // 12 tool_server (S)
    out.push(BbsMessage {
        index: 12,
        field: "tool_server".to_string(),
        encoding: "S".to_string(),
        bytes_hex: hex::encode(body.tool_server.as_bytes()),
        wholesale_only: false,
    });

    // 13 trust_level (S via as_str())
    out.push(BbsMessage {
        index: 13,
        field: "trust_level".to_string(),
        encoding: "S".to_string(),
        bytes_hex: hex::encode(body.trust_level.as_str().as_bytes()),
        wholesale_only: false,
    });

    Ok(out)
}

fn validate_disclosure_set(set: &DisclosureSet) -> Result<(), SelectiveDisclosureError> {
    let mut seen = [false; 14];
    for &idx in &set.0 {
        if idx >= 14 {
            return Err(SelectiveDisclosureError::DisclosureIndexOutOfRange(idx));
        }
        if seen[idx as usize] {
            return Err(SelectiveDisclosureError::DisclosureDuplicateIndex(idx));
        }
        seen[idx as usize] = true;
    }
    Ok(())
}

fn subject_receipt_sha256(body: &ChioReceiptBody) -> Result<[u8; 32], SelectiveDisclosureError> {
    hash_canonical(body)
}

/// Compute the stub-proof binding: SHA-256 over the canonical JSON of
/// `(sorted_disclosed_indices, withheld_messages_in_index_order,
/// disclosed_encodings_in_index_order)`. This anchors the disclosure
/// to the projection deterministically; a verifier with the pinned
/// receipt and the disclosure set recomputes the same hash and checks
/// equality.
///
/// The commitment also binds the per-disclosed-index `encoding`
/// string (`S`/`Hx`/`H`/`U64`/`Opt<S>`). A producer that keeps the
/// same disclosed `bytes_hex` but re-tags the encoding (e.g. `utf-8`
/// -> `hex`) would otherwise slip past the verifier and mislead
/// downstream decoders; binding the encoding shuts that gap.
fn proof_commitment(
    disclosure: &DisclosureSet,
    projection: &[BbsMessage],
) -> Result<[u8; 32], SelectiveDisclosureError> {
    let mut disclosed_indices: Vec<u8> = disclosure.0.clone();
    disclosed_indices.sort_unstable();
    let withheld: Vec<&BbsMessage> = projection
        .iter()
        .filter(|m| !disclosed_indices.contains(&m.index))
        .collect();
    // Canonicalise the disclosed encodings as `(index, encoding)`
    // pairs in disclosed-index order. The disclosed bytes themselves
    // are already covered by the auditor-side projection re-bind in
    // `verify_audit_view`, so the commitment only needs the encoding
    // tag and index to bind the encoding tampering vector.
    let disclosed_encodings: Vec<serde_json::Value> = disclosed_indices
        .iter()
        .map(|idx| {
            let enc = projection
                .iter()
                .find(|m| m.index == *idx)
                .map(|m| m.encoding.as_str())
                .unwrap_or("");
            serde_json::json!({
                "index": idx,
                "encoding": enc,
            })
        })
        .collect();
    let payload = serde_json::json!({
        "disclosed_indices": disclosed_indices,
        "withheld": withheld,
        "disclosed_encodings": disclosed_encodings,
    });
    let bytes = canonical_json_bytes(&payload)
        .map_err(|e| SelectiveDisclosureError::CanonicalJson(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Ok(arr)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Project a `ChioReceiptBody` and emit the auditor view exposing only
/// the messages indexed by `disclosure`.
///
/// The view is self-contained: an auditor that holds the receipt's
/// `subject_receipt_sha256` can verify the disclosure binds to a real
/// receipt without learning the withheld messages from this artifact.
///
/// `body` is the receipt body the disclosure is taken from; we accept
/// the body (not the signed `ChioReceipt`) so the projection runs over
/// the same canonical bytes the Ed25519 signature covers.
pub fn project_audit_view(
    body: &ChioReceiptBody,
    disclosure: &DisclosureSet,
) -> Result<BbsAuditView, SelectiveDisclosureError> {
    validate_disclosure_set(disclosure)?;
    let projection = project_receipt_body(body)?;
    let subject = subject_receipt_sha256(body)?;
    let proof = proof_commitment(disclosure, &projection)?;
    let mut disclosed_indices: Vec<u8> = disclosure.0.clone();
    disclosed_indices.sort_unstable();
    let disclosed: Vec<DisclosedMessage> = disclosed_indices
        .iter()
        .filter_map(|&idx| {
            projection
                .iter()
                .find(|m| m.index == idx)
                .map(|m| DisclosedMessage {
                    index: m.index,
                    field: m.field.clone(),
                    encoding: m.encoding.clone(),
                    bytes_hex: m.bytes_hex.clone(),
                })
        })
        .collect();
    Ok(BbsAuditView {
        schema: AUDIT_VIEW_SCHEMA_STUB.to_string(),
        projection_version: PROJECTION_VERSION_RECEIPT_V1.to_string(),
        subject_receipt_sha256_hex: hex::encode(subject),
        disclosed,
        proof_bytes_hex: hex::encode(proof),
    })
}

/// Verify an audit view against a pinned receipt body. Returns the
/// disclosed fields (as held by the auditor) iff the view's commitment
/// binds to the pinned receipt under the same disclosure set.
///
/// The pinned `body` is the verifier's locally-resolved receipt
/// (matching spec §9 step 2, `pinned_receipt` argument). Verifiers
/// that cannot resolve a pinned body MUST refuse to call this function
/// - there is no "proof-carrying-receipt" mode in v0.1.
pub fn verify_audit_view(
    view: &BbsAuditView,
    pinned: &ChioReceiptBody,
) -> Result<DisclosedFields, SelectiveDisclosureError> {
    if view.schema != AUDIT_VIEW_SCHEMA_STUB {
        return Err(SelectiveDisclosureError::SchemaMismatch(
            view.schema.clone(),
        ));
    }
    if view.projection_version != PROJECTION_VERSION_RECEIPT_V1 {
        return Err(SelectiveDisclosureError::ProjectionVersionMismatch(
            view.projection_version.clone(),
        ));
    }
    let pinned_subject_hex = hex::encode(subject_receipt_sha256(pinned)?);
    if view.subject_receipt_sha256_hex != pinned_subject_hex {
        return Err(SelectiveDisclosureError::SubjectReceiptMismatch);
    }
    // Re-run the projection against the pinned receipt and re-derive
    // the disclosure set from the disclosed indices on the view.
    let projection = project_receipt_body(pinned)?;
    let disclosed_indices: Vec<u8> = view.disclosed.iter().map(|m| m.index).collect();
    let disclosure = DisclosureSet(disclosed_indices);
    validate_disclosure_set(&disclosure)?;
    // For each disclosed message in the view, the bytes MUST match the
    // pinned projection. This is the "auditor sees what the projection
    // allows" check - a producer who tried to alter the disclosed
    // value without altering the receipt would be caught here.
    //
    // Encoding is also checked explicitly. The proof commitment binds
    // the encoding too (see `proof_commitment`), so a substituted
    // encoding will also flunk the binding check, but the typed
    // `DisclosedEncodingMismatch` makes the failure mode explicit for
    // auditors and conformance fixtures.
    for disclosed in &view.disclosed {
        let pinned_msg = projection
            .iter()
            .find(|m| m.index == disclosed.index)
            .ok_or(SelectiveDisclosureError::DisclosedMessageMismatch(
                disclosed.index,
            ))?;
        if pinned_msg.bytes_hex != disclosed.bytes_hex || pinned_msg.field != disclosed.field {
            return Err(SelectiveDisclosureError::DisclosedMessageMismatch(
                disclosed.index,
            ));
        }
        if pinned_msg.encoding != disclosed.encoding {
            return Err(SelectiveDisclosureError::DisclosedEncodingMismatch(
                disclosed.index,
            ));
        }
    }
    let recomputed = proof_commitment(&disclosure, &projection)?;
    if hex::encode(recomputed) != view.proof_bytes_hex {
        return Err(SelectiveDisclosureError::ProofBindingFailed);
    }
    Ok(DisclosedFields {
        subject_receipt_sha256_hex: view.subject_receipt_sha256_hex.clone(),
        fields: view.disclosed.clone(),
    })
}

// ---------------------------------------------------------------------------
// Inline tests (round-trip + tamper-detection only). End-to-end test
// lives in crates/chio-conformance/tests/c5_selective_disclosure_stub.rs
// behind the same `bbs-stub` feature.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core_types::crypto::{sha256_hex, Keypair};
    use chio_core_types::receipt::{ChioReceiptBody, Decision, ToolCallAction, TrustLevel};

    fn sample_body(kp: &Keypair) -> ChioReceiptBody {
        ChioReceiptBody {
            id: "rcpt-c5-test".to_string(),
            timestamp: 1_736_500_000,
            capability_id: "cap-c5-test".to_string(),
            tool_server: "srv-c5".to_string(),
            tool_name: "file_read".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"k":"v"})).unwrap(),
            decision: Decision::Allow,
            content_hash: sha256_hex(b"{}"),
            policy_hash: sha256_hex(b"policy"),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: Some("tenant-c5".to_string()),
            kernel_key: kp.public_key(),
        }
    }

    #[test]
    fn projection_emits_fourteen_messages_in_alphabetical_order() {
        let kp = Keypair::generate();
        let body = sample_body(&kp);
        let projection = project_receipt_body(&body).unwrap();
        assert_eq!(projection.len(), 14);
        let fields: Vec<&str> = projection.iter().map(|m| m.field.as_str()).collect();
        assert_eq!(
            fields,
            vec![
                "action",
                "capability_id",
                "content_hash",
                "decision",
                "evidence",
                "id",
                "kernel_key",
                "metadata",
                "policy_hash",
                "tenant_id",
                "timestamp",
                "tool_name",
                "tool_server",
                "trust_level",
            ]
        );
    }

    #[test]
    fn audit_view_round_trip_reveals_only_disclosed_fields() {
        let kp = Keypair::generate();
        let body = sample_body(&kp);
        // Disclose: capability_id (1), id (5), tool_name (11).
        let disclosure = DisclosureSet(vec![1, 5, 11]);
        let view = project_audit_view(&body, &disclosure).unwrap();
        assert_eq!(view.disclosed.len(), 3);
        let fields: Vec<&str> = view.disclosed.iter().map(|d| d.field.as_str()).collect();
        assert_eq!(fields, vec!["capability_id", "id", "tool_name"]);
        // Verify accepts under the pinned body.
        let disclosed = verify_audit_view(&view, &body).unwrap();
        assert_eq!(disclosed.fields.len(), 3);
    }

    #[test]
    fn audit_view_fails_when_pinned_receipt_diverges() {
        let kp = Keypair::generate();
        let body = sample_body(&kp);
        let view = project_audit_view(&body, &DisclosureSet(vec![5])).unwrap();
        let mut tampered = body.clone();
        tampered.id = "rcpt-c5-test-tamper".to_string();
        let result = verify_audit_view(&view, &tampered);
        assert!(matches!(
            result,
            Err(SelectiveDisclosureError::SubjectReceiptMismatch)
        ));
    }

    #[test]
    fn audit_view_rejects_out_of_range_disclosure() {
        let kp = Keypair::generate();
        let body = sample_body(&kp);
        let result = project_audit_view(&body, &DisclosureSet(vec![14]));
        assert!(matches!(
            result,
            Err(SelectiveDisclosureError::DisclosureIndexOutOfRange(14))
        ));
    }

    #[test]
    fn audit_view_rejects_duplicate_disclosure_index() {
        let kp = Keypair::generate();
        let body = sample_body(&kp);
        let result = project_audit_view(&body, &DisclosureSet(vec![5, 5]));
        assert!(matches!(
            result,
            Err(SelectiveDisclosureError::DisclosureDuplicateIndex(5))
        ));
    }

    #[test]
    fn audit_view_verify_rejects_duplicate_disclosed_index_with_matching_stub_proof() {
        let kp = Keypair::generate();
        let body = sample_body(&kp);
        let mut view = project_audit_view(&body, &DisclosureSet(vec![5])).unwrap();
        view.disclosed.push(view.disclosed[0].clone());
        let projection = project_receipt_body(&body).unwrap();
        let proof = proof_commitment(&DisclosureSet(vec![5, 5]), &projection).unwrap();
        view.proof_bytes_hex = hex::encode(proof);

        let result = verify_audit_view(&view, &body);

        assert!(matches!(
            result,
            Err(SelectiveDisclosureError::DisclosureDuplicateIndex(5))
        ));
    }

    #[test]
    fn audit_view_rejects_tampered_disclosed_field() {
        let kp = Keypair::generate();
        let body = sample_body(&kp);
        let mut view = project_audit_view(&body, &DisclosureSet(vec![1, 11])).unwrap();
        // Producer tries to substitute a different disclosed field
        // value while keeping the same subject_receipt_sha256_hex.
        // The verifier MUST catch this when re-projecting.
        view.disclosed[0].bytes_hex = hex::encode("forged-cap".as_bytes());
        let result = verify_audit_view(&view, &body);
        assert!(matches!(
            result,
            Err(SelectiveDisclosureError::DisclosedMessageMismatch(_))
        ));
    }

    // -----------------------------------------------------------------
    // Malformed Hx fields must fail closed
    // -----------------------------------------------------------------

    fn body_with_content_hash(kp: &Keypair, content_hash: &str) -> ChioReceiptBody {
        let mut b = sample_body(kp);
        b.content_hash = content_hash.to_string();
        b
    }

    fn body_with_policy_hash(kp: &Keypair, policy_hash: &str) -> ChioReceiptBody {
        let mut b = sample_body(kp);
        b.policy_hash = policy_hash.to_string();
        b
    }

    #[test]
    fn projection_rejects_invalid_hex_content_hash() {
        let kp = Keypair::generate();
        // "ZZ..." is the right length for 32 bytes of hex but is not
        // valid hex.
        let bad = "ZZ".repeat(32);
        let body = body_with_content_hash(&kp, &bad);
        let result = project_audit_view(&body, &DisclosureSet(vec![2]));
        match result {
            Err(SelectiveDisclosureError::MalformedHexField { field, reason }) => {
                assert_eq!(field, "content_hash");
                assert!(
                    reason.contains("not valid hex"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected MalformedHexField, got {other:?}"),
        }
    }

    #[test]
    fn projection_rejects_short_hex_content_hash() {
        let kp = Keypair::generate();
        // 16 bytes of hex (32 chars) - half the required SHA-256 length.
        let short = "ab".repeat(16);
        let body = body_with_content_hash(&kp, &short);
        let result = project_audit_view(&body, &DisclosureSet(vec![2]));
        match result {
            Err(SelectiveDisclosureError::MalformedHexField { field, reason }) => {
                assert_eq!(field, "content_hash");
                assert!(reason.contains("16 bytes"), "unexpected reason: {reason}");
            }
            other => panic!("expected MalformedHexField, got {other:?}"),
        }
    }

    #[test]
    fn projection_rejects_long_hex_content_hash() {
        let kp = Keypair::generate();
        // 64 bytes of hex - twice the required length.
        let long = "ab".repeat(64);
        let body = body_with_content_hash(&kp, &long);
        let result = project_audit_view(&body, &DisclosureSet(vec![2]));
        match result {
            Err(SelectiveDisclosureError::MalformedHexField { field, reason }) => {
                assert_eq!(field, "content_hash");
                assert!(reason.contains("64 bytes"), "unexpected reason: {reason}");
            }
            other => panic!("expected MalformedHexField, got {other:?}"),
        }
    }

    #[test]
    fn projection_rejects_empty_hex_content_hash() {
        let kp = Keypair::generate();
        let body = body_with_content_hash(&kp, "");
        let result = project_audit_view(&body, &DisclosureSet(vec![2]));
        match result {
            Err(SelectiveDisclosureError::MalformedHexField { field, reason }) => {
                assert_eq!(field, "content_hash");
                assert!(reason.contains("empty"), "unexpected reason: {reason}");
            }
            other => panic!("expected MalformedHexField, got {other:?}"),
        }
    }

    #[test]
    fn projection_rejects_malformed_policy_hash() {
        let kp = Keypair::generate();
        // 16 bytes of hex - half the required SHA-256 length.
        let short = "00".repeat(16);
        let body = body_with_policy_hash(&kp, &short);
        let result = project_audit_view(&body, &DisclosureSet(vec![8]));
        match result {
            Err(SelectiveDisclosureError::MalformedHexField { field, .. }) => {
                assert_eq!(field, "policy_hash");
            }
            other => panic!("expected MalformedHexField, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Encoding tampering must be rejected
    // -----------------------------------------------------------------

    #[test]
    fn audit_view_rejects_tampered_disclosed_encoding() {
        let kp = Keypair::generate();
        let body = sample_body(&kp);
        // Disclose capability_id (S) and tool_name (S).
        let mut view = project_audit_view(&body, &DisclosureSet(vec![1, 11])).unwrap();
        // Producer relabels capability_id's encoding from S (utf-8) to
        // Hx so that downstream decoders parse the bytes as a hex
        // digest instead of a UTF-8 string.
        view.disclosed[0].encoding = "Hx".to_string();
        let result = verify_audit_view(&view, &body);
        // Either the explicit encoding-mismatch gate or the proof
        // binding gate (which now also covers encoding) must reject.
        match result {
            Err(SelectiveDisclosureError::DisclosedEncodingMismatch(_)) => {}
            Err(SelectiveDisclosureError::ProofBindingFailed) => {}
            other => {
                panic!("expected DisclosedEncodingMismatch or ProofBindingFailed, got {other:?}")
            }
        }
    }
}
