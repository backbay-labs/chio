//! ## Why this module exists
//!
//! ## Wire format
//!
//! ```text
//! envelope = {
//!     "payloadType": "application/vnd.in-toto+json",
//!     "payload":     base64(canonical_json(in_toto_statement)),
//!     "signatures":  [
//!         { "keyid": sha256_hex(passport_pubkey_a), "sig": base64(sig_a) },
//!         { "keyid": sha256_hex(passport_pubkey_b), "sig": base64(sig_b) },
//!     ],
//! }
//! ```
//!
//! Each signature is Ed25519 over the PAE bytes:
//!
//! ```text
//! pae = "DSSEv1" SP LEN(payloadType) SP payloadType SP
//!                 LEN(statement_bytes) SP statement_bytes
//! ```
//!
//! where `statement_bytes` is the raw canonical-JSON of the in-toto Statement
//! (NOT the base64 of it: that goes on the wire, but the signed message is the
//! pre-base64 bytes). LEN values are decimal ASCII per the DSSE v1 spec.
//!
//! ## Scope boundary
//!
//! This module intentionally emits a DSSE signature-slice profile, not the
//! strict `CHIODOS_BILATERAL_COSIGN_INVOCATION` predicate. The strict
//! CHIODOS schema requires fields this API does not receive
//! (`tool_args_hash`, non-optional lease and policy summaries) and forbids
//! the local `receipt_canonical_json` helper field. Callers must not present
//! this artifact as a CHIODOS bilateral invocation envelope.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{Ed25519Backend, Keypair, PublicKey, Signature, SigningBackend};
use chio_core_types::receipt::ChioReceipt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bilateral::BilateralCoSigningError;

// ---------------------------------------------------------------------------
// Constants (DSSE signature-slice profile)
// ---------------------------------------------------------------------------

/// DSSE v1 payload type used by chiodos bilateral signature-slice envelopes.
///
/// The literal string is part of the PAE preimage: changing it changes the
/// signed bytes.
pub const PAYLOAD_TYPE_IN_TOTO: &str = "application/vnd.in-toto+json";

/// Predicate type for the in-toto Statement carried in the DSSE signature
/// slice. Deliberately distinct from the strict CHIODOS bilateral
/// invocation predicate.
pub const PREDICATE_TYPE_BILATERAL: &str = "chio.bilateral-signature-slice.v1";

/// In-toto Statement `_type` per the v1 attestation framework (DSSE doc).
pub const STATEMENT_TYPE_V1: &str = "https://in-toto.io/Statement/v1";

/// Schema discriminator carried by the chio-bilateral signature-slice
/// predicate body. It intentionally matches `predicateType` so the signed
/// artifact has a single verifier-facing profile identifier.
pub const PREDICATE_BODY_SCHEMA: &str = PREDICATE_TYPE_BILATERAL;

/// Fixed prefix tag of the DSSE Pre-Authentication Encoding (DSSE v1).
const PAE_PREFIX: &str = "DSSEv1";

/// Historical profile identifier for the Chio bilateral DSSE signature-slice.
///
/// Standard DSSE envelopes do not carry a top-level `schema` member. This
/// value is retained only for callers that need an out-of-band profile label;
/// emitters and verifiers must rely on `payloadType`, the in-toto Statement
/// `_type`, and `predicateType` on the signed payload.
pub const BILATERAL_DSSE_ENVELOPE_SCHEMA: &str = PREDICATE_TYPE_BILATERAL;

/// Canonical in-toto subject-name prefix for signed Chio receipt bodies.
pub const RECEIPT_SUBJECT_NAME_PREFIX: &str = "chio-receipt:";

pub const DEFAULT_CONSISTENCY_MODEL: &str = "crdt-commutative";

pub const DEFAULT_CROSS_ORG_VISIBILITY: &str = "federated";

pub const DEFAULT_COSIGN_MODE: &str = "bilateral_required";

pub const VALID_CROSS_ORG_VISIBILITY: &[&str] = &["private", "treaty_only", "federated", "public"];

// ---------------------------------------------------------------------------
// Public types (kept narrow; see module docs §"Bounded scope" for exclusions)
// ---------------------------------------------------------------------------

/// SHA-256 fingerprint of a kernel's passport public key (hex, lowercase),
/// used as the DSSE `keyid` and as the `tool_server_*`
/// `passport_key_fingerprint` in this signature-slice profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Keyid(pub String);

impl Keyid {
    /// Compute the DSSE keyid for the given public key.
    ///
    /// Hash the raw public-key bytes. Hashing the hex string instead
    /// would produce a different fingerprint than peers that follow
    /// the raw-key convention, causing cross-implementation envelopes
    /// to be rejected.
    #[must_use]
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        use chio_core_types::crypto::SigningAlgorithm;
        let mut hasher = Sha256::new();
        match public_key.algorithm() {
            SigningAlgorithm::Ed25519 => {
                hasher.update(public_key.as_bytes());
            }
            _ => {
                hasher.update(public_key.to_hex().as_bytes());
            }
        }
        Self(hex::encode(hasher.finalize()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// In-toto Statement `subject` entry: the receipt body that the bilateral
/// co-signature attests. The digest is the SHA-256 of the canonical-JSON
/// encoding of the receipt body, hex-lowercase per spec §7 step 7.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatementSubject {
    /// Identifier of the underlying receipt (e.g. `ChioReceipt::id`).
    pub name: String,
    /// `{"sha256": "<hex>"}` per spec.
    pub digest: SubjectDigest,
}

/// SHA-256 hash record. The wrapping struct exists for spec parity with
/// `subject[].digest = { "sha256": "..." }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectDigest {
    pub sha256: String,
}

/// Identity of one of the two kernels participating in the bilateral
/// invocation, per `kernelIdentity` defined in spec §5 lines 268-286.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct KernelIdentity {
    /// `did:chio` identifier of the participating kernel.
    pub kernel_id: String,
    /// SHA-256 of the kernel's passport public key (hex-lowercase).
    pub passport_key_fingerprint: Keyid,
    pub alg: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BilateralPredicate {
    /// Internal schema discriminator (`PREDICATE_BODY_SCHEMA`), matching
    /// `predicateType` on the parent Statement.
    pub schema: String,
    pub invocation_id: String,
    /// Origin kernel (Org A) identity.
    pub tool_server_a: KernelIdentity,
    /// Tool-host kernel (Org B) identity.
    pub tool_server_b: KernelIdentity,
    /// Tool name as exposed by both kernels.
    pub tool_name: String,
    pub co_sign: String,
    pub consistency_model: String,
    pub cross_org_visibility: String,
    /// Tool-server B's wall-clock timestamp at the moment the joint body
    /// was canonicalised (Unix milliseconds).
    pub timestamp_unix_ms: u64,
    /// Canonical-JSON of the underlying `ChioReceipt`. Carried in the
    /// predicate so verifiers without an independent receipt-resolver can
    /// re-hash and confirm subject membership without dereferencing an
    /// external pointer (mirroring the existing `CoSigningBody`
    /// `receipt_canonical_json` pattern).
    pub receipt_canonical_json: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_lease_ref: Option<CapabilityLeaseRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_evaluation_summary: Option<PolicyEvaluationSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_receipt_ref: Option<GovernanceReceiptRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_anchor: Option<String>,
}

/// Capability lease reference, per spec §5 (`capability_lease_ref`).
/// Carries the lease id, issuing kernel, and an absolute Unix-ms
/// expiry that the §7 step 14 verifier compares against the verifier's
/// pinned-epoch wall clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CapabilityLeaseRef {
    /// Globally-unique lease id. The verifier (step 14) MUST resolve
    /// this against a trusted lease registry; an unresolvable id
    /// fails-closed with `capability.lease_expired_or_unknown`.
    pub lease_id: String,
    /// `did:chio` identifier of the kernel that minted the lease. Step
    /// 14 verifies the resolved registry record's issuer matches.
    pub issuer: String,
    /// Absolute lease expiry in Unix milliseconds. Step 14 enforces
    /// `expires_at_unix_ms > pinned_epoch.now`; a non-strictly-greater
    /// value is rejected as expired.
    pub expires_at_unix_ms: u64,
    /// Optional SHA-256 of the canonical-JSON encoding of the
    /// capability scope (`{"alg":"sha256","value":"..."}`). When
    /// present the registry record's scope digest MUST match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_digest: Option<HashRecord>,
}

/// SHA-256 hash record (`{"alg":"sha256","value":"<hex>"}`) used by
/// `tool_args_hash`, `capability_lease_ref.scope_digest`, and
/// `governance_receipt_ref.digest` per spec §5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HashRecord {
    pub alg: String,
    /// Hex-lowercase 64-character SHA-256.
    pub value: String,
}

/// Single kernel's policy verdict, per spec §5 (`policyVerdict`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PolicyVerdict {
    /// `"allow"` or `"deny"`. Step 13 of the §7 verifier requires the
    /// two kernels' verdicts to be equal.
    pub verdict: String,
    /// Identifier of the policy that produced the verdict.
    pub policy_id: String,
    /// Version of the policy (e.g. `"v1.2.0"` or a content hash).
    pub policy_version: String,
    /// Optional rationale code (verifier-opaque; logged for receipt review).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale_code: Option<String>,
}

/// Joint policy evaluation summary covering both kernels, per spec
/// §5 (`policy_evaluation_summary`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PolicyEvaluationSummary {
    /// Org A (origin kernel) policy verdict.
    pub server_a_verdict: PolicyVerdict,
    /// Org B (tool-host kernel) policy verdict.
    pub server_b_verdict: PolicyVerdict,
    /// Joint disposition; spec §5 line 213 says it MUST equal `"allow"`
    /// only when both verdicts are `"allow"`. Optional on the wire so
    /// callers that haven't computed it can still emit a predicate;
    /// the §7 step 13 verifier still cross-checks the two
    /// `server_*_verdict` strings directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joint_disposition: Option<String>,
}

/// Governance receipt reference, per spec §5 (`governance_receipt_ref`).
/// REQUIRED when the action-class is declared `receipt-backed` in the
/// local ladder manifest (§7 step 15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct GovernanceReceiptRef {
    /// Globally-unique receipt id. The verifier (step 15) resolves
    /// this against a governance receipt store.
    pub receipt_id: String,
    /// `did:chio` identifier of the kernel that issued the receipt.
    pub kernel_id: String,
    /// SHA-256 of the canonical-JSON of the resolved receipt body.
    pub digest: HashRecord,
}

/// In-toto Statement carried inside the DSSE envelope's `payload` (after
/// canonical-JSON encoding and base64-wrapping).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DsseStatement {
    /// `_type` per in-toto v1: `"https://in-toto.io/Statement/v1"`.
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<StatementSubject>,
    /// `predicateType` distinguishing chio bilateral envelopes from other
    /// in-toto attestations.
    pub predicate_type: String,
    pub predicate: BilateralPredicate,
}

impl DsseStatement {
    /// Encode the Statement as canonical JSON bytes. These are the bytes
    /// the DSSE PAE wraps and the bytes that downstream verifiers SHA-256
    /// against the subject's digest.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BilateralCoSigningError> {
        canonical_json_bytes(self)
            .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))
    }
}

/// One signature inside a [`DsseEnvelope`] (`signatures[i]` per spec §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseSignature {
    /// SHA-256 fingerprint of the corresponding kernel's passport public
    /// key (hex-lowercase). MUST equal the `passport_key_fingerprint` of
    /// the matching `tool_server_*` in the predicate.
    pub keyid: String,
    /// Base64 (RFC 4648 standard alphabet) of the Ed25519 signature over
    /// the DSSE PAE bytes.
    pub sig: String,
}

/// DSSE v1 envelope carrying the bilateral signature-slice artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DsseEnvelope {
    pub payload_type: String,
    /// Base64 (standard alphabet) of canonical-JSON of [`DsseStatement`].
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

impl DsseEnvelope {
    /// Recompute the DSSE PAE bytes that the signatures cover. Useful for
    /// the negative conformance fixture (which compares this preimage
    /// byte-for-byte against the legacy `CoSigningBody` preimage).
    pub fn pae_bytes(&self) -> Result<Vec<u8>, BilateralCoSigningError> {
        let payload_bytes = BASE64_STANDARD
            .decode(self.payload.as_bytes())
            .map_err(|e| BilateralCoSigningError::CanonicalJson(format!("payload base64: {e}")))?;
        Ok(pae(&self.payload_type, &payload_bytes))
    }

    /// Decode the wrapped Statement back from its base64 payload. Returns
    /// the canonical-JSON bytes alongside the parsed Statement so callers
    /// can re-hash without re-canonicalising.
    pub fn decode_statement(&self) -> Result<(DsseStatement, Vec<u8>), BilateralCoSigningError> {
        let bytes = BASE64_STANDARD
            .decode(self.payload.as_bytes())
            .map_err(|e| BilateralCoSigningError::CanonicalJson(format!("payload base64: {e}")))?;
        let statement: DsseStatement = serde_json::from_slice(&bytes)
            .map_err(|e| BilateralCoSigningError::CanonicalJson(format!("payload json: {e}")))?;
        Ok((statement, bytes))
    }
}

// ---------------------------------------------------------------------------
// Pure encoding helpers
// ---------------------------------------------------------------------------

/// DSSE Pre-Authentication Encoding (DSSE v1 spec, secure-systems-lab/dsse).
///
/// The output bytes are what each kernel's Ed25519 signature covers per spec
/// §6 lines 338-343. The encoding is deterministic and does NOT include any
/// kernel-derived nonce: two kernels signing the same `(payload_type,
/// payload_bytes)` produce signatures over identical preimages.
///
/// Format: `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body` where SP is a
/// single ASCII space (0x20) and LEN values are decimal ASCII.
#[must_use]
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let type_len = payload_type.len().to_string();
    let payload_len = payload.len().to_string();
    let mut out = Vec::with_capacity(
        PAE_PREFIX.len()
            + 1
            + type_len.len()
            + 1
            + payload_type.len()
            + 1
            + payload_len.len()
            + 1
            + payload.len(),
    );
    out.extend_from_slice(PAE_PREFIX.as_bytes());
    out.push(b' ');
    out.extend_from_slice(type_len.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_len.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Canonical subject name for the signed Chio receipt body.
#[must_use]
pub fn receipt_subject_name(receipt_id: &str) -> String {
    format!("{RECEIPT_SUBJECT_NAME_PREFIX}{receipt_id}")
}

/// Build a `BilateralPredicate` from a receipt and the two participating
/// kernels' identities. Used by both the local sign path and the
/// in-process verifier under test.
pub fn build_predicate(
    receipt: &ChioReceipt,
    org_a: KernelIdentity,
    org_b: KernelIdentity,
    tool_name: &str,
    timestamp_unix_ms: u64,
) -> Result<BilateralPredicate, BilateralCoSigningError> {
    if receipt.tool_name != tool_name {
        return Err(BilateralCoSigningError::ReceiptMismatch);
    }
    let receipt_canonical = canonical_json_bytes(receipt)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    let receipt_canonical_json = String::from_utf8(receipt_canonical)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    Ok(BilateralPredicate {
        schema: PREDICATE_BODY_SCHEMA.to_string(),
        invocation_id: receipt.id.clone(),
        tool_server_a: org_a,
        tool_server_b: org_b,
        tool_name: tool_name.to_string(),
        co_sign: DEFAULT_COSIGN_MODE.to_string(),
        consistency_model: DEFAULT_CONSISTENCY_MODEL.to_string(),
        cross_org_visibility: DEFAULT_CROSS_ORG_VISIBILITY.to_string(),
        timestamp_unix_ms,
        receipt_canonical_json,
        capability_lease_ref: None,
        policy_evaluation_summary: None,
        governance_receipt_ref: None,
        consistency_anchor: None,
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BilateralPredicateExtensions {
    /// Spec §5 `capability_lease_ref`; required by §7 step 14.
    pub capability_lease_ref: Option<CapabilityLeaseRef>,
    /// Spec §5 `policy_evaluation_summary`; required by §7 step 13.
    pub policy_evaluation_summary: Option<PolicyEvaluationSummary>,
    /// Spec §5 `governance_receipt_ref`; required by §7 step 15 when
    /// the action-class is `receipt-backed`.
    pub governance_receipt_ref: Option<GovernanceReceiptRef>,
    /// Spec §5 `consistency_anchor`; required by §7 step 16 for
    /// non-`crdt-commutative` consistency models.
    pub consistency_anchor: Option<String>,
    /// Override `consistency_model`. None = `DEFAULT_CONSISTENCY_MODEL`
    /// (`crdt-commutative`).
    pub consistency_model: Option<String>,
    /// Override `cross_org_visibility`. None =
    /// `DEFAULT_CROSS_ORG_VISIBILITY` (`federated`).
    pub cross_org_visibility: Option<String>,
}

pub fn build_predicate_full(
    receipt: &ChioReceipt,
    org_a: KernelIdentity,
    org_b: KernelIdentity,
    tool_name: &str,
    timestamp_unix_ms: u64,
    extensions: BilateralPredicateExtensions,
) -> Result<BilateralPredicate, BilateralCoSigningError> {
    let mut predicate = build_predicate(receipt, org_a, org_b, tool_name, timestamp_unix_ms)?;
    if let Some(model) = extensions.consistency_model {
        predicate.consistency_model = model;
    }
    if let Some(vis) = extensions.cross_org_visibility {
        predicate.cross_org_visibility = vis;
    }
    predicate.capability_lease_ref = extensions.capability_lease_ref;
    predicate.policy_evaluation_summary = extensions.policy_evaluation_summary;
    predicate.governance_receipt_ref = extensions.governance_receipt_ref;
    predicate.consistency_anchor = extensions.consistency_anchor;
    Ok(predicate)
}

/// Build the in-toto Statement carrying the bilateral predicate.
///
/// The subject digest binds the receipt BODY (`ChioReceiptBody`), not
/// the full signed wrapper. Hashing the full `ChioReceipt` (including
/// the envelope's `signature` field) would make the verifier's
/// "resolve the receipt from a store and re-derive the subject" path
/// produce a different digest than the producer signed, breaking
/// cross-impl resolution. Hashing the body lets verifiers re-derive
/// the subject from any source that exposes the body (the receipt
/// store's signed wrapper, a receipt log, or a peer's re-emission).
pub fn build_statement(
    receipt: &ChioReceipt,
    predicate: BilateralPredicate,
) -> Result<DsseStatement, BilateralCoSigningError> {
    let body = receipt.body();
    let body_canonical = canonical_json_bytes(&body)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(&body_canonical);
    let digest_hex = hex::encode(hasher.finalize());
    Ok(DsseStatement {
        statement_type: STATEMENT_TYPE_V1.to_string(),
        subject: vec![StatementSubject {
            name: receipt_subject_name(&receipt.id),
            digest: SubjectDigest { sha256: digest_hex },
        }],
        predicate_type: PREDICATE_TYPE_BILATERAL.to_string(),
        predicate,
    })
}

// ---------------------------------------------------------------------------
// Sign / verify
// ---------------------------------------------------------------------------

/// Sign a bilateral DSSE signature-slice envelope.
///
/// `org_a_keypair` is the origin kernel (Org A); `org_b_keypair` is the
/// tool-host kernel (Org B). Both signatures cover the same DSSE PAE bytes.
///
/// Returns a fully-assembled [`DsseEnvelope`]; the function self-checks via
/// [`verify_dsse_envelope`] before returning so callers receive only
/// envelopes that already pass the signature-slice verification subset.
pub fn sign_dsse_envelope(
    receipt: &ChioReceipt,
    org_a_keypair: &Keypair,
    org_b_keypair: &Keypair,
    org_a_kernel_id: &str,
    org_b_kernel_id: &str,
    tool_name: &str,
    timestamp_unix_ms: u64,
) -> Result<DsseEnvelope, BilateralCoSigningError> {
    sign_dsse_envelope_full(
        receipt,
        org_a_keypair,
        org_b_keypair,
        org_a_kernel_id,
        org_b_kernel_id,
        tool_name,
        timestamp_unix_ms,
        BilateralPredicateExtensions::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sign_dsse_envelope_full(
    receipt: &ChioReceipt,
    org_a_keypair: &Keypair,
    org_b_keypair: &Keypair,
    org_a_kernel_id: &str,
    org_b_kernel_id: &str,
    tool_name: &str,
    timestamp_unix_ms: u64,
    extensions: BilateralPredicateExtensions,
) -> Result<DsseEnvelope, BilateralCoSigningError> {
    let org_a_pub = org_a_keypair.public_key();
    let org_b_pub = org_b_keypair.public_key();
    let org_a_keyid = Keyid::from_public_key(&org_a_pub);
    let org_b_keyid = Keyid::from_public_key(&org_b_pub);

    let predicate = build_predicate_full(
        receipt,
        KernelIdentity {
            kernel_id: org_a_kernel_id.to_string(),
            passport_key_fingerprint: org_a_keyid.clone(),
            alg: "ed25519".to_string(),
        },
        KernelIdentity {
            kernel_id: org_b_kernel_id.to_string(),
            passport_key_fingerprint: org_b_keyid.clone(),
            alg: "ed25519".to_string(),
        },
        tool_name,
        timestamp_unix_ms,
        extensions,
    )?;

    let statement = build_statement(receipt, predicate)?;
    let statement_bytes = statement.canonical_bytes()?;
    let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, &statement_bytes);

    let backend_a = Ed25519Backend::new(org_a_keypair.clone());
    let backend_b = Ed25519Backend::new(org_b_keypair.clone());
    let sig_a = backend_a
        .sign_bytes(&pae_bytes)
        .map_err(|e| BilateralCoSigningError::TransportFailure(e.to_string()))?;
    let sig_b = backend_b
        .sign_bytes(&pae_bytes)
        .map_err(|e| BilateralCoSigningError::TransportFailure(e.to_string()))?;

    let envelope = DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: BASE64_STANDARD.encode(&statement_bytes),
        signatures: vec![
            DsseSignature {
                keyid: org_a_keyid.0.clone(),
                sig: BASE64_STANDARD.encode(sig_a.to_bytes()),
            },
            DsseSignature {
                keyid: org_b_keyid.0.clone(),
                sig: BASE64_STANDARD.encode(sig_b.to_bytes()),
            },
        ],
    };

    // Self-check: the envelope verifies under the same public keys we signed
    // with. Mirrors the assertion `co_sign_with_origin` makes about the
    // legacy `DualSignedReceipt` so any subtle encoding drift is caught at
    // the producer.
    verify_dsse_envelope(&envelope, &org_a_pub, &org_b_pub)?;
    Ok(envelope)
}

/// Verify a DSSE signature-slice envelope. Returns the parsed Statement on
/// success so callers can drive subsequent checks (peer pinning, lease
/// resolution, anchor reconciliation) against a single decoded payload.
///
/// 1. Payload base64-decodes (`dsse.malformed`).
/// 2. Statement is parseable canonical JSON (`statement.malformed`).
/// 3. `payload_type == PAYLOAD_TYPE_IN_TOTO` (PAE preimage shape).
/// 4. `predicate_type` is `PREDICATE_TYPE_BILATERAL`.
/// 5. `signatures` carries exactly two entries. Their array order is not
///    security-relevant; signatures are matched by `keyid`.
/// 6. Each required `keyid` matches the SHA-256 of the corresponding
///    public key the verifier was given (`peer.unpinned_or_keyid_mismatch`).
/// 7. Each signature, base64-decoded, is a valid Ed25519 signature over
///    the recomputed DSSE PAE bytes (`signature.server_*_invalid`).
pub fn verify_dsse_envelope(
    envelope: &DsseEnvelope,
    org_a_public_key: &PublicKey,
    org_b_public_key: &PublicKey,
) -> Result<DsseStatement, BilateralCoSigningError> {
    if envelope.payload_type != PAYLOAD_TYPE_IN_TOTO {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "dsse.malformed: payloadType '{}' is not '{}'",
            envelope.payload_type, PAYLOAD_TYPE_IN_TOTO
        )));
    }
    if envelope.signatures.len() != 2 {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "dsse.malformed: expected exactly 2 signatures, got {}",
            envelope.signatures.len()
        )));
    }

    let (statement, statement_bytes) = envelope.decode_statement()?;
    let canonical_statement_bytes = statement.canonical_bytes()?;
    if canonical_statement_bytes != statement_bytes {
        return Err(BilateralCoSigningError::CanonicalJson(
            "statement.malformed: payload is not canonical JSON".to_string(),
        ));
    }

    if statement.statement_type != STATEMENT_TYPE_V1 {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "statement.schema_invalid: _type '{}' is not '{}'",
            statement.statement_type, STATEMENT_TYPE_V1
        )));
    }
    if statement.predicate_type != PREDICATE_TYPE_BILATERAL {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.type_unrecognised: '{}'",
            statement.predicate_type
        )));
    }
    validate_signature_slice_predicate(&statement.predicate)?;

    // Single-subject invariant: the bilateral envelope profile
    // binds exactly ONE subject (the receipt body). The pre-fix
    // verifier only rejected the empty-list case, so a multi-subject
    // envelope was accepted and only `subject[0]` was bound. A
    // signer could insert an arbitrary second subject digest and
    // verifiers that walked the full subject list (which is the
    // spec-conformant behavior for in-toto subject membership) would
    // resolve a different receipt than the producer signed.
    if statement.subject.len() != 1 {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "statement.malformed: bilateral envelope must carry exactly 1 subject, got {}",
            statement.subject.len()
        )));
    }
    let expected_subject_name = receipt_subject_name(&statement.predicate.invocation_id);
    if statement.subject[0].name != expected_subject_name {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "statement.malformed: subject name '{}' is not canonical receipt subject '{}'",
            statement.subject[0].name, expected_subject_name
        )));
    }

    let org_a_keyid = Keyid::from_public_key(org_a_public_key);
    let org_b_keyid = Keyid::from_public_key(org_b_public_key);

    // Bind verified keyids to the predicate's declared
    // `passport_key_fingerprint` for both tool servers. Without this
    // check, a signer could produce a validly signed envelope whose
    // predicate names different passport fingerprints, and downstream
    // peer-pinning and verification steps would act on identities that were
    // never verified.
    if statement.predicate.tool_server_a.passport_key_fingerprint != org_a_keyid {
        return Err(BilateralCoSigningError::OrgASignatureInvalid);
    }
    if statement.predicate.tool_server_b.passport_key_fingerprint != org_b_keyid {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }

    if org_a_keyid == org_b_keyid {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }

    let embedded_receipt = decode_embedded_receipt(&statement.predicate)?;
    if embedded_receipt.id != statement.predicate.invocation_id {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: invocation_id {:?} does not match embedded receipt id {:?}",
            statement.predicate.invocation_id, embedded_receipt.id
        )));
    }
    if embedded_receipt.tool_name != statement.predicate.tool_name {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: tool_name {:?} does not match embedded receipt tool_name {:?}",
            statement.predicate.tool_name, embedded_receipt.tool_name
        )));
    }
    if embedded_receipt.kernel_key != *org_b_public_key {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }
    let receipt_signature_valid = embedded_receipt
        .verify_signature()
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    if !receipt_signature_valid {
        return Err(BilateralCoSigningError::ReceiptMismatch);
    }
    let embedded_receipt_digest = receipt_body_digest_hex(&embedded_receipt)?;
    if statement.subject[0].digest.sha256 != embedded_receipt_digest {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "subject.digest_mismatch: subject digest {} != sha256(canonical_json(embedded_receipt.body())) {}",
            statement.subject[0].digest.sha256, embedded_receipt_digest
        )));
    }

    let pae_bytes = pae(&envelope.payload_type, &statement_bytes);

    let sig_a = signature_for_keyid(&envelope.signatures, org_a_keyid.as_str())
        .ok_or(BilateralCoSigningError::OrgASignatureInvalid)?;
    let sig_b = signature_for_keyid(&envelope.signatures, org_b_keyid.as_str())
        .ok_or(BilateralCoSigningError::OrgBSignatureInvalid)?;

    let sig_a_bytes = decode_ed25519_signature(&sig_a.sig)
        .ok_or(BilateralCoSigningError::OrgASignatureInvalid)?;
    let sig_b_bytes = decode_ed25519_signature(&sig_b.sig)
        .ok_or(BilateralCoSigningError::OrgBSignatureInvalid)?;

    let sig_a_struct = Signature::from_bytes(&sig_a_bytes);
    let sig_b_struct = Signature::from_bytes(&sig_b_bytes);

    // Spec §7 step 11.
    if !org_a_public_key.verify(&pae_bytes, &sig_a_struct) {
        return Err(BilateralCoSigningError::OrgASignatureInvalid);
    }
    // Spec §7 step 12.
    if !org_b_public_key.verify(&pae_bytes, &sig_b_struct) {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }

    Ok(statement)
}

fn validate_signature_slice_predicate(
    pred: &BilateralPredicate,
) -> Result<(), BilateralCoSigningError> {
    if pred.schema != PREDICATE_BODY_SCHEMA {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: schema {:?} is not {:?}",
            pred.schema, PREDICATE_BODY_SCHEMA
        )));
    }
    require_non_empty_schema_string("invocation_id", &pred.invocation_id)?;
    require_non_empty_schema_string("tool_name", &pred.tool_name)?;
    require_non_empty_schema_string("tool_server_a.kernel_id", &pred.tool_server_a.kernel_id)?;
    require_non_empty_schema_string("tool_server_b.kernel_id", &pred.tool_server_b.kernel_id)?;
    if pred.tool_server_a.alg != "ed25519" {
        return Err(BilateralCoSigningError::OrgASignatureInvalid);
    }
    if pred.tool_server_b.alg != "ed25519" {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }
    if !is_sha256_hex(pred.tool_server_a.passport_key_fingerprint.as_str())
        || !is_sha256_hex(pred.tool_server_b.passport_key_fingerprint.as_str())
    {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: passport_key_fingerprint is not 64 lowercase hex"
                .to_string(),
        ));
    }
    match pred.co_sign.as_str() {
        "bilateral_required" | "bilateral_if_cross_org" => {}
        _ => {
            return Err(BilateralCoSigningError::CanonicalJson(format!(
                "predicate.schema_invalid: co_sign {:?} is not supported",
                pred.co_sign
            )))
        }
    }
    if pred.consistency_model != DEFAULT_CONSISTENCY_MODEL {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: consistency_model {:?} is not supported by the signature-slice profile",
            pred.consistency_model
        )));
    }
    if !VALID_CROSS_ORG_VISIBILITY.contains(&pred.cross_org_visibility.as_str()) {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: cross_org_visibility {:?} is unsupported",
            pred.cross_org_visibility
        )));
    }
    Ok(())
}

fn require_non_empty_schema_string(
    field: &str,
    value: &str,
) -> Result<(), BilateralCoSigningError> {
    if value.is_empty() {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: {field} must be non-empty"
        )));
    }
    Ok(())
}

fn decode_embedded_receipt(
    pred: &BilateralPredicate,
) -> Result<ChioReceipt, BilateralCoSigningError> {
    let receipt: ChioReceipt = serde_json::from_str(&pred.receipt_canonical_json)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(format!("receipt json: {e}")))?;
    let canonical = canonical_json_bytes(&receipt)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    let canonical_json = String::from_utf8(canonical)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    if canonical_json != pred.receipt_canonical_json {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: receipt_canonical_json is not canonical".to_string(),
        ));
    }
    Ok(receipt)
}

fn receipt_body_digest_hex(receipt: &ChioReceipt) -> Result<String, BilateralCoSigningError> {
    let body = receipt.body();
    let body_canonical = canonical_json_bytes(&body)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(&body_canonical);
    Ok(hex::encode(hasher.finalize()))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn decode_ed25519_signature(b64: &str) -> Option<[u8; 64]> {
    let bytes = BASE64_STANDARD.decode(b64.as_bytes()).ok()?;
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn signature_for_keyid<'a>(
    signatures: &'a [DsseSignature],
    keyid: &str,
) -> Option<&'a DsseSignature> {
    signatures.iter().find(|signature| signature.keyid == keyid)
}

// ---------------------------------------------------------------------------
// Tests (encoding round-trip + happy path; negative paths live in
// chio-conformance/tests/b4_bilateral_dsse_signature_slice.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core_types::crypto::sha256_hex;
    use chio_core_types::receipt::{
        ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel,
    };

    fn sample_receipt(kp: &Keypair) -> ChioReceipt {
        let body = ChioReceiptBody {
            id: "rcpt-bilateral-b4-sample".to_string(),
            timestamp: 1_734_000_000,
            capability_id: "cap-bilateral-b4".to_string(),
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
            kernel_key: kp.public_key(),
        };
        ChioReceipt::sign(body, kp).unwrap()
    }

    #[test]
    fn pae_matches_dsse_v1_format_known_vector() {
        // Sanity: the leading bytes are literally "DSSEv1 ".
        let bytes = pae("application/x", b"hello");
        assert!(bytes.starts_with(b"DSSEv1 "));
        // "DSSEv1 13 application/x 5 hello"
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            "DSSEv1 13 application/x 5 hello"
        );
    }

    #[test]
    fn happy_path_signs_and_verifies() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let envelope = sign_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "kernel.org-a",
            "kernel.org-b",
            "file_read",
            1_734_000_000_000,
        )
        .unwrap();
        assert_eq!(envelope.signatures.len(), 2);
        let statement = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
            .expect("envelope must verify under matching public keys");
        assert_eq!(
            statement.predicate_type, PREDICATE_TYPE_BILATERAL,
            "predicate type emitted by bilateral hot path"
        );
        assert_eq!(statement.subject.len(), 1);
        assert_eq!(statement.subject[0].name, receipt_subject_name(&receipt.id));
    }

    #[test]
    fn round_trip_preserves_pae_bytes() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let envelope = sign_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "kernel.org-a",
            "kernel.org-b",
            "file_read",
            1_734_000_000_000,
        )
        .unwrap();
        let pae_a = envelope.pae_bytes().unwrap();
        // Re-decode and re-derive: the bytes are stable.
        let (_stmt, bytes) = envelope.decode_statement().unwrap();
        let pae_b = pae(&envelope.payload_type, &bytes);
        assert_eq!(pae_a, pae_b);
    }

    #[test]
    fn keyid_is_sha256_of_raw_ed25519_public_key_bytes() {
        // Key-identifier invariant: the spec's keyid contract is
        // SHA-256 of RAW key material (Ed25519 = 32 verifying-key
        // bytes). An earlier revision hashed `to_hex().as_bytes()`
        // which silently broke cross-implementation interop. This
        // test pins the raw-bytes invariant.
        let kp = Keypair::generate();
        let pk = kp.public_key();
        let keyid = Keyid::from_public_key(&pk);
        let want = sha256_hex(pk.as_bytes());
        assert_eq!(keyid.0, want);
        // Belt-and-suspenders: hashing the hex form must NOT match.
        let hex_form = sha256_hex(pk.to_hex().as_bytes());
        assert_ne!(
            keyid.0, hex_form,
            "Ed25519 keyid must hash raw bytes, not hex string"
        );
    }

    #[test]
    fn signer_rejects_empty_schema_required_identifiers() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let mut empty_receipt_id = sample_receipt(&kp_b);
        empty_receipt_id.id.clear();
        let err = sign_dsse_envelope(
            &empty_receipt_id,
            &kp_a,
            &kp_b,
            "kernel.org-a",
            "kernel.org-b",
            "file_read",
            1_734_000_000_000,
        )
        .expect_err("empty receipt id must not sign");
        assert!(err.to_string().contains("invocation_id must be non-empty"));

        let mut empty_tool = sample_receipt(&kp_b);
        empty_tool.tool_name.clear();
        let err = sign_dsse_envelope(
            &empty_tool,
            &kp_a,
            &kp_b,
            "kernel.org-a",
            "kernel.org-b",
            "",
            1_734_000_000_000,
        )
        .expect_err("empty tool name must not sign");
        assert!(err.to_string().contains("tool_name must be non-empty"));

        let receipt = sample_receipt(&kp_b);
        let err = sign_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "",
            "kernel.org-b",
            "file_read",
            1_734_000_000_000,
        )
        .expect_err("empty org-a kernel id must not sign");
        assert!(err
            .to_string()
            .contains("tool_server_a.kernel_id must be non-empty"));

        let err = sign_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "kernel.org-a",
            "",
            "file_read",
            1_734_000_000_000,
        )
        .expect_err("empty org-b kernel id must not sign");
        assert!(err
            .to_string()
            .contains("tool_server_b.kernel_id must be non-empty"));
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let mut envelope = sign_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "kernel.org-a",
            "kernel.org-b",
            "file_read",
            1_734_000_000_000,
        )
        .unwrap();
        envelope.payload.push('A'); // breaks base64 + PAE preimage
        let result = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key());
        assert!(result.is_err());
    }

    #[test]
    fn mismatched_payload_type_fails_verification() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let mut envelope = sign_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "kernel.org-a",
            "kernel.org-b",
            "file_read",
            1_734_000_000_000,
        )
        .unwrap();
        envelope.payload_type = "application/json".to_string();
        let result = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key());
        assert!(result.is_err());
    }

    #[test]
    fn verifier_accepts_reversed_signature_order_by_keyid() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let mut envelope = sign_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "kernel.org-a",
            "kernel.org-b",
            "file_read",
            1_734_000_000_000,
        )
        .unwrap();
        envelope.signatures.swap(0, 1);
        verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
            .expect("signature array order is not security-relevant");
    }

    #[test]
    fn verifier_rejects_noncanonical_statement_payload_even_if_resigned() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let mut envelope = sign_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "kernel.org-a",
            "kernel.org-b",
            "file_read",
            1_734_000_000_000,
        )
        .unwrap();
        let (statement, _) = envelope.decode_statement().unwrap();
        let noncanonical = serde_json::to_vec_pretty(&statement).unwrap();
        resign_payload(&mut envelope, &kp_a, &kp_b, &noncanonical);

        let err = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
            .expect_err("non-canonical payload bytes must be rejected");
        assert!(err.to_string().contains("not canonical JSON"));
    }

    #[test]
    fn verifier_rejects_invalid_embedded_receipt_signature_even_if_dsse_resigned() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let mut envelope = sign_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "kernel.org-a",
            "kernel.org-b",
            "file_read",
            1_734_000_000_000,
        )
        .unwrap();
        let (mut statement, _) = envelope.decode_statement().unwrap();
        let mut embedded: ChioReceipt =
            serde_json::from_str(&statement.predicate.receipt_canonical_json).unwrap();
        embedded.content_hash = sha256_hex(b"tampered-content");
        statement.predicate.receipt_canonical_json =
            String::from_utf8(canonical_json_bytes(&embedded).unwrap()).unwrap();
        let bytes = statement.canonical_bytes().unwrap();
        resign_payload(&mut envelope, &kp_a, &kp_b, &bytes);

        let err = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
            .expect_err("embedded receipt signature must be checked");
        assert_eq!(err, BilateralCoSigningError::ReceiptMismatch);
    }

    #[test]
    fn verifier_rejects_embedded_receipt_not_signed_by_tool_host() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let rogue_kp = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let rogue_receipt = sample_receipt(&rogue_kp);
        let mut envelope = sign_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "kernel.org-a",
            "kernel.org-b",
            "file_read",
            1_734_000_000_000,
        )
        .unwrap();
        let (mut statement, _) = envelope.decode_statement().unwrap();
        statement.predicate.receipt_canonical_json =
            String::from_utf8(canonical_json_bytes(&rogue_receipt).unwrap()).unwrap();
        statement.subject[0].digest.sha256 = receipt_body_digest_hex(&rogue_receipt).unwrap();
        let bytes = statement.canonical_bytes().unwrap();
        resign_payload(&mut envelope, &kp_a, &kp_b, &bytes);

        let err = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
            .expect_err("embedded receipt kernel_key must equal Org B passport key");
        assert_eq!(err, BilateralCoSigningError::OrgBSignatureInvalid);
    }

    #[test]
    fn verifier_rejects_ordered_or_quorum_consistency_claims_without_anchor_metadata() {
        for unsupported in ["totally-ordered", "quorum-required"] {
            let kp_a = Keypair::generate();
            let kp_b = Keypair::generate();
            let receipt = sample_receipt(&kp_b);
            let mut envelope = sign_dsse_envelope(
                &receipt,
                &kp_a,
                &kp_b,
                "kernel.org-a",
                "kernel.org-b",
                "file_read",
                1_734_000_000_000,
            )
            .unwrap();
            let (mut statement, _) = envelope.decode_statement().unwrap();
            statement.predicate.consistency_model = unsupported.to_string();
            let bytes = statement.canonical_bytes().unwrap();
            resign_payload(&mut envelope, &kp_a, &kp_b, &bytes);

            let err = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
                .expect_err("signature-slice profile cannot verify ordered/quorum claims");
            assert!(err.to_string().contains(&format!(
                "consistency_model \"{unsupported}\" is not supported"
            )));
        }
    }

    #[test]
    fn signer_rejects_tool_name_that_does_not_match_receipt() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let err = sign_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "kernel.org-a",
            "kernel.org-b",
            "file_write",
            1_734_000_000_000,
        )
        .expect_err("producer must bind predicate.tool_name to receipt.tool_name");
        assert_eq!(err, BilateralCoSigningError::ReceiptMismatch);
    }

    fn resign_payload(
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
}
