use super::*;

// ---------------------------------------------------------------------------
// Constants (DSSE signature-slice profile)
// ---------------------------------------------------------------------------

/// DSSE v1 payload type used by chio bilateral signature-slice envelopes.
///
/// The literal string is part of the PAE preimage: changing it changes the
/// signed bytes.
pub const PAYLOAD_TYPE_IN_TOTO: &str = "application/vnd.in-toto+json";

/// Predicate type for the in-toto Statement carried in the DSSE signature
/// slice. Deliberately distinct from the strict Chio bilateral
/// invocation predicate.
pub const PREDICATE_TYPE_BILATERAL: &str = "chio.bilateral-signature-slice.v1";

/// Predicate type for strict Chio bilateral invocation envelopes.
pub const PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION: &str = "chio.bilateral-cosign-invocation.v1";

/// In-toto Statement `_type` per the v1 attestation framework (DSSE doc).
pub const STATEMENT_TYPE_V1: &str = "https://in-toto.io/Statement/v1";

/// Schema discriminator carried by the chio-bilateral signature-slice
/// predicate body. It intentionally matches `predicateType` so the signed
/// artifact has a single verifier-facing profile identifier.
pub const PREDICATE_BODY_SCHEMA: &str = PREDICATE_TYPE_BILATERAL;

/// Fixed prefix tag of the DSSE Pre-Authentication Encoding (DSSE v1).
pub(super) const PAE_PREFIX: &str = "DSSEv1";

/// Out-of-band profile identifier for the Chio bilateral DSSE signature-slice.
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
// Public types
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
    /// Internal schema discriminator for the compatibility signature-slice profile.
    ///
    /// Strict Chio predicates omit this field because the signed
    /// `predicateType` is the verifier-facing schema discriminator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
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
    /// SHA-256 over canonical tool arguments. Required by the strict
    /// Chio profile and intentionally omitted from the compatibility
    /// signature-slice profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_args_hash: Option<HashRecord>,
    /// Canonical-JSON of the underlying `ChioReceipt`. This is a compatibility
    /// signature-slice helper field and must be absent from strict Chio
    /// predicates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_canonical_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_lease_ref: Option<CapabilityLeaseRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_evaluation_summary: Option<PolicyEvaluationSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_receipt_ref: Option<GovernanceReceiptRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_anchor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub treaty_binding_ref: Option<TreatyBindingRef>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TreatyBindingRef {
    pub treaty_id: String,
    pub treaty_scope_sha256: String,
    pub ladder_intersection_sha256: String,
    pub admission_report_sha256: String,
    pub continuation_sha256: String,
    pub lineage_bundle_sha256: String,
    pub action_class_id: String,
    pub consistency_model: String,
    pub request_sha256: String,
    pub outcome_sha256: String,
    pub local_receipt_sha256: String,
    pub remote_receipt_sha256: String,
    pub lease_refs: Vec<String>,
    pub governance_refs: Vec<String>,
    pub signer_kernel_ids: Vec<String>,
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
    /// byte-for-byte against the `CoSigningBody` preimage used by
    /// `DualSignedReceipt`).
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
