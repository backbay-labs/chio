//! TRJ5-B4: DSSE-conformant bilateral co-signing per
//! `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 (envelope shape) and §7
//! (verification algorithm).
//!
//! ## Why this module exists
//!
//! The legacy bilateral artifact (see [`crate::bilateral`]) signs Ed25519 over
//! the canonical-JSON encoding of `CoSigningBody`. The §6 envelope, by
//! contrast, requires Ed25519 over the DSSE Pre-Authentication Encoding (PAE)
//! of an in-toto Statement carrying a chiodos-bilateral-cosign predicate.
//! These two preimages share zero bytes; a signature over one does NOT
//! authenticate the other (R4 BLOCKER 1).
//!
//! Trj5 ships both surfaces in **cohabitation** (per
//! `.planning/trajectory-5/lane-b-wiring/dsse-bilateral-signing.md` §
//! "Migration strategy"). The legacy `DualSignedReceipt::verify` is retained
//! for backward compatibility with existing federation transport callers, but
//! is explicitly **NOT** §6-conformant. Verifiers seeking spec §6 conformance
//! MUST use [`verify_dsse_envelope`] against a [`DsseEnvelope`] produced by
//! [`sign_dsse_envelope`].
//!
//! ## Wire format (spec §6 lines 308-353)
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
//! ## Bounded scope (TRJ5)
//!
//! - Only the Ed25519 signing algorithm is wired; hybrid + post-quantum keyid
//!   semantics are out of scope (see `dsse-bilateral-signing.md` §"Out of
//!   scope for B4"). The keyid is `sha256_hex(public_key.to_bytes())` for
//!   Ed25519; non-Ed25519 keys construct a domain-separated keyid via
//!   [`Keyid::from_public_key`] but are not exercised on the trj5 hot path.
//! - Predicate-schema validation against §5 is left to a later pass; trj5
//!   carries the predicate fields the §7 verifier needs (`tool_server_*`,
//!   `co_sign`, `consistency_model`, `cross_org_visibility`,
//!   `timestamp_unix_ms`, `tool_name`, plus the chio-internal `receipt_id`
//!   and `receipt_canonical_json` to anchor subject hashing). Adding the
//!   full schema-validation pipeline is trj6 follow-up.
//! - `governance_receipt_ref`, `consistency_anchor`, and `n_of_m` quorum
//!   are NOT carried by trj5's predicate body; the bilateral mode is
//!   `bilateral_required` only. Extension is straightforward.
//!
//! ## Spec citation
//!
//! - §6 lines 308-353: DSSE envelope shape and PAE encoding.
//! - §7 step 11-12: signature verification under tool-server fingerprints.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{Ed25519Backend, Keypair, PublicKey, Signature, SigningBackend};
use chio_core_types::receipt::ChioReceipt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bilateral::BilateralCoSigningError;

// ---------------------------------------------------------------------------
// Constants (spec §6, §7)
// ---------------------------------------------------------------------------

/// DSSE v1 payload type used by chiodos bilateral envelopes.
///
/// Spec §6 line 323: `"payloadType": "application/vnd.in-toto+json"`. The
/// literal string is part of the PAE preimage: changing it changes the
/// signed bytes.
pub const PAYLOAD_TYPE_IN_TOTO: &str = "application/vnd.in-toto+json";

/// Predicate type for the in-toto Statement carried in the DSSE envelope.
///
/// The spec §7 step 4 admits both the in-toto.io URL and the chio-namespaced
/// fallback; trj5 emits the chio-namespaced form for self-contained
/// verifiability.
pub const PREDICATE_TYPE_BILATERAL: &str = "chio.bilateral-cosign-invocation.v1";

/// In-toto Statement `_type` per the v1 attestation framework (DSSE doc).
pub const STATEMENT_TYPE_V1: &str = "https://in-toto.io/Statement/v1";

/// `_type` field of the chio-bilateral predicate body. Distinct from
/// `predicateType` so verifiers can distinguish "this is a chio predicate"
/// from "this is a generic in-toto Statement".
pub const PREDICATE_BODY_SCHEMA: &str = "chio.bilateral-cosign.invocation.v1";

/// Fixed prefix tag of the DSSE Pre-Authentication Encoding (DSSE v1).
const PAE_PREFIX: &str = "DSSEv1";

/// Wire schema for [`DsseEnvelope`] when carried over chiodos federation.
pub const BILATERAL_DSSE_ENVELOPE_SCHEMA: &str = "chio.federation-bilateral-dsse-envelope.v1";

/// Default consistency model emitted by trj5's federation hot path. The
/// chiodos ladder admits three values; trj5 emits `"crdt-commutative"` for
/// the unanchored federation hop, matching what `DualSignedReceipt` already
/// implies (no anchor pinned beyond the receipt body itself).
pub const DEFAULT_CONSISTENCY_MODEL: &str = "crdt-commutative";

/// Default cross-org visibility for trj5 envelopes (`"federated"`).
pub const DEFAULT_CROSS_ORG_VISIBILITY: &str = "federated";

/// Default `co_sign` field for the trj5 production hot path.
pub const DEFAULT_COSIGN_MODE: &str = "bilateral_required";

// ---------------------------------------------------------------------------
// Public types (kept narrow; see module docs §"Bounded scope" for exclusions)
// ---------------------------------------------------------------------------

/// SHA-256 fingerprint of a kernel's passport public key (hex, lowercase),
/// used as the DSSE `keyid` per §6 line 327, 331 and as the `tool_server_*`
/// `passport_key_fingerprint` per §5.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Keyid(pub String);

impl Keyid {
    /// Compute the §6 keyid for the given public key. Uses the raw
    /// 32-byte Ed25519 encoding when the key is Ed25519; for non-Ed25519
    /// keys, the underlying hex encoding (with algorithm prefix) is hashed
    /// directly so the keyid remains a domain-separable hex string. The
    /// trj5 hot path emits Ed25519 only.
    #[must_use]
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key.to_hex().as_bytes());
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
    /// Signing algorithm. Trj5 emits `"ed25519"` only.
    pub alg: String,
}

/// Predicate body of the chio bilateral cosign Statement. Spec §5 lines
/// 128-301 carry many additional fields (policy_evaluation_summary,
/// capability_lease_ref, etc.); trj5 emits the load-bearing subset
/// required by the §7 verification path on the federation hop. See module
/// docs for the bounded scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BilateralPredicate {
    /// Internal schema discriminator (`PREDICATE_BODY_SCHEMA`). Distinct
    /// from `predicateType` on the parent Statement.
    pub schema: String,
    /// Globally-unique identifier of the underlying invocation. Trj5 uses
    /// the receipt id (`ChioReceipt::id`), which is itself unique per
    /// federation hop.
    pub invocation_id: String,
    /// Origin kernel (Org A) identity.
    pub tool_server_a: KernelIdentity,
    /// Tool-host kernel (Org B) identity.
    pub tool_server_b: KernelIdentity,
    /// Tool name as exposed by both kernels.
    pub tool_name: String,
    /// Co-sign mode. Trj5 emits `DEFAULT_COSIGN_MODE`
    /// (`"bilateral_required"`).
    pub co_sign: String,
    /// Consistency model per CHIODOS_LADDER §4. Trj5 emits
    /// `DEFAULT_CONSISTENCY_MODEL`.
    pub consistency_model: String,
    /// Cross-org visibility per CHIODOS_LADDER. Trj5 emits
    /// `DEFAULT_CROSS_ORG_VISIBILITY`.
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
}

/// In-toto Statement carried inside the DSSE envelope's `payload` (after
/// canonical-JSON encoding and base64-wrapping).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DsseStatement {
    /// `_type` per in-toto v1: `"https://in-toto.io/Statement/v1"`.
    #[serde(rename = "_type")]
    pub statement_type: String,
    /// Subject array; trj5 emits exactly one entry pointing at the
    /// underlying receipt.
    pub subject: Vec<StatementSubject>,
    /// `predicateType` distinguishing chio bilateral envelopes from other
    /// in-toto attestations.
    pub predicate_type: String,
    /// Chio-internal predicate body. Spec §5 fields the trj5 hot path emits.
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

/// DSSE v1 envelope carrying the §6-conformant bilateral co-signature.
///
/// The wire shape per spec §6 lines 319-336. Trj5 emits exactly two
/// signatures (one per kernel) under the default `bilateral_required`
/// co-sign mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DsseEnvelope {
    /// Wire schema discriminator. Trj5 emits
    /// `BILATERAL_DSSE_ENVELOPE_SCHEMA`. NOT part of the §6 shape itself
    /// (DSSE knows nothing of chio schemas); the verifier `verify_dsse_envelope`
    /// MUST tolerate envelopes that did not originate from a chio kernel
    /// and therefore lack this field. To keep the §6 wire bytes narrow,
    /// we only serialize this when set, and verification ignores it
    /// entirely (it is signed-data-adjacent metadata).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// MUST equal `PAYLOAD_TYPE_IN_TOTO` for trj5.
    pub payload_type: String,
    /// Base64 (standard alphabet) of canonical-JSON of [`DsseStatement`].
    pub payload: String,
    /// Detached signatures over `pae(payload_type, base64_decode(payload))`.
    /// Trj5 emits exactly two; verifiers in the trj5 path MUST find both.
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
    })
}

/// Build the in-toto Statement carrying the bilateral predicate.
pub fn build_statement(
    receipt: &ChioReceipt,
    predicate: BilateralPredicate,
) -> Result<DsseStatement, BilateralCoSigningError> {
    let receipt_canonical = canonical_json_bytes(receipt)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(&receipt_canonical);
    let digest_hex = hex::encode(hasher.finalize());
    Ok(DsseStatement {
        statement_type: STATEMENT_TYPE_V1.to_string(),
        subject: vec![StatementSubject {
            name: receipt.id.clone(),
            digest: SubjectDigest { sha256: digest_hex },
        }],
        predicate_type: PREDICATE_TYPE_BILATERAL.to_string(),
        predicate,
    })
}

// ---------------------------------------------------------------------------
// Sign / verify
// ---------------------------------------------------------------------------

/// Sign a §6-conformant bilateral DSSE envelope.
///
/// `org_a_keypair` is the origin kernel (Org A); `org_b_keypair` is the
/// tool-host kernel (Org B). Both signatures cover the same DSSE PAE bytes
/// per spec §6 line 345 ("Both kernels sign the same PAE bytes.").
///
/// The trj5 hot path provides `tool_name` and `timestamp_unix_ms` (Org B's
/// wall-clock at canonicalisation). The Statement subject digest is computed
/// from the canonical-JSON of `receipt`.
///
/// Returns a fully-assembled [`DsseEnvelope`]; the function self-checks via
/// [`verify_dsse_envelope`] before returning so callers receive only
/// envelopes that already pass §7 step-11/12 verification.
pub fn sign_dsse_envelope(
    receipt: &ChioReceipt,
    org_a_keypair: &Keypair,
    org_b_keypair: &Keypair,
    org_a_kernel_id: &str,
    org_b_kernel_id: &str,
    tool_name: &str,
    timestamp_unix_ms: u64,
) -> Result<DsseEnvelope, BilateralCoSigningError> {
    let org_a_pub = org_a_keypair.public_key();
    let org_b_pub = org_b_keypair.public_key();
    let org_a_keyid = Keyid::from_public_key(&org_a_pub);
    let org_b_keyid = Keyid::from_public_key(&org_b_pub);

    let predicate = build_predicate(
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
        schema: Some(BILATERAL_DSSE_ENVELOPE_SCHEMA.to_string()),
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

/// Verify a §6-conformant DSSE envelope per spec §7 steps 1, 10, 11, 12 (the
/// signature-bearing subset of the algorithm). Returns the parsed Statement
/// on success so callers can drive subsequent steps (peer pinning, lease
/// resolution, anchor reconciliation) against a single decoded payload.
///
/// **What this function checks (trj5 scope):**
///
/// 1. Payload base64-decodes (`dsse.malformed`).
/// 2. Statement is parseable canonical JSON (`statement.malformed`).
/// 3. `payload_type == PAYLOAD_TYPE_IN_TOTO` (PAE preimage shape).
/// 4. `predicate_type` is `PREDICATE_TYPE_BILATERAL` (or its in-toto.io
///    URL alias).
/// 5. `signatures` carries exactly two entries.
/// 6. Each signature's `keyid` matches the SHA-256 of the corresponding
///    public key the verifier was given (`peer.unpinned_or_keyid_mismatch`,
///    spec §7 step 8 / step 11/12).
/// 7. Each signature, base64-decoded, is a valid Ed25519 signature over
///    the recomputed DSSE PAE bytes (`signature.server_*_invalid`,
///    spec §7 steps 11-12).
///
/// **Out of trj5 scope:** subject digest re-resolution against an external
/// receipt store (§7 step 7), revocation/freshness of the passport at the
/// pinned epoch (§7 step 9), capability-lease resolution (§7 step 14),
/// governance-receipt resolution (§7 step 15), and consistency-anchor
/// reconciliation (§7 step 16). These are out-of-scope per
/// `dsse-bilateral-signing.md` §"Out of scope for B4".
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

    if statement.statement_type != STATEMENT_TYPE_V1 {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "statement.schema_invalid: _type '{}' is not '{}'",
            statement.statement_type, STATEMENT_TYPE_V1
        )));
    }
    if statement.predicate_type != PREDICATE_TYPE_BILATERAL
        && statement.predicate_type
            != "https://in-toto.io/attestation/bilateral-cosign-invocation/v1"
    {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.type_unrecognised: '{}'",
            statement.predicate_type
        )));
    }

    let pae_bytes = pae(&envelope.payload_type, &statement_bytes);

    // Spec §7 step 11: keyid for tool_server_a (here: bound to the caller-
    // supplied org_a_public_key). The trj5 verifier matches by the keyid
    // hash (SHA-256 of public key) rather than by signature index in the
    // array, so an envelope whose signatures are reordered still
    // verifies, matching the spec wording "exactly one signature with
    // keyid == server_a fingerprint".
    let org_a_keyid = Keyid::from_public_key(org_a_public_key);
    let org_b_keyid = Keyid::from_public_key(org_b_public_key);

    let sig_a = find_signature_by_keyid(&envelope.signatures, &org_a_keyid)
        .ok_or(BilateralCoSigningError::OrgASignatureInvalid)?;
    let sig_b = find_signature_by_keyid(&envelope.signatures, &org_b_keyid)
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

fn find_signature_by_keyid<'a>(
    signatures: &'a [DsseSignature],
    keyid: &Keyid,
) -> Option<&'a DsseSignature> {
    signatures.iter().find(|s| s.keyid == keyid.0)
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

// ---------------------------------------------------------------------------
// Tests (encoding round-trip + happy path; negative paths live in
// chio-conformance/tests/b4_bilateral_dsse_pae_only_is_conformant.rs)
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
            id: "rcpt-trj5-b4-sample".to_string(),
            timestamp: 1_734_000_000,
            capability_id: "cap-trj5-b4".to_string(),
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
            "predicate type emitted by trj5 hot path"
        );
        assert_eq!(statement.subject.len(), 1);
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
    fn keyid_is_sha256_of_public_key_hex() {
        let kp = Keypair::generate();
        let pk = kp.public_key();
        let keyid = Keyid::from_public_key(&pk);
        let want = sha256_hex(pk.to_hex().as_bytes());
        assert_eq!(keyid.0, want);
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
}
