//! Real Rekor (Sigstore transparency log) witness-lane client.
//!
//! `RekorClient::publish` POSTs the canonical-JSON encoding of
//! `batch.body` to `${endpoint}/api/v1/log/entries` with a Sigstore
//! "intoto" v0.0.2 DSSE envelope shape; `verify_inclusion` GETs
//! `${endpoint}/api/v1/log/entries/${uuid}` and asserts that:
//!
//! 1. The returned `body.spec.content.hash.value` matches
//!    `sha256(canonical(batch.body))` (lane substitution defense).
//! 2. The `verification.signedEntryTimestamp` (SET) is a valid
//!    ECDSA P-256/SHA-256 signature, by Rekor's pinned public key,
//!    over the canonical JSON of `{body, integratedTime, logID,
//!    logIndex}` (Rekor SET spec).
//!
//! The SET signature check is load-bearing: inspecting only the body
//! hash and treating any well-formed JSON response as valid would let a
//! malicious mirror forge inclusion responses.
//!
//! In addition, when the response carries a
//! `verification.inclusionProof`, [`verify_inclusion_proof`] rebuilds
//! the Merkle tree head from the entry leaf hash and the audit path
//! per RFC 6962 / the Rekor transparency-log algorithm and asserts the
//! recomputed root equals `inclusionProof.rootHash`. The proof's
//! `logIndex` is required to equal the SET-signed `logIndex`, so the
//! Merkle path is bound to the same (body, logIndex) the pinned Rekor
//! key already authenticated. Any malformed, truncated, or mismatched
//! proof fails closed.
//!
//! This module makes a real HTTP call (via `reqwest`). The negative
//! conformance test
//! `crates/chio-conformance/tests/anchor_batch_witness_impersonation_rejected.rs`
//! exercises the full surface against a `tiny_http` mock server.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chio_core::canonical_json_bytes;
use chio_core::hashing::{sha256, Hash};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};

use crate::batch::{AnchorBatch, AnchorBatchWitnessKind};
use crate::witness::{batch_body_hash, AnchorWitnessClient, AnchorWitnessError, WitnessReceipt};

/// Rekor public key (Sigstore production log) in PKIX/SubjectPublicKeyInfo PEM.
///
/// Sourced from `https://rekor.sigstore.dev/api/v1/log/publicKey`. Pinned
/// here so a man-in-the-middle on the API endpoint cannot substitute
/// their own key. ECDSA P-256.
pub const REKOR_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
     MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n\
     kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n\
     -----END PUBLIC KEY-----\n";

/// Production Rekor client. The endpoint is configurable so tests can
/// point at a local mock; production wiring uses
/// `https://rekor.sigstore.dev`.
#[derive(Debug, Clone)]
pub struct RekorClient {
    endpoint: String,
    http: reqwest::Client,
    /// Maximum age in seconds for a witness receipt. Receipts older
    /// than this are reported as `AnchorWitnessError::Stale` on
    /// `verify_inclusion`.
    max_witness_age_seconds: i64,
    /// Trusted Rekor public keys (PEM-encoded ECDSA P-256). The
    /// production set defaults to [`REKOR_PUBLIC_KEY_PEM`]; tests
    /// substitute their own ephemeral key via [`Self::with_trusted_keys`].
    trusted_keys: Vec<String>,
}

impl RekorClient {
    /// `endpoint` example: `"https://rekor.sigstore.dev"` (no
    /// trailing slash). `max_witness_age_seconds` MUST be
    /// non-negative. The client trusts only the production Rekor
    /// public key by default; use [`Self::with_trusted_keys`] to
    /// override (e.g. for test mocks).
    pub fn new(
        endpoint: impl Into<String>,
        max_witness_age_seconds: i64,
    ) -> Result<Self, AnchorWitnessError> {
        let endpoint = endpoint.into();
        if endpoint.is_empty() {
            return Err(AnchorWitnessError::Config(
                "rekor endpoint must be non-empty".to_string(),
            ));
        }
        if max_witness_age_seconds < 0 {
            return Err(AnchorWitnessError::Config(
                "max_witness_age_seconds must be non-negative".to_string(),
            ));
        }
        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: Sigstore Rekor witness lane;
        // threading an HttpEgressContract through RekorClient::new is a
        // dedicated refactor, not yet wired here.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .https_only(false)
            .build()
            .map_err(|error| AnchorWitnessError::Config(error.to_string()))?;
        Ok(RekorClient {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            http,
            max_witness_age_seconds,
            trusted_keys: vec![REKOR_PUBLIC_KEY_PEM.to_string()],
        })
    }

    /// Replace the trusted-public-key set. The default constructor
    /// pins [`REKOR_PUBLIC_KEY_PEM`]. Tests use this to inject an
    /// ephemeral P-256 key whose private half they hold so they can
    /// mint valid SETs in their `tiny_http` mock.
    pub fn with_trusted_keys(mut self, keys: Vec<String>) -> Self {
        self.trusted_keys = keys;
        self
    }

    fn entries_url(&self) -> String {
        format!("{}/api/v1/log/entries", self.endpoint)
    }

    fn entry_by_uuid_url(&self, uuid: &str) -> String {
        format!("{}/api/v1/log/entries/{}", self.endpoint, uuid)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RekorIntotoSpec<'a> {
    content: RekorIntotoContent<'a>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RekorIntotoContent<'a> {
    envelope: RekorIntotoEnvelope<'a>,
    /// SHA-256 of the canonical-JSON batch body, hex-prefixed.
    hash: RekorHash<'a>,
}

/// DSSE in-toto statement envelope per the sigstore Rekor schema.
///
/// Rekor's `intoto` (v0.0.1+) entry expects a real DSSE envelope:
///
/// ```text
/// { "payloadType": "application/vnd.in-toto+json",
///   "payload": <base64(body)>,
///   "signatures": [{"keyid": <hex|empty>,
///                   "publicKey": <base64>,
///                   "sig": <base64>}] }
/// ```
///
/// The wire shape MUST serialize Rekor's canonical `payloadType`
/// (camelCase), not `payload_type` (snake_case): real Rekor would
/// either reject the envelope or canonicalize it to a shape that would
/// no longer match the SET signature input.
///
/// The intoto v0.0.2 schema requires a signature object with `publicKey`
/// and `sig` (an empty `signatures` array is rejected), so the entry
/// forwards the batch signer key and batch signature into the DSSE
/// envelope.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RekorIntotoEnvelope<'a> {
    payload: &'a str,
    payload_type: &'a str,
    signatures: Vec<RekorIntotoSignature<'a>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RekorIntotoSignature<'a> {
    keyid: &'a str,
    public_key: &'a str,
    sig: &'a str,
}

/// DSSE payload-type constant for in-toto statements, per the
/// sigstore intoto schema.
pub const REKOR_INTOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

#[derive(Debug, Serialize, Deserialize)]
struct RekorHash<'a> {
    algorithm: &'a str,
    /// Hex-encoded SHA-256 (no `0x` prefix per Rekor convention).
    value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RekorEntryRequest<'a> {
    api_version: &'a str,
    kind: &'a str,
    spec: RekorIntotoSpec<'a>,
}

#[derive(Debug)]
struct RekorIntotoSignatureMaterial {
    keyid: String,
    public_key: String,
    sig: String,
}

impl RekorIntotoSignatureMaterial {
    fn as_signature(&self) -> RekorIntotoSignature<'_> {
        RekorIntotoSignature {
            keyid: self.keyid.as_str(),
            public_key: self.public_key.as_str(),
            sig: self.sig.as_str(),
        }
    }
}

fn decode_unprefixed_hex(value: &str, expected_len: usize) -> Option<Vec<u8>> {
    if value.len() == expected_len && value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        hex::decode(value).ok()
    } else {
        None
    }
}

fn decode_prefixed_hex(value: &str, prefix: &str) -> Option<Vec<u8>> {
    value
        .strip_prefix(prefix)
        .and_then(|rest| hex::decode(rest).ok())
}

fn rekor_public_key_material(public_key_hex: &str) -> Vec<u8> {
    decode_unprefixed_hex(public_key_hex, 64)
        .or_else(|| decode_prefixed_hex(public_key_hex, "p256:"))
        .or_else(|| decode_prefixed_hex(public_key_hex, "p384:"))
        .unwrap_or_else(|| public_key_hex.as_bytes().to_vec())
}

fn rekor_signature_material(signature_hex: &str) -> Vec<u8> {
    decode_unprefixed_hex(signature_hex, 128)
        .or_else(|| decode_prefixed_hex(signature_hex, "p256:"))
        .or_else(|| decode_prefixed_hex(signature_hex, "p384:"))
        .unwrap_or_else(|| signature_hex.as_bytes().to_vec())
}

fn rekor_dsse_signature_material(batch: &AnchorBatch) -> RekorIntotoSignatureMaterial {
    let keyid = batch.body.signer_key.to_hex();
    let signature_hex = batch.signature.to_hex();
    RekorIntotoSignatureMaterial {
        public_key: BASE64_STANDARD.encode(rekor_public_key_material(&keyid)),
        sig: BASE64_STANDARD.encode(rekor_signature_material(&signature_hex)),
        keyid,
    }
}

/// Returned by `POST /api/v1/log/entries`. Rekor's real response is a
/// map keyed by UUID; we treat the first key as the canonical UUID.
#[derive(Debug, Deserialize)]
struct RekorPublishResponse {
    #[serde(flatten)]
    entries: std::collections::BTreeMap<String, RekorEntry>,
}

/// A single Rekor entry. `body` is base64-JCS of the original
/// `RekorEntryRequest`; we re-decode and pull
/// `spec.content.hash.value` to detect lane-side substitution.
///
/// The SET (signedEntryTimestamp) is the Rekor-key-signed envelope
/// over `{body, integratedTime, logID, logIndex}` in canonical JSON.
/// We rebuild that envelope locally, hash it under SHA-256, and
/// verify the ECDSA signature against [`REKOR_PUBLIC_KEY_PEM`].
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RekorEntry {
    body: String,
    integrated_time: i64,
    #[serde(rename = "logID")]
    log_id: String,
    log_index: i64,
    #[serde(default)]
    verification: Option<RekorVerification>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RekorVerification {
    #[serde(default)]
    inclusion_proof: Option<RekorInclusionProof>,
    #[serde(default)]
    signed_entry_timestamp: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RekorInclusionProof {
    log_index: Option<i64>,
    root_hash: Option<String>,
    tree_size: Option<i64>,
    hashes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RekorEntryBody {
    spec: RekorEntryBodySpec,
}

#[derive(Debug, Deserialize)]
struct RekorEntryBodySpec {
    content: RekorEntryBodyContent,
}

#[derive(Debug, Deserialize)]
struct RekorEntryBodyContent {
    hash: RekorHashOwned,
}

#[derive(Debug, Deserialize)]
struct RekorHashOwned {
    algorithm: String,
    value: String,
}

fn extract_lane_body_hash(entry: &RekorEntry) -> Result<String, AnchorWitnessError> {
    let raw = BASE64_STANDARD
        .decode(entry.body.as_bytes())
        .map_err(|error| AnchorWitnessError::Decode(format!("rekor body base64: {error}")))?;
    let parsed: RekorEntryBody = serde_json::from_slice(&raw)
        .map_err(|error| AnchorWitnessError::Decode(format!("rekor body json: {error}")))?;
    if !parsed
        .spec
        .content
        .hash
        .algorithm
        .eq_ignore_ascii_case("sha256")
    {
        return Err(AnchorWitnessError::Decode(format!(
            "rekor entry hash algorithm {} is not sha256",
            parsed.spec.content.hash.algorithm
        )));
    }
    Ok(parsed.spec.content.hash.value.to_ascii_lowercase())
}

/// Re-canonicalize the SET-signed envelope per Rekor's spec.
///
/// Per `pkg/api/rekor_pubsub.go` and the OpenAPI spec, the SET is an
/// ECDSA signature (DER, P-256/SHA-256) over the canonical JSON of:
///
/// ```text
/// { "body": <body_b64>, "integratedTime": <i64>, "logID": <hex>, "logIndex": <i64> }
/// ```
///
/// Field order must match the canonical key ordering RFC 8785 / JCS
/// produces (alphabetical at every level). We use the workspace's
/// existing JCS canonicalizer to stay byte-equivalent with Rekor's
/// implementation.
fn build_set_canonical_envelope(entry: &RekorEntry) -> Result<Vec<u8>, AnchorWitnessError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SetCanonical<'a> {
        body: &'a str,
        integrated_time: i64,
        #[serde(rename = "logID")]
        log_id: &'a str,
        log_index: i64,
    }
    let payload = SetCanonical {
        body: entry.body.as_str(),
        integrated_time: entry.integrated_time,
        log_id: entry.log_id.as_str(),
        log_index: entry.log_index,
    };
    canonical_json_bytes(&payload)
        .map_err(|error| AnchorWitnessError::Decode(format!("rekor SET canonicalize: {error}")))
}

fn verify_set_signature(
    entry: &RekorEntry,
    trusted_keys_pem: &[String],
) -> Result<(), AnchorWitnessError> {
    let verification = entry.verification.as_ref().ok_or_else(|| {
        AnchorWitnessError::SignatureInvalid(
            "rekor entry has no verification block (no SET to validate)".to_string(),
        )
    })?;
    let set_b64 = verification
        .signed_entry_timestamp
        .as_deref()
        .ok_or_else(|| {
            AnchorWitnessError::SignatureInvalid(
                "rekor entry verification block has no signedEntryTimestamp".to_string(),
            )
        })?;
    let set_bytes = BASE64_STANDARD
        .decode(set_b64.as_bytes())
        .map_err(|error| AnchorWitnessError::Decode(format!("rekor SET base64: {error}")))?;
    let signature = P256Signature::from_der(&set_bytes).map_err(|error| {
        AnchorWitnessError::SignatureInvalid(format!("rekor SET ECDSA DER decode: {error}"))
    })?;
    let envelope = build_set_canonical_envelope(entry)?;

    let mut last_error: Option<String> = None;
    for pem_str in trusted_keys_pem {
        match VerifyingKey::from_public_key_pem(pem_str) {
            Ok(key) => match key.verify(&envelope, &signature) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error.to_string()),
            },
            Err(error) => {
                last_error = Some(format!("trusted key PEM parse: {error}"));
            }
        }
    }
    Err(AnchorWitnessError::SignatureInvalid(format!(
        "rekor SET signature did not verify against any pinned key: {}",
        last_error.unwrap_or_else(|| "no trusted keys configured".to_string())
    )))
}

/// RFC 6962 leaf-hash domain prefix (`MTH({d}) = SHA-256(0x00 || d)`).
const RFC6962_LEAF_PREFIX: u8 = 0x00;
/// RFC 6962 node-hash domain prefix
/// (`MTH(D) = SHA-256(0x01 || left || right)`).
const RFC6962_NODE_PREFIX: u8 = 0x01;

/// Hash a transparency-log leaf per RFC 6962 section 2.1:
/// `SHA-256(0x00 || leaf_bytes)`. For a Rekor entry the leaf bytes are
/// the base64-decoded canonical `body`.
fn rfc6962_leaf_hash(leaf_bytes: &[u8]) -> Hash {
    let mut buffer = Vec::with_capacity(1 + leaf_bytes.len());
    buffer.push(RFC6962_LEAF_PREFIX);
    buffer.extend_from_slice(leaf_bytes);
    sha256(&buffer)
}

/// Hash two child subtree roots into their parent per RFC 6962:
/// `SHA-256(0x01 || left || right)`.
fn rfc6962_node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut buffer = [0u8; 1 + 32 + 32];
    buffer[0] = RFC6962_NODE_PREFIX;
    buffer[1..33].copy_from_slice(left.as_bytes());
    buffer[33..].copy_from_slice(right.as_bytes());
    sha256(&buffer)
}

/// Recompute a Merkle tree head from an inclusion proof per RFC 6962
/// section 2.1.1 (the algorithm Rekor's transparency log uses).
///
/// `leaf_index` is the zero-based position of the leaf in a tree of
/// `tree_size` leaves; `audit_path` is the ordered list of sibling
/// hashes from the leaf up to the root. Returns the computed root or a
/// fail-closed error if the index is out of range or the path length
/// does not match the tree geometry (a truncated or padded path is a
/// forged proof).
fn rfc6962_root_from_inclusion_proof(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: Hash,
    audit_path: &[Hash],
) -> Result<Hash, AnchorWitnessError> {
    if tree_size == 0 {
        return Err(AnchorWitnessError::SignatureInvalid(
            "rekor inclusion proof has zero tree size".to_string(),
        ));
    }
    if leaf_index >= tree_size {
        return Err(AnchorWitnessError::SignatureInvalid(format!(
            "rekor inclusion proof logIndex {leaf_index} is out of range for treeSize {tree_size}"
        )));
    }

    // `fn`/`sn` track the leaf index and the index of the last leaf as
    // we ascend the tree (RFC 6962 verifier algorithm). At each level a
    // node is a right child when its index is odd, or when it is the
    // rightmost node at that level (`fn == sn`); otherwise it is a left
    // child and its sibling is to the right.
    let mut node_index = leaf_index;
    let mut last_index = tree_size - 1;
    let mut computed = leaf_hash;
    let mut consumed = 0usize;

    while last_index > 0 {
        let sibling = audit_path.get(consumed).ok_or_else(|| {
            AnchorWitnessError::SignatureInvalid(format!(
                "rekor inclusion proof audit path too short: needed more than {} hashes for treeSize {tree_size}",
                audit_path.len()
            ))
        })?;
        consumed += 1;

        if !node_index.is_multiple_of(2) || node_index == last_index {
            computed = rfc6962_node_hash(sibling, &computed);
            // Skip levels where this node has no left sibling until it
            // settles into a left/odd position (handles the rightmost
            // edge of an unbalanced tree).
            while node_index.is_multiple_of(2) {
                node_index >>= 1;
                last_index >>= 1;
            }
        } else {
            computed = rfc6962_node_hash(&computed, sibling);
        }
        node_index >>= 1;
        last_index >>= 1;
    }

    if consumed != audit_path.len() {
        return Err(AnchorWitnessError::SignatureInvalid(format!(
            "rekor inclusion proof audit path too long: consumed {consumed} of {} hashes for treeSize {tree_size}",
            audit_path.len()
        )));
    }
    Ok(computed)
}

/// Decode a Rekor inclusion-proof hash. Rekor encodes audit-path and
/// root hashes as unprefixed lowercase hex; we accept an optional `0x`
/// prefix defensively. Must decode to exactly 32 bytes (SHA-256).
fn decode_proof_hash(value: &str, label: &str) -> Result<Hash, AnchorWitnessError> {
    Hash::from_hex(value).map_err(|error| {
        AnchorWitnessError::SignatureInvalid(format!(
            "rekor inclusion proof {label} is not a 32-byte hex hash: {error}"
        ))
    })
}

/// Verify the Rekor inclusion proof, when present, against the entry.
///
/// This is the Merkle half of inclusion verification (the SET is the
/// signature half). The proof is bound to the SET-authenticated entry
/// by two checks:
///
/// 1. The leaf hashed into the tree is `SHA-256(0x00 || body_bytes)`
///    for the SAME base64 `body` the SET signed, so a mirror cannot
///    swap in a proof for a different entry.
/// 2. The proof's `logIndex`, when carried, MUST equal the entry's
///    SET-signed `logIndex`.
///
/// The recomputed RFC 6962 tree head must then equal the proof's
/// `rootHash`. Any missing required field (rootHash, treeSize), a
/// logIndex disagreement, an out-of-range index, a malformed hash, a
/// truncated or padded audit path, or a root mismatch fails closed.
///
/// When the entry carries no `verification.inclusionProof`, this is a
/// no-op: the SET remains the authoritative authentication. Rekor
/// responses are not guaranteed to inline an inclusion proof, and the
/// pinned-key SET already binds the (body, logIndex) tuple.
fn verify_inclusion_proof(entry: &RekorEntry) -> Result<(), AnchorWitnessError> {
    let Some(proof) = entry
        .verification
        .as_ref()
        .and_then(|verification| verification.inclusion_proof.as_ref())
    else {
        return Ok(());
    };

    let tree_size = proof.tree_size.ok_or_else(|| {
        AnchorWitnessError::SignatureInvalid(
            "rekor inclusion proof is missing treeSize".to_string(),
        )
    })?;
    if tree_size <= 0 {
        return Err(AnchorWitnessError::SignatureInvalid(format!(
            "rekor inclusion proof treeSize {tree_size} is not positive"
        )));
    }
    let tree_size = tree_size as u64;

    // The proof index defaults to the SET-signed logIndex; when the
    // proof carries its own logIndex it MUST agree (a disagreement
    // means the mirror stapled a proof for a different leaf).
    let proof_index = match proof.log_index {
        Some(index) => {
            if index != entry.log_index {
                return Err(AnchorWitnessError::SignatureInvalid(format!(
                    "rekor inclusion proof logIndex {index} does not match SET-signed logIndex {}",
                    entry.log_index
                )));
            }
            index
        }
        None => entry.log_index,
    };
    if proof_index < 0 {
        return Err(AnchorWitnessError::SignatureInvalid(format!(
            "rekor inclusion proof logIndex {proof_index} is negative"
        )));
    }
    let proof_index = proof_index as u64;

    let root_hash_hex = proof.root_hash.as_deref().ok_or_else(|| {
        AnchorWitnessError::SignatureInvalid(
            "rekor inclusion proof is missing rootHash".to_string(),
        )
    })?;
    let expected_root = decode_proof_hash(root_hash_hex, "rootHash")?;

    let audit_path = proof
        .hashes
        .as_deref()
        .ok_or_else(|| {
            AnchorWitnessError::SignatureInvalid(
                "rekor inclusion proof is missing audit path hashes".to_string(),
            )
        })?
        .iter()
        .map(|hash_hex| decode_proof_hash(hash_hex, "audit path hash"))
        .collect::<Result<Vec<Hash>, AnchorWitnessError>>()?;

    let leaf_bytes = BASE64_STANDARD
        .decode(entry.body.as_bytes())
        .map_err(|error| {
            AnchorWitnessError::Decode(format!("rekor inclusion proof body base64: {error}"))
        })?;
    let leaf_hash = rfc6962_leaf_hash(&leaf_bytes);

    let computed_root =
        rfc6962_root_from_inclusion_proof(proof_index, tree_size, leaf_hash, &audit_path)?;
    if computed_root != expected_root {
        return Err(AnchorWitnessError::SignatureInvalid(format!(
            "rekor inclusion proof root mismatch: recomputed {} but proof asserts {}",
            computed_root.to_hex(),
            expected_root.to_hex()
        )));
    }
    Ok(())
}

#[async_trait::async_trait]
impl AnchorWitnessClient for RekorClient {
    async fn publish(&self, batch: &AnchorBatch) -> Result<WitnessReceipt, AnchorWitnessError> {
        let body_hash = batch_body_hash(batch)?;
        let body_hash_hex = body_hash.to_hex();
        let body_bytes = canonical_json_bytes(&batch.body)
            .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
        let payload_b64 = BASE64_STANDARD.encode(&body_bytes);
        let dsse_signature = rekor_dsse_signature_material(batch);
        let request = RekorEntryRequest {
            api_version: "0.0.2",
            kind: "intoto",
            spec: RekorIntotoSpec {
                content: RekorIntotoContent {
                    envelope: RekorIntotoEnvelope {
                        payload: &payload_b64,
                        payload_type: REKOR_INTOTO_PAYLOAD_TYPE,
                        signatures: vec![dsse_signature.as_signature()],
                    },
                    hash: RekorHash {
                        algorithm: "sha256",
                        value: body_hash_hex.clone(),
                    },
                },
            },
        };

        let response = self
            .http
            .post(self.entries_url())
            .json(&request)
            // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: paired with builder above.
            .send()
            .await
            .map_err(|error| AnchorWitnessError::Network(error.to_string()))?;
        let status = response.status();
        let raw_body = response
            .text()
            .await
            .map_err(|error| AnchorWitnessError::Network(error.to_string()))?;
        if !status.is_success() {
            return Err(AnchorWitnessError::Http {
                status: status.as_u16(),
                body: raw_body,
            });
        }
        let parsed: RekorPublishResponse = serde_json::from_str(&raw_body)
            .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
        let (uuid, entry) = parsed.entries.into_iter().next().ok_or_else(|| {
            AnchorWitnessError::Decode("rekor publish returned no entries".to_string())
        })?;
        let lane_hash = extract_lane_body_hash(&entry)?;
        if lane_hash != body_hash_hex.to_ascii_lowercase() {
            return Err(AnchorWitnessError::BodyHashMismatch {
                lane: lane_hash,
                batch: body_hash_hex,
            });
        }
        // Rekor's publish response carries a SET; verify it now so we
        // never persist a Witnessed receipt that fails the lane-pinned
        // signature check.
        verify_set_signature(&entry, &self.trusted_keys)?;
        // If the response inlines a Merkle inclusion proof, verify it
        // against the entry leaf and the asserted root before we treat
        // the entry as witnessed. Absent proof leaves the SET as the
        // authoritative authentication.
        verify_inclusion_proof(&entry)?;
        let inclusion_proof_bytes = entry
            .verification
            .as_ref()
            .and_then(|verification| verification.inclusion_proof.as_ref())
            .and_then(|proof| serde_json::to_vec(proof).ok())
            .unwrap_or_default();
        Ok(WitnessReceipt {
            kind: AnchorBatchWitnessKind::Rekor,
            external_uuid: uuid,
            published_at: entry.integrated_time,
            inclusion_proof: inclusion_proof_bytes,
            witness_root: batch.body.tree_root,
            body_hash,
        })
    }

    async fn verify_inclusion(&self, receipt: &WitnessReceipt) -> Result<(), AnchorWitnessError> {
        if receipt.kind != AnchorBatchWitnessKind::Rekor {
            return Err(AnchorWitnessError::Config(format!(
                "RekorClient asked to verify {:?} receipt",
                receipt.kind
            )));
        }
        let response = self
            .http
            .get(self.entry_by_uuid_url(&receipt.external_uuid))
            // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: paired with builder above.
            .send()
            .await
            .map_err(|error| AnchorWitnessError::Network(error.to_string()))?;
        let status = response.status();
        let raw_body = response
            .text()
            .await
            .map_err(|error| AnchorWitnessError::Network(error.to_string()))?;
        if !status.is_success() {
            return Err(AnchorWitnessError::Http {
                status: status.as_u16(),
                body: raw_body,
            });
        }
        let parsed: RekorPublishResponse = serde_json::from_str(&raw_body)
            .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
        let entry = parsed.entries.get(&receipt.external_uuid).ok_or_else(|| {
            AnchorWitnessError::Decode(format!(
                "rekor returned no entry for uuid {}",
                receipt.external_uuid
            ))
        })?;
        let lane_hash_hex = extract_lane_body_hash(entry)?;
        let expected_hex = receipt.body_hash.to_hex();
        if lane_hash_hex != expected_hex.to_ascii_lowercase() {
            return Err(AnchorWitnessError::BodyHashMismatch {
                lane: lane_hash_hex,
                batch: expected_hex,
            });
        }
        // SET signature against the pinned Rekor public key. This is
        // the substantive authentication of the inclusion response;
        // without it, a malicious mirror could forge any
        // body+integratedTime triple.
        verify_set_signature(entry, &self.trusted_keys)?;
        // Merkle inclusion proof, when the lane returns one: rebuild
        // the RFC 6962 tree head from the entry leaf and audit path and
        // assert it equals the asserted root, bound to the SET-signed
        // logIndex. Fails closed on any malformed or mismatched proof.
        verify_inclusion_proof(entry)?;

        let now = chrono_now_unix();
        if self.max_witness_age_seconds > 0
            && now.saturating_sub(entry.integrated_time) > self.max_witness_age_seconds
        {
            return Err(AnchorWitnessError::Stale {
                published_at: entry.integrated_time,
                now,
                max_age_seconds: self.max_witness_age_seconds,
            });
        }
        Ok(())
    }
}

fn chrono_now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// Build the canonical Rekor "body" payload that a real Rekor server
/// would echo back. Exposed so tests (and the negative conformance
/// suite) can stage faithful mock responses without depending on the
/// production Rekor staging deployment.
pub fn build_rekor_entry_body_b64(batch: &AnchorBatch) -> Result<String, AnchorWitnessError> {
    let body_hash = batch_body_hash(batch)?;
    let body_hash_hex = body_hash.to_hex();
    let canonical = canonical_json_bytes(&batch.body)
        .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
    let payload_b64 = BASE64_STANDARD.encode(&canonical);
    let dsse_signature = rekor_dsse_signature_material(batch);
    let request = RekorEntryRequest {
        api_version: "0.0.2",
        kind: "intoto",
        spec: RekorIntotoSpec {
            content: RekorIntotoContent {
                envelope: RekorIntotoEnvelope {
                    payload: &payload_b64,
                    payload_type: REKOR_INTOTO_PAYLOAD_TYPE,
                    signatures: vec![dsse_signature.as_signature()],
                },
                hash: RekorHash {
                    algorithm: "sha256",
                    value: body_hash_hex,
                },
            },
        },
    };
    let bytes = serde_json::to_vec(&request)
        .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
    Ok(BASE64_STANDARD.encode(bytes))
}

/// Build a Rekor body payload that commits to `forged_hash` instead of
/// the batch's real body hash. Used by the witness-impersonation
/// negative test to simulate a lane that returns an entry whose
/// `spec.content.hash.value` does not match the batch.
pub fn build_rekor_entry_body_b64_with_hash(
    batch: &AnchorBatch,
    forged_hash_hex: &str,
) -> Result<String, AnchorWitnessError> {
    let canonical = canonical_json_bytes(&batch.body)
        .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
    let payload_b64 = BASE64_STANDARD.encode(&canonical);
    let dsse_signature = rekor_dsse_signature_material(batch);
    let request = RekorEntryRequest {
        api_version: "0.0.2",
        kind: "intoto",
        spec: RekorIntotoSpec {
            content: RekorIntotoContent {
                envelope: RekorIntotoEnvelope {
                    payload: &payload_b64,
                    payload_type: REKOR_INTOTO_PAYLOAD_TYPE,
                    signatures: vec![dsse_signature.as_signature()],
                },
                hash: RekorHash {
                    algorithm: "sha256",
                    value: forged_hash_hex.to_string(),
                },
            },
        },
    };
    let bytes = serde_json::to_vec(&request)
        .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
    Ok(BASE64_STANDARD.encode(bytes))
}

/// Build a synthetic Rekor publish response payload. Tests use this
/// to stage mock-server responses that look indistinguishable from
/// production Rekor.
///
/// The `signed_entry_timestamp_b64` argument carries the
/// pre-computed SET (base64 ECDSA-DER over the canonical envelope).
/// Tests that want to exercise the SET-verification path generate it
/// with [`sign_set_with_test_key`]. Tests that want to exercise the
/// SET-rejection path pass a SET signed by a non-pinned key, or
/// `None` for "no SET at all".
pub fn build_rekor_publish_response(
    uuid: &str,
    body_b64: &str,
    integrated_time: i64,
    log_index: i64,
) -> serde_json::Value {
    serde_json::json!({
        uuid: {
            "body": body_b64,
            "integratedTime": integrated_time,
            "logID": "0".repeat(64),
            "logIndex": log_index,
        }
    })
}

/// Like [`build_rekor_publish_response`] but also embeds a
/// pre-computed signed-entry-timestamp under
/// `verification.signedEntryTimestamp`. Tests use this to stage a
/// faithful response that the SET-aware verifier will accept (when
/// the SET was signed by a key in the client's trusted set).
pub fn build_rekor_publish_response_with_set(
    uuid: &str,
    body_b64: &str,
    integrated_time: i64,
    log_index: i64,
    signed_entry_timestamp_b64: &str,
) -> serde_json::Value {
    serde_json::json!({
        uuid: {
            "body": body_b64,
            "integratedTime": integrated_time,
            "logID": "0".repeat(64),
            "logIndex": log_index,
            "verification": {
                "signedEntryTimestamp": signed_entry_timestamp_b64,
            }
        }
    })
}

/// Sign the canonical SET envelope `{body, integratedTime, logID,
/// logIndex}` with a P-256 signing key and return the base64-DER
/// signature. Test-only; never called from production paths.
pub fn sign_set_with_test_key(
    body_b64: &str,
    integrated_time: i64,
    log_id_hex: &str,
    log_index: i64,
    signing_key: &p256::ecdsa::SigningKey,
) -> Result<String, AnchorWitnessError> {
    use p256::ecdsa::signature::Signer;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SetCanonical<'a> {
        body: &'a str,
        integrated_time: i64,
        #[serde(rename = "logID")]
        log_id: &'a str,
        log_index: i64,
    }
    let payload = SetCanonical {
        body: body_b64,
        integrated_time,
        log_id: log_id_hex,
        log_index,
    };
    let envelope = canonical_json_bytes(&payload)
        .map_err(|error| AnchorWitnessError::Decode(format!("test SET canonicalize: {error}")))?;
    let signature: P256Signature = signing_key.sign(&envelope);
    Ok(BASE64_STANDARD.encode(signature.to_der().as_bytes()))
}

/// Tests-only: encode a `p256::ecdsa::VerifyingKey` to PEM so it can
/// be installed via [`RekorClient::with_trusted_keys`].
pub fn verifying_key_to_pem(key: &p256::ecdsa::VerifyingKey) -> Result<String, AnchorWitnessError> {
    use p256::pkcs8::EncodePublicKey;
    key.to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|error| AnchorWitnessError::Decode(format!("test pubkey PEM: {error}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::batch::{build_anchor_batch, AnchorBatchWitness, AnchorBatchWitnessKind};
    use crate::witness::batch_body_hash;
    use chio_core::hashing::Hash;
    use chio_core::Keypair;

    fn sample_batch() -> AnchorBatch {
        let kp = Keypair::generate();
        let witness = AnchorBatchWitness {
            kind: AnchorBatchWitnessKind::Rekor,
            witness_id: "rekor:placeholder".to_string(),
            root: Hash::zero(),
            observed_at: Some(1_700_000_000),
        };
        build_anchor_batch(
            vec!["ck-1".to_string(), "ck-2".to_string()],
            witness,
            1_700_000_000,
            &kp,
        )
        .unwrap()
    }

    #[test]
    fn rekor_body_b64_round_trips_real_batch_hash() {
        let batch = sample_batch();
        let body = build_rekor_entry_body_b64(&batch).unwrap();
        let raw = BASE64_STANDARD.decode(body.as_bytes()).unwrap();
        let parsed: RekorEntryBody = serde_json::from_slice(&raw).unwrap();
        let expected = batch_body_hash(&batch).unwrap().to_hex();
        assert_eq!(parsed.spec.content.hash.value, expected);
    }

    /// The DSSE envelope wire shape
    /// MUST use Rekor's canonical camelCase keys (`payloadType`,
    /// `apiVersion`) and the in-toto payload type. Inspect the raw
    /// JSON bytes to catch any future serde drift.
    #[test]
    fn rekor_intoto_envelope_uses_camel_case_wire_shape() {
        let batch = sample_batch();
        let body_b64 = build_rekor_entry_body_b64(&batch).unwrap();
        let raw = BASE64_STANDARD.decode(body_b64.as_bytes()).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();

        // apiVersion, not api_version, at the top level.
        assert!(
            value.get("apiVersion").is_some(),
            "expected apiVersion key, got: {value}"
        );
        assert_eq!(value["apiVersion"].as_str(), Some("0.0.2"));
        assert!(
            value.get("api_version").is_none(),
            "snake_case api_version leaked into wire shape: {value}"
        );

        // payloadType, not payload_type, inside the envelope.
        let envelope = &value["spec"]["content"]["envelope"];
        assert_eq!(
            envelope["payloadType"].as_str(),
            Some(REKOR_INTOTO_PAYLOAD_TYPE),
            "expected DSSE in-toto payloadType, got: {envelope}"
        );
        assert!(
            envelope.get("payload_type").is_none(),
            "snake_case payload_type leaked into wire shape: {envelope}"
        );
        // P1: intoto v0.0.2 requires at least one publicKey/sig entry.
        assert!(
            envelope["signatures"].is_array(),
            "DSSE envelope must carry a signatures array: {envelope}"
        );
        let signatures = envelope["signatures"].as_array().unwrap();
        assert_eq!(signatures.len(), 1);
        let signature = &signatures[0];
        assert!(
            signature["publicKey"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "DSSE signature must carry publicKey material: {signature}"
        );
        assert!(
            signature["sig"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "DSSE signature must carry signature material: {signature}"
        );
    }

    #[test]
    fn rekor_client_rejects_blank_endpoint() {
        let err = RekorClient::new("", 60).unwrap_err();
        assert!(matches!(err, AnchorWitnessError::Config(_)));
    }

    /// SET signature round-trip: a SET signed by a known P-256 key
    /// verifies under the same key but is rejected under any other
    /// key (including the pinned production Rekor key).
    #[test]
    fn rekor_set_signature_round_trips() {
        use p256::ecdsa::SigningKey;
        let mut rng = rand::rngs::OsRng;
        let signing = SigningKey::random(&mut rng);
        let verifying_pem = verifying_key_to_pem(signing.verifying_key()).unwrap();

        let body_b64 = "ZHVtbXktYm9keQ==";
        let log_id = "0".repeat(64);
        let set_b64 =
            sign_set_with_test_key(body_b64, 1_700_000_010, &log_id, 42, &signing).unwrap();

        let entry = RekorEntry {
            body: body_b64.to_string(),
            integrated_time: 1_700_000_010,
            log_id: log_id.clone(),
            log_index: 42,
            verification: Some(RekorVerification {
                inclusion_proof: None,
                signed_entry_timestamp: Some(set_b64),
            }),
        };
        verify_set_signature(&entry, &[verifying_pem]).expect("SET must verify under signer key");
        // A different key (the pinned production key) must NOT
        // verify the test SET.
        let err = verify_set_signature(&entry, &[REKOR_PUBLIC_KEY_PEM.to_string()])
            .expect_err("SET must be rejected under a non-signing key");
        assert!(matches!(err, AnchorWitnessError::SignatureInvalid(_)));
    }

    // --- Inclusion-proof (RFC 6962) test fixtures and vectors -------
    //
    // The fixture below builds a reference Merkle tree from leaf bytes
    // using the SAME RFC 6962 hashing the verifier uses
    // (`SHA-256(0x00 || leaf)` for leaves, `SHA-256(0x01 || l || r)`
    // for nodes) and derives the audit path for any leaf. Because the
    // tree is built independently of `rfc6962_root_from_inclusion_proof`
    // (recursive split-at-largest-power-of-two vs the iterative
    // verifier ascent), a passing round-trip is a genuine cross-check,
    // not a tautology. The known-good vectors are then tampered to
    // confirm fail-closed behavior.

    /// Reference RFC 6962 Merkle tree over arbitrary leaf byte strings.
    struct ReferenceMerkleTree {
        leaf_hashes: Vec<Hash>,
    }

    impl ReferenceMerkleTree {
        fn from_leaves(leaves: &[&[u8]]) -> Self {
            let leaf_hashes = leaves
                .iter()
                .map(|leaf| rfc6962_leaf_hash(leaf))
                .collect::<Vec<_>>();
            ReferenceMerkleTree { leaf_hashes }
        }

        fn size(&self) -> u64 {
            self.leaf_hashes.len() as u64
        }

        /// Root of the subtree spanning `leaves` (RFC 6962 section 2.1:
        /// split at the largest power of two strictly less than the
        /// subtree width).
        fn subtree_root(leaves: &[Hash]) -> Hash {
            match leaves {
                [] => rfc6962_leaf_hash(&[]),
                [single] => *single,
                _ => {
                    let split = largest_power_of_two_below(leaves.len());
                    let left = Self::subtree_root(&leaves[..split]);
                    let right = Self::subtree_root(&leaves[split..]);
                    rfc6962_node_hash(&left, &right)
                }
            }
        }

        fn root(&self) -> Hash {
            Self::subtree_root(&self.leaf_hashes)
        }

        /// Audit path for `index`: the ordered sibling hashes from the
        /// leaf up to (but excluding) the root.
        fn audit_path(&self, index: usize) -> Vec<Hash> {
            let mut path = Vec::new();
            Self::collect_path(&self.leaf_hashes, index, &mut path);
            path
        }

        fn collect_path(leaves: &[Hash], index: usize, path: &mut Vec<Hash>) {
            if leaves.len() <= 1 {
                return;
            }
            let split = largest_power_of_two_below(leaves.len());
            if index < split {
                // Target is in the left subtree; sibling is the right
                // subtree root.
                let right = Self::subtree_root(&leaves[split..]);
                Self::collect_path(&leaves[..split], index, path);
                path.push(right);
            } else {
                // Target is in the right subtree; sibling is the left
                // subtree root.
                let left = Self::subtree_root(&leaves[..split]);
                Self::collect_path(&leaves[split..], index - split, path);
                path.push(left);
            }
        }
    }

    /// Largest power of two strictly less than `n` (RFC 6962 split
    /// point). `n` must be >= 2.
    fn largest_power_of_two_below(n: usize) -> usize {
        let mut k = 1usize;
        while k < n {
            k <<= 1;
        }
        k >> 1
    }

    fn proof_from_reference(tree: &ReferenceMerkleTree, index: usize) -> RekorInclusionProof {
        RekorInclusionProof {
            log_index: Some(index as i64),
            root_hash: Some(tree.root().to_hex()),
            tree_size: Some(tree.size() as i64),
            hashes: Some(tree.audit_path(index).iter().map(Hash::to_hex).collect()),
        }
    }

    fn entry_with_inclusion_proof(
        body_bytes: &[u8],
        log_index: i64,
        proof: RekorInclusionProof,
    ) -> RekorEntry {
        RekorEntry {
            body: BASE64_STANDARD.encode(body_bytes),
            integrated_time: 1_700_000_010,
            log_id: "0".repeat(64),
            log_index,
            verification: Some(RekorVerification {
                inclusion_proof: Some(proof),
                signed_entry_timestamp: None,
            }),
        }
    }

    /// The verifier's iterative ascent must reproduce the reference
    /// tree root for every leaf, across balanced and unbalanced trees.
    #[test]
    fn rfc6962_recomputes_reference_root_for_every_leaf() {
        for leaf_count in 1usize..=9 {
            let owned: Vec<Vec<u8>> = (0..leaf_count)
                .map(|i| format!("rekor-leaf-{i}").into_bytes())
                .collect();
            let leaves: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
            let tree = ReferenceMerkleTree::from_leaves(&leaves);
            let expected_root = tree.root();
            for (index, &leaf) in leaves.iter().enumerate() {
                let leaf_hash = rfc6962_leaf_hash(leaf);
                let path = tree.audit_path(index);
                let computed = rfc6962_root_from_inclusion_proof(
                    index as u64,
                    leaf_count as u64,
                    leaf_hash,
                    &path,
                )
                .expect("known-good proof must recompute the root");
                assert_eq!(
                    computed, expected_root,
                    "leaf {index} of {leaf_count}-leaf tree must recompute the reference root"
                );
            }
        }
    }

    /// End-to-end known-good inclusion proof over a Rekor entry: a
    /// 5-leaf (unbalanced) tree exercises the rightmost-edge ascent.
    #[test]
    fn verify_inclusion_proof_accepts_known_good_vector() {
        let bodies: Vec<Vec<u8>> = (0..5).map(|i| format!("body-{i}").into_bytes()).collect();
        let leaves: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
        let tree = ReferenceMerkleTree::from_leaves(&leaves);
        // Pick the last leaf (index 4) so the audit path climbs the
        // unbalanced right edge.
        let index = 4usize;
        let proof = proof_from_reference(&tree, index);
        let entry = entry_with_inclusion_proof(leaves[index], index as i64, proof);
        verify_inclusion_proof(&entry).expect("known-good inclusion proof must verify");
    }

    /// Absent inclusion proof is a no-op: the SET remains the
    /// authoritative authentication and verification must not fail.
    #[test]
    fn verify_inclusion_proof_is_noop_when_absent() {
        let entry = RekorEntry {
            body: BASE64_STANDARD.encode(b"no-proof-body"),
            integrated_time: 1_700_000_010,
            log_id: "0".repeat(64),
            log_index: 3,
            verification: Some(RekorVerification {
                inclusion_proof: None,
                signed_entry_timestamp: Some("set".to_string()),
            }),
        };
        verify_inclusion_proof(&entry).expect("absent inclusion proof must be a no-op");

        // Also a no-op when there is no verification block at all.
        let bare = RekorEntry {
            body: BASE64_STANDARD.encode(b"bare-body"),
            integrated_time: 1_700_000_010,
            log_id: "0".repeat(64),
            log_index: 0,
            verification: None,
        };
        verify_inclusion_proof(&bare).expect("missing verification block must be a no-op");
    }

    /// Tamper: a wrong root hash must be rejected.
    #[test]
    fn verify_inclusion_proof_rejects_wrong_root() {
        let bodies: Vec<Vec<u8>> = (0..4).map(|i| format!("body-{i}").into_bytes()).collect();
        let leaves: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
        let tree = ReferenceMerkleTree::from_leaves(&leaves);
        let index = 1usize;
        let mut proof = proof_from_reference(&tree, index);
        // Flip the asserted root to an unrelated hash.
        proof.root_hash = Some(sha256(b"attacker-root").to_hex());
        let entry = entry_with_inclusion_proof(leaves[index], index as i64, proof);
        let err = verify_inclusion_proof(&entry).expect_err("a wrong root hash must fail closed");
        assert!(
            matches!(&err, AnchorWitnessError::SignatureInvalid(message) if message.contains("root mismatch")),
            "expected root-mismatch SignatureInvalid, got: {err:?}"
        );
    }

    /// Tamper: a wrong tree size must be rejected (the geometry no
    /// longer matches the audit-path length, or the recomputed root
    /// diverges).
    #[test]
    fn verify_inclusion_proof_rejects_wrong_tree_size() {
        let bodies: Vec<Vec<u8>> = (0..4).map(|i| format!("body-{i}").into_bytes()).collect();
        let leaves: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
        let tree = ReferenceMerkleTree::from_leaves(&leaves);
        let index = 1usize;
        let mut proof = proof_from_reference(&tree, index);
        // Claim a tree of 8 leaves while supplying a 4-leaf audit path.
        proof.tree_size = Some(8);
        let entry = entry_with_inclusion_proof(leaves[index], index as i64, proof);
        let err = verify_inclusion_proof(&entry).expect_err("a wrong tree size must fail closed");
        assert!(
            matches!(err, AnchorWitnessError::SignatureInvalid(_)),
            "expected SignatureInvalid for wrong tree size, got: {err:?}"
        );
    }

    /// Tamper: a truncated audit path (one sibling removed) must be
    /// rejected as too short.
    #[test]
    fn verify_inclusion_proof_rejects_truncated_path() {
        let bodies: Vec<Vec<u8>> = (0..5).map(|i| format!("body-{i}").into_bytes()).collect();
        let leaves: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
        let tree = ReferenceMerkleTree::from_leaves(&leaves);
        let index = 2usize;
        let mut proof = proof_from_reference(&tree, index);
        let mut hashes = proof.hashes.take().unwrap();
        assert!(!hashes.is_empty(), "fixture must have a non-empty path");
        hashes.pop();
        proof.hashes = Some(hashes);
        let entry = entry_with_inclusion_proof(leaves[index], index as i64, proof);
        let err =
            verify_inclusion_proof(&entry).expect_err("a truncated audit path must fail closed");
        assert!(
            matches!(&err, AnchorWitnessError::SignatureInvalid(message) if message.contains("too short")),
            "expected too-short SignatureInvalid, got: {err:?}"
        );
    }

    /// Tamper: a padded audit path (one extra sibling) must be
    /// rejected as too long.
    #[test]
    fn verify_inclusion_proof_rejects_padded_path() {
        let bodies: Vec<Vec<u8>> = (0..4).map(|i| format!("body-{i}").into_bytes()).collect();
        let leaves: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
        let tree = ReferenceMerkleTree::from_leaves(&leaves);
        let index = 0usize;
        let mut proof = proof_from_reference(&tree, index);
        let mut hashes = proof.hashes.take().unwrap();
        hashes.push(sha256(b"extra-sibling").to_hex());
        proof.hashes = Some(hashes);
        let entry = entry_with_inclusion_proof(leaves[index], index as i64, proof);
        let err = verify_inclusion_proof(&entry).expect_err("a padded audit path must fail closed");
        assert!(
            matches!(&err, AnchorWitnessError::SignatureInvalid(message) if message.contains("too long")),
            "expected too-long SignatureInvalid, got: {err:?}"
        );
    }

    /// Tamper: a proof logIndex that disagrees with the SET-signed
    /// logIndex must be rejected (a mirror stapling a foreign proof).
    #[test]
    fn verify_inclusion_proof_rejects_log_index_disagreement() {
        let bodies: Vec<Vec<u8>> = (0..4).map(|i| format!("body-{i}").into_bytes()).collect();
        let leaves: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
        let tree = ReferenceMerkleTree::from_leaves(&leaves);
        let index = 2usize;
        let proof = proof_from_reference(&tree, index);
        // Entry's SET-signed logIndex says 3, proof says 2.
        let entry = entry_with_inclusion_proof(leaves[index], 3, proof);
        let err =
            verify_inclusion_proof(&entry).expect_err("a logIndex disagreement must fail closed");
        assert!(
            matches!(&err, AnchorWitnessError::SignatureInvalid(message) if message.contains("logIndex")),
            "expected logIndex-mismatch SignatureInvalid, got: {err:?}"
        );
    }

    /// Tamper: an out-of-range logIndex (>= treeSize) must be rejected.
    #[test]
    fn verify_inclusion_proof_rejects_out_of_range_index() {
        let bodies: Vec<Vec<u8>> = (0..4).map(|i| format!("body-{i}").into_bytes()).collect();
        let leaves: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
        let tree = ReferenceMerkleTree::from_leaves(&leaves);
        let mut proof = proof_from_reference(&tree, 0);
        proof.log_index = Some(4); // treeSize is 4, so index 4 is out of range
        let entry = entry_with_inclusion_proof(leaves[0], 4, proof);
        let err =
            verify_inclusion_proof(&entry).expect_err("an out-of-range logIndex must fail closed");
        assert!(
            matches!(&err, AnchorWitnessError::SignatureInvalid(message) if message.contains("out of range")),
            "expected out-of-range SignatureInvalid, got: {err:?}"
        );
    }

    /// Tamper: a missing rootHash must be rejected.
    #[test]
    fn verify_inclusion_proof_rejects_missing_root_hash() {
        let bodies: Vec<Vec<u8>> = (0..4).map(|i| format!("body-{i}").into_bytes()).collect();
        let leaves: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
        let tree = ReferenceMerkleTree::from_leaves(&leaves);
        let mut proof = proof_from_reference(&tree, 1);
        proof.root_hash = None;
        let entry = entry_with_inclusion_proof(leaves[1], 1, proof);
        let err = verify_inclusion_proof(&entry).expect_err("a missing rootHash must fail closed");
        assert!(
            matches!(&err, AnchorWitnessError::SignatureInvalid(message) if message.contains("rootHash")),
            "expected missing-rootHash SignatureInvalid, got: {err:?}"
        );
    }

    /// Tamper: a missing treeSize must be rejected.
    #[test]
    fn verify_inclusion_proof_rejects_missing_tree_size() {
        let bodies: Vec<Vec<u8>> = (0..4).map(|i| format!("body-{i}").into_bytes()).collect();
        let leaves: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
        let tree = ReferenceMerkleTree::from_leaves(&leaves);
        let mut proof = proof_from_reference(&tree, 1);
        proof.tree_size = None;
        let entry = entry_with_inclusion_proof(leaves[1], 1, proof);
        let err = verify_inclusion_proof(&entry).expect_err("a missing treeSize must fail closed");
        assert!(
            matches!(&err, AnchorWitnessError::SignatureInvalid(message) if message.contains("treeSize")),
            "expected missing-treeSize SignatureInvalid, got: {err:?}"
        );
    }

    /// Tamper: a malformed (non-hex / wrong-length) audit-path hash
    /// must be rejected.
    #[test]
    fn verify_inclusion_proof_rejects_malformed_hash() {
        let bodies: Vec<Vec<u8>> = (0..4).map(|i| format!("body-{i}").into_bytes()).collect();
        let leaves: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
        let tree = ReferenceMerkleTree::from_leaves(&leaves);
        let mut proof = proof_from_reference(&tree, 1);
        let mut hashes = proof.hashes.take().unwrap();
        hashes[0] = "not-a-valid-hash".to_string();
        proof.hashes = Some(hashes);
        let entry = entry_with_inclusion_proof(leaves[1], 1, proof);
        let err = verify_inclusion_proof(&entry)
            .expect_err("a malformed audit-path hash must fail closed");
        assert!(
            matches!(err, AnchorWitnessError::SignatureInvalid(_)),
            "expected SignatureInvalid for malformed hash, got: {err:?}"
        );
    }
}
