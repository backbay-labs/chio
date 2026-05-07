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
//! HIGH-3 in PR #594 review: previously the client only inspected the
//! body hash and treated any well-formed JSON response as valid,
//! letting a malicious mirror forge inclusion responses. The SET
//! signature check fixes that. Inclusion-proof Merkle verification
//! against the log root is a follow-up (see TODO at hard expiry
//! 2026-08-01 below).
//!
//! This module makes a real HTTP call (via `reqwest`). The negative
//! conformance test
//! `crates/chio-conformance/tests/anchor_batch_witness_impersonation_rejected.rs`
//! exercises the full surface against a `tiny_http` mock server.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chio_core::canonical_json_bytes;
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
/// HIGH-2 (PR #594 round-2 review): the previous shape serialized
/// `payload_type` (snake_case) instead of Rekor's canonical
/// `payloadType` (camelCase). Real Rekor would either reject the
/// envelope or canonicalize it to a shape that would no longer
/// match the SET signature input. The `rename_all` annotation
/// fixes the wire shape.
///
/// P1 (PR #594 round-3 review): the previous shape carried an empty
/// `signatures` array. The intoto v0.0.2 schema requires a signature
/// object with `publicKey` and `sig`, so the entry now forwards the
/// batch signer key and batch signature into the DSSE envelope.
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
    // TODO(2026-08-01): also verify `verification.inclusionProof`
    // (rebuild the Merkle root from leaf_hash + audit_path; assert it
    // equals `inclusionProof.rootHash`; verify the checkpoint signed
    // by the Rekor log key). Until then we accept the SET as the
    // authoritative authentication of the entry. A malicious mirror
    // that controls the Rekor private key is out-of-scope for this
    // PR; that's the threat model the SET pinning addresses.
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
        // body+integratedTime triple. (HIGH-3 fix.)
        verify_set_signature(entry, &self.trusted_keys)?;

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
/// signature. Exposed for tests; production code never calls this.
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

    /// HIGH-2 (PR #594 round-2 review): the DSSE envelope wire shape
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
}
