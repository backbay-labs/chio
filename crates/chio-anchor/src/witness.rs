//! Public-witness lane clients for `chio.anchor_batch.v1`.
//!
//! Provides the [`AnchorWitnessClient`] trait, Rekor production verification,
//! OTS advisory parsing, and the [`WitnessState`] state machine consumed by
//! `verify_anchor_batch_with_witness_policy`.
//!
//! The clients implement the actual HTTP protocols used by Rekor REST
//! and OpenTimestamps calendars. Tests substitute mock servers where
//! load-bearing verification is available.
//!
//! # Soundness notes (PR #594 review fixes)
//!
//! - The receipt's `body_hash` binds a stable [`BatchHashInput`] view
//!   of the batch body that EXCLUDES `witness_state` and lane-assigned
//!   witness identifiers. This breaks the circular reference where
//!   signing a witnessed body would otherwise change the body the
//!   receipt was supposed to commit to.
//! - Honoring `WitnessState::Witnessed` against
//!   `require_public_witness=true` requires an active call to
//!   [`AnchorWitnessClient::verify_inclusion`]. Self-carried
//!   `Witnessed` states are not sufficient.
//! - `WitnessState::Stale` is admitted only if the recomputed
//!   [`batch_body_hash`] of the current batch maps to a verifier-owned
//!   `verified_at` timestamp inside the caller-supplied
//!   [`VerifiedWitnessCache`]. Producers cannot bootstrap themselves
//!   into the verified cache or refresh it by signing a fresh
//!   `last_verified` value.

pub mod ots;
pub mod rekor;

use std::collections::HashMap;

use chio_core::canonical_json_bytes;
use chio_core::hashing::{sha256, Hash};
use chio_core::PublicKey;
use serde::{Deserialize, Serialize};

use crate::batch::{AnchorBatch, AnchorBatchBody, AnchorBatchInclusion, AnchorBatchWitnessKind};

/// Receipt returned by an [`AnchorWitnessClient`] on successful
/// publication.
///
/// All fields are wire-stable and travel with the batch through
/// [`WitnessState::Witnessed`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WitnessReceipt {
    pub kind: AnchorBatchWitnessKind,
    /// External identifier returned by the witness lane (Rekor UUID,
    /// OTS calendar URI, Solana signature, etc.).
    pub external_uuid: String,
    /// Lane-side observation time (UNIX seconds, UTC).
    pub published_at: i64,
    /// Inclusion proof bytes returned by the lane (Rekor logEntry
    /// `body` hash chain, OTS DER blob, etc.). Opaque to the verifier
    /// other than via `verify_inclusion`.
    #[serde(with = "serde_bytes_b64")]
    pub inclusion_proof: Vec<u8>,
    /// Root that the witness lane committed to. MUST equal
    /// `batch.body.tree_root` for the receipt to be accepted.
    pub witness_root: Hash,
    /// SHA-256 digest of the canonical-JSON encoding of the
    /// [`BatchHashInput`] view of `batch.body` (excluding
    /// `witness_state`, `witness_id`, and witness observation time).
    /// Used by `verify_inclusion` to detect
    /// lane-side substitution attacks (the lane returned an entry that
    /// does not commit to our batch).
    pub body_hash: Hash,
}

mod serde_bytes_b64 {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BASE64_STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Errors raised by [`AnchorWitnessClient`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum AnchorWitnessError {
    #[error("witness network error: {0}")]
    Network(String),
    #[error("witness HTTP {status}: {body}")]
    Http { status: u16, body: String },
    #[error("witness body-hash mismatch: lane committed to {lane}, batch body hashes to {batch}")]
    BodyHashMismatch { lane: String, batch: String },
    #[error("witness root mismatch: lane committed to {lane}, batch tree_root is {batch}")]
    RootMismatch { lane: String, batch: String },
    #[error("witness receipt is stale: published_at={published_at} now={now} max_age_seconds={max_age_seconds}")]
    Stale {
        published_at: i64,
        now: i64,
        max_age_seconds: i64,
    },
    #[error("witness payload could not be parsed: {0}")]
    Decode(String),
    #[error("witness configuration error: {0}")]
    Config(String),
    #[error("witness lane signature verification failed: {0}")]
    SignatureInvalid(String),
}

/// Witness-lane interface. [`rekor::RekorClient`] can satisfy
/// load-bearing public-witness policy; [`ots::OtsClient`] currently
/// fails closed for that policy until trusted Bitcoin evidence is part
/// of the receipt contract.
///
/// Implementations MUST be fail-closed: a failed publish or a failed
/// inclusion-verify returns `Err(_)`, never silently downgrades the
/// batch to `WitnessState::Witnessed`.
#[async_trait::async_trait]
pub trait AnchorWitnessClient: Send + Sync {
    async fn publish(&self, batch: &AnchorBatch) -> Result<WitnessReceipt, AnchorWitnessError>;
    async fn verify_inclusion(&self, receipt: &WitnessReceipt) -> Result<(), AnchorWitnessError>;
}

/// Verifier-owned witness cache keyed by [`batch_body_hash`].
///
/// The value is the verifier's own UNIX-second timestamp from the
/// successful `AnchorWitnessClient::verify_inclusion` round-trip. It
/// is intentionally separate from producer-signed
/// `WitnessState::Stale::last_verified`, which remains telemetry only
/// and is not trusted for stale admission.
pub type VerifiedWitnessCache = HashMap<Hash, i64>;

/// Stable hash-input view of [`AnchorBatchBody`] used to compute the
/// receipt's `body_hash`.
///
/// The view EXCLUDES `witness_state` plus lane-assigned witness ids and
/// observation timestamps, breaking the circular reference in which
/// signing the batch with `WitnessState::Witnessed { receipt .. }`
/// would change the body that `receipt.body_hash` was supposed to
/// commit to. Verifiers re-derive this view from the final signed batch
/// and recompute the SHA-256.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchHashInput<'a> {
    pub schema: &'a str,
    pub tree_root: &'a Hash,
    pub checkpoint_ids: &'a [String],
    pub inclusions: &'a [AnchorBatchInclusion],
    pub witness: BatchHashWitnessInput<'a>,
    pub issued_at: u64,
    pub signer_key: &'a PublicKey,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchHashWitnessInput<'a> {
    pub kind: &'a AnchorBatchWitnessKind,
    pub root: &'a Hash,
}

impl<'a> BatchHashInput<'a> {
    /// Project an [`AnchorBatchBody`] into the stable hash-input view.
    pub fn from_body(body: &'a AnchorBatchBody) -> Self {
        BatchHashInput {
            schema: &body.schema,
            tree_root: &body.tree_root,
            checkpoint_ids: &body.checkpoint_ids,
            inclusions: &body.inclusions,
            witness: BatchHashWitnessInput {
                kind: &body.witness.kind,
                root: &body.witness.root,
            },
            issued_at: body.issued_at,
            signer_key: &body.signer_key,
        }
    }
}

/// Compute the canonical-JSON SHA-256 of `batch.body` over the
/// stable [`BatchHashInput`] view. Both publish and verify_inclusion
/// bind to this value; lanes MUST commit to it.
pub fn batch_body_hash(batch: &AnchorBatch) -> Result<Hash, AnchorWitnessError> {
    batch_body_hash_from_body(&batch.body)
}

/// Compute the canonical-JSON SHA-256 of an [`AnchorBatchBody`] over
/// the stable [`BatchHashInput`] view. Pre-witness signing paths use
/// this to compute the receipt body_hash before the batch has been
/// re-signed with the receipt embedded.
pub fn batch_body_hash_from_body(body: &AnchorBatchBody) -> Result<Hash, AnchorWitnessError> {
    let view = BatchHashInput::from_body(body);
    let bytes = canonical_json_bytes(&view)
        .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
    Ok(sha256(&bytes))
}

/// Public-witness lifecycle for a batch.
///
/// `Pending`: the batch was minted locally; no lane has confirmed
/// inclusion yet. Verifier policy `require_public_witness=true`
/// rejects pending batches.
///
/// `Witnessed`: an [`AnchorWitnessClient`] returned a [`WitnessReceipt`]
/// whose `witness_root == batch.body.tree_root` and whose
/// `body_hash == batch_body_hash(batch)`.
///
/// `Stale`: the producer reports that the witness lane was last
/// verified at `last_verified` and re-verification returned an error.
/// Verifier policy `require_public_witness=true` treats
/// `last_verified` as untrusted telemetry and admits stale batches
/// only when the verifier-owned [`VerifiedWitnessCache`] has a fresh
/// `verified_at` timestamp for the recomputed batch body hash.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum WitnessState {
    #[default]
    Pending,
    Witnessed {
        receipt: WitnessReceipt,
        observed_at: i64,
    },
    Stale {
        last_verified: i64,
        error: String,
    },
}

/// Verifier policy controlling whether the public-witness lane is
/// advisory or load-bearing. [`Default::default`] is load-bearing;
/// callers that want structural checks only must use
/// [`WitnessPolicy::advisory`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WitnessPolicy {
    /// When true, batches in [`WitnessState::Pending`] are rejected,
    /// self-asserted [`WitnessState::Witnessed`] requires the async
    /// verifier path, and [`WitnessState::Stale`] requires a
    /// verifier-owned cache entry. When false, all states are accepted
    /// after structural checks (advisory).
    pub require_public_witness: bool,
    /// Tolerance window for already-witnessed-but-temporarily-down
    /// lanes. Only consulted when `require_public_witness=true`.
    pub stale_window_seconds: i64,
}

impl WitnessPolicy {
    pub const DEFAULT_STALE_WINDOW_SECONDS: i64 = 24 * 60 * 60;

    /// Load-bearing public-witness policy. This is also the default so
    /// deployments cannot accidentally rely on advisory-only semantics.
    #[must_use]
    pub fn require_public_witness() -> Self {
        Self {
            require_public_witness: true,
            stale_window_seconds: Self::DEFAULT_STALE_WINDOW_SECONDS,
        }
    }

    /// Explicit advisory policy for callers that only want structural
    /// witness-state checks. This mode does not satisfy public-witness
    /// enforcement.
    #[must_use]
    pub fn advisory() -> Self {
        Self {
            require_public_witness: false,
            stale_window_seconds: Self::DEFAULT_STALE_WINDOW_SECONDS,
        }
    }

    #[must_use]
    pub fn with_stale_window_seconds(mut self, stale_window_seconds: i64) -> Self {
        self.stale_window_seconds = stale_window_seconds;
        self
    }
}

impl Default for WitnessPolicy {
    fn default() -> Self {
        WitnessPolicy::require_public_witness()
    }
}

/// Reasons a witness-lane policy check rejected a batch.
#[derive(Debug, thiserror::Error)]
pub enum WitnessPolicyError {
    #[error("require_public_witness=true but batch is in Pending state")]
    PendingNotAllowed,
    #[error("require_public_witness=true and stale verifier cache window exceeded: verified_at={verified_at} now={now} stale_window_seconds={stale_window_seconds}")]
    StaleVerifierCacheWindowExceeded {
        verified_at: i64,
        now: i64,
        stale_window_seconds: i64,
    },
    #[error("witness receipt root {receipt_root} does not match batch tree_root {batch_root}")]
    WitnessReceiptRootMismatch {
        receipt_root: String,
        batch_root: String,
    },
    #[error("witness receipt body_hash {receipt_hash} does not match recomputed batch body hash {batch_hash}")]
    WitnessReceiptBodyHashMismatch {
        receipt_hash: String,
        batch_hash: String,
    },
    #[error("witness receipt kind {receipt_kind:?} does not match declared batch witness kind {batch_kind:?}")]
    WitnessReceiptKindMismatch {
        receipt_kind: AnchorBatchWitnessKind,
        batch_kind: AnchorBatchWitnessKind,
    },
    #[error("require_public_witness=true requires an AnchorWitnessClient verifier but none was supplied")]
    VerifierRequired,
    #[error("require_public_witness=true rejects self-asserted Witnessed without a live AnchorWitnessClient verifier")]
    SelfAssertedWitnessed,
    #[error("witness lane verification failed: {0}")]
    VerifierRejected(String),
    #[error("require_public_witness=true and stale batch body_hash is not in the verifier-owned previously_verified cache: batch_body_hash={batch_body_hash}")]
    StaleNotPreviouslyVerified { batch_body_hash: String },
    #[error("require_public_witness=true and stale verifier cache timestamp verified_at={verified_at} is later than verifier clock now={now}")]
    StaleVerifierCacheInFuture { verified_at: i64, now: i64 },
}

/// Apply [`WitnessPolicy`] without performing live witness-lane
/// verification.
///
/// This advisory variant is suitable for callers that want only the
/// shape checks (Pending vs Witnessed vs Stale, root binding,
/// body-hash binding, stale window). It MUST NOT be used to honor
/// `require_public_witness=true`: a producer can put any
/// `WitnessState::Witnessed` in the signed body without ever talking
/// to the lane. Use [`evaluate_witness_policy_with_verifier`] for the
/// load-bearing path.
pub fn evaluate_witness_policy(
    batch: &AnchorBatch,
    state: &WitnessState,
    policy: &WitnessPolicy,
    _now: i64,
) -> Result<(), WitnessPolicyError> {
    match state {
        WitnessState::Witnessed { receipt, .. } => {
            check_witnessed_invariants(batch, receipt)?;
            if policy.require_public_witness {
                Err(WitnessPolicyError::SelfAssertedWitnessed)
            } else {
                Ok(())
            }
        }
        WitnessState::Pending => {
            if policy.require_public_witness {
                Err(WitnessPolicyError::PendingNotAllowed)
            } else {
                Ok(())
            }
        }
        WitnessState::Stale { .. } => {
            if !policy.require_public_witness {
                return Ok(());
            }
            let candidate = batch_body_hash(batch).map_err(|error| {
                WitnessPolicyError::VerifierRejected(format!(
                    "recompute batch_body_hash for stale admission: {error}"
                ))
            })?;
            Err(WitnessPolicyError::StaleNotPreviouslyVerified {
                batch_body_hash: candidate.to_hex_prefixed(),
            })
        }
    }
}

fn check_witnessed_invariants(
    batch: &AnchorBatch,
    receipt: &WitnessReceipt,
) -> Result<(), WitnessPolicyError> {
    if receipt.kind != batch.body.witness.kind {
        return Err(WitnessPolicyError::WitnessReceiptKindMismatch {
            receipt_kind: receipt.kind.clone(),
            batch_kind: batch.body.witness.kind.clone(),
        });
    }
    if receipt.witness_root != batch.body.tree_root {
        return Err(WitnessPolicyError::WitnessReceiptRootMismatch {
            receipt_root: receipt.witness_root.to_hex_prefixed(),
            batch_root: batch.body.tree_root.to_hex_prefixed(),
        });
    }
    let recomputed = batch_body_hash(batch).map_err(|error| {
        WitnessPolicyError::VerifierRejected(format!("recompute body_hash: {error}"))
    })?;
    if recomputed != receipt.body_hash {
        return Err(WitnessPolicyError::WitnessReceiptBodyHashMismatch {
            receipt_hash: receipt.body_hash.to_hex_prefixed(),
            batch_hash: recomputed.to_hex_prefixed(),
        });
    }
    Ok(())
}

/// Apply [`WitnessPolicy`] WITH live witness-lane verification.
///
/// When `require_public_witness=true`:
///
/// - `Witnessed`: the receipt's invariants
///   (`witness_root == batch.body.tree_root` and
///   `body_hash == batch_body_hash(batch)`) are checked first, then
///   `client.verify_inclusion(receipt)` is invoked. The receipt is
///   not honored unless both pass.
/// - `Stale`: the recomputed [`batch_body_hash`] of the current batch
///   MUST map to a verifier-owned `verified_at` timestamp in
///   `previously_verified_witnesses` (i.e. some prior call to
///   `client.verify_inclusion` succeeded against the SAME batch
///   content at that verifier time). Binding to the batch hash and
///   verifier timestamp, not the witness id or producer-signed
///   `last_verified`, prevents an attacker from re-issuing arbitrary
///   stale batches under a fresh self-asserted timestamp.
/// - `Pending`: rejected outright.
///
/// When `require_public_witness=false` this function delegates to the
/// sync [`evaluate_witness_policy`] path.
pub async fn evaluate_witness_policy_with_verifier(
    batch: &AnchorBatch,
    state: &WitnessState,
    policy: &WitnessPolicy,
    now: i64,
    client: Option<&dyn AnchorWitnessClient>,
    previously_verified_witnesses: &VerifiedWitnessCache,
) -> Result<(), WitnessPolicyError> {
    if !policy.require_public_witness {
        return evaluate_witness_policy(batch, state, policy, now);
    }
    match state {
        WitnessState::Pending => Err(WitnessPolicyError::PendingNotAllowed),
        WitnessState::Witnessed { receipt, .. } => {
            check_witnessed_invariants(batch, receipt)?;
            let client = client.ok_or(WitnessPolicyError::VerifierRequired)?;
            client
                .verify_inclusion(receipt)
                .await
                .map_err(|error| WitnessPolicyError::VerifierRejected(error.to_string()))?;
            Ok(())
        }
        WitnessState::Stale { .. } => {
            let candidate = batch_body_hash(batch).map_err(|error| {
                WitnessPolicyError::VerifierRejected(format!(
                    "recompute batch_body_hash for stale admission: {error}"
                ))
            })?;
            let Some(verified_at) = previously_verified_witnesses.get(&candidate).copied() else {
                return Err(WitnessPolicyError::StaleNotPreviouslyVerified {
                    batch_body_hash: candidate.to_hex_prefixed(),
                });
            };
            if verified_at > now {
                return Err(WitnessPolicyError::StaleVerifierCacheInFuture { verified_at, now });
            }
            if now.saturating_sub(verified_at) > policy.stale_window_seconds {
                return Err(WitnessPolicyError::StaleVerifierCacheWindowExceeded {
                    verified_at,
                    now,
                    stale_window_seconds: policy.stale_window_seconds,
                });
            }
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::batch::{build_anchor_batch, AnchorBatchWitness, AnchorBatchWitnessKind};
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
    fn witness_policy_rejects_pending_when_required() {
        let batch = sample_batch();
        let state = WitnessState::Pending;
        let policy = WitnessPolicy {
            require_public_witness: true,
            stale_window_seconds: 60,
        };
        let err = evaluate_witness_policy(&batch, &state, &policy, 1_700_000_100).unwrap_err();
        assert!(matches!(err, WitnessPolicyError::PendingNotAllowed));
    }

    #[test]
    fn witness_policy_accepts_pending_when_advisory() {
        let batch = sample_batch();
        let state = WitnessState::Pending;
        let policy = WitnessPolicy::advisory().with_stale_window_seconds(60);
        evaluate_witness_policy(&batch, &state, &policy, 1_700_000_100).unwrap();
    }

    #[test]
    fn witness_policy_rejects_stale_without_verifier_cache() {
        let batch = sample_batch();
        let state = WitnessState::Stale {
            last_verified: 1_700_000_000,
            error: "lane down".to_string(),
        };
        let policy = WitnessPolicy {
            require_public_witness: true,
            stale_window_seconds: 60,
        };
        let err = evaluate_witness_policy(&batch, &state, &policy, 1_700_000_500).unwrap_err();
        assert!(matches!(
            err,
            WitnessPolicyError::StaleNotPreviouslyVerified { .. }
        ));
    }

    #[test]
    fn witness_policy_accepts_stale_already_witnessed_advisory() {
        let batch = sample_batch();
        let state = WitnessState::Stale {
            last_verified: 1_700_000_000,
            error: "lane down".to_string(),
        };
        let policy = WitnessPolicy::advisory().with_stale_window_seconds(60);
        evaluate_witness_policy(&batch, &state, &policy, 1_700_000_500).unwrap();
    }

    #[test]
    fn witness_policy_default_is_load_bearing_public_witness() {
        let policy = WitnessPolicy::default();
        assert!(
            policy.require_public_witness,
            "default WitnessPolicy must be load-bearing; use WitnessPolicy::advisory() explicitly"
        );
        assert_eq!(
            policy.stale_window_seconds,
            WitnessPolicy::DEFAULT_STALE_WINDOW_SECONDS
        );
    }

    #[test]
    fn witness_policy_rejects_root_mismatch_on_witnessed() {
        let batch = sample_batch();
        let receipt = WitnessReceipt {
            kind: AnchorBatchWitnessKind::Rekor,
            external_uuid: "uuid-1".to_string(),
            published_at: 1_700_000_010,
            inclusion_proof: vec![1, 2, 3],
            witness_root: Hash::zero(),
            body_hash: batch_body_hash(&batch).unwrap(),
        };
        let state = WitnessState::Witnessed {
            receipt,
            observed_at: 1_700_000_010,
        };
        let policy = WitnessPolicy::default();
        let err = evaluate_witness_policy(&batch, &state, &policy, 1_700_000_100).unwrap_err();
        assert!(matches!(
            err,
            WitnessPolicyError::WitnessReceiptRootMismatch { .. }
        ));
    }

    #[test]
    fn sync_require_public_witness_rejects_self_asserted_witnessed() {
        let batch = sample_batch();
        let receipt = WitnessReceipt {
            kind: AnchorBatchWitnessKind::Rekor,
            external_uuid: "uuid-self-asserted".to_string(),
            published_at: 1_700_000_010,
            inclusion_proof: vec![1, 2, 3],
            witness_root: batch.body.tree_root,
            body_hash: batch_body_hash(&batch).unwrap(),
        };
        let state = WitnessState::Witnessed {
            receipt,
            observed_at: 1_700_000_010,
        };
        let policy = WitnessPolicy {
            require_public_witness: true,
            stale_window_seconds: 60,
        };
        let err = evaluate_witness_policy(&batch, &state, &policy, 1_700_000_100).unwrap_err();
        assert!(matches!(err, WitnessPolicyError::SelfAssertedWitnessed));
    }

    #[test]
    fn advisory_mode_accepts_witnessed_with_structural_invariants() {
        let batch = sample_batch();
        let receipt = WitnessReceipt {
            kind: AnchorBatchWitnessKind::Rekor,
            external_uuid: "uuid-advisory".to_string(),
            published_at: 1_700_000_010,
            inclusion_proof: vec![1, 2, 3],
            witness_root: batch.body.tree_root,
            body_hash: batch_body_hash(&batch).unwrap(),
        };
        let state = WitnessState::Witnessed {
            receipt,
            observed_at: 1_700_000_010,
        };
        evaluate_witness_policy(&batch, &state, &WitnessPolicy::advisory(), 1_700_000_100)
            .expect("advisory mode still accepts structurally-valid Witnessed state");
    }

    #[test]
    fn witnessed_receipt_kind_must_match_declared_lane() {
        let batch = sample_batch();
        let receipt = WitnessReceipt {
            kind: AnchorBatchWitnessKind::Ots,
            external_uuid: "uuid-wrong-lane".to_string(),
            published_at: 1_700_000_010,
            inclusion_proof: vec![1, 2, 3],
            witness_root: batch.body.tree_root,
            body_hash: batch_body_hash(&batch).unwrap(),
        };
        let state = WitnessState::Witnessed {
            receipt,
            observed_at: 1_700_000_010,
        };
        let err = evaluate_witness_policy(&batch, &state, &WitnessPolicy::default(), 1_700_000_100)
            .unwrap_err();
        assert!(matches!(
            err,
            WitnessPolicyError::WitnessReceiptKindMismatch { .. }
        ));
    }

    /// HIGH-1 regression: the body_hash bound by a receipt MUST be
    /// identical between the Pending body and the same body once
    /// signed under WitnessState::Witnessed. If batch_body_hash
    /// reads witness_state, the two values diverge and the receipt
    /// no longer commits to the final signed batch.
    #[test]
    fn body_hash_is_stable_across_witness_state_transitions() {
        let kp = Keypair::generate();
        let mut pending = sample_batch();
        let pending_hash = batch_body_hash(&pending).unwrap();

        // Move to Witnessed with a populated receipt and re-sign.
        let receipt = WitnessReceipt {
            kind: AnchorBatchWitnessKind::Rekor,
            external_uuid: "uuid-A".to_string(),
            published_at: 1_700_000_010,
            inclusion_proof: vec![9, 9, 9, 9],
            witness_root: pending.body.tree_root,
            body_hash: pending_hash,
        };
        pending.body.witness_state = WitnessState::Witnessed {
            receipt,
            observed_at: 1_700_000_010,
        };
        let resigned = AnchorBatch::sign(pending.body.clone(), &kp).unwrap();
        let witnessed_hash = batch_body_hash(&resigned).unwrap();
        assert_eq!(
            pending_hash, witnessed_hash,
            "BatchHashInput must exclude witness_state"
        );

        // Move to Stale and re-sign; same invariant must hold.
        let mut stale_body = pending.body.clone();
        stale_body.witness_state = WitnessState::Stale {
            last_verified: 1_700_000_500,
            error: "rekor 503".to_string(),
        };
        let resigned_stale = AnchorBatch::sign(stale_body, &kp).unwrap();
        let stale_hash = batch_body_hash(&resigned_stale).unwrap();
        assert_eq!(
            pending_hash, stale_hash,
            "BatchHashInput must be identical across Pending/Witnessed/Stale"
        );
    }

    #[test]
    fn body_hash_ignores_lane_assigned_witness_id_and_observation_time() {
        let mut batch = sample_batch();
        let original_hash = batch_body_hash(&batch).unwrap();

        batch.body.witness.witness_id = "rekor:uuid-after-publish".to_string();
        batch.body.witness.observed_at = Some(1_700_000_500);
        let with_lane_metadata = batch_body_hash(&batch).unwrap();
        assert_eq!(original_hash, with_lane_metadata);

        batch.body.witness.kind = AnchorBatchWitnessKind::Ots;
        let different_lane = batch_body_hash(&batch).unwrap();
        assert_ne!(original_hash, different_lane);
    }

    /// HIGH-2 regression: a self-asserted Witnessed state must NOT
    /// satisfy require_public_witness=true on its own. The verifier
    /// path requires a real client.verify_inclusion call.
    #[tokio::test]
    async fn require_public_witness_rejects_self_asserted_witnessed() {
        struct AlwaysFailClient;
        #[async_trait::async_trait]
        impl AnchorWitnessClient for AlwaysFailClient {
            async fn publish(&self, _: &AnchorBatch) -> Result<WitnessReceipt, AnchorWitnessError> {
                unreachable!()
            }
            async fn verify_inclusion(&self, _: &WitnessReceipt) -> Result<(), AnchorWitnessError> {
                Err(AnchorWitnessError::SignatureInvalid(
                    "no SET on this self-asserted receipt".to_string(),
                ))
            }
        }
        let kp = Keypair::generate();
        let mut batch = sample_batch();
        let body_hash = batch_body_hash(&batch).unwrap();
        batch.body.witness_state = WitnessState::Witnessed {
            receipt: WitnessReceipt {
                kind: AnchorBatchWitnessKind::Rekor,
                external_uuid: "uuid-self-asserted".to_string(),
                published_at: 1_700_000_010,
                inclusion_proof: vec![],
                witness_root: batch.body.tree_root,
                body_hash,
            },
            observed_at: 1_700_000_010,
        };
        let signed = AnchorBatch::sign(batch.body, &kp).unwrap();
        let client = AlwaysFailClient;
        let policy = WitnessPolicy {
            require_public_witness: true,
            stale_window_seconds: 60 * 60,
        };
        let err = evaluate_witness_policy_with_verifier(
            &signed,
            &signed.body.witness_state,
            &policy,
            1_700_000_100,
            Some(&client),
            &VerifiedWitnessCache::new(),
        )
        .await
        .expect_err("self-asserted Witnessed must be rejected by the verifier client");
        assert!(matches!(err, WitnessPolicyError::VerifierRejected(_)));
    }

    /// HIGH-2 regression for Stale: a stale state with no prior
    /// verified record must be rejected when require_public_witness.
    #[tokio::test]
    async fn require_public_witness_rejects_stale_without_prior_verification() {
        let kp = Keypair::generate();
        let mut batch = sample_batch();
        batch.body.witness.witness_id = "rekor:uuid-some".to_string();
        batch.body.witness_state = WitnessState::Stale {
            last_verified: 1_700_000_000,
            error: "rekor 503".to_string(),
        };
        let signed = AnchorBatch::sign(batch.body, &kp).unwrap();
        let policy = WitnessPolicy {
            require_public_witness: true,
            stale_window_seconds: 60 * 60,
        };
        let err = evaluate_witness_policy_with_verifier(
            &signed,
            &signed.body.witness_state,
            &policy,
            1_700_000_100,
            None,
            &VerifiedWitnessCache::new(),
        )
        .await
        .expect_err("stale without prior verification must be rejected");
        assert!(matches!(
            err,
            WitnessPolicyError::StaleNotPreviouslyVerified { .. }
        ));
    }

    #[tokio::test]
    async fn require_public_witness_admits_stale_when_previously_verified() {
        let kp = Keypair::generate();
        let mut batch = sample_batch();
        batch.body.witness.witness_id = "rekor:uuid-prior".to_string();
        batch.body.witness_state = WitnessState::Stale {
            last_verified: 1_700_000_000,
            error: "rekor 503".to_string(),
        };
        let signed = AnchorBatch::sign(batch.body, &kp).unwrap();
        let policy = WitnessPolicy {
            require_public_witness: true,
            stale_window_seconds: 60 * 60,
        };
        let mut verified = VerifiedWitnessCache::new();
        verified.insert(batch_body_hash(&signed).unwrap(), 1_700_000_000);
        evaluate_witness_policy_with_verifier(
            &signed,
            &signed.body.witness_state,
            &policy,
            1_700_000_100,
            None,
            &verified,
        )
        .await
        .expect("previously verified stale receipt is admissible");
    }

    /// HIGH-1 (round-2 review): a Stale receipt id that an attacker
    /// has previously observed must NOT admit a different batch's
    /// content. The previously-verified set is keyed by recomputed
    /// batch_body_hash, so a fresh-content batch with the same
    /// receipt id is rejected.
    #[tokio::test]
    async fn stale_admission_does_not_replay_against_different_batch_content() {
        // Single keypair so both batches' signer_key matches.
        let kp = Keypair::generate();
        let witness_a = AnchorBatchWitness {
            kind: AnchorBatchWitnessKind::Rekor,
            witness_id: "rekor:uuid-replay-target".to_string(),
            root: Hash::zero(),
            observed_at: Some(1_700_000_000),
        };
        let mut batch_a = build_anchor_batch(
            vec!["ck-A-1".to_string(), "ck-A-2".to_string()],
            witness_a,
            1_700_000_000,
            &kp,
        )
        .unwrap();
        batch_a.body.witness_state = WitnessState::Stale {
            last_verified: 1_700_000_000,
            error: "rekor 503".to_string(),
        };
        let signed_a = AnchorBatch::sign(batch_a.body, &kp).unwrap();
        let body_hash_a = batch_body_hash(&signed_a).unwrap();

        // Batch B: same witness_id (attacker chose this), DIFFERENT
        // checkpoint set so the body content (and therefore the
        // recomputed body_hash) differs from batch A.
        let witness_b = AnchorBatchWitness {
            kind: AnchorBatchWitnessKind::Rekor,
            witness_id: "rekor:uuid-replay-target".to_string(),
            root: Hash::zero(),
            observed_at: Some(1_700_000_000),
        };
        let mut batch_b = build_anchor_batch(
            vec!["ck-attacker-1".to_string(), "ck-attacker-2".to_string()],
            witness_b,
            1_700_000_000,
            &kp,
        )
        .unwrap();
        batch_b.body.witness_state = WitnessState::Stale {
            last_verified: 1_700_000_000,
            error: "rekor 503".to_string(),
        };
        let signed_b = AnchorBatch::sign(batch_b.body, &kp).unwrap();
        let body_hash_b = batch_body_hash(&signed_b).unwrap();
        assert_ne!(body_hash_a, body_hash_b);

        let policy = WitnessPolicy {
            require_public_witness: true,
            stale_window_seconds: 60 * 60,
        };
        // Verifier remembers ONLY batch A's body hash.
        let mut verified = VerifiedWitnessCache::new();
        verified.insert(body_hash_a, 1_700_000_000);

        // Batch B (same receipt id, different content) must be
        // rejected even though the receipt id appears identical.
        let err = evaluate_witness_policy_with_verifier(
            &signed_b,
            &signed_b.body.witness_state,
            &policy,
            1_700_000_100,
            None,
            &verified,
        )
        .await
        .expect_err("replay of receipt id against different batch content must be rejected");
        assert!(matches!(
            err,
            WitnessPolicyError::StaleNotPreviouslyVerified { .. }
        ));
    }

    /// Regression guard: stale admission uses the verifier-owned
    /// `verified_at` cache timestamp, not the producer-signed
    /// `last_verified` value. A producer cannot refresh a stale cache
    /// by signing a fresh artifact timestamp.
    #[tokio::test]
    async fn require_public_witness_rejects_stale_with_fresh_producer_timestamp_but_stale_cache() {
        let kp = Keypair::generate();
        let mut batch = sample_batch();
        batch.body.witness.witness_id = "rekor:uuid-stale-cache".to_string();
        batch.body.witness_state = WitnessState::Stale {
            // Producer claims freshness. This value is not trusted for
            // stale admission.
            last_verified: 1_700_000_500,
            error: "rekor 503".to_string(),
        };
        let signed = AnchorBatch::sign(batch.body, &kp).unwrap();
        let policy = WitnessPolicy {
            require_public_witness: true,
            stale_window_seconds: 60,
        };
        let mut verified = VerifiedWitnessCache::new();
        verified.insert(batch_body_hash(&signed).unwrap(), 1_700_000_000);
        let err = evaluate_witness_policy_with_verifier(
            &signed,
            &signed.body.witness_state,
            &policy,
            1_700_000_500,
            None,
            &verified,
        )
        .await
        .expect_err("stale verifier cache timestamp must control admission");
        assert!(matches!(
            err,
            WitnessPolicyError::StaleVerifierCacheWindowExceeded { .. }
        ));
    }
}
