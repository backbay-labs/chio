//! OpenTimestamps witness-lane client bound to `AnchorBatch`.
//!
//! The OTS protocol is a digest-based stamping service: a client
//! submits SHA-256(payload) over HTTP to a calendar (e.g.
//! `https://alice.btc.calendar.opentimestamps.org/digest`); the
//! calendar returns a serialised `Timestamp` blob that, once a Bitcoin
//! attestation is appended, anchors `payload` into the Bitcoin chain.
//!
//! This module's `OtsClient`:
//!
//! 1. computes `body_hash := SHA-256(canonical_jcs(BatchHashInput))`,
//! 2. POSTs `body_hash` to the configured calendar URL,
//! 3. parses the returned blob through the existing
//!    `opentimestamps` crate (already a chio-anchor dependency for
//!    the bitcoin super-root path),
//! 4. preserves the returned OTS blob as advisory timestamp material.
//!
//! Important: a local OTS parse plus a Bitcoin attestation marker is
//! not enough to satisfy `require_public_witness`. Until the receipt
//! schema carries trusted Bitcoin block-header evidence or an
//! independently verified calendar commitment, this client can return
//! advisory receipts from `publish`, but `verify_inclusion` fails
//! closed for load-bearing public-witness policy.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chio_core::hashing::Hash;
use opentimestamps::attestation::Attestation;
use opentimestamps::ser::{Deserializer, DigestType};
use opentimestamps::timestamp::{Step, StepData, Timestamp};
use opentimestamps::DetachedTimestampFile;

use crate::batch::{AnchorBatch, AnchorBatchWitnessKind};
use crate::witness::{batch_body_hash, AnchorWitnessClient, AnchorWitnessError, WitnessReceipt};

/// OpenTimestamps advisory client. `calendar_url` example:
/// `https://alice.btc.calendar.opentimestamps.org`. The calendar's
/// `/digest` endpoint accepts a 32-byte SHA-256 payload and returns a
/// serialised `Timestamp`.
#[derive(Debug, Clone)]
pub struct OtsClient {
    calendar_url: String,
    http: reqwest::Client,
    /// Maximum age in seconds for the Bitcoin attestation. Receipts
    /// whose attestation is older than this are reported as
    /// `AnchorWitnessError::Stale` on `verify_inclusion`.
    max_witness_age_seconds: i64,
    /// When set, parses receipts that lack a Bitcoin attestation
    /// (calendar-only, still pending block confirmation) instead of
    /// rejecting them immediately. OTS remains advisory either way and
    /// does not satisfy `require_public_witness`.
    pub accept_pending_attestation: bool,
}

impl OtsClient {
    pub fn new(
        calendar_url: impl Into<String>,
        max_witness_age_seconds: i64,
    ) -> Result<Self, AnchorWitnessError> {
        let calendar_url = calendar_url.into();
        if calendar_url.is_empty() {
            return Err(AnchorWitnessError::Config(
                "ots calendar url must be non-empty".to_string(),
            ));
        }
        if max_witness_age_seconds < 0 {
            return Err(AnchorWitnessError::Config(
                "max_witness_age_seconds must be non-negative".to_string(),
            ));
        }
        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: OpenTimestamps calendar
        // witness lane; threading an HttpEgressContract through OtsClient::new
        // is a dedicated refactor, not yet wired here.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .https_only(false)
            .build()
            .map_err(|error| AnchorWitnessError::Config(error.to_string()))?;
        Ok(OtsClient {
            calendar_url: calendar_url.trim_end_matches('/').to_string(),
            http,
            max_witness_age_seconds,
            accept_pending_attestation: false,
        })
    }

    fn digest_url(&self) -> String {
        format!("{}/digest", self.calendar_url)
    }
}

#[async_trait::async_trait]
impl AnchorWitnessClient for OtsClient {
    async fn publish(&self, batch: &AnchorBatch) -> Result<WitnessReceipt, AnchorWitnessError> {
        // Hash the witness-state-excluded BatchHashInput view, not the full
        // body. Hashing the full body creates a circular reference
        // through `witness_state` (the receipt embeds the body_hash
        // and the body embeds the receipt). The Rekor lane already
        // routes through `batch_body_hash`; OTS must do the same so
        // both lanes commit to the same canonical pre-witness view.
        let body_hash = batch_body_hash(batch)?;
        let body_hash_bytes = body_hash.as_bytes().to_vec();

        let response = self
            .http
            .post(self.digest_url())
            .header("Content-Type", "application/octet-stream")
            .body(body_hash_bytes.clone())
            // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: paired with builder above.
            .send()
            .await
            .map_err(|error| AnchorWitnessError::Network(error.to_string()))?;
        let status = response.status();
        let blob = response
            .bytes()
            .await
            .map_err(|error| AnchorWitnessError::Network(error.to_string()))?;
        if !status.is_success() {
            return Err(AnchorWitnessError::Http {
                status: status.as_u16(),
                body: String::from_utf8_lossy(&blob).into_owned(),
            });
        }

        // Calendar returns a raw timestamp blob (not detached file).
        let mut deser = Deserializer::new(blob.as_ref());
        let timestamp =
            Timestamp::deserialize(&mut deser, body_hash_bytes.clone()).map_err(|error| {
                AnchorWitnessError::Decode(format!("ots calendar timestamp parse: {error}"))
            })?;

        let mut bitcoin_heights = Vec::new();
        let mut pending = Vec::new();
        collect_attestations(&timestamp.first_step, &mut bitcoin_heights, &mut pending);

        if bitcoin_heights.is_empty() && !self.accept_pending_attestation {
            // Pending calendar material has no Bitcoin marker and
            // cannot be treated as witnessed.
            return Err(AnchorWitnessError::Decode(
                "ots calendar returned a pending timestamp without Bitcoin attestation".to_string(),
            ));
        }

        reject_stale_bitcoin_attestation(&bitcoin_heights, self.max_witness_age_seconds)?;
        let inclusion_proof = encode_detached_timestamp(&timestamp)?;
        let published_at = bitcoin_heights
            .iter()
            .map(|height| height_to_unix_lower_bound(*height))
            .min()
            .unwrap_or_else(chrono_now_unix);
        Ok(WitnessReceipt {
            kind: AnchorBatchWitnessKind::Ots,
            external_uuid: format!("ots:{}:{}", self.calendar_url, body_hash.to_hex()),
            published_at,
            inclusion_proof,
            witness_root: batch.body.tree_root,
            body_hash,
        })
    }

    async fn verify_inclusion(&self, receipt: &WitnessReceipt) -> Result<(), AnchorWitnessError> {
        if receipt.kind != AnchorBatchWitnessKind::Ots {
            return Err(AnchorWitnessError::Config(format!(
                "OtsClient asked to verify {:?} receipt",
                receipt.kind
            )));
        }
        let detached = DetachedTimestampFile::from_reader(receipt.inclusion_proof.as_slice())
            .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
        if detached.digest_type != DigestType::Sha256 {
            return Err(AnchorWitnessError::Decode(format!(
                "ots digest type {:?} is not sha256",
                detached.digest_type
            )));
        }
        let lane_start_hex = hex::encode(&detached.timestamp.start_digest);
        let expected_hex = receipt.body_hash.to_hex();
        if !lane_start_hex.eq_ignore_ascii_case(&expected_hex) {
            return Err(AnchorWitnessError::BodyHashMismatch {
                lane: lane_start_hex,
                batch: expected_hex,
            });
        }

        let mut bitcoin_heights = Vec::new();
        let mut pending = Vec::new();
        collect_attestations(
            &detached.timestamp.first_step,
            &mut bitcoin_heights,
            &mut pending,
        );

        if bitcoin_heights.is_empty() && !self.accept_pending_attestation {
            return Err(AnchorWitnessError::Decode(
                "ots receipt has no Bitcoin attestation".to_string(),
            ));
        }

        reject_stale_bitcoin_attestation(&bitcoin_heights, self.max_witness_age_seconds)?;
        Err(ots_advisory_only_error())
    }
}

fn ots_advisory_only_error() -> AnchorWitnessError {
    AnchorWitnessError::SignatureInvalid(
        "ots receipt lacks trusted Bitcoin header or calendar-backed commitment evidence; OTS is advisory-only for require_public_witness".to_string(),
    )
}

fn encode_detached_timestamp(timestamp: &Timestamp) -> Result<Vec<u8>, AnchorWitnessError> {
    let detached = DetachedTimestampFile {
        digest_type: DigestType::Sha256,
        timestamp: timestamp.clone(),
    };
    let mut out = Vec::new();
    detached
        .to_writer(&mut out)
        .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
    Ok(out)
}

fn reject_stale_bitcoin_attestation(
    bitcoin_heights: &[u64],
    max_witness_age_seconds: i64,
) -> Result<(), AnchorWitnessError> {
    if max_witness_age_seconds <= 0 {
        return Ok(());
    }
    let now = chrono_now_unix();
    let earliest = bitcoin_heights
        .iter()
        .map(|height| height_to_unix_lower_bound(*height))
        .min()
        .unwrap_or(now);
    if now.saturating_sub(earliest) > max_witness_age_seconds {
        return Err(AnchorWitnessError::Stale {
            published_at: earliest,
            now,
            max_age_seconds: max_witness_age_seconds,
        });
    }
    Ok(())
}

fn collect_attestations(
    step: &Step,
    bitcoin_attestation_heights: &mut Vec<u64>,
    pending_calendars: &mut Vec<String>,
) {
    if let StepData::Attestation(attestation) = &step.data {
        match attestation {
            Attestation::Bitcoin { height } => bitcoin_attestation_heights.push(*height as u64),
            Attestation::Pending { uri } => pending_calendars.push(uri.clone()),
            Attestation::Unknown { .. } => {}
        }
    }
    for next in &step.next {
        collect_attestations(next, bitcoin_attestation_heights, pending_calendars);
    }
}

/// Height-to-unix lower bound: Bitcoin block 0 was at 2009-01-03; an
/// average inter-block interval of 600s gives a floor estimate that
/// is good enough for staleness checks. Production callers should
/// substitute a real chain-tip oracle. Returns 0 for height 0.
fn height_to_unix_lower_bound(height: u64) -> i64 {
    const GENESIS_UNIX: i64 = 1_231_006_505; // 2009-01-03T18:15:05Z
    GENESIS_UNIX.saturating_add(600i64.saturating_mul(height as i64))
}

fn chrono_now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// Build a synthetic OTS detached timestamp file that commits to
/// `body_hash` at `bitcoin_height`. Tests use this to stage faithful
/// mock-server responses without depending on the production
/// calendar.
pub fn build_ots_inclusion_proof(
    body_hash: &Hash,
    bitcoin_height: u64,
) -> Result<Vec<u8>, AnchorWitnessError> {
    let bytes = body_hash.as_bytes().to_vec();
    let detached = DetachedTimestampFile {
        digest_type: DigestType::Sha256,
        timestamp: Timestamp {
            start_digest: bytes.clone(),
            first_step: Step {
                data: StepData::Attestation(Attestation::Bitcoin {
                    height: bitcoin_height as usize,
                }),
                output: bytes,
                next: Vec::new(),
            },
        },
    };
    let mut out = Vec::new();
    detached
        .to_writer(&mut out)
        .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
    Ok(out)
}

/// Build an OTS proof that commits to a *different* digest than
/// `body_hash`. Used by the witness-impersonation negative test to
/// simulate a lane that returns a timestamp file whose `start_digest`
/// does not match the batch's body hash.
pub fn build_ots_inclusion_proof_with_forged_digest(
    forged: &Hash,
    bitcoin_height: u64,
) -> Result<Vec<u8>, AnchorWitnessError> {
    build_ots_inclusion_proof(forged, bitcoin_height)
}

/// Base64-encoded helper used in tests.
pub fn build_ots_inclusion_proof_b64(
    body_hash: &Hash,
    bitcoin_height: u64,
) -> Result<String, AnchorWitnessError> {
    Ok(BASE64_STANDARD.encode(build_ots_inclusion_proof(body_hash, bitcoin_height)?))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ots_inclusion_proof_round_trips_through_parser() {
        let payload_hash = chio_core::hashing::sha256(b"chio-anchor-batch-test");
        let blob = build_ots_inclusion_proof(&payload_hash, 900_000).unwrap();
        let parsed = DetachedTimestampFile::from_reader(blob.as_slice()).unwrap();
        assert_eq!(
            parsed.timestamp.start_digest,
            payload_hash.as_bytes().to_vec()
        );
    }

    #[test]
    fn ots_client_rejects_blank_calendar() {
        let err = OtsClient::new("", 60).unwrap_err();
        assert!(matches!(err, AnchorWitnessError::Config(_)));
    }

    #[test]
    fn ots_client_rejects_negative_max_age() {
        let err = OtsClient::new("https://example.com", -1).unwrap_err();
        assert!(matches!(err, AnchorWitnessError::Config(_)));
    }

    #[tokio::test]
    async fn ots_verify_inclusion_rejects_bitcoin_marker_without_trusted_evidence() {
        let payload_hash = chio_core::hashing::sha256(b"chio-anchor-batch-test");
        let blob = build_ots_inclusion_proof(&payload_hash, 900_000).unwrap();
        let receipt = WitnessReceipt {
            kind: AnchorBatchWitnessKind::Ots,
            external_uuid: payload_hash.to_hex(),
            published_at: 1_700_000_010,
            inclusion_proof: blob,
            witness_root: Hash::zero(),
            body_hash: payload_hash,
        };
        let client = OtsClient::new("http://127.0.0.1:9", 0).unwrap();
        let err = client.verify_inclusion(&receipt).await.unwrap_err();
        match err {
            AnchorWitnessError::SignatureInvalid(message) => {
                assert!(
                    message.contains("advisory-only"),
                    "expected OTS advisory-only rejection, got: {message}"
                );
            }
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }
}
