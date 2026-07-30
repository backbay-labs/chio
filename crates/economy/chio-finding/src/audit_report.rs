//! `chio.finding.audit-report.v1`: the venue's signed result for one audit
//! round, published AFTER the reveal.
//!
//! The report reveals the seed its epoch committed, names the listings the
//! selection algorithm produced from it, and accounts for every one of them
//! with either an attempt receipt or a recorded miss. A round that reports
//! only its successes is not an enforceable rate, so misses are first-class
//! members with their own reasons rather than an absence.
//!
//! The epoch and the report are two artifacts, never one mutable one:
//! [`verify_audit_report_epoch_binding`] re-derives the epoch's commitment
//! from the revealed seed, so a venue cannot pick the seed after seeing
//! which listings it would select.

use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::audit_epoch::{derive_audit_seed_commitment, SignedFindingAuditEpoch};
use crate::envelope::signed_envelope_sha256;
use crate::validate::{
    require_bounded_id, require_hex64, require_non_empty, require_nonzero, FindingError,
};

/// Venue-signed audit round result.
pub const FINDING_AUDIT_REPORT_SCHEMA_V1: &str =
    chio_core_types::signed_artifact::CHIO_FINDING_AUDIT_REPORT_V1_SCHEMA;

/// Bound on one round's selection and on each list derived from it.
pub const MAX_AUDIT_SELECTION: usize = 256;

/// One selected listing the round did not complete, and why.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingMissedAudit {
    pub finding_id: String,
    pub reason: String,
}

/// Audit round result body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingAuditReport {
    pub schema: String,
    /// Content-addressed: sha256 of the canonical body with
    /// `audit_report_id` cleared.
    pub audit_report_id: String,
    /// Digest of the exact signed epoch ENVELOPE this round executed.
    pub audit_epoch_envelope_sha256: String,
    /// The seed whose commitment the epoch published.
    pub revealed_seed: String,
    pub selected_finding_ids: Vec<String>,
    pub attempt_receipt_ids: Vec<String>,
    pub missed_attempts: Vec<FindingMissedAudit>,
    pub outcome_envelope_digests: Vec<String>,
    pub reported_at: u64,
}

/// Venue-signed envelope for the report.
pub type SignedFindingAuditReport = SignedExportEnvelope<FindingAuditReport>;

impl FindingAuditReport {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_AUDIT_REPORT_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.audit_report_id, "audit_report_id")?;
        require_hex64(
            &self.audit_epoch_envelope_sha256,
            "audit_epoch_envelope_sha256",
        )?;
        require_hex64(&self.revealed_seed, "revealed_seed")?;
        if self.selected_finding_ids.len() > MAX_AUDIT_SELECTION {
            return Err(FindingError::SizeLimitExceeded("selected_finding_ids"));
        }
        let mut selected = BTreeSet::new();
        for finding_id in &self.selected_finding_ids {
            require_hex64(finding_id, "selected_finding_ids[]")?;
            if !selected.insert(finding_id.as_str()) {
                return Err(FindingError::DuplicateEntry("selected_finding_ids[]"));
            }
        }
        if self.attempt_receipt_ids.len() > MAX_AUDIT_SELECTION {
            return Err(FindingError::SizeLimitExceeded("attempt_receipt_ids"));
        }
        let mut attempts = BTreeSet::new();
        for receipt_id in &self.attempt_receipt_ids {
            require_bounded_id(receipt_id, "attempt_receipt_ids[]")?;
            if !attempts.insert(receipt_id.as_str()) {
                return Err(FindingError::DuplicateEntry("attempt_receipt_ids[]"));
            }
        }
        if self.missed_attempts.len() > self.selected_finding_ids.len() {
            return Err(FindingError::SizeLimitExceeded("missed_attempts"));
        }
        let mut missed = BTreeSet::new();
        for miss in &self.missed_attempts {
            require_hex64(&miss.finding_id, "missed_attempts[].finding_id")?;
            require_non_empty(&miss.reason, "missed_attempts[].reason")?;
            if !selected.contains(miss.finding_id.as_str()) {
                return Err(FindingError::InvalidField("missed_attempts[]"));
            }
            if !missed.insert(miss.finding_id.as_str()) {
                return Err(FindingError::DuplicateEntry("missed_attempts[]"));
            }
        }
        // Every selection is accounted for: a round that recorded no miss
        // for a selected listing owes at least one attempt receipt.
        if missed.len() < selected.len() && self.attempt_receipt_ids.is_empty() {
            return Err(FindingError::MissingEntry("attempt_receipt_ids"));
        }
        if self.outcome_envelope_digests.len() > MAX_AUDIT_SELECTION {
            return Err(FindingError::SizeLimitExceeded("outcome_envelope_digests"));
        }
        let mut outcomes = BTreeSet::new();
        for digest in &self.outcome_envelope_digests {
            require_hex64(digest, "outcome_envelope_digests[]")?;
            if !outcomes.insert(digest.as_str()) {
                return Err(FindingError::DuplicateEntry("outcome_envelope_digests[]"));
            }
        }
        require_nonzero(self.reported_at, "reported_at")?;
        self.verify_audit_report_id()
    }

    /// Recompute and compare the content-addressed report id.
    pub fn verify_audit_report_id(&self) -> Result<(), FindingError> {
        let expected = compute_audit_report_id(self)?;
        if expected == self.audit_report_id {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("audit_report_id"))
        }
    }
}

/// Content-addressed report id: sha256 over the canonical body with
/// `audit_report_id` cleared.
pub fn compute_audit_report_id(report: &FindingAuditReport) -> Result<String, FindingError> {
    let mut body = report.clone();
    body.audit_report_id = String::new();
    let bytes =
        chio_core_types::canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    Ok(chio_core_types::crypto::sha256_hex(&bytes))
}

/// Verify that a report belongs to a signed epoch and that its revealed
/// seed reproduces that epoch's commitment.
///
/// Both halves matter: the envelope digest proves which round was executed,
/// and the reproduced commitment proves the randomness was fixed before the
/// selection rather than chosen to fit it.
pub fn verify_audit_report_epoch_binding(
    report: &FindingAuditReport,
    epoch: &SignedFindingAuditEpoch,
) -> Result<(), FindingError> {
    let expected_envelope = signed_envelope_sha256(epoch)?;
    if expected_envelope != report.audit_epoch_envelope_sha256 {
        return Err(FindingError::ArtifactIdMismatch(
            "audit_epoch_envelope_sha256",
        ));
    }
    if derive_audit_seed_commitment(&report.revealed_seed) != epoch.body.seed_commitment {
        return Err(FindingError::ArtifactIdMismatch("revealed_seed"));
    }
    Ok(())
}

/// Verify a signed report against the externally pinned audit authority.
pub fn verify_signed_audit_report(
    signed: &SignedFindingAuditReport,
    pinned_audit_authority: &PublicKey,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    crate::envelope::verify_pinned_envelope(signed, pinned_audit_authority, "audit_report")
}
