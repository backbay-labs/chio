//! Digest-addressed filing artifacts retained by the single-operator runtime.

use chio_finding::{
    signed_envelope_sha256, verify_signed_admission, verify_signed_profile, SignedFindingAdmission,
    SignedFindingMarketTerms,
};
use chio_open_market::fee_schedule::SignedOpenMarketFeeSchedule;
use chio_store_sqlite::{
    FindingOperatorBundleArtifactIndex, FindingOperatorBundleArtifactKind,
    FindingOperatorBundleStoreError, SqliteFindingOperatorBundleStore,
};

use super::finding_challenge_coordinator::{FindingAuditRound, FindingFilingResolver};
use super::finding_operator_bundle::FindingOperatorBundle;
use super::{FindingAuthorityPin, FindingMarketConfig};

const ARTIFACT_INDEX_BACKFILL_BATCH: u64 = 16;

/// Resolver over the exact durable bundles admitted by this operator.
/// Unsupported artifact families return `None`, which keeps later challenge
/// phases fail closed instead of inventing historical policy.
pub struct FindingOperatorFilingResolver {
    bundles: SqliteFindingOperatorBundleStore,
}

struct IndexedOperatorBundle {
    bundle: FindingOperatorBundle,
    authority_policy_json: Option<Vec<u8>>,
}

impl FindingOperatorFilingResolver {
    pub fn new(
        bundles: SqliteFindingOperatorBundleStore,
        market: FindingMarketConfig,
    ) -> Result<Self, String> {
        market.validate().map_err(|error| error.to_string())?;
        loop {
            let records = bundles
                .list_without_complete_artifact_index(ARTIFACT_INDEX_BACKFILL_BATCH)
                .map_err(|error| error.to_string())?;
            if records.is_empty() {
                break;
            }
            for record in records {
                let bundle: FindingOperatorBundle = serde_json::from_slice(&record.bundle_json)
                    .map_err(|error| format!("retained operator bundle is invalid: {error}"))?;
                let indexes = finding_operator_bundle_artifact_indexes(&bundle, None)?;
                bundles
                    .put_with_artifact_indexes(&record.finding_id, &record.bundle_json, &indexes)
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok(Self { bundles })
    }

    fn indexed_bundle(
        &self,
        kind: FindingOperatorBundleArtifactKind,
        envelope_sha256: &str,
    ) -> Result<Option<IndexedOperatorBundle>, String> {
        let record = match self.bundles.get_by_artifact(kind, envelope_sha256) {
            Ok(record) => record,
            Err(FindingOperatorBundleStoreError::NotFound) => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let bundle: FindingOperatorBundle = serde_json::from_slice(&record.bundle_json)
            .map_err(|error| format!("retained operator bundle is invalid: {error}"))?;
        let expected = finding_operator_bundle_artifact_indexes(&bundle, None)?
            .into_iter()
            .find(|index| index.kind == kind)
            .ok_or_else(|| "retained operator bundle artifact index is incomplete".to_owned())?;
        if expected.envelope_sha256 != envelope_sha256 {
            return Err("retained operator bundle artifact index is inconsistent".to_owned());
        }
        Ok(Some(IndexedOperatorBundle {
            bundle,
            authority_policy_json: record.authority_policy_json,
        }))
    }
}

/// Derive the four challenge-facing signed-envelope indexes carried by one
/// verified operator bundle. New admissions supply the authenticating market
/// profile so the exact venue and governance policies are retained with their
/// indexes. A policy-less call is only for legacy digest-index backfill and
/// remains fail closed for historical authority resolution.
pub fn finding_operator_bundle_artifact_indexes(
    bundle: &FindingOperatorBundle,
    market: Option<&FindingMarketConfig>,
) -> Result<[FindingOperatorBundleArtifactIndex; 4], String> {
    if let Some(market) = market {
        market.validate().map_err(|error| error.to_string())?;
        let venue = market.venue.key().map_err(|error| error.to_string())?;
        if !market.venue.covers(bundle.admission.body.issued_at)
            || verify_signed_admission(&bundle.admission, &venue, &market.venue_id).is_err()
        {
            return Err("venue policy does not authenticate the indexed admission".to_owned());
        }
        let governance = market
            .governance_root
            .key()
            .map_err(|error| error.to_string())?;
        if !market
            .governance_root
            .covers(bundle.verifier_profile.body.issued_at)
            || verify_signed_profile(&bundle.verifier_profile, &governance).is_err()
        {
            return Err(
                "governance policy does not authenticate the indexed verifier profile".to_owned(),
            );
        }
    }
    let venue_policy_json = market
        .map(|market| chio_core::canonical_json_bytes(&market.venue))
        .transpose()
        .map_err(|error| error.to_string())?;
    let governance_policy_json = market
        .map(|market| chio_core::canonical_json_bytes(&market.governance_root))
        .transpose()
        .map_err(|error| error.to_string())?;
    Ok([
        FindingOperatorBundleArtifactIndex {
            kind: FindingOperatorBundleArtifactKind::FeeSchedule,
            envelope_sha256: signed_envelope_sha256(&bundle.fee_schedule)
                .map_err(|error| error.to_string())?,
            authority_policy_json: None,
        },
        FindingOperatorBundleArtifactIndex {
            kind: FindingOperatorBundleArtifactKind::Admission,
            envelope_sha256: signed_envelope_sha256(&bundle.admission)
                .map_err(|error| error.to_string())?,
            authority_policy_json: venue_policy_json,
        },
        FindingOperatorBundleArtifactIndex {
            kind: FindingOperatorBundleArtifactKind::VerifierProfile,
            envelope_sha256: signed_envelope_sha256(&bundle.verifier_profile)
                .map_err(|error| error.to_string())?,
            authority_policy_json: governance_policy_json,
        },
        FindingOperatorBundleArtifactIndex {
            kind: FindingOperatorBundleArtifactKind::MarketTerms,
            envelope_sha256: signed_envelope_sha256(&bundle.market_terms)
                .map_err(|error| error.to_string())?,
            authority_policy_json: None,
        },
    ])
}

impl FindingFilingResolver for FindingOperatorFilingResolver {
    fn fee_schedule(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<SignedOpenMarketFeeSchedule>, String> {
        Ok(self
            .indexed_bundle(
                FindingOperatorBundleArtifactKind::FeeSchedule,
                envelope_sha256,
            )?
            .map(|indexed| indexed.bundle.fee_schedule))
    }

    fn audit_round(
        &self,
        _epoch_envelope_sha256: &str,
    ) -> Result<Option<FindingAuditRound>, String> {
        Ok(None)
    }

    fn admission_for_backing(
        &self,
        finding_id: &str,
        listing_id: &str,
        backing_envelope_sha256: &str,
    ) -> Result<Option<SignedFindingAdmission>, String> {
        let record = match self.bundles.get(finding_id) {
            Ok(record) => record,
            Err(FindingOperatorBundleStoreError::NotFound) => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let bundle: FindingOperatorBundle = serde_json::from_slice(&record.bundle_json)
            .map_err(|error| format!("retained operator bundle is invalid: {error}"))?;
        let admission = bundle.admission;
        Ok((admission.body.finding_id == finding_id
            && admission.body.listing_id == listing_id
            && admission.body.backing_envelope_sha256 == backing_envelope_sha256)
            .then_some(admission))
    }

    fn admission_by_envelope_sha256(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<SignedFindingAdmission>, String> {
        Ok(self
            .indexed_bundle(
                FindingOperatorBundleArtifactKind::Admission,
                envelope_sha256,
            )?
            .map(|indexed| indexed.bundle.admission))
    }

    fn venue_policy_for_admission(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        let Some(indexed) = self.indexed_bundle(
            FindingOperatorBundleArtifactKind::Admission,
            envelope_sha256,
        )?
        else {
            return Ok(None);
        };
        let Some(policy_json) = indexed.authority_policy_json else {
            return Ok(None);
        };
        let policy: FindingAuthorityPin = serde_json::from_slice(&policy_json)
            .map_err(|error| format!("retained venue policy is invalid: {error}"))?;
        let key = policy
            .validate("retained venue")
            .map_err(|error| error.to_string())?;
        if !policy.covers(indexed.bundle.admission.body.issued_at)
            || verify_signed_admission(
                &indexed.bundle.admission,
                &key,
                &indexed.bundle.admission.body.venue_id,
            )
            .is_err()
        {
            return Err("retained venue policy does not authenticate its admission".to_owned());
        }
        Ok(Some(policy))
    }

    fn governance_policy_for_profile(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        let Some(indexed) = self.indexed_bundle(
            FindingOperatorBundleArtifactKind::VerifierProfile,
            envelope_sha256,
        )?
        else {
            return Ok(None);
        };
        let Some(policy_json) = indexed.authority_policy_json else {
            return Ok(None);
        };
        let policy: FindingAuthorityPin = serde_json::from_slice(&policy_json)
            .map_err(|error| format!("retained governance policy is invalid: {error}"))?;
        let key = policy
            .validate("retained governance")
            .map_err(|error| error.to_string())?;
        if !policy.covers(indexed.bundle.verifier_profile.body.issued_at)
            || verify_signed_profile(&indexed.bundle.verifier_profile, &key).is_err()
        {
            return Err(
                "retained governance policy does not authenticate its verifier profile".to_owned(),
            );
        }
        Ok(Some(policy))
    }

    fn governance_policy_for_case(
        &self,
        _envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(None)
    }

    fn governance_policy_for_activation(
        &self,
        _envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(None)
    }

    fn penalty_policy_for_penalty(
        &self,
        _envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(None)
    }

    fn retain_penalty_policy(
        &self,
        _envelope_sha256: &str,
        _policy: &FindingAuthorityPin,
    ) -> Result<(), String> {
        Err("operator penalty policy retention is not configured".to_owned())
    }

    fn evaluator_policy_for_outcome(
        &self,
        _envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(None)
    }

    fn retain_evaluator_policy(
        &self,
        _envelope_sha256: &str,
        _policy: &FindingAuthorityPin,
    ) -> Result<(), String> {
        Err("operator evaluator policy retention is not configured".to_owned())
    }

    fn audit_policy_for_epoch(
        &self,
        _epoch_envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(None)
    }

    fn randomness_witness_policy_for_epoch(
        &self,
        _epoch_envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(None)
    }

    fn governance_policy_for_audit_authorization(
        &self,
        _authorization_envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(None)
    }

    fn market_terms(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<SignedFindingMarketTerms>, String> {
        Ok(self
            .indexed_bundle(
                FindingOperatorBundleArtifactKind::MarketTerms,
                envelope_sha256,
            )?
            .map(|indexed| indexed.bundle.market_terms))
    }
}
