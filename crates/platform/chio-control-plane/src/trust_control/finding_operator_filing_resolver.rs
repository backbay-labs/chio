//! Digest-addressed filing artifacts retained by the single-operator runtime.

use chio_finding::{signed_envelope_sha256, SignedFindingAdmission, SignedFindingMarketTerms};
use chio_open_market::fee_schedule::SignedOpenMarketFeeSchedule;
use chio_store_sqlite::SqliteFindingOperatorBundleStore;

use super::finding_challenge_coordinator::{FindingAuditRound, FindingFilingResolver};
use super::finding_operator_bundle::FindingOperatorBundle;
use super::{FindingAuthorityPin, FindingMarketConfig};

/// Resolver over the exact durable bundles admitted by this operator.
/// Unsupported artifact families return `None`, which keeps later challenge
/// phases fail closed instead of inventing historical policy.
pub struct FindingOperatorFilingResolver {
    bundles: SqliteFindingOperatorBundleStore,
    market: FindingMarketConfig,
}

impl FindingOperatorFilingResolver {
    pub fn new(
        bundles: SqliteFindingOperatorBundleStore,
        market: FindingMarketConfig,
    ) -> Result<Self, String> {
        market.validate().map_err(|error| error.to_string())?;
        Ok(Self { bundles, market })
    }

    fn find_bundle(
        &self,
        mut predicate: impl FnMut(&FindingOperatorBundle) -> bool,
    ) -> Option<FindingOperatorBundle> {
        let mut matched = None;
        self.bundles
            .find_bundle(|bytes| {
                let Ok(bundle) = serde_json::from_slice::<FindingOperatorBundle>(bytes) else {
                    return false;
                };
                if predicate(&bundle) {
                    matched = Some(bundle);
                    true
                } else {
                    false
                }
            })
            .ok()??;
        matched
    }
}

impl FindingFilingResolver for FindingOperatorFilingResolver {
    fn fee_schedule(&self, envelope_sha256: &str) -> Option<SignedOpenMarketFeeSchedule> {
        self.find_bundle(|bundle| {
            signed_envelope_sha256(&bundle.fee_schedule)
                .is_ok_and(|digest| digest == envelope_sha256)
        })
        .map(|bundle| bundle.fee_schedule)
    }

    fn audit_round(&self, _epoch_envelope_sha256: &str) -> Option<FindingAuditRound> {
        None
    }

    fn admission_for_backing(
        &self,
        finding_id: &str,
        listing_id: &str,
        backing_envelope_sha256: &str,
    ) -> Option<SignedFindingAdmission> {
        let record = self.bundles.get(finding_id).ok()?;
        let bundle: FindingOperatorBundle = serde_json::from_slice(&record.bundle_json).ok()?;
        let admission = bundle.admission;
        (admission.body.finding_id == finding_id
            && admission.body.listing_id == listing_id
            && admission.body.backing_envelope_sha256 == backing_envelope_sha256)
            .then_some(admission)
    }

    fn admission_by_envelope_sha256(
        &self,
        envelope_sha256: &str,
    ) -> Option<SignedFindingAdmission> {
        self.find_bundle(|bundle| {
            signed_envelope_sha256(&bundle.admission).is_ok_and(|digest| digest == envelope_sha256)
        })
        .map(|bundle| bundle.admission)
    }

    fn venue_policy_for_admission(&self, envelope_sha256: &str) -> Option<FindingAuthorityPin> {
        self.admission_by_envelope_sha256(envelope_sha256)
            .map(|_| self.market.venue.clone())
    }

    fn governance_policy_for_profile(&self, envelope_sha256: &str) -> Option<FindingAuthorityPin> {
        self.find_bundle(|bundle| {
            signed_envelope_sha256(&bundle.verifier_profile)
                .is_ok_and(|digest| digest == envelope_sha256)
        })
        .map(|_| self.market.governance_root.clone())
    }

    fn governance_policy_for_case(&self, _envelope_sha256: &str) -> Option<FindingAuthorityPin> {
        None
    }

    fn governance_policy_for_activation(
        &self,
        _envelope_sha256: &str,
    ) -> Option<FindingAuthorityPin> {
        None
    }

    fn penalty_policy_for_penalty(&self, _envelope_sha256: &str) -> Option<FindingAuthorityPin> {
        None
    }

    fn retain_penalty_policy(
        &self,
        _envelope_sha256: &str,
        _policy: &FindingAuthorityPin,
    ) -> Result<(), String> {
        Err("operator penalty policy retention is not configured".to_owned())
    }

    fn evaluator_policy_for_outcome(&self, _envelope_sha256: &str) -> Option<FindingAuthorityPin> {
        None
    }

    fn retain_evaluator_policy(
        &self,
        _envelope_sha256: &str,
        _policy: &FindingAuthorityPin,
    ) -> Result<(), String> {
        Err("operator evaluator policy retention is not configured".to_owned())
    }

    fn audit_policy_for_epoch(&self, _epoch_envelope_sha256: &str) -> Option<FindingAuthorityPin> {
        None
    }

    fn randomness_witness_policy_for_epoch(
        &self,
        _epoch_envelope_sha256: &str,
    ) -> Option<FindingAuthorityPin> {
        None
    }

    fn governance_policy_for_audit_authorization(
        &self,
        _authorization_envelope_sha256: &str,
    ) -> Option<FindingAuthorityPin> {
        None
    }

    fn market_terms(&self, envelope_sha256: &str) -> Option<SignedFindingMarketTerms> {
        self.find_bundle(|bundle| {
            signed_envelope_sha256(&bundle.market_terms)
                .is_ok_and(|digest| digest == envelope_sha256)
        })
        .map(|bundle| bundle.market_terms)
    }
}
