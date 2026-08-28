//! Digest-addressed filing artifacts retained by the single-operator runtime.

use chio_finding::{
    audit_epoch_precommitment_sha256, signed_envelope_sha256, verify_signed_admission,
    verify_signed_audit_epoch, verify_signed_audit_round_authorization, verify_signed_profile,
    SignedFindingAdmission, SignedFindingMarketTerms,
};
use chio_open_market::fee_schedule::SignedOpenMarketFeeSchedule;
use chio_open_market::finding_audit::select_audit_targets;
use chio_store_sqlite::{
    FindingOperatorBundleArtifactIndex, FindingOperatorBundleArtifactKind,
    FindingOperatorBundleStoreError, FindingOperatorRetainedPolicyArtifactKind,
    FindingOperatorRetainedPolicyRole, SqliteFindingOperatorBundleStore,
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
    market: FindingMarketConfig,
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
        Ok(Self { bundles, market })
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

    fn retained_policy(
        &self,
        artifact_kind: FindingOperatorRetainedPolicyArtifactKind,
        envelope_sha256: &str,
        policy_role: FindingOperatorRetainedPolicyRole,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        let record = match self.bundles.get_retained_challenge_policy(
            artifact_kind,
            envelope_sha256,
            policy_role,
        ) {
            Ok(record) => record,
            Err(FindingOperatorBundleStoreError::NotFound) => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let policy: FindingAuthorityPin = serde_json::from_slice(&record.policy_json)
            .map_err(|_| "retained challenge authority policy is invalid".to_owned())?;
        policy
            .validate("retained challenge authority")
            .map_err(|_| "retained challenge authority policy is invalid".to_owned())?;
        Ok(Some(policy))
    }

    fn retain_policy(
        &self,
        artifact_kind: FindingOperatorRetainedPolicyArtifactKind,
        envelope_sha256: &str,
        policy_role: FindingOperatorRetainedPolicyRole,
        policy: &FindingAuthorityPin,
        expected: &FindingAuthorityPin,
    ) -> Result<(), String> {
        policy
            .validate("retained challenge authority")
            .map_err(|_| "retained challenge authority policy is invalid".to_owned())?;
        if policy != expected {
            return Err("retained challenge authority policy is not configured".to_owned());
        }
        let policy_json =
            chio_core::canonical_json_bytes(policy).map_err(|error| error.to_string())?;
        self.bundles
            .put_retained_challenge_policy(
                artifact_kind,
                envelope_sha256,
                policy_role,
                &policy_json,
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn retain_governance_case_policy(
        &self,
        envelope_sha256: &str,
        policy: &FindingAuthorityPin,
    ) -> Result<(), String> {
        self.retain_policy(
            FindingOperatorRetainedPolicyArtifactKind::GovernanceCase,
            envelope_sha256,
            FindingOperatorRetainedPolicyRole::Governance,
            policy,
            &self.market.governance_root,
        )
    }

    pub fn retain_governance_activation_policy(
        &self,
        envelope_sha256: &str,
        policy: &FindingAuthorityPin,
    ) -> Result<(), String> {
        self.retain_policy(
            FindingOperatorRetainedPolicyArtifactKind::TrustActivation,
            envelope_sha256,
            FindingOperatorRetainedPolicyRole::Governance,
            policy,
            &self.market.governance_root,
        )
    }

    pub fn retain_audit_epoch_policies(
        &self,
        envelope_sha256: &str,
        audit_policy: &FindingAuthorityPin,
        randomness_policy: &FindingAuthorityPin,
    ) -> Result<(), String> {
        self.retain_policy(
            FindingOperatorRetainedPolicyArtifactKind::AuditEpoch,
            envelope_sha256,
            FindingOperatorRetainedPolicyRole::AuditAuthority,
            audit_policy,
            &self.market.audit_authority,
        )?;
        self.retain_policy(
            FindingOperatorRetainedPolicyArtifactKind::AuditEpoch,
            envelope_sha256,
            FindingOperatorRetainedPolicyRole::RandomnessWitness,
            randomness_policy,
            &self.market.audit_randomness_witness,
        )
    }

    pub fn retain_audit_authorization_policy(
        &self,
        envelope_sha256: &str,
        policy: &FindingAuthorityPin,
    ) -> Result<(), String> {
        self.retain_policy(
            FindingOperatorRetainedPolicyArtifactKind::AuditAuthorization,
            envelope_sha256,
            FindingOperatorRetainedPolicyRole::Governance,
            policy,
            &self.market.governance_root,
        )
    }

    /// Validate and retain one fully published audit round and every
    /// historical authority policy needed to replay it after rotation.
    pub fn retain_audit_round(&self, round: &FindingAuditRound) -> Result<String, String> {
        let epoch_digest =
            signed_envelope_sha256(&round.epoch).map_err(|error| error.to_string())?;
        let authorization_digest =
            signed_envelope_sha256(&round.authorization).map_err(|error| error.to_string())?;
        if round.epoch.body.authorization_digest != authorization_digest {
            return Err("audit round does not bind its authorization envelope".to_owned());
        }
        if round.authorization.body.epoch_precommitment_sha256
            != audit_epoch_precommitment_sha256(&round.epoch.body)
                .map_err(|error| error.to_string())?
        {
            return Err("audit round authorization does not bind its epoch".to_owned());
        }
        if round.authorization.body.authorized_at > round.epoch.body.committed_at
            || round.authorization.body.expires_at <= round.epoch.body.committed_at
        {
            return Err("audit round authorization does not cover commitment time".to_owned());
        }
        for (label, policy, acted_at) in [
            (
                "audit authority",
                &self.market.audit_authority,
                round.epoch.body.committed_at,
            ),
            (
                "audit randomness witness",
                &self.market.audit_randomness_witness,
                round.epoch.body.seed_witnessed_at,
            ),
            (
                "audit governance",
                &self.market.governance_root,
                round.authorization.body.authorized_at,
            ),
        ] {
            policy.validate(label).map_err(|error| error.to_string())?;
            if !policy.covers(acted_at) {
                return Err(format!("{label} policy does not cover the signed action"));
            }
        }
        let audit_key = self
            .market
            .audit_authority
            .key()
            .map_err(|error| error.to_string())?;
        let witness_key = self
            .market
            .audit_randomness_witness
            .key()
            .map_err(|error| error.to_string())?;
        let governance_key = self
            .market
            .governance_root
            .key()
            .map_err(|error| error.to_string())?;
        verify_signed_audit_epoch(&round.epoch, &audit_key, &witness_key)
            .map_err(|_| "audit round epoch signature is invalid".to_owned())?;
        verify_signed_audit_round_authorization(&round.authorization, &governance_key)
            .map_err(|_| "audit round authorization signature is invalid".to_owned())?;
        select_audit_targets(
            &round.epoch.body,
            &witness_key,
            &round.revealed_seed,
            &round.eligible,
        )
        .map_err(|_| "audit round selection inputs are invalid".to_owned())?;
        let round_json =
            chio_core::canonical_json_bytes(round).map_err(|error| error.to_string())?;

        self.retain_audit_epoch_policies(
            &epoch_digest,
            &self.market.audit_authority,
            &self.market.audit_randomness_witness,
        )?;
        self.retain_audit_authorization_policy(
            &authorization_digest,
            &self.market.governance_root,
        )?;
        self.bundles
            .put_audit_round(&epoch_digest, &round_json)
            .map_err(|error| error.to_string())?;
        Ok(epoch_digest)
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
        epoch_envelope_sha256: &str,
    ) -> Result<Option<FindingAuditRound>, String> {
        let record = match self.bundles.get_audit_round(epoch_envelope_sha256) {
            Ok(record) => record,
            Err(FindingOperatorBundleStoreError::NotFound) => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let round: FindingAuditRound = serde_json::from_slice(&record.round_json)
            .map_err(|_| "retained audit round is invalid".to_owned())?;
        if signed_envelope_sha256(&round.epoch).map_err(|error| error.to_string())?
            != epoch_envelope_sha256
        {
            return Err("retained audit round does not match its epoch digest".to_owned());
        }
        Ok(Some(round))
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
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        self.retained_policy(
            FindingOperatorRetainedPolicyArtifactKind::GovernanceCase,
            envelope_sha256,
            FindingOperatorRetainedPolicyRole::Governance,
        )
    }

    fn governance_policy_for_activation(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        self.retained_policy(
            FindingOperatorRetainedPolicyArtifactKind::TrustActivation,
            envelope_sha256,
            FindingOperatorRetainedPolicyRole::Governance,
        )
    }

    fn penalty_policy_for_penalty(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        self.retained_policy(
            FindingOperatorRetainedPolicyArtifactKind::Penalty,
            envelope_sha256,
            FindingOperatorRetainedPolicyRole::PenaltyAuthority,
        )
    }

    fn retain_penalty_policy(
        &self,
        envelope_sha256: &str,
        policy: &FindingAuthorityPin,
    ) -> Result<(), String> {
        self.retain_policy(
            FindingOperatorRetainedPolicyArtifactKind::Penalty,
            envelope_sha256,
            FindingOperatorRetainedPolicyRole::PenaltyAuthority,
            policy,
            &self.market.market_penalty,
        )
    }

    fn evaluator_policy_for_outcome(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        self.retained_policy(
            FindingOperatorRetainedPolicyArtifactKind::ChallengeOutcome,
            envelope_sha256,
            FindingOperatorRetainedPolicyRole::Evaluator,
        )
    }

    fn retain_evaluator_policy(
        &self,
        envelope_sha256: &str,
        policy: &FindingAuthorityPin,
    ) -> Result<(), String> {
        self.retain_policy(
            FindingOperatorRetainedPolicyArtifactKind::ChallengeOutcome,
            envelope_sha256,
            FindingOperatorRetainedPolicyRole::Evaluator,
            policy,
            &self.market.challenge_evaluator,
        )
    }

    fn audit_policy_for_epoch(
        &self,
        epoch_envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        self.retained_policy(
            FindingOperatorRetainedPolicyArtifactKind::AuditEpoch,
            epoch_envelope_sha256,
            FindingOperatorRetainedPolicyRole::AuditAuthority,
        )
    }

    fn randomness_witness_policy_for_epoch(
        &self,
        epoch_envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        self.retained_policy(
            FindingOperatorRetainedPolicyArtifactKind::AuditEpoch,
            epoch_envelope_sha256,
            FindingOperatorRetainedPolicyRole::RandomnessWitness,
        )
    }

    fn governance_policy_for_audit_authorization(
        &self,
        authorization_envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        self.retained_policy(
            FindingOperatorRetainedPolicyArtifactKind::AuditAuthorization,
            authorization_envelope_sha256,
            FindingOperatorRetainedPolicyRole::Governance,
        )
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
