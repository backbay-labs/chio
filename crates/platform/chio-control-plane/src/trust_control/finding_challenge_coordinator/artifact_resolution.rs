impl FindingChallengeCoordinator {
    fn require_finding_status_feed_binding(
        &self,
        finding: &Finding,
        admission: &SignedFindingAdmission,
    ) -> Result<(), ChallengeCoordinatorError> {
        if finding.status_feed_ref != self.status_feed_operator_ref {
            return Err(ChallengeCoordinatorError::FindingBinding("status_feed_ref"));
        }
        if admission.body.status_feed_operator_ref != finding.status_feed_ref {
            return Err(ChallengeCoordinatorError::AdmissionBinding(
                "status_feed_operator_ref",
            ));
        }
        Ok(())
    }

    fn require_finalizing_status_feed_binding(
        &self,
        record: &FindingLiabilityRecord,
        admission: &SignedFindingAdmission,
    ) -> Result<(), ChallengeCoordinatorError> {
        if admission.body.finding_id != record.finding_id
            || admission.body.listing_id != record.listing_id
            || admission.body.backing_allocation_id != record.allocation_id
            || admission.body.status_feed_operator_ref != self.status_feed_operator_ref
        {
            return Err(ChallengeCoordinatorError::AdmissionBinding(
                "status_feed_operator_ref",
            ));
        }
        Ok(())
    }

    /// Resolve the finding from the exact bytes whose digest the
    /// challenge binds. A typed view handed in beside those bytes would
    /// be a different artifact with the same name, so only the bytes are
    /// accepted here.
    fn resolve_finding(
        &self,
        raw_finding: &str,
        challenge: &FindingChallenge,
    ) -> Result<Finding, ChallengeCoordinatorError> {
        if raw_finding.len() > MAX_RAW_FINDING_BYTES {
            return Err(ChallengeCoordinatorError::FindingArtifact(
                "raw finding artifact exceeds the ingress bound".to_owned(),
            ));
        }
        if sha256_hex(raw_finding.as_bytes()) != challenge.finding_artifact_sha256 {
            return Err(ChallengeCoordinatorError::FindingBinding(
                "finding_artifact_sha256",
            ));
        }
        let strict = canonical_json_bytes_from_str(raw_finding).map_err(|_| {
            ChallengeCoordinatorError::FindingArtifact(
                "raw finding is not strict canonical I-JSON".to_owned(),
            )
        })?;
        if strict.as_slice() != raw_finding.as_bytes() {
            return Err(ChallengeCoordinatorError::FindingArtifact(
                "raw finding bytes are not the canonical serialization".to_owned(),
            ));
        }
        let finding: Finding = serde_json::from_str(raw_finding)
            .map_err(|error| ChallengeCoordinatorError::FindingArtifact(error.to_string()))?;
        let typed = canonical_json_bytes(&finding).map_err(|_| {
            ChallengeCoordinatorError::FindingArtifact(
                "raw finding could not be canonically serialized".to_owned(),
            )
        })?;
        if typed != strict {
            return Err(ChallengeCoordinatorError::FindingArtifact(
                "raw finding does not match its typed canonical body".to_owned(),
            ));
        }
        verify_finding(&finding)
            .map_err(|error| ChallengeCoordinatorError::FindingArtifact(error.to_string()))?;
        if finding.finding_id != challenge.finding_id {
            return Err(ChallengeCoordinatorError::FindingBinding("finding_id"));
        }
        Ok(finding)
    }
}
