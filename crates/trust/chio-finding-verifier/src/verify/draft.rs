use super::*;

impl FindingVerifierDraft {
    /// Exact Finding whose canonical bytes were evaluated. The binding is
    /// read-only so report signing cannot relabel derived facet outcomes.
    #[must_use]
    pub const fn finding(&self) -> &Finding {
        &self.finding
    }

    /// Digest of the exact canonical Finding artifact evaluated by this draft.
    #[must_use]
    pub fn finding_artifact_sha256(&self) -> &str {
        &self.finding_artifact_sha256
    }

    #[must_use]
    pub fn resolved_evidence_bundle_sha256(&self) -> &str {
        &self.resolved_evidence_bundle_sha256
    }

    #[must_use]
    pub fn replay_recipe_input_sha256(&self) -> Option<&str> {
        self.replay_recipe_input_sha256.as_deref()
    }

    #[must_use]
    pub fn status_proof_input_sha256(&self) -> Option<&str> {
        self.status_proof_input_sha256.as_deref()
    }

    #[must_use]
    pub const fn evaluation_time(&self) -> u64 {
        self.evaluation_time
    }

    /// Canonically ordered facet results derived during evidence
    /// verification. Callers may inspect but cannot replace or rewrite
    /// outcomes before report signing.
    #[must_use]
    pub fn facets(&self) -> &[FindingFacetResult] {
        &self.facets
    }

    /// Authenticated, checkpointed post-purchase receipt derived during
    /// evidence verification. Callers may inspect but cannot replace it
    /// before report signing.
    #[must_use]
    pub fn finding_delivery_receipt_id(&self) -> Option<&str> {
        self.finding_delivery_receipt_id.as_deref()
    }

    /// Collateral allocation derived from verified bond evidence, when any.
    #[must_use]
    pub fn backing_allocation_id(&self) -> Option<&str> {
        self.backing_allocation_id.as_deref()
    }

    /// Outcome for one facet kind.
    pub fn facet_outcome(&self, kind: FindingFacetKind) -> Option<FindingFacetOutcome> {
        self.facets
            .iter()
            .find(|result| result.facet == kind)
            .map(|result| result.outcome)
    }

    /// The facets this finding REQUIRES to be exactly verified: the
    /// profile's floor plus every claim the artifact makes. Nothing here
    /// waives a facet the profile lists.
    pub fn required_facets(
        &self,
        profile: &FindingChallengeVerifierProfile,
    ) -> Vec<FindingFacetKind> {
        required_finding_facets(&self.finding, profile)
    }

    /// True when no facet failed and every required facet is exactly
    /// `verified`. `Failed` records a check that ran and contradicted its
    /// evidence, so it denies even when the profile did not require that
    /// facet. Optional `asserted` and `unavailable` results remain visible
    /// without being upgraded to verified.
    pub fn satisfies_required_facets(&self, profile: &FindingChallengeVerifierProfile) -> bool {
        !self
            .facets
            .iter()
            .any(|result| result.outcome == FindingFacetOutcome::Failed)
            && self
                .required_facets(profile)
                .into_iter()
                .all(|kind| self.facet_outcome(kind) == Some(FindingFacetOutcome::Verified))
    }
}
