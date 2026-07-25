use super::*;

impl ClearingRoundLifecycleRecordV1 {
    #[must_use]
    pub fn round_id(&self) -> &str {
        &self.round_id
    }

    #[must_use]
    pub fn governance_scope_id(&self) -> &str {
        &self.governance_scope_id
    }

    #[must_use]
    pub fn round_core_digest(&self) -> &str {
        &self.round_core_digest
    }

    #[must_use]
    pub fn reservation_root(&self) -> &str {
        &self.reservation_root
    }

    #[must_use]
    pub const fn reservation_count(&self) -> u64 {
        self.reservation_count
    }

    #[must_use]
    pub fn output_manifest_digest(&self) -> Option<&str> {
        self.output_manifest_digest.as_deref()
    }

    #[must_use]
    pub fn participant_acceptance_root(&self) -> Option<&str> {
        self.participant_acceptance_root.as_deref()
    }

    #[must_use]
    pub const fn participant_acceptance_count(&self) -> Option<u64> {
        self.participant_acceptance_count
    }

    #[must_use]
    pub fn abort_digest(&self) -> Option<&str> {
        self.abort_digest.as_deref()
    }

    #[must_use]
    pub fn first_dispatch_operation_id(&self) -> Option<&str> {
        self.first_dispatch_operation_id.as_deref()
    }

    #[must_use]
    pub fn last_transition_digest(&self) -> &str {
        &self.last_transition_digest
    }

    #[must_use]
    pub const fn state(&self) -> ClearingRoundLifecycleStateV1 {
        self.state
    }

    #[must_use]
    pub const fn row_version(&self) -> u64 {
        self.row_version
    }

    #[must_use]
    pub const fn fence(&self) -> u64 {
        self.fence
    }
}
