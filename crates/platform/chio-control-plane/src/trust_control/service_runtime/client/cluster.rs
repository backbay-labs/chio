use super::super::*;

impl TrustControlClient {
    pub(crate) fn cluster_status(&self) -> Result<ClusterStatusResponse, CliError> {
        self.get_internal_json(INTERNAL_CLUSTER_STATUS_PATH, None)
    }

    pub(crate) fn authority_snapshot(&self) -> Result<AuthoritySnapshotView, CliError> {
        self.get_internal_json(INTERNAL_AUTHORITY_SNAPSHOT_PATH, None)
    }

    pub(crate) fn cluster_snapshot(&self) -> Result<ClusterStateSnapshotResponse, CliError> {
        self.get_internal_json(INTERNAL_CLUSTER_SNAPSHOT_PATH, None)
    }

    pub(crate) fn revocation_deltas(
        &self,
        query: &RevocationDeltaQuery,
    ) -> Result<RevocationDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_REVOCATIONS_DELTA_PATH, query, None)
    }

    pub(crate) fn tool_receipt_deltas(
        &self,
        query: &ReceiptDeltaQuery,
    ) -> Result<ReceiptDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_TOOL_RECEIPTS_DELTA_PATH, query, None)
    }

    pub(crate) fn child_receipt_deltas(
        &self,
        query: &ReceiptDeltaQuery,
    ) -> Result<ReceiptDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_CHILD_RECEIPTS_DELTA_PATH, query, None)
    }

    pub(crate) fn lineage_deltas(
        &self,
        query: &ReceiptDeltaQuery,
    ) -> Result<LineageDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_LINEAGE_DELTA_PATH, query, None)
    }

    pub(crate) fn budget_deltas(
        &self,
        query: &BudgetDeltaQuery,
    ) -> Result<BudgetDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_BUDGETS_DELTA_PATH, query, None)
    }
}
