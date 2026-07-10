use chio_kernel::receipt_query::{ReceiptQuery, ReceiptQueryResult};
use chio_kernel::ReceiptStoreError;

use crate::receipt_store::SqliteReceiptStore;

impl SqliteReceiptStore {
    /// Query tool receipts with multi-filter support and cursor-based pagination.
    ///
    /// Filters are applied with AND semantics. The cursor parameter enables
    /// forward-only pagination using the seq column as a stable cursor.
    ///
    /// The limit is capped at MAX_QUERY_LIMIT. total_count reflects the full
    /// filtered set (no cursor applied), regardless of the page limit.
    pub fn query_receipts(
        &self,
        query: &ReceiptQuery,
    ) -> Result<ReceiptQueryResult, ReceiptStoreError> {
        // Delegate to the impl in receipt_store.rs (which can access the private connection field).
        self.query_receipts_impl(query)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
