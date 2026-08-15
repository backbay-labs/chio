use super::*;

#[path = "bootstrap/federated.rs"]
mod federated;
#[path = "bootstrap/listing.rs"]
mod listing;
#[path = "bootstrap/open.rs"]
mod open;
#[path = "bootstrap/qualification.rs"]
mod qualification;

pub(super) use qualification::{
    receipt_actor_saturated_error, receipt_actor_unavailable_error, ReceiptWriterQualification,
};
pub(crate) use qualification::{
    receipt_pool_connection, verify_rollback, ReceiptSinkQualification,
};

fn require_admin_list_context(
    read_context: &ReceiptReadContext,
    operation: &str,
) -> Result<(), ReceiptStoreError> {
    match read_context.boundary {
        ReceiptReadBoundary::AdminAll => Ok(()),
        ReceiptReadBoundary::TenantScoped { .. } => Err(ReceiptStoreError::ReadBoundary(format!(
            "{operation} requires explicit admin receipt read context"
        ))),
    }
}
