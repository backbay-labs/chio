use chio_core::{
    receipt::kinds::BoundaryClass, receipt::kinds::ReceiptKind, receipt::kinds::RedactionMode,
    receipt::kinds::ToolOrigin, receipt::signing::ReceiptSigningHandle,
};
use chio_log_redact::redacted;

use super::*;

mod allow_responses;
mod deny_responses;
mod finalization;
mod receipt_persistence;
mod terminal_responses;

pub(crate) use allow_responses::{AllowResponseNonce, ReservedHoldStamp};
pub(crate) use finalization::FinalizeToolOutputCostContext;

#[derive(Clone, Copy)]
enum ReceiptRecordMode {
    WithFederation,
    LocalOnly,
}
