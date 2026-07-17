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

pub(crate) use finalization::FinalizeToolOutputCostContext;

pub(crate) struct ReceiptResponseContext<'a> {
    pub(crate) request: &'a ToolCallRequest,
    pub(crate) evaluation_context: &'a EvaluationReceiptContext,
    pub(crate) timestamp: u64,
    pub(crate) matched_grant_index: Option<usize>,
    pub(crate) extra_metadata: Option<serde_json::Value>,
}

#[derive(Clone, Copy)]
enum ReceiptRecordMode {
    WithFederation,
    LocalOnly,
}
