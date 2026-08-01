mod receipt_building;
mod receipt_content;
mod receipt_metadata;
mod receipt_scopes;
mod signing;

#[cfg(test)]
mod tests;

pub(crate) use receipt_building::{
    build_child_request_receipt, child_outcome_payload, child_terminal_state, next_receipt_id,
};
pub(crate) use receipt_content::{
    accumulate_stream_under_caps, receipt_content_for_output, stream_limit_reason,
    truncate_stream_to_limits,
};
#[cfg(test)]
pub(crate) use receipt_metadata::governed_request_metadata;
pub(crate) use receipt_metadata::{
    merge_metadata_objects, receipt_attribution_metadata, request_receipt_metadata,
    request_receipt_metadata_with_payee_binding, verify_governed_runtime_attestation_record,
};
pub(crate) use receipt_scopes::{
    current_post_invocation_guard_evidence, current_pre_invocation_guard_evidence,
    scope_governed_call_chain_receipt_evidence, scope_governed_runtime_attestation_receipt_record,
    scope_post_invocation_guard_evidence, scope_pre_invocation_guard_evidence,
    GovernedCallChainReceiptEvidence,
};
pub use receipt_scopes::{
    fixed_runtime_unix_secs_for_current_thread, scope_fixed_runtime_for_current_thread,
    FixedRuntimeScope,
};
pub use signing::{
    kernel_signing_backend, sign_receipt_body_hybrid_canonical, sign_receipt_body_with_backend,
    KernelCryptoFloor, KernelSigningBackendError, SignedHybridReceipt,
};
