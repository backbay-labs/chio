mod coupling;
mod receipt_building;
mod receipt_content;
mod receipt_metadata;
mod receipt_scopes;
mod signing;

#[cfg(test)]
mod tests;

pub use coupling::{receipt_body_fields_coupled, ReceiptCouplingExpectation};
pub(crate) use receipt_building::{
    build_child_request_receipt, child_outcome_payload, child_terminal_state, next_receipt_id,
};
pub(crate) use receipt_content::{
    accumulate_stream_under_caps, receipt_content_for_output, stream_limit_reason,
    truncate_stream_to_limits,
};
#[cfg(test)]
pub(crate) use receipt_metadata::{governed_request_metadata, request_receipt_metadata};
pub(crate) use receipt_metadata::{
    merge_metadata_objects, normalize_external_receipt_metadata,
    project_runtime_admission_receipt_metadata, receipt_attribution_metadata,
    request_receipt_metadata_with_context, sanitize_external_receipt_metadata,
    strip_external_receipt_provenance, validate_runtime_admission_receipt_metadata,
    verify_governed_runtime_attestation_record,
};
pub(crate) use receipt_scopes::{
    current_post_invocation_guard_evidence, current_pre_invocation_guard_evidence,
    fixed_runtime_unix_secs_for_current_thread, scope_post_invocation_guard_evidence,
    scope_pre_invocation_guard_evidence, GovernedCallChainReceiptEvidence,
};
pub use receipt_scopes::{scope_fixed_runtime_for_current_thread, FixedRuntimeScope};
#[cfg(test)]
pub(crate) use receipt_scopes::{
    scope_governed_call_chain_receipt_evidence, scope_governed_runtime_attestation_receipt_record,
};
pub use signing::{
    kernel_signing_backend, sign_receipt_body_hybrid_canonical, sign_receipt_body_with_backend,
    KernelCryptoFloor, KernelSigningBackendError, SignedHybridReceipt,
};
