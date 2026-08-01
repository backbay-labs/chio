use super::*;

impl ChioKernel {
    pub fn evaluate_tool_call_blocking(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_inner(request, None, None)
    }

    /// Crate-private sync entrypoint invoked by the
    /// [`crate::kernel::evaluator::ToolEvaluator`] default
    /// implementation. Wraps the long-form
    /// `evaluate_tool_call_sync_inner` so the trait body does
    /// not need to plumb the `session_filesystem_roots` /
    /// `extra_metadata` parameters; both default to `None` on this path,
    /// matching the previous direct delegation from
    /// `evaluate_tool_call`.
    pub(crate) fn evaluate_tool_call_sync(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_inner(request, None, None)
    }

    pub fn evaluate_tool_call_blocking_with_metadata(
        &self,
        request: &ToolCallRequest,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_inner(request, None, extra_metadata)
    }

    #[doc(hidden)]
    fn evaluate_tool_call_sync_inner(
        &self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_with_session_context(
            request,
            session_filesystem_roots,
            extra_metadata,
            None,
        )
    }

    /// Evaluate a tool call sync path with access to the owning session,
    /// so the kernel can tag the resulting receipt with the session's
    /// tenant_id (multi-tenant receipt isolation).
    ///
    /// `session_id` is the session that authenticated the caller, used only
    /// to resolve the tenant from `auth_context().enterprise_identity`. The
    /// tenant_id is NEVER read from `request` itself -- accepting a caller-
    /// provided tenant would defeat the isolation guarantee.
    pub(crate) fn evaluate_tool_call_sync_with_session_context(
        &self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
        extra_metadata: Option<serde_json::Value>,
        session_id: Option<&SessionId>,
    ) -> Result<ToolCallResponse, KernelError> {
        block_on_async_tool_dispatch(self.evaluate_tool_call_async_with_session_context(
            request,
            session_filesystem_roots,
            extra_metadata,
            session_id,
            PreflightHoldDisposition::ReverseForRetry,
        ))
    }

    /// Pre-execution authorization gate for callers that execute the tool
    /// themselves (the sidecar mediated `/v1/evaluate` route).
    ///
    /// Runs the full pre-dispatch verification pipeline (capability, DPoP,
    /// governed intent, approval token, guards, runtime admission), reserves
    /// the pre-execution budget hold and KEEPS IT OPEN, and mints a fresh
    /// execution nonce. It never dispatches a tool server, never consumes a
    /// presented nonce, and never signs a completed or settled spend. The
    /// returned receipt is intentionally non-authoritative: the hold is
    /// reserved, not reconciled, so `is_authoritative_spend_receipt` rejects it.
    ///
    /// The reserved open hold is what enforces `max_total_cost` against
    /// concurrent authorizations: a second authorization for a grant whose
    /// budget is already fully reserved is denied. The caller presents the
    /// minted nonce to the real tool server, which verifies and consumes it and
    /// reconciles the reserved hold at the execution site.
    ///
    /// The request MUST NOT carry a presented execution nonce: this entry point
    /// mints nonces, it does not settle them. The invariant is enforced here
    /// fail-closed: a request with a presented nonce is rejected with
    /// [`KernelError::ReservingAuthorizationRejectsPresentedNonce`] rather than
    /// silently skipping the reserve path (a presented nonce makes
    /// `execution_nonce_preflight_required` return false) and falling through to
    /// dispatch, which is the opposite of the documented reserve behavior.
    pub fn authorize_tool_call_reserving_blocking_with_metadata(
        &self,
        request: &ToolCallRequest,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        if request.execution_nonce.is_some() {
            return Err(KernelError::ReservingAuthorizationRejectsPresentedNonce);
        }
        block_on_async_tool_dispatch(self.evaluate_tool_call_async_with_session_context(
            request,
            None,
            extra_metadata,
            None,
            PreflightHoldDisposition::ReserveForCaller,
        ))
    }
}
