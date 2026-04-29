//! Tool-call evaluation surface.
//!
//! Defines the [`ToolEvaluator`] trait that names the four logical phases of
//! a tool-call evaluation (capability validation, guard pipeline, dispatch,
//! receipt signing). The default [`BlockingToolEvaluator`] wraps the existing
//! synchronous helpers; async-native implementations can override individual
//! phase methods without re-shaping the public surface.

use crate::kernel::ChioKernel;
use crate::{
    ChioReceipt, ChioReceiptBody, KernelError, ToolCallRequest, ToolCallResponse,
    ToolInvocationCost, ToolServerOutput, Verdict,
};

/// The four logical phases of a tool-call evaluation, surfaced as an
/// async-capable trait so each phase can be replaced with an async-native
/// implementation without re-shaping the public surface.
///
/// The default [`BlockingToolEvaluator`] preserves the semantics of
/// `ChioKernel::evaluate_tool_call_sync_inner` by delegating to the
/// `evaluate_tool_call_sync` shim. The four step methods
/// (`validate_capability`, `run_guards`, `dispatch`, `sign_receipt`) default
/// to forwarding through the full synchronous pipeline; override them to swap
/// in async-native step bodies.
#[allow(async_fn_in_trait)]
pub trait ToolEvaluator: Send + Sync {
    /// Run the full evaluation pipeline for `request` against `kernel` and
    /// return the resulting `ToolCallResponse`.
    async fn evaluate(
        &self,
        kernel: &ChioKernel,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError>;

    /// Run the full evaluation pipeline with additional receipt metadata.
    async fn evaluate_with_metadata(
        &self,
        kernel: &ChioKernel,
        request: &ToolCallRequest,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let _ = extra_metadata;
        self.evaluate(kernel, request).await
    }

    /// Validate the capability token attached to `request`.
    async fn validate_capability(
        &self,
        kernel: &ChioKernel,
        request: &ToolCallRequest,
    ) -> Result<Verdict, KernelError> {
        let response = self.evaluate(kernel, request).await?;
        Ok(response.verdict)
    }

    /// Run the registered guard pipeline against `request`.
    async fn run_guards(
        &self,
        kernel: &ChioKernel,
        request: &ToolCallRequest,
    ) -> Result<Verdict, KernelError> {
        let response = self.evaluate(kernel, request).await?;
        Ok(response.verdict)
    }

    /// Dispatch the validated request to the appropriate tool server.
    ///
    /// The default body routes through
    /// [`ChioKernel::dispatch_tool_call_with_cost`], which preserves the
    /// pre-T4 dispatch order: try streaming first, use `invoke_with_cost`
    /// only for monetary grants, and report `None` cost for non-monetary
    /// grants.
    async fn dispatch(
        &self,
        kernel: &ChioKernel,
        request: &ToolCallRequest,
        has_monetary_grant: bool,
    ) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
        kernel
            .dispatch_tool_call_with_cost(request, has_monetary_grant)
            .await
    }

    /// Sign the receipt for the (allow or deny) outcome of a tool call.
    ///
    /// Accepts a fully-constructed [`ChioReceiptBody`] and returns the signed
    /// [`ChioReceipt`]. The default body routes through
    /// `kernel.sign_receipt_via_channel` (the mpsc-backed signing task);
    /// producers wait on bounded backpressure, never on a receipt-log mutex.
    /// The signed receipt is byte-identical to the inline
    /// `build_and_sign_receipt` path because both delegate to
    /// `chio_kernel_core::sign_receipt`.
    async fn sign_receipt(
        &self,
        kernel: &ChioKernel,
        body: ChioReceiptBody,
    ) -> Result<ChioReceipt, KernelError> {
        kernel.sign_receipt_via_channel(body).await
    }
}

/// Default [`ToolEvaluator`] implementation: delegates the entire pipeline
/// to the existing synchronous flow on [`ChioKernel`].
///
/// Inside a multi-threaded tokio runtime the call is wrapped in
/// `tokio::task::block_in_place` so the worker thread is released back to
/// the scheduler while the synchronous body runs. Outside such a runtime
/// (current-thread runtime, or no runtime at all) the call is direct.
#[derive(Debug, Default, Clone, Copy)]
pub struct BlockingToolEvaluator;

impl ToolEvaluator for BlockingToolEvaluator {
    async fn evaluate(
        &self,
        kernel: &ChioKernel,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        // Reach into the existing synchronous pipeline. The wrapper isolates
        // the (potentially blocking) sync work from the async runtime when
        // we are inside one; otherwise it is a direct call.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| kernel.evaluate_tool_call_sync(request))
            }
            _ => kernel.evaluate_tool_call_sync(request),
        }
    }

    async fn evaluate_with_metadata(
        &self,
        kernel: &ChioKernel,
        request: &ToolCallRequest,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| {
                    kernel.evaluate_tool_call_blocking_with_metadata(request, extra_metadata)
                })
            }
            _ => kernel.evaluate_tool_call_blocking_with_metadata(request, extra_metadata),
        }
    }
}
