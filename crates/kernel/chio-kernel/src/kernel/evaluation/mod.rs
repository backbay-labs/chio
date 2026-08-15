//! `ChioKernel` tool-call and plan evaluation path.
//!
//! Holds the synchronous and asynchronous evaluate entrypoints, the plan
//! evaluation helpers, and the long-form evaluation cores.

use chio_log_redact::redacted;

use self::responses::FinalizeToolOutputCostContext;
use super::*;

mod async_evaluation_core;
mod evaluation_entry;
pub(crate) mod evaluation_helpers;
mod nested_flow_evaluation;
mod sync_evaluation_wrapper;

/// Disposition of the pre-execution budget hold when a strict-nonce preflight
/// is reached (nonce required, no nonce presented on the request).
///
/// The preflight is the point in the evaluation pipeline where the capability,
/// DPoP, governed-transaction, guard, runtime-admission, and budget checks have
/// all passed but the tool has not yet been dispatched. What happens to the
/// reserved hold there depends on who executes the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreflightHoldDisposition {
    /// Reverse the pre-execution hold and return an incomplete preflight
    /// receipt. The same kernel re-takes the hold when the caller retries
    /// presenting the minted nonce, then dispatches the tool. This is the
    /// default for every in-process strict-nonce dispatch surface.
    ReverseForRetry,
    /// Keep the pre-execution hold reserved (open) and return a
    /// non-authoritative authorization receipt carrying the minted nonce. The
    /// kernel does not dispatch the tool: the caller presents the nonce to the
    /// real tool server, which verifies and consumes it and reconciles the
    /// reserved hold. Used by the sidecar mediated `/v1/evaluate` pre-execution
    /// authorization gate, where the reserved hold enforces `max_total_cost`
    /// against concurrent authorizations. An orphaned reserved hold (the caller
    /// never executes) is fail-closed: budget stays over-reserved until the
    /// crash reaper reclaims it, never over-subscribed.
    ReserveForCaller,
}
