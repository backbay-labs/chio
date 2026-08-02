//! Injected broadcast seam for a fenced impairment intent.

use thiserror::Error;

use super::plan::{FindingImpairmentIntent, PlannedFindingImpairment};
use super::reconcile::{
    reconcile_finding_impairment, FindingImpairmentAttempt, FindingImpairmentOutcome,
};
use crate::PreparedEvmCall;

/// Failure surfaced by a [`FindingImpairmentPublisher`].
///
/// These are transport dispositions, not settlement outcomes. A publisher
/// that cannot say what happened returns an error and leaves the liability
/// where it was; it never manufactures an attempt.
#[derive(Debug, Error)]
pub enum FindingImpairmentPublishError {
    /// The intent was not durably fenced before dispatch was attempted.
    #[error("impairment intent is not durably fenced: {0}")]
    IntentNotFenced(String),
    /// The publisher could not reach the chain and may succeed on replay.
    #[error("transient impairment publisher failure: {0}")]
    Transient(String),
    /// The publisher rejected the dispatch and replay cannot succeed.
    #[error("permanent impairment publisher failure: {0}")]
    Permanent(String),
}

/// Durable publisher for one frozen impairment intent.
///
/// The trait is dyn-compatible so a coordinator can hold an
/// `Arc<dyn FindingImpairmentPublisher>`. Implementations MUST:
///
/// - refuse any intent whose id they have not already fenced durably, so
///   nothing external is dispatched before its semantic intent is persisted;
/// - be idempotent by `intent.intent_id` across process restarts and lease
///   recovery, since dispatch is at-least-once;
/// - broadcast the supplied call verbatim, never a re-derived one, and store
///   the raw transaction they broadcast before it can land;
/// - return what they actually observed. An implementation that cannot
///   determine which transaction consumed the evidence reports the stored
///   transaction it has, including the absence of an input, rather than
///   asserting a match.
///
/// This crate ships no production adapter. Broadcast is injected so the
/// preparation and reconciliation rules can be exercised without a chain.
pub trait FindingImpairmentPublisher: Send + Sync {
    /// Broadcast the prepared call for a fenced intent and report the result.
    fn publish(
        &self,
        intent: &FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError>;

    /// Re-observe the stored transaction for an already broadcast intent.
    ///
    /// This method MUST NOT broadcast. It re-reads the transaction receipt,
    /// canonical block identity, and configured finality depth immediately
    /// before the coordinator commits confirmation or settlement. `call` is
    /// supplied only so the returned raw transaction can be checked against
    /// the same frozen bytes as the original publication.
    fn observe(
        &self,
        intent: &FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError>;
}

/// Dispatch a planned impairment through a publisher and reconcile the
/// result against the frozen intent.
///
/// The publisher's report is never trusted as an outcome on its own: whatever
/// it returns goes through [`reconcile_finding_impairment`], so a publisher
/// cannot confirm an impairment the frozen intent does not match.
pub fn dispatch_finding_impairment(
    planned: &PlannedFindingImpairment,
    publisher: &dyn FindingImpairmentPublisher,
) -> Result<FindingImpairmentOutcome, FindingImpairmentPublishError> {
    let attempt = publisher.publish(planned.intent(), planned.call())?;
    Ok(reconcile_finding_impairment(planned.intent(), &attempt))
}

/// Re-observe and reconcile an already broadcast impairment without
/// dispatching it again.
pub fn reobserve_finding_impairment(
    planned: &PlannedFindingImpairment,
    publisher: &dyn FindingImpairmentPublisher,
) -> Result<FindingImpairmentOutcome, FindingImpairmentPublishError> {
    let attempt = publisher.observe(planned.intent(), planned.call())?;
    Ok(reconcile_finding_impairment(planned.intent(), &attempt))
}
