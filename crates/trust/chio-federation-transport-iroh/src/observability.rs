//! Tracing span/event helpers for the iroh federation-transport lanes.
//!
//! Mirrors the house style in `chio-wasm-guards/src/observability.rs`: a small
//! module of `pub const SPAN_*` names plus `*_span()` builders that use
//! `tracing::info_span!` with dotted field names (`lane`, `outcome`,
//! `endpoint`, `reason`). Purely additive: these carry security-relevant
//! structured fields ALONGSIDE the existing fail-closed logic and change no
//! decision. Only endpoint SHORT-forms are ever recorded, never full keys.

use tracing::{field, Span};

/// Span covering one lane accept-handler body (from permit acquire to teardown).
pub const SPAN_IROH_LANE_ACCEPT: &str = "chio.iroh.lane_accept";

/// Tracing target for admission-gate events (the 403 reject is the #1 signal).
pub const TARGET_ADMISSION: &str = "chio.iroh.admission";
/// Tracing target for per-seam verification-failure events.
pub const TARGET_VERIFY: &str = "chio.iroh.verify";
/// Tracing target for per-lane accept-handler events.
pub const TARGET_LANE: &str = "chio.iroh.lane";
/// Tracing target for revocation catch-up events (epoch gaps, root failures).
pub const TARGET_CATCHUP: &str = "chio.iroh.catchup";
/// Tracing target for pheromone outbox drain events (retry / dead-letter).
pub const TARGET_OUTBOX: &str = "chio.iroh.outbox";

/// Build the accept-handler span for a lane. The `outcome` field is recorded on
/// completion via [`record_outcome`]. Wrap the handler body with
/// `.instrument(lane_accept_span(lane))` so the span never crosses an `.await`
/// as an entered guard (the async-span footgun).
#[must_use]
pub fn lane_accept_span(lane: &str) -> Span {
    tracing::info_span!(
        "chio.iroh.lane_accept",
        lane = %lane,
        outcome = field::Empty,
    )
}

/// Record the terminal `outcome` on a lane accept span.
pub fn record_outcome(span: &Span, outcome: &str) {
    span.record("outcome", outcome);
}
