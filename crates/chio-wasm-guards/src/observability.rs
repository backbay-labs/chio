//! Tracing span helpers for WASM guard observability.

use tracing::{field, Span};

pub const SPAN_GUARD_EVALUATE: &str = "chio.guard.evaluate";
pub const SPAN_GUARD_HOST_CALL: &str = "chio.guard.host_call";
pub const SPAN_GUARD_FETCH_BLOB: &str = "chio.guard.fetch_blob";
pub const SPAN_GUARD_RELOAD: &str = "chio.guard.reload";
pub const SPAN_GUARD_VERIFY: &str = "chio.guard.verify";

pub const DEFAULT_GUARD_VERSION: &str = "0.0.0";
pub const UNKNOWN_GUARD_DIGEST: &str = "unknown";

pub const VERDICT_ALLOW: &str = "allow";
pub const VERDICT_DENY: &str = "deny";
pub const VERDICT_REWRITE: &str = "rewrite";
pub const VERDICT_ERROR: &str = "error";

pub const HOST_LOG: &str = "log";
pub const HOST_GET_CONFIG: &str = "get_config";
pub const HOST_GET_TIME_UNIX_SECS: &str = "get_time_unix_secs";
pub const HOST_FETCH_BLOB: &str = "fetch_blob";

pub const RELOAD_APPLIED: &str = "applied";
pub const RELOAD_CANARY_FAILED: &str = "canary_failed";
pub const RELOAD_ROLLED_BACK: &str = "rolled_back";

pub const VERIFY_MODE_ED25519: &str = "ed25519";
pub const VERIFY_RESULT_OK: &str = "ok";
pub const VERIFY_RESULT_FAIL: &str = "fail";

#[must_use]
pub fn guard_digest_or_unknown(digest: Option<&str>) -> &str {
    digest.unwrap_or(UNKNOWN_GUARD_DIGEST)
}

#[must_use]
pub fn guard_evaluate_span(
    guard_id: &str,
    guard_version: &str,
    guard_digest: &str,
    guard_epoch: u64,
    guard_reload_seq: u64,
    verdict: Option<&str>,
) -> Span {
    let span = tracing::info_span!(
        "chio.guard.evaluate",
        guard.id = %guard_id,
        guard.version = %guard_version,
        guard.digest = %guard_digest,
        guard.epoch = guard_epoch,
        guard.reload_seq = guard_reload_seq,
        verdict = field::Empty,
    );
    if let Some(verdict) = verdict {
        span.record("verdict", verdict);
    }
    span
}

#[must_use]
pub fn guard_host_call_span(host_name: &str) -> Span {
    tracing::info_span!("chio.guard.host_call", host.name = %host_name)
}

#[must_use]
pub fn guard_fetch_blob_span(bundle_id: &str, bytes: u64) -> Span {
    let span = tracing::info_span!(
        "chio.guard.fetch_blob",
        bundle.id = %bundle_id,
        bytes = field::Empty
    );
    span.record("bytes", bytes);
    span
}

#[must_use]
pub fn guard_reload_span(outcome: &str, reload_seq: u64) -> Span {
    tracing::info_span!("chio.guard.reload", outcome = %outcome, reload_seq = reload_seq)
}

#[must_use]
pub fn guard_verify_span(mode: &str, result: Option<&str>) -> Span {
    let span = tracing::info_span!(
        "chio.guard.verify",
        mode = %mode,
        result = field::Empty,
    );
    if let Some(result) = result {
        span.record("result", result);
    }
    span
}
