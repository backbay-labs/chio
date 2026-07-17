//! Tracing span helpers for WASM guard observability.

use tracing::{field, Span};

/// Tracing target every guard span emits under. The span NAMES are
/// `chio.guard.evaluate` etc., but a span's tracing TARGET defaults to the Rust
/// module path (`chio_wasm_guards::observability`), and `EnvFilter` directives
/// (e.g. the CLI default `chio.guard=info`) match on the TARGET, not the name.
/// Pinning every guard span to this single target is what makes `chio.guard=info`
/// enable them; without an explicit target these info-level spans would sit under
/// the module path and be dropped by the default `warn` filter.
pub const GUARD_SPAN_TARGET: &str = "chio.guard";

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
        target: GUARD_SPAN_TARGET,
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
    tracing::info_span!(target: GUARD_SPAN_TARGET, "chio.guard.host_call", host.name = %host_name)
}

#[must_use]
pub fn guard_fetch_blob_span(bundle_id: &str, bytes: u64) -> Span {
    let span = tracing::info_span!(
        target: GUARD_SPAN_TARGET,
        "chio.guard.fetch_blob",
        bundle.id = %bundle_id,
        bytes = field::Empty
    );
    span.record("bytes", bytes);
    span
}

#[must_use]
pub fn guard_reload_span(outcome: &str, reload_seq: u64) -> Span {
    tracing::info_span!(target: GUARD_SPAN_TARGET, "chio.guard.reload", outcome = %outcome, reload_seq = reload_seq)
}

#[must_use]
pub fn guard_verify_span(mode: &str, result: Option<&str>) -> Span {
    let span = tracing::info_span!(
        target: GUARD_SPAN_TARGET,
        "chio.guard.verify",
        mode = %mode,
        result = field::Empty,
    );
    if let Some(result) = result {
        span.record("result", result);
    }
    span
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    /// The guard spans must emit under the `chio.guard` TARGET so the CLI default
    /// filter `warn,chio.guard=info` actually enables them. A span's target
    /// defaults to the Rust module path, which the default `warn` filter drops at
    /// info level; the control span below proves the filter is genuinely
    /// filtering, and each guard span proves it survives it.
    #[test]
    fn guard_spans_are_enabled_by_the_default_chio_guard_filter() {
        let filter = tracing_subscriber::EnvFilter::new("warn,chio.guard=info");
        let subscriber = tracing_subscriber::registry().with(filter);
        tracing::subscriber::with_default(subscriber, || {
            // Control: an info span under a module-path target is dropped by the
            // default `warn`, proving the filter is actually filtering (not
            // enabling everything).
            let control = tracing::info_span!("control.span");
            assert!(
                control.is_disabled(),
                "a module-path info span must be dropped by the default warn filter"
            );
            // Each guard span must be ENABLED (not a no-op) under the same filter.
            assert!(
                !guard_evaluate_span("g", "v", "d", 1, 0, Some(VERDICT_ALLOW)).is_disabled(),
                "guard.evaluate must emit under the chio.guard target"
            );
            assert!(
                !guard_host_call_span(HOST_LOG).is_disabled(),
                "guard.host_call must emit under the chio.guard target"
            );
            assert!(
                !guard_fetch_blob_span("b", 10).is_disabled(),
                "guard.fetch_blob must emit under the chio.guard target"
            );
            assert!(
                !guard_reload_span(RELOAD_APPLIED, 1).is_disabled(),
                "guard.reload must emit under the chio.guard target"
            );
            assert!(
                !guard_verify_span(VERIFY_MODE_ED25519, Some(VERIFY_RESULT_OK)).is_disabled(),
                "guard.verify must emit under the chio.guard target"
            );
        });
    }

    /// The span TARGET (what EnvFilter keys on) must be exactly the string the
    /// default filter names, and independent of the module path.
    #[test]
    fn guard_span_target_is_chio_guard() {
        assert_eq!(GUARD_SPAN_TARGET, "chio.guard");
        tracing::subscriber::with_default(
            tracing_subscriber::registry()
                .with(tracing_subscriber::EnvFilter::new("chio.guard=info")),
            || {
                let span = guard_evaluate_span("g", "v", "d", 1, 0, None);
                let target = span
                    .metadata()
                    .map(|meta| meta.target().to_string())
                    .unwrap_or_default();
                assert_eq!(
                    target, "chio.guard",
                    "the guard span must carry the chio.guard target the default filter enables"
                );
            },
        );
    }
}
