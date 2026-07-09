# RFC-0009: Observability and alerting wiring: emit the metrics, watch the log, account for drops

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: ADR-0009 (SIEM isolation)
- Depends on: none
- Closes findings: F57, F75, F77, F79, F83, F80, F58, F81, F82, F78 (see ./README.md and the readiness review)

## Summary

Chio ships a full alerting and SLO apparatus (a Prometheus rule pack, a
recording-rule set, a workspace metric registry, a SIEM export pipeline, and a
kernel `/metrics` renderer) whose instruments report zero or nothing. The p0
fail-open PagerDuty alert points at a series that has no emission site anywhere
in the workspace; the kernel `/metrics` endpoint renders a hardcoded `0` for
every guard family it advertises; no deployed serving surface mounts a scrape
route at all; the SIEM export loop, OTLP ingress, and log redaction run only in
tests; malformed rows and dead-lettered batches drop with a warn line and no
counter; and an OTEL partial-batch retry mints duplicate signed receipts into
the append-only log. This RFC turns the registry into a live contract: it wires
each alert-referenced metric to a real emission site, replaces the kernel
placeholder renderer with process-global counters incremented on the guard hot
path, mounts a scrape endpoint on every serving surface, moves the SIEM/OTLP/
redaction path into a production serve mode, fixes SIEM delivery to at-least-once
with persisted accounting, adds a continuous receipt-log gap/lag watchdog, counts
every drop, and makes the OTEL retry deterministic. It also defines the metric
taxonomy, the emit-on-all-paths-including-errors rule, and a conformance gate
that fails the build when a registered, alert-referenced metric has no exercised
emission site.

## Motivation

The article lens ("internal accounting must be trustworthy or loudly broken;
know the blast radius when a component dies mid-operation; overload must fail
early, local, and graceful") is inverted across the observability plane: the
accounting is silently broken (permanent zeros), and the one tripwire that is
supposed to detect a security-enforcement bypass is structurally incapable of
firing while auditing as present.

Blast radius, per finding:

- F57 (critical). Trigger: a genuine fail-open event (chio-tower's
  `with_fail_open(true)` forwarding unenforced traffic after an evaluation
  error), a dispatch-failure burst, or revocation-lag growth. Effect:
  `increase()`/`histogram_quantile` over a series that has never existed returns
  empty, so the p0 `ChioFailOpenSuspected` page and the p1 dispatch/revocation
  alerts cannot fire, and there is no `absent_over_time` backstop for exactly
  those three. Impact: a security-relevant enforcement regression runs
  undetected while the alert pack looks deployed and green.
- F77 (high). Trigger: routine operation with the shipped rules loaded. Effect:
  the single alert whose purpose is detecting fail-open behavior is wired to
  PagerDuty at p0 and can never fire; DLQ depth and SOC export lag are invisible
  except as warn/error logs. The worst L3 shape: a dead safety tripwire that
  audits as present.
- F75 (high). Trigger: any deployment scrapes the kernel's documented `/metrics`
  surface. Effect: `chio_guard_deny_total`, `chio_guard_verdict_total`,
  `chio_otel_ingress_drop_total`, and every histogram read `0` with empty label
  values forever, regardless of actual denies, reloads, fuel burn, or drops.
  Alerting, SLOs, and capacity decisions built on those families measure nothing
  while looking healthy.
- F58 (high). Trigger: an operator deploys the reference stack plus the rule
  pack. Effect: Prometheus has no target exposing any kernel/edge family, so
  every recording rule evaluates over empty series, burn-rate SLO alerts cannot
  fire, and the missing-data alerts fire permanently. The mediation-hot-path SLO
  program is decorative while appearing shipped.
- F79 (high). Trigger: a standard production deployment configured per the docs
  to expect SIEM export, OTLP trace-to-receipt ingress, `/metrics`, and redacted
  logging. Effect: `ExporterManager::run` is never spawned, no OTLP listener
  exists, no binary mounts a scrape route, the default `warn` filter discards the
  `info_span!` guard telemetry that is the only real signal, and log redaction
  has no subscriber-level backstop. The operator has log lines at warn+ and
  nothing else, discovered during an incident.
- F78 (medium). Trigger: a SIEM backend outage longer than the retry budget.
  Effect: the batch goes to a 1000-entry in-memory DLQ nothing drains, the cursor
  advances past it, and those receipts never reach the SIEM for the process
  lifetime. Silent gaps in the compliance stream, revealed only by a manual seq
  diff or a full restart replay.
- F80 (medium). Trigger: kernel/receipt schema skew or a corrupted `raw_json`
  row. Effect: `poll_once` skips the row with a single warn and advances the
  cursor; the receipt never reaches any backend. SOC detections and compliance
  evidence silently miss events while the loop reports healthy. Mitigation: the
  row still exists in the store.
- F81 (medium). Trigger: the sqlite commit actor saturates mid-batch under load.
  Effect: `export_traces` has appended k of n signed receipts, returns a `Pool`
  error, the drain retains the whole batch, and the next drain re-signs every
  span with a fresh `otel-<uuid7>` id and re-appends the first k. Duplicate
  signed `TraceObservation` receipts land permanently in the append-only Merkle
  log; each failed retry adds another k. Audit-log pollution, double-counted
  evidence, skewed counters.
- F82 (low). Trigger: a sustained large-receipt workload exhausts the aggregate
  byte budget while the channel still has slots. Effect: every affected request
  inline-signs on the tool-call hot path while `chio_signing_queue_block_total`
  stays flat, so an operator sizing the queue sees zero backpressure and
  misattributes the latency.
- F83 (medium). Trigger: checkpoint creation stops running for weeks, or SIEM
  export stalls. Effect: the uncheckpointed seq range grows silently and export
  lag has no metric; nobody is paged, discovery requires a human running
  `chio receipt health` against the local db.

The unifying theme is a wiring gap. The registry, the renderer, the export loop,
and the redaction layer all exist and are tested in isolation; none of them is
mounted on a production path, and the one metric that gates a security bypass has
no producer at all.

## Current behavior (verified 2026-07-04)

Re-verified against live code. Quoted signatures are current; line numbers are
as read today.

### The alert-pack metrics have no emission site

`crates/observability/chio-metrics-spec/src/lib.rs` is the workspace registry.
The alert-pack names are declared as constants and as `REGISTRY` descriptors but
are emitted nowhere:

```rust
// lib.rs:115-116, 118-121, 176-177 (constants; interleaved unrelated names elided)
pub const CHIO_ALERT_DISPATCH_TOTAL: &str = "chio_alert_dispatch_total";
pub const CHIO_ALERT_DISPATCH_LATENCY_SECONDS: &str = "chio_alert_dispatch_latency_seconds";
pub const CHIO_CAPABILITY_REVOCATION_LAG_SECONDS: &str = "chio_capability_revocation_lag_seconds";
pub const CHIO_DISPATCH_FAILURE_TOTAL: &str = "chio_dispatch_failure_total";
pub const CHIO_DLQ_DEPTH: &str = "chio_dlq_depth";
pub const CHIO_FAIL_OPEN_SUSPECTED_TOTAL: &str = "chio_fail_open_suspected_total";
pub const CHIO_SOC_EXPORT_TOTAL: &str = "chio_soc_export_total";
pub const CHIO_SOC_EXPORT_LAG_SECONDS: &str = "chio_soc_export_lag_seconds";
```

A repo-wide grep for the eight literal names (and their `CHIO_*` constants)
returns, outside `chio-metrics-spec`, exactly one hit: the recording-rule string
`sum by (route, outcome, le) (rate(chio_alert_dispatch_latency_seconds_bucket[5m]))`
asserted by `crates/tooling/chio-conformance/tests/metrics_registry_consumed.rs:682`.
No `.rs` file increments or observes any of them.

The rule pack consumes them regardless. `deploy/prometheus/chio-alert-rules.yml`:

```yaml
# :112-122 (p0, PagerDuty, for: 0m)
- alert: ChioFailOpenSuspected
  expr: increase(chio_fail_open_suspected_total[5m]) > 0
# :124-134 (p1)
- alert: ChioDispatchFailure
  expr: increase(chio_dispatch_failure_total[5m]) > 0
# :136-150 (p1)
- alert: ChioRevocationLagHigh
  expr: histogram_quantile(0.95, sum by (le) (rate(chio_capability_revocation_lag_seconds_bucket[5m]))) > 30
```

These three have no `absent_over_time` companion, so they are inert, not loud.
The three that do (`ChioSidecarMetricsMissing`, `ChioAlertDispatchMetricsMissing`,
`ChioSocExportMetricsMissing` at `:46-56`, `:73-83`, `:100-110`) would page
"metrics missing" permanently from day one.

The fail-open bypass itself is real. `crates/protocol/chio-tower/src/service.rs:132-148`:

```rust
let prepared = match prepared {
    Ok(r) => r,
    Err(e) => {
        if evaluator.is_fail_open() {
            tracing::warn!(
                error = %e,
                "Chio evaluation failed; fail-open enabled, forwarding request WITHOUT enforcement"
            );
            return inner.call(req).await.map_err(Into::into);
        }
        tracing::error!("Chio evaluation failed: {e}");
        // ... BAD_GATEWAY ...
    }
};
```

`is_fail_open()` reads the `fail_open` field set by `with_fail_open`
(`crates/protocol/chio-tower/src/evaluator.rs:56`, `:86-88`, `:92-93`). The warn
line is the only trace; no counter moves.

### The kernel /metrics endpoint renders permanent zeros

`crates/kernel/chio-kernel/src/observability/metrics.rs` advertises seven guard
families plus three runtime counters and renders them all as zero. Only the
signing-queue counter is backed:

```rust
// :166-171
fn scalar_metric_value(family: &GuardMetricFamily) -> u64 {
    match family.name {
        CHIO_SIGNING_QUEUE_BLOCK_TOTAL => signing_queue_block_total(),
        _ => 0,
    }
}
```

Histograms are hardcoded (`:173-192`): every `_bucket`, `_sum`, `_count` line is
literally `" 0"`. Labels render as empty strings (`:202-215`: `guard_id=""`).
`chio_otel_ingress_drop_total` and `chio_otel_sink_drop_total` fall through the
`_ => 0` arm even though the OTLP ingress queue already tracks the real drop
counts in its snapshot (`crates/observability/chio-otel-receipt-exporter/src/ingress.rs:99-114`:
`dropped_oldest_batches`, `dropped_incoming_batches`, `append_error_batches`).
The endpoint test asserts the zeros verbatim as the contract
(`crates/kernel/chio-kernel/tests/metrics_endpoint.rs:105-117`,
`:120-153`). Real guard telemetry is `tracing::info_span!` only
(`crates/guards/chio-wasm-guards/src/observability.rs:46-93`,
`guard_evaluate_span`/`guard_host_call_span`/`guard_reload_span`), filtered out
by the default `warn` env filter.

The pattern to copy already exists in the workspace.
`crates/platform/chio-http-core/src/metrics.rs` backs the HTTP-edge families with
process-global atomics (`static GUARD_EVAL_ALLOW: AtomicU64`, bucket arrays
`DECISION_LATENCY_ALLOW_BUCKETS: [AtomicU64; N]`) incremented from
`HttpAuthority::evaluate` and rendered by `render_http_core_metrics_prometheus`.
`crates/guards/chio-wasm-guards` already exposes a per-label-set pool registry
(`register_guard_pool_metric_families`, `GUARD_POOL_METRIC_FAMILIES`,
`METRIC_CHIO_GUARD_POOL_CHECKOUT_TOTAL`) for dynamic `guard_id`/`tenant_id`
labels.

### No serving surface mounts a scrape route

`GUARD_METRICS_PATH = "/metrics"` and `guard_metrics_endpoint(path)` exist
(`metrics.rs:14`, `:120-130`) and are re-exported from `chio_kernel`
(`crates/kernel/chio-kernel/src/lib.rs:349`), but grep shows the only callers are
the endpoint test and the re-export. The api-protect router lists every route and
has no metrics route (`crates/products/chio-api-protect/src/proxy/router.rs:3-65`:
`/chio/evaluate`, `/chio/verify`, `/chio/health`, capability/receipt routes,
`/{*path}` catch-all). The only production surface that mounts a metrics route is
the pheromone relay, which is the model to generalize
(`crates/trust/chio-pheromone-relay/src/service.rs`):

```rust
// service.rs serve():
let router = Router::new()
    // ...
    .route(PHEROMONE_RELAY_OBSERVABILITY_PATH, get(handle_observability))
    .route(PHEROMONE_RELAY_METRICS_PATH, get(handle_metrics))
    // ...
```

and it composes process-global families through an optional hook
(`service.rs:204-246`: `ExtraMetricsHook`, whose Prometheus output
`handle_metrics` appends to the relay `/metrics` body). The deploy manifests
(`deploy/cloud-run/service.yaml`, `deploy/ecs/task-definition.json`,
`deploy/azure/container-app.bicep`) contain no scrape annotation or port.

### The SIEM/OTLP/redaction path is tests-only

`ExporterManager` (`crates/observability/chio-siem/src/manager.rs:92-100`,
`run` at `:164-182`) is spawned only under `#[cfg(test)]` in
`crates/products/chio-wall/src/commands.rs:1247-1258`. `OtlpGrpcIngress` is
constructed only in tests/examples. `RedactionLayer` has no reference outside
`chio-log-redact`; the only subscriber init in the product crates
(`crates/products/chio-cli/src/cli/dispatch/mod.rs`) is
`tracing_subscriber::fmt().with_env_filter(EnvFilter::try_from_default_env()
.unwrap_or_else(|_| EnvFilter::new("warn"))).with_writer(std::io::stderr).init()`,
with no redaction layer and a `warn` default that drops the guard `info_span!`s.

### SIEM at-most-once, malformed-drop, and unaccounted DLQ

`poll_once` (`manager.rs:188-317`) advances the cursor past everything:

```rust
// :243-254 (malformed row: warn, then advance)
Err(e) => {
    tracing::warn!(seq = seq, error = %redact_for_operator_log(&e),
        "Failed to deserialize receipt -- skipping");
    if *seq > max_seq { max_seq = *seq; }
}
// :257-261 (all-malformed batch: advance, Ok)
if events.is_empty() { self.cursor = max_seq; return Ok(()); }
// :306-314 (retry-exhausted batch DLQ'd, cursor still advances)
self.cursor = max_seq;
```

The DLQ is used only for exporter failures (`:277-303`), is in-memory and
drop-oldest at 1000 (`crates/observability/chio-siem/src/dlq.rs:48-68`), and its
`drain()` (`dlq.rs:81-83`) is called only from `dlq_bounded.rs`. The cursor is
not persisted (`manager.rs:80-86`: "re-exports all receipts from seq=0" on
restart). `dlq_len()` exists (`:152-154`) but nothing reads it into a metric.
There is no metrics or counter code anywhere in `chio-siem`.

### OTEL partial-batch retry mints duplicates

`crates/observability/chio-otel-receipt-exporter/src/sink.rs:168-185`:

```rust
pub fn export_traces(&self, export: &OtlpGrpcTraceExport)
    -> Result<ReceiptStoreSinkSummary, OTelReceiptExportError> {
    validate_export_batch_limits(export)?;
    let receipts = export.spans()
        .map(|span| self.canonical_receipt_for_span(span))
        .collect::<Result<Vec<_>, _>>()?;
    let mut summary = ReceiptStoreSinkSummary::default();
    for receipt in receipts {
        self.sink.append_chio_receipt_canonical(receipt)?; // aborts after k appends
        summary.accepted_spans += 1;
        summary.appended_receipts += 1;
    }
    Ok(summary)
}
```

`canonical_receipt_for_span` sets `id: next_receipt_id()` (`:226`), and
`next_receipt_id()` is `format!("otel-{}", Uuid::now_v7())` (`:407-409`), so every
regeneration mints new ids. On a retryable append failure the ingress retains the
whole batch (`ingress.rs:246-269`: `drain_locked`, `if !retain_batch { pop_front }`),
counts the whole batch as `record_append_error`, and re-drains, re-running
`export_traces` from span 0 with fresh ids. `is_retryable_batch_error` covers
`ReceiptStoreError::Pool` (`sink.rs:135-142`), which the bounded commit actor
raises routinely under load.

### Signing-queue counter undercounts

`crates/kernel/chio-kernel/src/kernel/signing_task.rs`: the counter
(`record_signing_queue_block`, `:170-172`) is incremented only in the channel-full
arm (`:596-599`). The byte-budget branch returns `Backpressure` with no increment
(`:580-583`), the oversized-single-preimage branch inline-signs with no increment
(`:672-674`), and the caller's `Backpressure` arm inline-signs with no increment
(`:691-693`).

### Receipt-log completeness is operator-pull only

`ReceiptStoreHealthReport` and friends carry the right fields
(`crates/kernel/chio-kernel/src/receipt_store.rs:41-117`:
`ReceiptWriterCounters`, `ReceiptCheckpointStatusReport`,
`ReceiptStoreHealthReport` with `uncheckpointed_start_seq`,
`uncheckpointed_end_seq`, `latest_committed_entry_seq`,
`latest_checkpointed_entry_seq`, `checkpoint_error`), but they are consumed only
by the on-demand CLI (`crates/products/chio-cli/src/cli/trust/receipt/health.rs`:
`cmd_receipt_health` requires a local `--receipt-db`; remote is explicitly
refused). No periodic watchdog or gauge exists.

## Design

Nine parts. Part A defines the taxonomy and the emission contract shared by the
rest. Parts B-D are the emission wiring (alert pack, kernel families, scrape
mount). Part E is the production serve mode. Parts F-I are the correctness fixes
(SIEM delivery/accounting, OTEL dedup, signing counter, watchdog). Every proposed
path is fail-closed and uses `?`/typed errors; no `.unwrap()`/`.expect()` appears
in proposed code, matching the workspace clippy gate.

### A. Metric taxonomy and the emission contract

The single source of truth stays `chio-metrics-spec::REGISTRY`. No new metric
name is introduced by this RFC; every name it emits already has a descriptor. The
alert-pack families and their canonical labels (from the current registry) are:

| metric | kind | labels | semantics |
| --- | --- | --- | --- |
| `chio_fail_open_suspected_total` | counter | `surface` | +1 each time an evaluation error is forwarded unenforced |
| `chio_dispatch_failure_total` | counter | `surface`, `outcome` | tool-dispatch failures that did NOT bypass mediation |
| `chio_capability_revocation_lag_seconds` | histogram | `authority` | seconds from revoke to enforcement-visible |
| `chio_dlq_depth` | gauge | `exporter` | current dead-letter depth per exporter |
| `chio_soc_export_total` | counter | `exporter`, `outcome` | per-row export outcome (`ok`/`malformed`/`dlq`/`error`) |
| `chio_soc_export_lag_seconds` | histogram | `exporter`, `severity` | seconds from persistence to sink ack |
| `chio_alert_dispatch_total` | counter | `route`, `outcome` | PagerDuty/OpsGenie dispatch outcomes |
| `chio_alert_dispatch_latency_seconds` | histogram | `route`, `outcome` | dispatch latency |

The emission contract (normative for this RFC and enforced by the conformance
gate in the test plan):

1. Emit on all paths, including errors. Every counter that has an `outcome`,
   `verdict`, or `result` label must be incremented on the deny/error/malformed/
   drop path, not only the happy path. A metric that only counts success is a
   silent-loss vector (F80, F82). Concretely: `chio_soc_export_total` is
   incremented with `outcome="malformed"` on a skip and `outcome="dlq"` on a
   dead-letter, never only with `outcome="ok"`.
2. Fail-closed observability. A missing series is a fault, not a default. Every
   alert whose `expr` is `increase(...) > 0` gains an `absent_over_time`
   companion so "the producer is gone" is loud rather than a silent green. Any
   family that backs an `absent_over_time` alert MUST pre-register its known
   label sets at zero at startup (`LabeledCounter::preregister`,
   `LabeledHistogram::preregister`), so the backstop distinguishes a vanished
   producer from an event that has simply not occurred yet. Because
   `LabeledCounter` renders only label sets an increment created, an unseeded
   counter that never fired looks identical to an absent metric, which would trip
   the backstop on a healthy deployment.
3. One producer per family, colocated with the truth. Each crate that owns a
   truth source owns the emission and a `render_*_prometheus()` function over its
   process-global state, following `chio-http-core::render_http_core_metrics_prometheus`
   and the pheromone relay's `ExtraMetricsHook`. Serving surfaces compose these;
   they never fabricate values (the ADR-0009 isolation boundary is preserved,
   because the SIEM emission stays inside `chio-siem`, guard emission inside the
   guard backend, and so on).

Emission uses two reusable primitives added to a small internal module
`chio-metrics-spec::runtime` (no new crate; ~120 LOC):

```rust
/// A process-global counter keyed by an ordered label tuple. Lock-free reads,
/// mutex-guarded insert of new label sets (cold path). Mirrors the pattern in
/// chio-wasm-guards' pool registry so dynamic labels (guard_id, exporter) do not
/// require a static per-value atomic.
pub struct LabeledCounter {
    name: &'static str,
    labels: &'static [&'static str],
    cells: std::sync::Mutex<std::collections::BTreeMap<Vec<String>, std::sync::Arc<std::sync::atomic::AtomicU64>>>,
}

impl LabeledCounter {
    #[must_use]
    pub const fn new(name: &'static str, labels: &'static [&'static str]) -> Self { /* ... */ }

    /// Increment the cell for `values`. `values.len()` must equal `labels.len()`;
    /// a mismatch is a programming error and is dropped after a debug assert
    /// rather than panicking (fail-closed: never abort the hot path for a metric).
    pub fn incr(&self, values: &[&str]) {
        let Ok(mut cells) = self.cells.lock() else { return };
        // resolve-or-insert Arc<AtomicU64>, fetch_add(1, Relaxed)
    }

    /// Pre-register a label set at zero so the series exists before its first
    /// event. `render` only emits label sets that an increment created, so
    /// without this a counter that has legitimately never fired ("no event yet")
    /// is byte-for-byte identical to a vanished producer ("metric absent"), and
    /// the `absent_over_time` backstop (rule 2) fires falsely on a healthy
    /// deployment. Called once at startup for every KNOWN label value. Same
    /// cold-path resolve-or-insert as `incr`, but leaves the cell at 0.
    pub fn preregister(&self, values: &[&str]) {
        let Ok(mut cells) = self.cells.lock() else { return };
        // resolve-or-insert Arc<AtomicU64> at 0 (no fetch_add)
    }

    /// Render all label sets in Prometheus text form. Callers never see a lock.
    pub fn render(&self, out: &mut String) { /* # HELP/# TYPE from descriptor_for(name) */ }
}
```

A `LabeledHistogram` with the same shape backs the latency/lag families over the
registry-declared bucket bounds. Both `render` into the exact
`chio-metrics-spec` descriptor metadata (`descriptor_for(name)`), so the emitted
`# HELP`/`# TYPE` cannot drift from the registry.

### B. Wire the alert-pack metrics (F57, F77)

- Fail-open (`chio_fail_open_suspected_total{surface}`). Add a
  `LabeledCounter` to a new `crates/protocol/chio-tower/src/metrics.rs` and
  increment it in the fail-open branch at `service.rs:135`, keeping the existing
  warn line:

  ```rust
  if evaluator.is_fail_open() {
      crate::metrics::record_fail_open_suspected("tower");
      tracing::warn!(error = %e, "Chio evaluation failed; fail-open enabled, forwarding request WITHOUT enforcement");
      return inner.call(req).await.map_err(Into::into);
  }
  ```

  The same counter is incremented at any other unenforced-forward site (the
  api-protect evaluation-error path, if a future fail-open mode is added there),
  always with a distinct `surface` label.

  Seed the series at zero at startup so the `absent_over_time` backstop below
  only fires on a true scrape gap, never on a deployment that has simply never
  failed open. The `chio-tower` metrics init pre-registers every known `surface`
  value once, before the layer serves:

  ```rust
  // chio-tower metrics init, run once at layer construction (before serving):
  metrics::FAIL_OPEN_SUSPECTED.preregister(&["tower"]);
  // ... plus each additional unenforced-forward surface as it is introduced,
  //     using the same fixed set of known `surface` label values ...
  ```

  Each family in this part follows the same rule: the known label sets an
  `absent_over_time` alert watches are pre-registered at zero, so "healthy and
  quiet" renders as `0` rather than as a missing series.
- Dispatch failure (`chio_dispatch_failure_total{surface, outcome}`). Emit from
  the kernel/authority dispatch path when a tool dispatch fails WITHOUT bypassing
  mediation (that is, the request was denied or errored, enforcement held). This
  is the complement of fail-open: a dispatch failure that is correctly enforced
  is `outcome="denied"`, one that errors the request is `outcome="error"`.
- Revocation lag (`chio_capability_revocation_lag_seconds{authority}`). Observe
  the delta between a capability's revoke timestamp and the first enforcement
  that reflects it, from the revocation propagation path in the control-plane
  authority. Where a remote revocation store carries a revoke instant, the lag is
  `now - revoked_at` at the enforcement point.
- DLQ depth, SOC export, alert dispatch. Emitted by `chio-siem` (parts F, G) and
  the alerting exporter; the manager exposes a metrics hook so the host renders
  them (part E).

Rule-pack change (`deploy/prometheus/chio-alert-rules.yml`): add an
`absent_over_time` companion for the three zero-tolerance alerts so a vanished
producer is loud:

```yaml
- alert: ChioFailOpenMetricsMissing
  expr: absent_over_time(chio_fail_open_suspected_total[10m])
  for: 5m
  labels: { severity: p1, notification_route: pagerduty, slo: fail-closed }
  annotations:
    summary: Chio fail-open detector counter is missing
    runbook: docs/operator-runbook/slo.md
# ... and the equivalents for chio_dispatch_failure_total and
#     chio_capability_revocation_lag_seconds_count ...
```

The p0 `ChioFailOpenSuspected` alert is unchanged; it now sits on a real series
(pre-registered at zero from startup, so it exists even before the first
fail-open event) plus an absence backstop. Because the series is present at `0`
on a healthy deployment, `absent_over_time` only fires on a genuine scrape gap (a
vanished producer), not on a deployment that has never failed open. Either a
fail-open event OR a missing producer pages; a healthy-and-quiet deployment does
neither.

### C. Back the kernel guard families with real values (F75)

Replace the placeholder renderer in
`crates/kernel/chio-kernel/src/observability/metrics.rs`:

- Delete the `_ => 0` fallthrough in `scalar_metric_value` and the hardcoded
  `" 0"` histogram rendering. Route `render_guard_metrics_prometheus` through
  `LabeledCounter::render`/`LabeledHistogram::render` for each family.
- Increment the counters from the wasmtime guard backend at the exact sites that
  already open the tracing spans in
  `crates/guards/chio-wasm-guards/src/observability.rs`. `guard_evaluate_span`
  gains a sibling `record_guard_verdict(guard_id, verdict)` and
  `record_guard_eval_duration(guard_id, verdict, elapsed)`; `guard_reload_span`
  gains `record_guard_reload(guard_id, outcome)`; a deny records
  `chio_guard_deny_total{guard_id, reason_class}`; module load records the
  `chio_guard_module_bytes{guard_id, epoch}` gauge; fuel accounting records
  `chio_guard_fuel_consumed_total{guard_id}`. Emission is unconditional on both
  allow and deny (contract rule 1).
- Feed `chio_otel_ingress_drop_total` and `chio_otel_sink_drop_total` from the
  OTLP ingress snapshot that already tracks them
  (`ingress.rs` `OtlpExporterQueueSnapshot::dropped_incoming_batches` +
  `dropped_oldest_batches` for ingress; `append_error_batches` for sink), via a
  process-global counter the ingress increments on each drop.
- Rewrite `crates/kernel/chio-kernel/tests/metrics_endpoint.rs` to exercise the
  production path (drive N guard evaluations with a known allow/deny mix, then
  scrape) and assert a NON-zero count for each family, replacing the current
  verbatim-zero assertions at `:94`, `:109-113`, `:120-153`.

### D. Mount a scrape endpoint on every serving surface (F58)

Generalize the pheromone-relay pattern. Add a shared composition helper in
`chio-http-core` (or a thin `chio-serving-metrics` module) that concatenates the
registered `render_*_prometheus()` bodies (the kernel's
`render_guard_metrics_prometheus`, the edge's
`render_http_core_metrics_prometheus`, the tower fail-open counter, and any
host-provided SIEM hook) into one Prometheus text body:

```rust
pub fn compose_metrics_body(sources: &[&dyn Fn() -> String]) -> String { /* ... */ }
```

Mount a `GET /metrics` route that returns `guard_metrics_endpoint`'s response
augmented with `compose_metrics_body` on:

- api-protect: add to `build_app`
  (`crates/products/chio-api-protect/src/proxy/router.rs:3`), served on a
  dedicated admin port (not the proxied traffic port), gated by the same
  `require_sidecar_control_middleware` posture used for approval routes so the
  scrape surface is not public.
- trust-control: the equivalent route on the trust-control service router
  (`crates/platform/chio-control-plane/src/trust_control/service_runtime/router.rs`),
  which currently mounts no metrics route.
- mcp-remote: the equivalent route on the remote-MCP HTTP service router
  (`crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs`), likewise
  currently without one.

Manifests: add Prometheus scrape annotations/config and expose the metrics port
in `deploy/cloud-run/service.yaml`, `deploy/ecs/task-definition.json`,
`deploy/azure/container-app.bicep`. A conformance test boots each production
router and asserts the scrape body contains the families the rule pack consumes.

### E. Production serve mode for SIEM, OTLP, and redaction (F79)

- Kernel-host serve mode. A `chio` serve subcommand (or a flag on the existing
  host command) mounts the part-D `/metrics` route and, when configured, an OTLP
  gRPC ingress listener that drives `OtlpGrpcIngress::export`.
- SIEM run task. An opt-in `chio siem export` subcommand (and the equivalent
  `chio-wall` task, promoted out of `#[cfg(test)]`) spawns
  `ExporterManager::run` with persisted config, wired to the metrics hook from
  part F.
- Subscriber init. Change `crates/products/chio-cli/src/cli/dispatch/mod.rs`
  (the `tracing_subscriber::fmt()` chain at `:74-80`) to install
  `RedactionLayer` as the sink-facing output layer and default the `chio.guard`
  targets to `info` so the guard spans that carry real telemetry are not
  dropped. One subtlety governs the shape: a tracing layer cannot rewrite event
  fields seen by a sibling `fmt` layer, so redaction cannot sit "under" `fmt()`
  as a filter. Instead, per `chio-log-redact`'s own crate contract ("install
  RedactionLayer as the sink-facing tracing layer"), the redaction layer
  replaces `fmt()` as the layer that formats operator output; its sink writes
  the already-redacted `RedactedEvent` fields to stderr. `RedactionLayer<Sink>`
  is generic over `RedactedEventSink` (a blanket impl covers
  `Fn(RedactedEvent)`) and is constructed fallibly:
  `RedactionLayer::new(sink) -> Result<Self, LogRedactError>`
  (`crates/observability/chio-log-redact/src/layer.rs:69`, `:78`). A
  construction failure aborts startup with a typed CLI error (fail-closed: do
  not serve with unredacted logging):

  ```rust
  let filter = tracing_subscriber::EnvFilter::try_from_default_env()
      .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,chio.guard=info"));
  let redaction = chio_log_redact::RedactionLayer::new(write_redacted_event_to_stderr)
      .map_err(|error| CliError::cli_other_error(format!("log redaction init failed: {error}")))?;
  tracing_subscriber::registry().with(filter).with(redaction).init();
  ```

  where `write_redacted_event_to_stderr` is a small `fn(RedactedEvent)` that
  formats target, level, and redacted fields as a stderr line. This is the
  subscriber-level backstop: any field that skips a `redacted!` call site is
  still redacted before it reaches stderr, because the only layer that formats
  events is the redacting one.

### F. At-least-once SIEM delivery with persisted accounting (F78, F80)

Change the delivery invariant from at-most-once to at-least-once with a persisted
high-water mark, keeping ADR-0009's read-only receipt-DB property intact by
storing progress in a separate SIEM-owned cursor DB.

- Persisted high-water mark. Add a small read-write SQLite file (the SIEM cursor
  store, distinct from the read-only receipt DB) with one row per exporter:
  `(exporter_name TEXT PRIMARY KEY, acked_seq INTEGER)`. Advance `acked_seq` only
  after an exporter confirms acceptance of a batch. On restart the manager
  resumes from `min(acked_seq)` across exporters instead of seq=0, so redelivery
  is targeted, not a full replay.
- Malformed rows (F80). A deserialize failure no longer silently advances. It
  increments `chio_soc_export_total{exporter="_", outcome="malformed"}` and
  DURABLY dead-letters a `FailedEvent` carrying the raw `seq` so the row is
  replayable once the schema skew is fixed. The existing DLQ is in-memory and
  drop-oldest, so an in-memory push alone is lost on a restart or a DLQ overflow
  while `acked_seq` would have skipped the receipt permanently, breaking the
  at-least-once invariant. The SIEM cursor DB (the same read-write file that holds
  `acked_seq`) therefore gains a `dead_letters(seq INTEGER PRIMARY KEY, event_json
  TEXT, error TEXT, failed_at INTEGER, exporter_name TEXT)` table; the cursor for a
  malformed row advances ONLY after the row is durably recorded there. If the
  durable write fails, the cursor is left behind the malformed row so it is re-read
  after restart. The drain/retry pass reads from this table, and the in-memory DLQ
  is a fast-path mirror, not the system of record.

  ```rust
  // manager.rs poll_once, replacing the warn-and-advance arm at :243-254
  Err(error) => {
      self.metrics.record_export("_", ExportOutcome::Malformed);
      // Same clock computation the exporter-failure arm already uses.
      let failed_at = SystemTime::now()
          .duration_since(UNIX_EPOCH)
          .map(|d| d.as_secs())
          .unwrap_or(0);
      let entry = FailedEvent {
          event_json: format!("{{\"raw_seq\":{seq}}}"),
          error: redact_for_operator_log(&error).to_string(),
          failed_at,
          exporter_name: "_deserialize".to_string(),
      };
      // DURABLY dead-letter BEFORE advancing the cursor. The in-memory DLQ is
      // drop-oldest and does not survive a restart or an overflow, so advancing
      // `acked_seq` after only an in-memory push would skip this receipt forever
      // while the `raw_seq` marker is lost - a broken at-least-once. Persist into
      // the SIEM cursor DB (the same read-write file as `acked_seq`) first, then
      // mirror into the in-memory DLQ for the fast drain pass.
      match self.cursor_store.record_dead_letter(*seq, &entry) {
          Ok(()) => {
              self.dlq.push(entry);
              // Safe to advance: the row is now durably captured.
              if *seq > max_seq { max_seq = *seq; }
          }
          Err(persist_error) => {
              // Could not dead-letter durably: leave the cursor BEHIND this row
              // (do not advance `max_seq`) and stop this poll so the row is
              // re-read next round / after restart instead of being skipped.
              self.metrics.record_export("_", ExportOutcome::Error);
              warn!(
                  raw_seq = *seq,
                  error = %redact_for_operator_log(&persist_error),
                  "failed to durably dead-letter malformed SIEM row; holding cursor behind it"
              );
              break;
          }
      }
  }
  ```

- DLQ accounting and drain. Emit `chio_dlq_depth{exporter}` from `dlq_len` on
  every poll, emit `chio_soc_export_lag_seconds{exporter, severity}` from the
  delta between a receipt's persistence time and sink ack, and add a drain/retry
  pass that re-attempts DLQ entries on a slower cadence. DLQ overflow increments a
  drop counter instead of only logging.
- Metrics hook. `ExporterManager` takes a `dyn SiemMetricsSink` so the host
  (part E) renders the SIEM families without `chio-siem` depending on any HTTP or
  Prometheus crate (ADR-0009 isolation):

  ```rust
  pub trait SiemMetricsSink: Send + Sync {
      fn record_export(&self, exporter: &str, outcome: ExportOutcome);
      fn observe_export_lag(&self, exporter: &str, severity: &str, lag_seconds: f64);
      fn set_dlq_depth(&self, exporter: &str, depth: u64);
  }

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum ExportOutcome { Ok, Malformed, Dlq, Error }
  ```

  The default sink is a no-op (`chio-siem` stays runnable headless); the host
  installs a `LabeledCounter`-backed sink.

### G. Deterministic OTEL retry, span-granular accounting (F81)

Make receipt generation once-per-span and resume retries at the first unappended
receipt, so a partial batch is never re-signed with fresh ids.

- Cache the signed receipts on the queued item. Extend `QueuedOtlpExport`
  (`ingress.rs:308-324`) with the prepared receipts and an append cursor:

  ```rust
  struct QueuedOtlpExport {
      export: OtlpGrpcTraceExport,
      spans: usize,
      bytes: usize,
      prepared: Option<Vec<CanonicalChioReceipt>>, // generated once, on first drain
      appended: usize,                             // per-batch resume cursor
  }
  ```

- Split the sink into generate and append. Replace the single `export_traces`
  loop (`sink.rs:168-185`) with a `prepare_receipts(&export) ->
  Result<Vec<CanonicalChioReceipt>, _>` (pure, deterministic per call but cached
  by the caller) and an `append_from(&receipts, start) -> Result<usize, _>` that
  returns how many it appended. `drain_locked` (`ingress.rs:246-269`) generates
  once, appends from `appended`, advances `appended` by the returned count on
  every partial success, and pops the batch only when `appended == spans`. A
  retryable failure keeps the batch, its `prepared` receipts, AND its `appended`
  cursor, so the next drain re-appends only receipts `appended..n` with the SAME
  ids.
- Span-granular counters. `record_appended`/`record_append_error` count the
  spans actually appended/failed this attempt, not the whole batch, fixing the
  skew where a partial batch counted as fully failed then fully appended.

Rejected sub-alternative: deriving the id deterministically from
`trace_id + span_id` and deduping on append. It also fixes the duplication but
changes the signed receipt bytes (the `id` field is inside the signed body,
`sink.rs:226`) and pushes a uniqueness check into the append-only store. The
cache-and-resume approach changes no receipt bytes and no store contract, so it
is primary.

### H. Signing-queue counter on all inline-fallback branches (F82)

Add a `reason` dimension and increment on every inline fallback in
`crates/kernel/chio-kernel/src/kernel/signing_task.rs`:

- byte-budget exhaustion (`:582`): `record_signing_queue_block("byte_budget")`
  before returning `Backpressure`.
- channel full (`:597`): `record_signing_queue_block("channel_full")` (existing
  site, now labeled).
- oversized single preimage (`:672-674`): `record_signing_queue_block("oversized")`
  before `sign_inline_if_open`.

Because `chio_signing_queue_block_total` is registered without labels, either add
a `reason` label to the descriptor (a registry change, so it flows through the
snapshot gate) or keep it unlabeled and add a sibling
`chio_signing_queue_block_reason_total{reason}`. This RFC adds the `reason` label
to the existing family (one descriptor edit; the snapshot test regenerates) and
fixes the help text from "blocked by bounded queue capacity" to "blocked by
bounded queue capacity or byte budget".

### I. Continuous receipt-log gap/lag watchdog (F83)

Add a kernel-side watchdog that turns the already-populated
`ReceiptStoreHealthReport` into gauges:

- `uncheckpointed_seq_range` (gauge): `uncheckpointed_end_seq -
  uncheckpointed_start_seq` when both are `Some`, else 0.
- `seconds_since_last_checkpoint` (gauge): derived from
  `ReceiptWriterCounters::last_commit_unix_ms` and the checkpoint status.

The watchdog runs on the kernel-host serve mode (part E), samples
`store.receipt_store_health()` on an interval, and updates the gauges rendered by
the part-D `/metrics` route, plus emits `chio_soc_export_lag_seconds` from the
export path (part F). A recording/alert rule pages when the uncheckpointed range
exceeds a threshold or the age crosses a bound, replacing the human `chio receipt
health` run.

### Error taxonomy (typed, fail-closed)

All new and changed paths use typed errors and never panic on the hot path:

- `SiemMetricsSink` methods are infallible by contract; a metric failure never
  aborts export.
- The SIEM cursor store surfaces `SiemError::DbError(String)` (existing) for open
  or write failure; a cursor-store failure denies advancing the high-water mark
  (fail-closed: better to redeliver than to skip).
- `LabeledCounter::incr` on a lock-poison or label-arity mismatch drops the
  sample (debug-asserted) rather than unwinding, so observability can degrade
  without taking down the mediation path (fail-closed at the system level: the
  guard/enforcement decision is never gated on the metric write).
- OTEL: `OTelReceiptExportError` (existing) is reused; the new `append_from`
  returns the same error type. `is_retryable_batch_error` is unchanged.

### Crates/dirs, rough LOC, CI tier

- `chio-metrics-spec`: `runtime` module (`LabeledCounter`, `LabeledHistogram`,
  composition), ~120 LOC. PR gate.
- `chio-tower`: `metrics.rs` + fail-open increment, ~40 LOC. PR gate.
- `chio-kernel`: renderer rewrite, guard emission hooks, watchdog gauges, signing
  counter labels, ~180 LOC. PR gate.
- `chio-wasm-guards`: emission calls at the span sites, ~60 LOC. PR gate.
- `chio-siem`: `SiemMetricsSink`, cursor store, malformed-to-DLQ, DLQ drain,
  lag/depth emission, ~200 LOC. PR gate.
- `chio-otel-receipt-exporter`: generate-once cache + resume cursor + span
  accounting, ~120 LOC. PR gate.
- `chio-api-protect`, trust-control, mcp-remote, chio-cli/chio-wall: scrape route,
  serve mode, subscriber init, ~180 LOC. PR gate.
- `deploy/*`: scrape annotations, no Rust. PR gate (lint only).
- Soak/chaos (SIEM outage, OTEL retry storm, checkpoint-staleness): nightly.

## Wire, schema, and receipt impact

No change to signed receipt payloads, receipt kinds, or canonical-JSON
(RFC 8785) preimages. The OTEL fix (part G) deliberately preserves receipt bytes:
receipts are generated once and reused, so their signed `id` and content hash are
unchanged; the only observable change is that duplicates stop being minted.

New non-wire surface:

- SIEM cursor store: a new read-write SQLite file owned by `chio-siem`
  (`(exporter_name, acked_seq)`), separate from the read-only receipt DB. Not
  protocol wire.
- Metric registry: `chio_signing_queue_block_total` gains a `reason` label (a
  `chio-metrics-spec` descriptor edit; the golden `metrics.snapshot` regenerates
  and the snapshot test is the gate). No new metric names.
- Alert rules: three new `absent_over_time` companion alerts; no change to the
  three existing p0/p1 expr alerts.
- New serving route `GET /metrics` on api-protect (admin port), trust-control,
  and mcp-remote, plus scrape config in the three deploy manifests.

## Migration and compatibility

Source-compatible and staged:

1. Land part A (`chio-metrics-spec::runtime`) plus the `SiemMetricsSink` trait
   with a no-op default. No behavior change; existing `ExporterManager::new`
   callers compile unchanged.
2. Land the emission sites (B, C, H, the guard hooks). These only add counter
   writes; scrape output changes from zeros to real values but the endpoint
   contract (families present, types/labels from the registry) is preserved.
   Rewrite the zero-asserting tests in the same commit.
3. Land the scrape mount and serve mode (D, E). Additive routes and an opt-in
   subcommand; nothing existing changes behavior until an operator enables it.
4. Land the correctness fixes (F, G, I). The SIEM cursor store is created on
   first run; a fresh deployment starts at `acked_seq = 0` and behaves like today
   until the first ack. The OTEL cache/resume is internal to the ingress and
   changes no external contract.

The `chio_signing_queue_block_total` label addition is the only registry-visible
change; a dashboard that queried the unlabeled series still matches via label
aggregation. No receipt data migration is required.

## Test and verification plan

Unit (PR gate, seconds):

- `LabeledCounter`/`LabeledHistogram`: concurrent `incr` across threads sums
  correctly; render matches `descriptor_for(name)` metadata; arity mismatch drops
  rather than panics.
- Fail-open emission: driving the tower service through an evaluation error with
  `with_fail_open(true)` increments `chio_fail_open_suspected_total{surface="tower"}`
  by exactly one and still forwards. Name:
  `fail_open_branch_increments_suspected_counter`.
- Kernel renderer: after N guard evaluations with a known allow/deny mix, the
  `/metrics` body reports `chio_guard_verdict_total` and `chio_guard_deny_total`
  equal to the driven counts (replaces the verbatim-zero assertions). Name:
  `guard_metrics_report_driven_counts`.
- Signing counter: each of the three inline-fallback branches increments the
  counter with the expected `reason`. Name:
  `signing_block_counter_covers_all_inline_fallbacks`.

Property (PR gate):

- OTEL retry idempotence: for any batch of n spans and any k in `0..n`, forcing a
  retryable append failure after k appends and then draining again yields exactly
  n distinct receipts with STABLE ids (no id changes across attempts) and no
  duplicates in the sink. Name: `otel_partial_retry_never_duplicates`.
- SIEM at-least-once: for any sequence of backend outages, every receipt seq is
  delivered at least once and `acked_seq` is monotonic; no seq between
  `acked_seq` bounds is permanently skipped. Name:
  `siem_high_water_mark_never_skips`.

Conformance gate (PR gate), extending
`crates/tooling/chio-conformance/tests/metrics_registry_consumed.rs`:

- Emission gate. For every metric name referenced by
  `deploy/prometheus/chio-alert-rules.yml` or `chio-recording-rules.yml`, require
  a driven non-zero sample from a production emission path. This is the gate that
  would have caught F57/F77: a registered, alert-referenced family with no
  producer fails the build. The existing gate covers receipt_write,
  guard_evaluations, decision latency, anchor, federation hop, pool, and iroh
  transport; this adds the eight alert-pack families and the seven guard families.
- Scrape gate. Boot each production router (api-protect, trust-control,
  mcp-remote) and assert `GET /metrics` returns a body containing the families
  the rule pack consumes. Name: `production_routers_serve_rule_pack_families`.

Soak / chaos (nightly, ties to the wave-3 load-chaos program in ./README.md):

- `siem_outage_no_silent_gap`: run the export loop against a flapping backend for
  a sustained window, then diff receipt seq against backend contents and assert
  zero permanent gaps and a bounded, drained DLQ.
- `otel_retry_storm_no_duplicates`: saturate the sqlite commit actor under a
  span-export storm, assert the receipt log contains each span exactly once and
  the appended/error counters reconcile at span granularity.
- `checkpoint_staleness_pages`: stop checkpoint creation and assert the
  uncheckpointed-range gauge crosses the alert threshold within the expected
  window. Honest runtime: ~8-12 minutes per scenario.

The formal-methods plan is not on the critical path here; the invariant it should
eventually model is "every persisted receipt reaches the SIEM at least once and
appears in the receipt log exactly once".

## Acceptance criteria

- Every metric referenced by an alert or recording rule has a production emission
  site that the conformance emission gate drives to a non-zero sample; the build
  fails otherwise.
- `chio_fail_open_suspected_total` increments on the tower fail-open branch; the
  p0 `ChioFailOpenSuspected` alert fires on a real event, and a vanished producer
  pages via the new `absent_over_time` companion.
- The kernel `/metrics` endpoint reports real, non-zero guard counts and
  histograms after exercise; no family renders a hardcoded zero, and the endpoint
  tests assert driven counts.
- api-protect, trust-control, and mcp-remote each serve `GET /metrics` with the
  rule-pack families, and all three deploy manifests carry scrape config.
- A production binary boots a serve mode that spawns `ExporterManager::run`,
  optionally an OTLP ingress, and installs `RedactionLayer` with `chio.guard=info`
  by default; an e2e test asserts the scrape and export surfaces respond.
- SIEM delivery is at-least-once: a per-exporter `acked_seq` persists across
  restart, advances only on confirmed acceptance, and no receipt seq is
  permanently skipped; malformed rows increment
  `chio_soc_export_total{outcome="malformed"}` and land in a replayable DLQ;
  `chio_dlq_depth` and `chio_soc_export_lag_seconds` are emitted.
- An OTEL partial-batch retry never mints a duplicate signed receipt; ids are
  stable across attempts and per-span accounting reconciles.
- The signing-queue block counter increments on all three inline-fallback
  branches with a `reason` label, and the help text names the byte budget.
- A kernel watchdog emits the uncheckpointed-range and checkpoint-age gauges, and
  a rule pages on staleness without a human CLI run.

## Risks and alternatives

Risk: emission on the guard hot path adds work per evaluation. Mitigation:
`LabeledCounter` is a `fetch_add` on a resolved atomic (the `BTreeMap` lock is hit
only when a new label set first appears), matching the cost profile of the
existing `chio-http-core` atomics; the guard decision is never gated on the metric
write, so a poisoned metric lock degrades observability without denying traffic.

Risk: at-least-once SIEM delivery increases duplicate exports downstream.
Accepted: ADR-0009 already requires idempotent ingest (Splunk timestamp dedup,
Elasticsearch `_id` upsert), and at-least-once with a persisted high-water mark
strictly reduces duplicates versus today's full seq=0 replay on every restart.

Risk: the OTEL cache holds prepared receipts in memory for the queued batch.
Bounded: the ingress queue is already bounded by batches/spans/bytes
(`OtlpExporterQueueConfig`), and caching the signed receipts adds a constant
factor over the spans already retained; the alternative (re-signing on every
retry) is both slower and the source of the duplication bug.

Rejected alternative: emit metrics from the serving layer by scraping internal
state on request. Rejected because it re-introduces the drift F57/F75 are about
(the serving layer inventing values) and breaks the ADR-0009 isolation boundary;
the producer must own the truth.

Rejected alternative: delete the never-emitted constants and their alert/recording
rules instead of implementing emission. Rejected for the p0 fail-open family: the
detector is a required security tripwire, so the correct fix is a producer, not
removal. Removal remains the right call only for any family with no security or
SLO consumer, which none of the eight are.

Rejected alternative (F78): persist the whole DLQ payload durably. Rejected as
over-scoped; a persisted per-exporter high-water mark plus a failed-range record
recovers the same coverage with far less write amplification, and the receipt DB
remains the durable system of record.

## Rollout and sequencing

This RFC has no RFC dependencies. Internal order follows the migration: part A and
the `SiemMetricsSink` trait first (pure additions); then the emission sites
(B, C, H) and their test rewrites; then the scrape mount and serve mode (D, E);
then the correctness fixes (F, G, I) with their soak scenarios joining the
load-chaos suite in ./README.md. Downstream, this RFC feeds RFC-0004's
bounded-memory size gauges (which need a live scrape surface to be visible) and
RFC-0008's health surface (which composes the same `/metrics` route and the
receipt-log watchdog gauges). The conformance emission gate lands with part C so
that every subsequent emission-site addition is enforced from the moment it is
wired.
