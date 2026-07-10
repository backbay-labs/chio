//! Security-grade transport metrics for the iroh federation-transport adapter,
//! surfaced through the workspace `chio-metrics-spec` registry.
//!
//! The slim iroh build deliberately drops iroh's own `metrics` feature, so
//! observability of this transport is entirely the crate's responsibility. This
//! module follows the house pattern (see `chio-federation/src/metrics.rs`):
//! hand-rolled `AtomicU64` statics plus a `render_*_prometheus() -> String`, with
//! NO new runtime dependency and without un-slimming iroh. The caller's existing
//! `/metrics` exporter concatenates [`render_iroh_transport_metrics_prometheus`].
//!
//! ## Purely additive
//!
//! Every counter here is incremented ALONGSIDE the existing fail-closed logic; it
//! reads the same `Err`/decision the code already produced and never changes a
//! trust decision, verification, or control flow. The admission-gate and verify
//! seams increment then return the SAME value they returned before.
//!
//! ## Families (all `chio_federation_transport_*`)
//!
//! - `admission_total{outcome}` - accept/reject at the admission gate (the #1
//!   security signal: a reject spike is someone probing the mesh).
//! - `verify_failures_total{seam,reason}` - per-seam verification failures tagged
//!   by the seam's bounded `code()` reason.
//! - `catchup_epoch_gap_total{source}` - revocation catch-up epoch gaps.
//! - `lane_total{lane,outcome}` - per-lane accept disposition
//!   (accept/reject/busy/timeout), making the slowloris sheds observable.
//! - `outbox_total{outcome}` - pheromone SQLite outbox drain outcomes.
//! - `accept_open{lane}` (gauge) - in-flight accept handlers (the slowloris
//!   detector: it climbs and stays high under a slow-trickle campaign).
//! - `accept_duration_seconds{lane}` (histogram) - accept-handler duration; its
//!   p95/p99 tail balloons under slow-trickle.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub use chio_metrics_spec::{
    CHIO_FEDERATION_TRANSPORT_ACCEPT_DURATION_SECONDS, CHIO_FEDERATION_TRANSPORT_ACCEPT_OPEN,
    CHIO_FEDERATION_TRANSPORT_ADMISSION_TOTAL, CHIO_FEDERATION_TRANSPORT_CATCHUP_EPOCH_GAP_TOTAL,
    CHIO_FEDERATION_TRANSPORT_DIRECTORY_RELOAD_TOTAL, CHIO_FEDERATION_TRANSPORT_LANE_TOTAL,
    CHIO_FEDERATION_TRANSPORT_OUTBOX_TOTAL, CHIO_FEDERATION_TRANSPORT_ROUTER_ALIVE,
    CHIO_FEDERATION_TRANSPORT_VERIFY_FAILURES_TOTAL,
    FEDERATION_TRANSPORT_ACCEPT_DURATION_BUCKETS_SECONDS,
};

// -- Bounded label vocabularies (the ONLY values callers pass) ---------------

/// Lane label: pheromone directed-batch lane (a).
pub const LANE_PHEROMONE: &str = "pheromone";
/// Lane label: revocation epoch-root lane (b).
pub const LANE_REVOCATION: &str = "revocation";
/// Lane label: bilateral DSSE co-sign lane (d).
pub const LANE_BILATERAL: &str = "bilateral";
/// Lane label: cross-operator fan-out lane (c).
pub const LANE_FANOUT: &str = "fanout";

/// Admission outcome: the endpoint resolved to an admitted kernel.
pub const ADMISSION_ACCEPT: &str = "accept";
/// Admission outcome: fail-closed 403 (endpoint not admitted).
pub const ADMISSION_REJECT: &str = "reject";

/// Lane outcome: the accept handler ran to completion.
pub const LANE_OUTCOME_ACCEPT: &str = "accept";
/// Lane outcome: fail-closed reset (framing / verification-plumbing failure).
pub const LANE_OUTCOME_REJECT: &str = "reject";
/// Lane outcome: shed under the in-flight concurrency cap (saturation).
pub const LANE_OUTCOME_BUSY: &str = "busy";
/// Lane outcome: a peer-dependent accept step exceeded its bound (slowloris).
pub const LANE_OUTCOME_TIMEOUT: &str = "timeout";
/// Lane outcome: a fan-out gossip receiver fell behind and iroh-gossip dropped
/// messages (Event::Lagged). Metered so the "gate looks green but measures
/// nothing" failure is visible; iroh-gossip 0.101 reports no drop count.
pub const LANE_OUTCOME_LAGGED: &str = "lagged";

/// Outbox outcome: a batch was accepted by its recipient.
pub const OUTBOX_DELIVERED: &str = "delivered";
/// Outbox outcome: a batch failed and was scheduled for retry.
pub const OUTBOX_RETRIED: &str = "retried";
/// Outbox outcome: a batch exhausted its attempts and was dead-lettered.
pub const OUTBOX_DEAD_LETTERED: &str = "dead_lettered";

/// Epoch-gap source: the content-addressed catch-up walk (lane e).
pub const CATCHUP_SOURCE_CATCHUP: &str = "catchup";
/// Epoch-gap source: the direct revocation push/catch-up control lane (lane b).
pub const CATCHUP_SOURCE_REVOCATION: &str = "revocation";

/// Verify seam: issuer-signed directory bundle load-time verification.
pub const SEAM_IDENTITY: &str = "identity";
/// Verify seam: content-addressed catch-up root verification (lane e).
pub const SEAM_CATCHUP: &str = "catchup";
/// Verify seam: revocation epoch-root pinned-signer verification (lane b).
pub const SEAM_REVOCATION: &str = "revocation";
/// Verify seam: cross-operator fan-out origin verification (lane c).
pub const SEAM_FANOUT: &str = "fanout";
/// Verify seam: bilateral DSSE co-sign verification (lane d).
pub const SEAM_BILATERAL: &str = "bilateral";

// -- Storage -----------------------------------------------------------------

const NUM_LANES: usize = 4;
const NUM_ADMISSION: usize = 2;
const NUM_LANE_OUTCOME: usize = 5;
const NUM_OUTBOX: usize = 3;
const NUM_CATCHUP_SOURCE: usize = 2;

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const ACCEPT_DURATION_BUCKET_UPPER_NANOS: [u64; 7] = [
    10_000_000,
    25_000_000,
    50_000_000,
    100_000_000,
    250_000_000,
    500_000_000,
    1_000_000_000,
];
const BUCKET_COUNT: usize = ACCEPT_DURATION_BUCKET_UPPER_NANOS.len() + 1;

// Atomic arrays are written out element-by-element (matching the house sibling
// `chio-federation/src/metrics.rs`) rather than via a `[CONST; N]` repeat, which
// clippy's `declare_interior_mutable_const` rejects for `AtomicU64`.
static ADMISSION: [AtomicU64; NUM_ADMISSION] = [AtomicU64::new(0), AtomicU64::new(0)];
static LANE_TOTAL: [[AtomicU64; NUM_LANE_OUTCOME]; NUM_LANES] = [
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ],
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ],
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ],
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ],
];
static OUTBOX: [AtomicU64; NUM_OUTBOX] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
static CATCHUP_GAP: [AtomicU64; NUM_CATCHUP_SOURCE] = [AtomicU64::new(0), AtomicU64::new(0)];
static ACCEPT_OPEN: [AtomicU64; NUM_LANES] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static ACCEPT_DURATION_SUM_NS: [AtomicU64; NUM_LANES] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static ACCEPT_DURATION_COUNT: [AtomicU64; NUM_LANES] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static ACCEPT_DURATION_BUCKETS: [[AtomicU64; BUCKET_COUNT]; NUM_LANES] = [
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ],
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ],
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ],
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ],
];

/// The `reason` label is genuinely dynamic-valued (every seam contributes its own
/// bounded `code()` table), so this one family uses a sorted map instead of static
/// atomics. It is written ONLY on the cold verification-failure path, so the lock
/// is never on a hot loop; the keys are `&'static str` from the seams' `code()`s.
static VERIFY_FAILURES: Mutex<BTreeMap<(&'static str, &'static str), u64>> =
    Mutex::new(BTreeMap::new());

// -- Index helpers (total functions; callers only pass the constants above) ---

fn lane_index(lane: &str) -> usize {
    match lane {
        "pheromone" => 0,
        "revocation" => 1,
        "bilateral" => 2,
        // "fanout" and any unreachable value fall here.
        _ => 3,
    }
}

fn admission_index(outcome: &str) -> usize {
    match outcome {
        "accept" => 0,
        _ => 1,
    }
}

fn lane_outcome_index(outcome: &str) -> usize {
    match outcome {
        "accept" => 0,
        "reject" => 1,
        "busy" => 2,
        "timeout" => 3,
        "lagged" => 4,
        _ => 1, // unknown outcomes count as reject (fail-closed accounting)
    }
}

fn outbox_index(outcome: &str) -> usize {
    match outcome {
        "delivered" => 0,
        "retried" => 1,
        _ => 2,
    }
}

fn catchup_source_index(source: &str) -> usize {
    match source {
        "catchup" => 0,
        _ => 1,
    }
}

// -- Recording (increment alongside the existing decision; never change it) ---

/// Record one admission-gate outcome ([`ADMISSION_ACCEPT`] / [`ADMISSION_REJECT`]).
pub fn record_admission(outcome: &str) {
    ADMISSION[admission_index(outcome)].fetch_add(1, Ordering::Relaxed);
}

/// Record one per-lane accept disposition ([`LANE_OUTCOME_ACCEPT`] etc.).
pub fn record_lane_frame(lane: &str, outcome: &str) {
    LANE_TOTAL[lane_index(lane)][lane_outcome_index(outcome)].fetch_add(1, Ordering::Relaxed);
}

/// Map a lane error's stable `code()` to the accept-disposition outcome label so
/// the accept-limiter sheds (`accept_timeout` / `accept_busy`) are countable
/// distinctly from a generic verification/framing reset. Every direct lane's
/// error delegates its accept-limit code to the shared `AcceptLimitError::code`,
/// so this mapping is uniform across lanes.
#[must_use]
pub fn accept_outcome_for_code(code: &str) -> &'static str {
    match code {
        "accept_timeout" => LANE_OUTCOME_TIMEOUT,
        "accept_busy" => LANE_OUTCOME_BUSY,
        "accept_peer_busy" => LANE_OUTCOME_BUSY,
        _ => LANE_OUTCOME_REJECT,
    }
}

/// Record one pheromone outbox drain outcome ([`OUTBOX_DELIVERED`] etc.).
pub fn record_outbox(outcome: &str) {
    OUTBOX[outbox_index(outcome)].fetch_add(1, Ordering::Relaxed);
}

/// Record one revocation catch-up epoch gap ([`CATCHUP_SOURCE_CATCHUP`] /
/// [`CATCHUP_SOURCE_REVOCATION`]).
pub fn record_catchup_epoch_gap(source: &str) {
    CATCHUP_GAP[catchup_source_index(source)].fetch_add(1, Ordering::Relaxed);
}

/// Record one verification failure, tagged by `seam` ([`SEAM_REVOCATION`] etc.)
/// and the seam's bounded `reason` code. A poisoned lock drops the sample
/// (best-effort observability never fails closed onto a panic).
pub fn record_verify_failure(seam: &'static str, reason: &'static str) {
    if let Ok(mut map) = VERIFY_FAILURES.lock() {
        map.entry((seam, reason))
            .and_modify(|value| *value = value.saturating_add(1))
            .or_insert(1);
    }
}

/// Observe one accept-handler duration sample (nanoseconds) for `lane`. Saturating
/// at u64 keeps the sum monotonic under sustained load without panicking.
pub fn observe_accept_duration_nanos(lane: &str, nanos: u64) {
    let index = lane_index(lane);
    ACCEPT_DURATION_SUM_NS[index].fetch_add(nanos, Ordering::Relaxed);
    ACCEPT_DURATION_COUNT[index].fetch_add(1, Ordering::Relaxed);
    for (bucket, upper) in ACCEPT_DURATION_BUCKET_UPPER_NANOS.iter().enumerate() {
        if nanos <= *upper {
            ACCEPT_DURATION_BUCKETS[index][bucket].fetch_add(1, Ordering::Relaxed);
        }
    }
    ACCEPT_DURATION_BUCKETS[index][ACCEPT_DURATION_BUCKET_UPPER_NANOS.len()]
        .fetch_add(1, Ordering::Relaxed);
}

/// RAII guard for the `accept_open` gauge: increments on [`Self::enter`] and
/// decrements on drop, so the gauge is exactly the number of live accept handlers
/// for a lane. Bind it for the whole handler body (`let _open = ...`).
#[derive(Debug)]
pub struct AcceptOpenGuard {
    index: usize,
}

impl AcceptOpenGuard {
    /// Enter the guard, incrementing the in-flight gauge for `lane`.
    #[must_use]
    pub fn enter(lane: &str) -> Self {
        let index = lane_index(lane);
        ACCEPT_OPEN[index].fetch_add(1, Ordering::Relaxed);
        Self { index }
    }
}

impl Drop for AcceptOpenGuard {
    fn drop(&mut self) {
        // enter/drop are 1:1, so the gauge never underflows; clamp defensively.
        let cell = &ACCEPT_OPEN[self.index];
        let mut current = cell.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(1);
            match cell.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }
}

// -- Read-back (getters, for tests and callers) ------------------------------

/// Current `admission_total` for `outcome`.
#[must_use]
pub fn admission_total(outcome: &str) -> u64 {
    ADMISSION[admission_index(outcome)].load(Ordering::Relaxed)
}

/// Current `lane_total` for `(lane, outcome)`.
#[must_use]
pub fn lane_total(lane: &str, outcome: &str) -> u64 {
    LANE_TOTAL[lane_index(lane)][lane_outcome_index(outcome)].load(Ordering::Relaxed)
}

/// Current `outbox_total` for `outcome`.
#[must_use]
pub fn outbox_total(outcome: &str) -> u64 {
    OUTBOX[outbox_index(outcome)].load(Ordering::Relaxed)
}

/// Current `catchup_epoch_gap_total` for `source`.
#[must_use]
pub fn catchup_epoch_gap_total(source: &str) -> u64 {
    CATCHUP_GAP[catchup_source_index(source)].load(Ordering::Relaxed)
}

/// Current `accept_open` gauge for `lane`.
#[must_use]
pub fn accept_open(lane: &str) -> u64 {
    ACCEPT_OPEN[lane_index(lane)].load(Ordering::Relaxed)
}

/// Current `accept_duration_seconds` sample count for `lane`.
#[must_use]
pub fn accept_duration_count(lane: &str) -> u64 {
    ACCEPT_DURATION_COUNT[lane_index(lane)].load(Ordering::Relaxed)
}

/// Current `verify_failures_total` for `(seam, reason)`.
#[must_use]
pub fn verify_failures_total(seam: &'static str, reason: &'static str) -> u64 {
    match VERIFY_FAILURES.lock() {
        Ok(map) => map.get(&(seam, reason)).copied().unwrap_or(0),
        Err(_) => 0,
    }
}

// -- Directory reload outcomes -----------------------------------------------

/// Reload outcome: a strictly-newer, in-window bundle re-verified and swapped in.
pub const RELOAD_UPDATED: &str = "updated";
/// Reload outcome: the on-disk bundle is unchanged and still in-window (no swap).
pub const RELOAD_UNCHANGED: &str = "unchanged";
/// Reload outcome: the running bundle expired with no valid successor; the gate
/// was swapped to deny-all (fail-closed) and an alarm raised. Operators alert on
/// this being non-zero.
pub const RELOAD_EXPIRED_FAILCLOSED: &str = "expired_failclosed";
/// Reload outcome: a strictly-newer, in-window successor re-verified but no longer
/// binds THIS node's local transport endpoint (it tombstoned or rotated this node);
/// the gate was swapped to deny-all (fail-closed) and an alarm raised. Operators
/// alert on this being non-zero (local-binding recheck).
pub const RELOAD_BINDING_REVOKED: &str = "binding_revoked";
/// Reload outcome: the running directory is UNCHANGED but its version is below a
/// trusted `minVersion` that operators raised above it; the unchanged fast path
/// honored the raised floor and swapped the gate to deny-all (fail-closed) with an
/// alarm, exactly as a restart would reject it. Operators alert on this being
/// non-zero.
pub const RELOAD_BELOW_MIN_VERSION: &str = "below_min_version";
/// Reload outcome: the running directory is UNCHANGED and in-window, but its
/// signing issuer is no longer in the current trusted-issuer set (operators rotated
/// or removed it); the unchanged fast path re-verified against the current roots,
/// found the bundle untrusted, and swapped the gate to deny-all (fail-closed) with
/// an alarm, exactly as a restart would reject it. Operators alert on this being
/// non-zero.
pub const RELOAD_TRUST_ROOTS_CHANGED: &str = "trust_roots_changed";
/// Reload outcome: the on-disk bundle carries the running version but a DIFFERENT
/// canonical body (the file was replaced without a version bump); it cannot be a
/// monotone successor, so the reloader failed closed to deny-all with an alarm rather
/// than keep the loaded directory admitting peers the replacement dropped. Operators
/// alert on this being non-zero.
pub const RELOAD_CURRENT_BODY_REPLACED: &str = "current_body_replaced";
/// Reload outcome: the trusted-issuers file parsed but pins NO issuer (operators removed
/// every issuer). Trusting no signer must admit nothing, so the reloader failed closed to
/// deny-all with an alarm rather than fold it into the keep-last-good read-error path, in
/// lockstep with startup rejecting the same empty configuration. Operators alert on this
/// being non-zero.
pub const RELOAD_TRUST_ROOTS_EMPTY: &str = "trust_roots_empty";
/// Reload outcome: a transient read/verify/rollback error; last-good is kept.
pub const RELOAD_ERROR: &str = "error";
const NUM_RELOAD_OUTCOME: usize = 9;

static DIRECTORY_RELOAD: [AtomicU64; NUM_RELOAD_OUTCOME] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

fn reload_outcome_index(outcome: &str) -> usize {
    match outcome {
        "updated" => 0,
        "unchanged" => 1,
        "expired_failclosed" => 2,
        "binding_revoked" => 3,
        "below_min_version" => 4,
        "trust_roots_changed" => 5,
        "current_body_replaced" => 6,
        "trust_roots_empty" => 7,
        _ => 8, // error
    }
}

/// Record one directory-reload outcome (observe-only).
pub fn record_directory_reload(outcome: &str) {
    DIRECTORY_RELOAD[reload_outcome_index(outcome)].fetch_add(1, Ordering::Relaxed);
}

/// The count of a directory-reload outcome (for tests / export).
#[must_use]
pub fn directory_reload_total(outcome: &str) -> u64 {
    DIRECTORY_RELOAD[reload_outcome_index(outcome)].load(Ordering::Relaxed)
}

// -- Router-liveness gauge ---------------------------------------------------

static ROUTER_ALIVE: AtomicU64 = AtomicU64::new(1);

/// Set the router-liveness gauge: 1 = the iroh Router run loop
/// and endpoint are live, 0 = the router died (a panicked accept task killed it)
/// while HTTP may keep serving. Operators alert on 0.
pub fn set_router_alive(alive: bool) {
    ROUTER_ALIVE.store(u64::from(alive), Ordering::Relaxed);
}

/// The current router-liveness gauge value (1 alive / 0 dead).
#[must_use]
pub fn router_alive() -> u64 {
    ROUTER_ALIVE.load(Ordering::Relaxed)
}

// -- Prometheus rendering ----------------------------------------------------

const LANES: [&str; NUM_LANES] = ["pheromone", "revocation", "bilateral", "fanout"];

fn push_meta(output: &mut String, name: &str, help: &str, kind: &str) {
    output.push_str("# HELP ");
    output.push_str(name);
    output.push(' ');
    output.push_str(help);
    output.push('\n');
    output.push_str("# TYPE ");
    output.push_str(name);
    output.push(' ');
    output.push_str(kind);
    output.push('\n');
}

fn push_labeled(output: &mut String, name: &str, labels: &[(&str, &str)], value: u64) {
    output.push_str(name);
    output.push('{');
    for (index, (label, label_value)) in labels.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(label);
        output.push_str("=\"");
        output.push_str(label_value);
        output.push('"');
    }
    output.push_str("} ");
    output.push_str(&value.to_string());
    output.push('\n');
}

fn format_seconds(nanos: u64) -> String {
    format!("{:.9}", (nanos as f64) / (NANOS_PER_SECOND as f64))
}

/// Render every iroh federation-transport metric family in Prometheus text
/// format. Fixed-label families always emit their full series (zero-valued until
/// first hit, matching Prometheus counter convention); `verify_failures_total`
/// emits one series per observed `(seam, reason)`.
#[must_use]
pub fn render_iroh_transport_metrics_prometheus() -> String {
    let mut output = String::new();

    // admission_total
    push_meta(
        &mut output,
        CHIO_FEDERATION_TRANSPORT_ADMISSION_TOTAL,
        "Total iroh federation-transport admission-gate outcomes at after_handshake.",
        "counter",
    );
    for outcome in [ADMISSION_ACCEPT, ADMISSION_REJECT] {
        push_labeled(
            &mut output,
            CHIO_FEDERATION_TRANSPORT_ADMISSION_TOTAL,
            &[("outcome", outcome)],
            admission_total(outcome),
        );
    }

    // verify_failures_total (dynamic reason)
    push_meta(
        &mut output,
        CHIO_FEDERATION_TRANSPORT_VERIFY_FAILURES_TOTAL,
        "Total iroh federation-transport verification failures by seam and bounded reason.",
        "counter",
    );
    if let Ok(map) = VERIFY_FAILURES.lock() {
        for ((seam, reason), value) in map.iter() {
            push_labeled(
                &mut output,
                CHIO_FEDERATION_TRANSPORT_VERIFY_FAILURES_TOTAL,
                &[("seam", seam), ("reason", reason)],
                *value,
            );
        }
    }

    // catchup_epoch_gap_total
    push_meta(
        &mut output,
        CHIO_FEDERATION_TRANSPORT_CATCHUP_EPOCH_GAP_TOTAL,
        "Total iroh federation-transport revocation catch-up epoch gaps detected.",
        "counter",
    );
    for source in [CATCHUP_SOURCE_CATCHUP, CATCHUP_SOURCE_REVOCATION] {
        push_labeled(
            &mut output,
            CHIO_FEDERATION_TRANSPORT_CATCHUP_EPOCH_GAP_TOTAL,
            &[("source", source)],
            catchup_epoch_gap_total(source),
        );
    }

    // lane_total
    push_meta(
        &mut output,
        CHIO_FEDERATION_TRANSPORT_LANE_TOTAL,
        "Total iroh federation-transport per-lane accept outcomes.",
        "counter",
    );
    for lane in LANES {
        for outcome in [
            LANE_OUTCOME_ACCEPT,
            LANE_OUTCOME_REJECT,
            LANE_OUTCOME_BUSY,
            LANE_OUTCOME_TIMEOUT,
            LANE_OUTCOME_LAGGED,
        ] {
            push_labeled(
                &mut output,
                CHIO_FEDERATION_TRANSPORT_LANE_TOTAL,
                &[("lane", lane), ("outcome", outcome)],
                lane_total(lane, outcome),
            );
        }
    }

    // outbox_total
    push_meta(
        &mut output,
        CHIO_FEDERATION_TRANSPORT_OUTBOX_TOTAL,
        "Total iroh federation-transport pheromone outbox drain outcomes.",
        "counter",
    );
    for outcome in [OUTBOX_DELIVERED, OUTBOX_RETRIED, OUTBOX_DEAD_LETTERED] {
        push_labeled(
            &mut output,
            CHIO_FEDERATION_TRANSPORT_OUTBOX_TOTAL,
            &[("outcome", outcome)],
            outbox_total(outcome),
        );
    }

    // accept_open (gauge)
    push_meta(
        &mut output,
        CHIO_FEDERATION_TRANSPORT_ACCEPT_OPEN,
        "Iroh federation-transport in-flight accept handlers by lane (slowloris gauge).",
        "gauge",
    );
    for lane in LANES {
        push_labeled(
            &mut output,
            CHIO_FEDERATION_TRANSPORT_ACCEPT_OPEN,
            &[("lane", lane)],
            accept_open(lane),
        );
    }

    // accept_duration_seconds (histogram)
    push_meta(
        &mut output,
        CHIO_FEDERATION_TRANSPORT_ACCEPT_DURATION_SECONDS,
        "Iroh federation-transport per-lane accept handler duration in seconds.",
        "histogram",
    );
    for lane in LANES {
        render_accept_duration_histogram(&mut output, lane);
    }

    // directory_reload_total. Recorded by run_directory_reloader; emit the full outcome
    // set here so the fail-closed expired_failclosed / binding_revoked cases operators
    // must alert on are visible to Prometheus on the serve path.
    push_meta(
        &mut output,
        CHIO_FEDERATION_TRANSPORT_DIRECTORY_RELOAD_TOTAL,
        "Total iroh federation-transport directory reload outcomes.",
        "counter",
    );
    for outcome in [
        RELOAD_UPDATED,
        RELOAD_UNCHANGED,
        RELOAD_EXPIRED_FAILCLOSED,
        RELOAD_BINDING_REVOKED,
        RELOAD_BELOW_MIN_VERSION,
        RELOAD_TRUST_ROOTS_CHANGED,
        RELOAD_CURRENT_BODY_REPLACED,
        RELOAD_TRUST_ROOTS_EMPTY,
        RELOAD_ERROR,
    ] {
        push_labeled(
            &mut output,
            CHIO_FEDERATION_TRANSPORT_DIRECTORY_RELOAD_TOTAL,
            &[("outcome", outcome)],
            directory_reload_total(outcome),
        );
    }

    // router_alive (gauge). Emit the single unlabeled gauge series so the router-down
    // case (a panicked accept task killing the Router while HTTP keeps serving) operators
    // alert on is visible to Prometheus.
    push_meta(
        &mut output,
        CHIO_FEDERATION_TRANSPORT_ROUTER_ALIVE,
        "Iroh federation-transport router liveness (1 alive, 0 the router died).",
        "gauge",
    );
    output.push_str(CHIO_FEDERATION_TRANSPORT_ROUTER_ALIVE);
    output.push(' ');
    output.push_str(&router_alive().to_string());
    output.push('\n');

    output
}

fn render_accept_duration_histogram(output: &mut String, lane: &str) {
    let index = lane_index(lane);
    for (bucket, le) in FEDERATION_TRANSPORT_ACCEPT_DURATION_BUCKETS_SECONDS
        .iter()
        .enumerate()
    {
        push_accept_duration_bucket(
            output,
            lane,
            le,
            ACCEPT_DURATION_BUCKETS[index][bucket].load(Ordering::Relaxed),
        );
    }
    push_accept_duration_bucket(
        output,
        lane,
        "+Inf",
        ACCEPT_DURATION_BUCKETS[index][ACCEPT_DURATION_BUCKET_UPPER_NANOS.len()]
            .load(Ordering::Relaxed),
    );
    output.push_str(CHIO_FEDERATION_TRANSPORT_ACCEPT_DURATION_SECONDS);
    output.push_str("_sum{lane=\"");
    output.push_str(lane);
    output.push_str("\"} ");
    output.push_str(&format_seconds(
        ACCEPT_DURATION_SUM_NS[index].load(Ordering::Relaxed),
    ));
    output.push('\n');
    output.push_str(CHIO_FEDERATION_TRANSPORT_ACCEPT_DURATION_SECONDS);
    output.push_str("_count{lane=\"");
    output.push_str(lane);
    output.push_str("\"} ");
    output.push_str(
        &ACCEPT_DURATION_COUNT[index]
            .load(Ordering::Relaxed)
            .to_string(),
    );
    output.push('\n');
}

fn push_accept_duration_bucket(output: &mut String, lane: &str, le: &str, count: u64) {
    output.push_str(CHIO_FEDERATION_TRANSPORT_ACCEPT_DURATION_SECONDS);
    output.push_str("_bucket{lane=\"");
    output.push_str(lane);
    output.push_str("\",le=\"");
    output.push_str(le);
    output.push_str("\"} ");
    output.push_str(&count.to_string());
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes every test that ASSERTS on the process-global `ROUTER_ALIVE` gauge, so
    /// the exact-value assertions cannot be perturbed by another test that mutates the same
    /// gauge under the default parallel test harness. Any NEW test that reads or writes
    /// `router_alive`/`set_router_alive` and asserts on it MUST acquire this guard. Poison
    /// is recovered (a panicking guard-holder already fails its own test) so the serialized
    /// siblings stay deterministic rather than cascade-failing.
    static ROUTER_ALIVE_GAUGE_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn registry_constants_match_spec() {
        assert_eq!(
            CHIO_FEDERATION_TRANSPORT_ADMISSION_TOTAL,
            "chio_federation_transport_admission_total"
        );
        assert_eq!(
            CHIO_FEDERATION_TRANSPORT_VERIFY_FAILURES_TOTAL,
            "chio_federation_transport_verify_failures_total"
        );
    }

    #[test]
    fn record_and_render_round_trip() {
        // Drive one of every family, then confirm the render surface carries each
        // registered name and reflects the recorded samples.
        record_admission(ADMISSION_ACCEPT);
        record_admission(ADMISSION_REJECT);
        record_lane_frame(LANE_REVOCATION, LANE_OUTCOME_REJECT);
        record_lane_frame(LANE_BILATERAL, LANE_OUTCOME_TIMEOUT);
        record_outbox(OUTBOX_DEAD_LETTERED);
        record_catchup_epoch_gap(CATCHUP_SOURCE_CATCHUP);
        record_verify_failure(SEAM_REVOCATION, "bad-signature");
        observe_accept_duration_nanos(LANE_REVOCATION, 5_000_000);
        // Exercise the AcceptOpenGuard enter/drop on LANE_FANOUT: no fan-out accept
        // handler is wired (lane c is disabled), so no concurrent test mutates this
        // gauge, keeping the exact enter=1 / post-drop=0 assertions robust. (The
        // three direct lanes' gauges are held by parallel over-QUIC handler tests, so
        // an exact absolute on those would be racy on a process-global gauge.)
        {
            let _open = AcceptOpenGuard::enter(LANE_FANOUT);
            assert_eq!(accept_open(LANE_FANOUT), 1);
        }
        assert_eq!(accept_open(LANE_FANOUT), 0);

        assert!(admission_total(ADMISSION_REJECT) >= 1);
        assert!(lane_total(LANE_REVOCATION, LANE_OUTCOME_REJECT) >= 1);
        assert!(lane_total(LANE_BILATERAL, LANE_OUTCOME_TIMEOUT) >= 1);
        assert!(outbox_total(OUTBOX_DEAD_LETTERED) >= 1);
        assert!(catchup_epoch_gap_total(CATCHUP_SOURCE_CATCHUP) >= 1);
        assert!(verify_failures_total(SEAM_REVOCATION, "bad-signature") >= 1);
        assert!(accept_duration_count(LANE_REVOCATION) >= 1);

        let body = render_iroh_transport_metrics_prometheus();
        for name in [
            CHIO_FEDERATION_TRANSPORT_ADMISSION_TOTAL,
            CHIO_FEDERATION_TRANSPORT_VERIFY_FAILURES_TOTAL,
            CHIO_FEDERATION_TRANSPORT_CATCHUP_EPOCH_GAP_TOTAL,
            CHIO_FEDERATION_TRANSPORT_LANE_TOTAL,
            CHIO_FEDERATION_TRANSPORT_OUTBOX_TOTAL,
            CHIO_FEDERATION_TRANSPORT_ACCEPT_OPEN,
            CHIO_FEDERATION_TRANSPORT_ACCEPT_DURATION_SECONDS,
        ] {
            assert!(body.contains(name), "render must contain {name}");
        }
        assert!(body.contains("outcome=\"reject\""));
        assert!(body.contains("seam=\"revocation\",reason=\"bad-signature\""));
        assert!(body.contains("chio_federation_transport_accept_duration_seconds_bucket"));
        assert!(body.contains("le=\"+Inf\""));
    }

    #[test]
    fn directory_reload_fail_closed_outcome_is_counted() {
        // Observe-only monotone lower bound: an expired-with-no-successor reload
        // increments its counter so operators can alert on it.
        let before = directory_reload_total(RELOAD_EXPIRED_FAILCLOSED);
        record_directory_reload(RELOAD_EXPIRED_FAILCLOSED);
        assert!(
            directory_reload_total(RELOAD_EXPIRED_FAILCLOSED) > before,
            "an expired-while-running reload must be counted"
        );
    }

    #[test]
    fn router_alive_gauge_reflects_liveness() {
        // Serialize against the sibling render test that also mutates ROUTER_ALIVE, so these
        // exact-value assertions are not flipped between the set and the read under the
        // parallel harness.
        let _serial = ROUTER_ALIVE_GAUGE_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set_router_alive(true);
        assert_eq!(router_alive(), 1);
        set_router_alive(false);
        assert_eq!(router_alive(), 0);
    }

    #[test]
    fn render_emits_the_reload_and_liveness_series() {
        // Instruments must not lie: the directory-reload counter and the router-liveness
        // gauge are RECORDED, so the render must also EMIT both or the expired_failclosed
        // / binding_revoked / router-down cases operators alert on stay invisible to
        // Prometheus on the serve path. Without the render wiring the reload/liveness
        // names are absent from the body.
        // Hold the same serial guard as router_alive_gauge_reflects_liveness: this test
        // MUTATES ROUTER_ALIVE, which would otherwise race that test's exact assertions.
        let _serial = ROUTER_ALIVE_GAUGE_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        record_directory_reload(RELOAD_BINDING_REVOKED);
        record_directory_reload(RELOAD_EXPIRED_FAILCLOSED);
        set_router_alive(true);

        let body = render_iroh_transport_metrics_prometheus();
        for name in [
            CHIO_FEDERATION_TRANSPORT_DIRECTORY_RELOAD_TOTAL,
            CHIO_FEDERATION_TRANSPORT_ROUTER_ALIVE,
        ] {
            assert!(body.contains(name), "render must contain {name}");
        }
        // The full reload outcome set is emitted, including the fail-closed series
        // operators alert on.
        assert!(body.contains(
            "chio_federation_transport_directory_reload_total{outcome=\"binding_revoked\"}"
        ));
        assert!(body.contains(
            "chio_federation_transport_directory_reload_total{outcome=\"expired_failclosed\"}"
        ));
        // The router-liveness gauge is emitted with its own TYPE line and an unlabeled
        // value series (value is process-global, so assert the line shape, not the value).
        assert!(body.contains("# TYPE chio_federation_transport_router_alive gauge"));
        assert!(
            body.lines()
                .any(|line| line.starts_with("chio_federation_transport_router_alive ")),
            "render must emit the router-alive gauge value line"
        );
    }
}
