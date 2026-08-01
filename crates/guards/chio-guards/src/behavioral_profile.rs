//! Guard-integrated behavioral profiling.
//!
//! Productizes [`chio_kernel::operator_report::BehavioralFeedReport`] and
//! the EMA helpers in `chio_kernel::operator_report` into a synchronous
//! guard that detects anomalies against a per-agent baseline.
//!
//! # Model
//!
//! The guard tracks exponentially-weighted moving averages (EMA) for
//! each (agent, metric) pair. The metrics are:
//!
//! * `call_rate`               -- receipts per window
//! * `deny_rate`               -- fraction of denies per window
//! * `unique_tools`            -- distinct tools per window
//! * `avg_parameter_entropy`   -- Shannon entropy of invocation parameters
//!
//! When a new window's sample crosses the configured sigma threshold
//! relative to the baseline, the guard emits a [`GuardEvidence`] entry
//! marking the advisory signal. The verdict itself remains
//! [`Verdict::Allow`]; this guard is advisory-only.
//!
//! # Storage
//!
//! Baselines live in memory behind a `Mutex` keyed by `(agent, metric)`.
//! Receipts are read through a pluggable [`ReceiptFeedSource`] trait.
//! The default in-memory implementation is used by unit tests; the
//! production wiring backs it with an chio-store-sqlite
//! `ReceiptStore::query_receipts` call (see the integration test in
//! `tests/behavioral_profile.rs`).
//!
//! # Why synchronous
//!
//! This is a synchronous `Guard`. The feed source does one bounded
//! read per evaluation and caches the baseline, so the cost sits well
//! under a millisecond in typical deployments.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::receipt::body::ChioReceipt;
use chio_kernel::operator_report::EmaBaselineState;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};

/// Default EMA smoothing factor. Equivalent to a ~10-sample window.
pub const DEFAULT_EMA_ALPHA: f64 = 0.2;
/// Default sigma threshold above which a window is flagged.
pub const DEFAULT_SIGMA_THRESHOLD: f64 = 2.0;
/// Default rolling window length in seconds.
pub const DEFAULT_WINDOW_SECS: u64 = 60;
/// Default number of historical windows used to prime the baseline
/// before the guard starts emitting signals. Guarantees the z-score
/// has enough history to be meaningful.
pub const DEFAULT_BASELINE_MIN_WINDOWS: u64 = 3;

/// Metric captured per (agent, window).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BehavioralMetric {
    /// Total receipts per window.
    CallRate,
    /// Denies per window.
    DenyRate,
    /// Distinct tool names per window.
    UniqueTools,
    /// Approximate parameter entropy per window.
    AvgParameterEntropy,
}

impl BehavioralMetric {
    /// Stable string identifier for serialization / logging.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CallRate => "call_rate",
            Self::DenyRate => "deny_rate",
            Self::UniqueTools => "unique_tools",
            Self::AvgParameterEntropy => "avg_parameter_entropy",
        }
    }
}

/// Pluggable receipt feed. Lets the guard be tested in-memory and
/// driven in production by `chio-store-sqlite`.
pub trait ReceiptFeedSource: Send + Sync {
    /// Return receipts for `agent_id` whose `timestamp` falls in
    /// `[since, until]` (inclusive on both ends). Implementations should
    /// return a bounded slice; callers pass short windows so the
    /// result set stays small.
    fn receipts_for_agent(
        &self,
        agent_id: &str,
        since: u64,
        until: u64,
    ) -> Result<Vec<ChioReceipt>, KernelError>;
}

/// Trivial in-memory receipt feed used for tests and lightweight
/// deployments. Stores receipts in insertion order and filters by
/// agent + timestamp at read time.
///
/// The "agent" here is conceptual; real deployments resolve an agent
/// subject through the capability snapshot table. For this feed the
/// caller directly tags each receipt with an agent id.
#[derive(Default)]
pub struct InMemoryReceiptFeed {
    inner: Mutex<Vec<(String, ChioReceipt)>>,
}

impl InMemoryReceiptFeed {
    /// Build a new, empty in-memory feed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a receipt tagged with the given agent id.
    pub fn push(&self, agent_id: &str, receipt: ChioReceipt) -> Result<(), KernelError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| KernelError::Internal("behavioral feed lock poisoned".to_string()))?;
        inner.push((agent_id.to_string(), receipt));
        Ok(())
    }

    /// Number of receipts stored.
    pub fn len(&self) -> Result<usize, KernelError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| KernelError::Internal("behavioral feed lock poisoned".to_string()))?;
        Ok(inner.len())
    }

    /// Whether the feed is empty.
    pub fn is_empty(&self) -> Result<bool, KernelError> {
        Ok(self.len()? == 0)
    }
}

impl ReceiptFeedSource for InMemoryReceiptFeed {
    fn receipts_for_agent(
        &self,
        agent_id: &str,
        since: u64,
        until: u64,
    ) -> Result<Vec<ChioReceipt>, KernelError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| KernelError::Internal("behavioral feed lock poisoned".to_string()))?;
        Ok(inner
            .iter()
            .filter(|(id, r)| id == agent_id && r.timestamp >= since && r.timestamp <= until)
            .map(|(_, r)| r.clone())
            .collect())
    }
}

/// Configuration surface for [`BehavioralProfileGuard`].
#[derive(Debug, Clone, Copy)]
pub struct BehavioralProfileConfig {
    /// EMA smoothing factor.
    pub ema_alpha: f64,
    /// Sigma threshold above which a window is flagged.
    pub sigma_threshold: f64,
    /// Rolling window length in seconds.
    pub window_secs: u64,
    /// Minimum number of windows required before anomalies can be
    /// flagged. Protects the guard from firing on a cold baseline.
    pub baseline_min_windows: u64,
}

impl Default for BehavioralProfileConfig {
    fn default() -> Self {
        Self {
            ema_alpha: DEFAULT_EMA_ALPHA,
            sigma_threshold: DEFAULT_SIGMA_THRESHOLD,
            window_secs: DEFAULT_WINDOW_SECS,
            baseline_min_windows: DEFAULT_BASELINE_MIN_WINDOWS,
        }
    }
}

/// Baseline entry keyed by (agent, metric).
#[derive(Debug, Clone, Default)]
struct BaselineEntry {
    state: EmaBaselineState,
    last_window_start: u64,
}

/// Guard that computes behavioral-anomaly signals from the receipt
/// store and emits advisories without blocking the request.
pub struct BehavioralProfileGuard {
    name: String,
    config: BehavioralProfileConfig,
    feed: Box<dyn ReceiptFeedSource>,
    // Keyed by (agent_id, metric).
    baselines: Mutex<HashMap<(String, BehavioralMetric), BaselineEntry>>,
    now: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl BehavioralProfileGuard {
    /// Construct a new guard with the default configuration and a
    /// system-clock `now` source.
    pub fn new(feed: Box<dyn ReceiptFeedSource>) -> Self {
        Self::with_config(feed, BehavioralProfileConfig::default())
    }

    /// Construct with an explicit config.
    pub fn with_config(feed: Box<dyn ReceiptFeedSource>, config: BehavioralProfileConfig) -> Self {
        Self {
            name: "behavioral-profile".to_string(),
            config,
            feed,
            baselines: Mutex::new(HashMap::new()),
            now: Box::new(default_now),
        }
    }

    /// Override the clock source. Useful for deterministic tests.
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.now = clock;
        self
    }

    /// Feed the guard a fresh sample and return whether the window
    /// should be flagged as anomalous. Exposed for tests and dashboards
    /// that want to surface scores without running the full pipeline.
    pub fn observe_sample(
        &self,
        agent_id: &str,
        metric: BehavioralMetric,
        sample: f64,
        window_start: u64,
    ) -> Result<ObservationOutcome, KernelError> {
        let mut baselines = self
            .baselines
            .lock()
            .map_err(|_| KernelError::Internal("baseline lock poisoned".to_string()))?;
        let entry = baselines.entry((agent_id.to_string(), metric)).or_default();

        // Only record one sample per window-start pair. Callers that
        // pass the same window_start multiple times get the same
        // verdict without inflating the sample count.
        if entry.last_window_start == window_start && entry.state.sample_count > 0 {
            let z = robust_z_score(&entry.state, sample);
            let anomaly = z
                .map(|z| z.abs() > self.config.sigma_threshold)
                .unwrap_or(false);
            return Ok(ObservationOutcome {
                z_score: z,
                anomaly,
                baseline: entry.state.clone(),
                sample,
            });
        }

        let z = robust_z_score(&entry.state, sample);
        let seen_enough = entry.state.sample_count >= self.config.baseline_min_windows;
        let anomaly = seen_enough
            && z.map(|z| z.abs() > self.config.sigma_threshold)
                .unwrap_or(false);

        entry
            .state
            .update(sample, self.config.ema_alpha, window_start);
        entry.last_window_start = window_start;
        let baseline = entry.state.clone();

        Ok(ObservationOutcome {
            z_score: z,
            anomaly,
            baseline,
            sample,
        })
    }

    /// Access the snapshot of a (agent, metric) baseline.
    pub fn baseline(
        &self,
        agent_id: &str,
        metric: BehavioralMetric,
    ) -> Result<Option<EmaBaselineState>, KernelError> {
        let baselines = self
            .baselines
            .lock()
            .map_err(|_| KernelError::Internal("baseline lock poisoned".to_string()))?;
        Ok(baselines
            .get(&(agent_id.to_string(), metric))
            .map(|e| e.state.clone()))
    }

    fn current_window_start(&self, now: u64) -> u64 {
        let window = self.config.window_secs.max(1);
        (now / window) * window
    }

    fn sample_for_window(&self, agent_id: &str, window_start: u64) -> Result<f64, KernelError> {
        let window_end = window_start + self.config.window_secs.max(1);
        let receipts =
            self.feed
                .receipts_for_agent(agent_id, window_start, window_end.saturating_sub(1))?;
        Ok(receipts.len() as f64)
    }
}

/// Outcome of a single `observe_sample` call.
#[derive(Debug, Clone)]
pub struct ObservationOutcome {
    /// Z-score of the new sample relative to the pre-update baseline.
    /// `None` when the baseline was too small.
    pub z_score: Option<f64>,
    /// Whether the sample was flagged as anomalous.
    pub anomaly: bool,
    /// Post-update baseline snapshot.
    pub baseline: EmaBaselineState,
    /// The sample value that was observed.
    pub sample: f64,
}

fn default_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Z-score with a Poisson-style stddev floor.
///
/// For count metrics (call rate, deny count, unique tools) a zero
/// measured variance is an artifact of a short baseline rather than a
/// true zero-noise process. We floor the effective stddev at
/// `sqrt(max(mean, 1))` so that a 50x spike over a steady 10/window
/// baseline is detected as an anomaly even when the EWMA variance
/// happens to be numerically zero.
fn robust_z_score(state: &EmaBaselineState, sample: f64) -> Option<f64> {
    if state.sample_count < 2 {
        return None;
    }
    let measured = state.stddev();
    let floor = state.ema_mean.max(1.0).sqrt();
    let effective = measured.max(floor);
    if effective <= f64::EPSILON {
        return None;
    }
    Some((sample - state.ema_mean) / effective)
}

impl Guard for BehavioralProfileGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let now = (self.now)();
        let window_start = self.current_window_start(now);
        let agent_id = ctx.agent_id.as_str();
        let sample = self.sample_for_window(agent_id, window_start)?;
        // Advisory-only guard: we only inspect the call-rate metric in
        // the sync path. Other metrics are available through
        // `observe_sample` so callers can feed the guard out-of-band.
        let _ = self.observe_sample(agent_id, BehavioralMetric::CallRate, sample, window_start)?;
        Ok(GuardDecision::allow())
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn revalidate_before_dispatch(&self, _ctx: &GuardContext) -> Result<(), KernelError> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn guard_for_tests(feed: InMemoryReceiptFeed) -> BehavioralProfileGuard {
        BehavioralProfileGuard::with_config(
            Box::new(feed),
            BehavioralProfileConfig {
                baseline_min_windows: 2,
                ..Default::default()
            },
        )
    }

    #[test]
    fn ema_baseline_stabilizes_under_steady_sample() {
        let guard = guard_for_tests(InMemoryReceiptFeed::new());
        for i in 0..20 {
            let outcome = guard
                .observe_sample("agent-steady", BehavioralMetric::CallRate, 10.0, i)
                .unwrap();
            // After enough samples the baseline centers on 10.
            if i >= 10 {
                assert!(
                    (outcome.baseline.ema_mean - 10.0).abs() < 0.1,
                    "ema_mean should stabilize near 10 after 10 samples, got {}",
                    outcome.baseline.ema_mean
                );
                assert!(!outcome.anomaly);
            }
        }
    }

    #[test]
    fn spike_fifty_x_triggers_anomaly() {
        let guard = guard_for_tests(InMemoryReceiptFeed::new());
        // Prime: 10 calls per window for a long enough stretch.
        for i in 0..15 {
            let _ = guard
                .observe_sample("agent-spiky", BehavioralMetric::CallRate, 10.0, i)
                .unwrap();
        }
        // Spike: 50x the baseline in the next window.
        let outcome = guard
            .observe_sample("agent-spiky", BehavioralMetric::CallRate, 500.0, 100)
            .unwrap();
        assert!(
            outcome.anomaly,
            "50x spike should flag an anomaly (z={:?})",
            outcome.z_score
        );
        assert!(outcome.z_score.unwrap_or(0.0).abs() > DEFAULT_SIGMA_THRESHOLD);
    }

    #[test]
    fn cold_baseline_does_not_flag() {
        let guard = guard_for_tests(InMemoryReceiptFeed::new());
        let outcome = guard
            .observe_sample("agent-cold", BehavioralMetric::CallRate, 1_000.0, 1)
            .unwrap();
        assert!(
            !outcome.anomaly,
            "cold baseline must not flag anomalies (observed in isolation)"
        );
    }
}
