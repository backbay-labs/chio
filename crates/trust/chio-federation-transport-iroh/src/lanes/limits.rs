//! Shared accept-side hardening for the three DIRECT custom lanes (pheromone,
//! revocation, bilateral).
//!
//! ADR-0014 production-robustness: an admission-gated but hostile peer must not
//! be able to hang a handler task (slowloris) or spawn unbounded accept tasks
//! (resource exhaustion). Each direct-lane `ProtocolHandler::accept` runs on a
//! freshly spawned tokio task and awaits peer-controlled progress at four points:
//! opening the bidi stream (`accept_bi`), reading the length-delimited request
//! frame (the biggest slowloris surface: a large declared length then a dribble
//! of bytes), writing the response, and lingering on `conn.closed()` so the
//! finished stream is not reset before the dialer reads it. Every one of those
//! is bounded here, and the number of concurrently admitted handlers is capped.
//!
//! ## Fail-closed, never trust-bypassing
//!
//! These bounds ONLY limit how long the handler waits and how many peers it
//! serves at once. A timeout drops / resets the connection; it never accepts,
//! short-circuits, or weakens verification. The trust verdict is produced by the
//! per-frame verifier ABOVE the transport and is unaffected: a bounded exchange
//! either runs the full verification or resets with no verdict at all.
//!
//! ## What this module deliberately does NOT set
//!
//! The QUIC `Endpoint::max_idle_timeout` is a transport-level backstop owned by
//! the WIRING (Phase 4), not by this crate. It should sit comfortably above the
//! app-level [`AcceptLimitConfig::linger_timeout`] so a legitimately slow but
//! live exchange is not killed underneath these bounds. See
//! [`RECOMMENDED_MAX_IDLE_TIMEOUT`] for the value the wiring can consume.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::Connection;
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::Semaphore;

/// QUIC application close code used when a handler resets after a fail-closed
/// lane error (framing / transport / verification-plumbing failure). Value `1`
/// matches the pheromone lane's historical reset code so the three direct lanes
/// share one reset vocabulary.
pub const LANE_RESET_CLOSE_CODE: u32 = 1;

/// QUIC application close code used when a handler resets a connection because a
/// peer-dependent await exceeded its bound (slowloris). Distinct from
/// [`LANE_RESET_CLOSE_CODE`] so a stalled peer is diagnosable on the wire.
pub const ACCEPT_TIMEOUT_CLOSE_CODE: u32 = 2;

/// QUIC application close code used when a handler SHEDS a connection because the
/// in-flight accept cap was saturated (the peer is asked to retry). Distinct so
/// back-pressure is diagnosable and never confused with a protocol reset.
pub const ACCEPT_BUSY_CLOSE_CODE: u32 = 3;

/// Bound on `accept_bi()`: how long to wait for an admitted peer to open its
/// bidi stream before giving up. A connected-but-silent peer is dropped here.
///
/// Generous: a cross-continent QUIC RTT is well under a second even under loss,
/// so 30s is > 50x realistic worst case while still bounding a stalled peer.
pub const DEFAULT_ACCEPT_STREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on reading ONE length-delimited request frame. This is the primary
/// slowloris surface: a peer that sends a large length prefix then dribbles (or
/// withholds) the body is dropped here.
///
/// Sized for a real request (a ~3.3KB ML-DSA-65 payload, or a small revocation
/// batch) over a lossy cross-continent path: such a frame transfers in well
/// under a second, so 30s bounds a stall with a wide legitimate margin.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on writing the response frame back to the peer. A peer that stops
/// reading (stalling our flow-controlled write) is dropped here.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on the post-exchange linger (`conn.closed()`). After the response is
/// written the handler waits for the dialer to read it and close so the finished
/// stream is not reset early; this caps that wait so a peer that completes the
/// exchange but never closes cannot pin the handler task.
///
/// Larger than the per-phase bounds: this is a clean-teardown grace window, not
/// an active-transfer bound, and a well-behaved dialer closes promptly.
pub const DEFAULT_LINGER_TIMEOUT: Duration = Duration::from_secs(60);

/// Default cap on concurrently admitted accept handlers for ONE lane. Sized high
/// enough for legitimate cross-operator fan-in (many peers dialing at once)
/// while bounding the tasks a single hostile peer (or a thundering herd) can
/// force into existence.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 1024;

/// Default bounded wait for an in-flight permit before shedding. A brief burst
/// above the cap waits this long for a slot; a sustained overload sheds fast
/// (bounded queueing, never unbounded) with [`ACCEPT_BUSY_CLOSE_CODE`].
pub const DEFAULT_SHED_WAIT: Duration = Duration::from_millis(250);

/// Recommended `Endpoint::max_idle_timeout` for the WIRING (Phase 4) to consume.
///
/// The QUIC idle timeout is a transport backstop BELOW these app-level bounds.
/// Set it above [`DEFAULT_LINGER_TIMEOUT`] so a legitimately slow live exchange
/// is not killed by the transport before the app-level bounds apply, while still
/// reaping truly dead connections. This crate does NOT set it; the endpoint
/// builder in the wiring does.
pub const RECOMMENDED_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Which peer-dependent await is being bounded, selecting its timeout and naming
/// it in diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptPhase {
    /// Waiting for the peer to open its bidi stream (`accept_bi`).
    AcceptStream,
    /// Reading the single length-delimited request frame (the slowloris surface).
    ReadFrame,
    /// Writing the response frame back to the peer.
    WriteResponse,
}

impl AcceptPhase {
    /// Stable, log-friendly label for the phase.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            AcceptPhase::AcceptStream => "accept_bi",
            AcceptPhase::ReadFrame => "read_frame",
            AcceptPhase::WriteResponse => "write_response",
        }
    }
}

impl std::fmt::Display for AcceptPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Tunable, fail-closed bounds shared by the three direct-lane accept handlers.
///
/// [`Default`] preserves the historically unbounded behavior generously: the
/// per-phase bounds are tens of seconds and the concurrency cap is high, so a
/// legitimate exchange never trips them, while a hostile peer can no longer hang
/// a task or spawn handlers without limit.
#[derive(Debug, Clone, Copy)]
pub struct AcceptLimitConfig {
    /// Bound on `accept_bi()`.
    pub accept_stream_timeout: Duration,
    /// Bound on reading the one length-delimited request frame.
    pub read_timeout: Duration,
    /// Bound on writing the response frame.
    pub write_timeout: Duration,
    /// Bound on the post-exchange `conn.closed()` linger.
    pub linger_timeout: Duration,
    /// Maximum concurrently admitted accept handlers for the lane.
    pub max_in_flight: usize,
    /// Bounded wait for an in-flight permit before shedding.
    pub shed_wait: Duration,
}

impl Default for AcceptLimitConfig {
    fn default() -> Self {
        Self {
            accept_stream_timeout: DEFAULT_ACCEPT_STREAM_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            linger_timeout: DEFAULT_LINGER_TIMEOUT,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            shed_wait: DEFAULT_SHED_WAIT,
        }
    }
}

impl AcceptLimitConfig {
    /// The bound for a given peer-dependent [`AcceptPhase`].
    #[must_use]
    pub fn phase_timeout(&self, phase: AcceptPhase) -> Duration {
        match phase {
            AcceptPhase::AcceptStream => self.accept_stream_timeout,
            AcceptPhase::ReadFrame => self.read_timeout,
            AcceptPhase::WriteResponse => self.write_timeout,
        }
    }
}

/// A fail-closed reason a bounded accept step stopped: either the in-flight cap
/// shed the connection, or a peer-dependent await exceeded its bound. Both drop
/// the connection; neither ever influences the trust verdict.
#[derive(Debug, thiserror::Error)]
pub enum AcceptLimitError {
    /// The in-flight cap was saturated and the bounded wait elapsed: shed.
    #[error("accept handler shed: in-flight cap of {cap} saturated")]
    Busy {
        /// The configured concurrency cap that was saturated.
        cap: usize,
    },
    /// A peer-dependent await exceeded its bound: reset (slowloris defense).
    #[error("{phase} exceeded its {timeout_ms}ms bound")]
    Timeout {
        /// Which peer-dependent step timed out.
        phase: AcceptPhase,
        /// The bound that was exceeded, in milliseconds.
        timeout_ms: u64,
    },
}

impl AcceptLimitError {
    /// Stable, log- and reason-string-friendly code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AcceptLimitError::Busy { .. } => "accept_busy",
            AcceptLimitError::Timeout { .. } => "accept_timeout",
        }
    }

    /// The distinct QUIC application close code for this outcome.
    #[must_use]
    pub fn close_code(&self) -> u32 {
        match self {
            AcceptLimitError::Busy { .. } => ACCEPT_BUSY_CLOSE_CODE,
            AcceptLimitError::Timeout { .. } => ACCEPT_TIMEOUT_CLOSE_CODE,
        }
    }
}

/// The single shared accept-hardening helper used identically by all three
/// direct lanes: a concurrency cap (semaphore) plus per-phase timeouts, tuned in
/// one place via [`AcceptLimitConfig`].
///
/// Cloning shares the underlying semaphore, so ONE limiter per lane bounds every
/// accept task of that lane. `Default` builds a limiter from the generous
/// [`AcceptLimitConfig::default`].
#[derive(Debug, Clone)]
pub struct AcceptLimiter {
    config: AcceptLimitConfig,
    semaphore: Arc<Semaphore>,
}

impl Default for AcceptLimiter {
    fn default() -> Self {
        Self::new(AcceptLimitConfig::default())
    }
}

impl AcceptLimiter {
    /// Build a limiter from `config`. The concurrency cap is clamped to at least
    /// one permit: a zero cap would deny every connection (a fail-closed footgun,
    /// not a useful configuration), so it is raised to one.
    #[must_use]
    pub fn new(config: AcceptLimitConfig) -> Self {
        let permits = config.max_in_flight.max(1);
        Self {
            config,
            semaphore: Arc::new(Semaphore::new(permits)),
        }
    }

    /// The bounds this limiter enforces.
    #[must_use]
    pub fn config(&self) -> &AcceptLimitConfig {
        &self.config
    }

    /// Acquire one in-flight permit, waiting at most [`AcceptLimitConfig::shed_wait`]
    /// under saturation before shedding ([`AcceptLimitError::Busy`]). The returned
    /// permit MUST be held for the lifetime of the handler (bind it, do not drop
    /// it) so the slot is released only when the handler task ends.
    pub async fn admit(&self) -> Result<OwnedSemaphorePermit, AcceptLimitError> {
        let cap = self.config.max_in_flight.max(1);
        match tokio::time::timeout(
            self.config.shed_wait,
            self.semaphore.clone().acquire_owned(),
        )
        .await
        {
            // A live permit: proceed.
            Ok(Ok(permit)) => Ok(permit),
            // The semaphore is never closed in this crate, but treat a closed
            // semaphore as saturation (fail-closed) rather than panicking.
            Ok(Err(_closed)) => Err(AcceptLimitError::Busy { cap }),
            // The bounded wait elapsed under sustained load: shed.
            Err(_elapsed) => Err(AcceptLimitError::Busy { cap }),
        }
    }

    /// Run a peer-dependent future bounded by the phase's timeout. On success the
    /// inner output is returned verbatim; on timeout the connection should be
    /// reset with [`AcceptLimitError::close_code`] (fail-closed).
    pub async fn bounded<F>(
        &self,
        phase: AcceptPhase,
        fut: F,
    ) -> Result<F::Output, AcceptLimitError>
    where
        F: Future,
    {
        let bound = self.config.phase_timeout(phase);
        match tokio::time::timeout(bound, fut).await {
            Ok(output) => Ok(output),
            Err(_elapsed) => Err(AcceptLimitError::Timeout {
                phase,
                timeout_ms: u64::try_from(bound.as_millis()).unwrap_or(u64::MAX),
            }),
        }
    }

    /// Best-effort bounded linger on `conn.closed()`. Waits up to
    /// [`AcceptLimitConfig::linger_timeout`] for the dialer to read the response
    /// and close, then returns regardless: a peer that never closes cannot pin
    /// the handler task past this bound. Returns `true` if the peer closed within
    /// the bound, `false` if the linger bound elapsed first.
    pub async fn linger(&self, conn: &Connection) -> bool {
        tokio::time::timeout(self.config.linger_timeout, conn.closed())
            .await
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn default_config_is_generous_and_bounded() {
        let config = AcceptLimitConfig::default();
        assert_eq!(config.read_timeout, DEFAULT_READ_TIMEOUT);
        assert_eq!(
            config.phase_timeout(AcceptPhase::ReadFrame),
            config.read_timeout
        );
        assert_eq!(
            config.phase_timeout(AcceptPhase::AcceptStream),
            config.accept_stream_timeout
        );
        assert_eq!(
            config.phase_timeout(AcceptPhase::WriteResponse),
            config.write_timeout
        );
        // The linger grace is larger than any per-phase active-transfer bound.
        assert!(config.linger_timeout > config.read_timeout);
        // The recommended idle backstop sits above the linger grace.
        assert!(RECOMMENDED_MAX_IDLE_TIMEOUT > config.linger_timeout);
    }

    #[test]
    fn distinct_close_codes() {
        assert_ne!(LANE_RESET_CLOSE_CODE, ACCEPT_TIMEOUT_CLOSE_CODE);
        assert_ne!(LANE_RESET_CLOSE_CODE, ACCEPT_BUSY_CLOSE_CODE);
        assert_ne!(ACCEPT_TIMEOUT_CLOSE_CODE, ACCEPT_BUSY_CLOSE_CODE);
        assert_eq!(
            AcceptLimitError::Busy { cap: 4 }.close_code(),
            ACCEPT_BUSY_CLOSE_CODE
        );
        assert_eq!(
            AcceptLimitError::Timeout {
                phase: AcceptPhase::ReadFrame,
                timeout_ms: 10,
            }
            .close_code(),
            ACCEPT_TIMEOUT_CLOSE_CODE
        );
    }

    #[tokio::test]
    async fn bounded_returns_inner_output_when_fast() {
        let limiter = AcceptLimiter::default();
        let value = limiter
            .bounded(AcceptPhase::ReadFrame, async { 7u32 })
            .await
            .expect("fast future is not bounded out");
        assert_eq!(value, 7);
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_times_out_a_stalled_future() {
        let config = AcceptLimitConfig {
            read_timeout: Duration::from_millis(50),
            ..AcceptLimitConfig::default()
        };
        let limiter = AcceptLimiter::new(config);
        let error = limiter
            .bounded(AcceptPhase::ReadFrame, async {
                // Never resolves within the bound: the slowloris shape.
                tokio::time::sleep(Duration::from_secs(3600)).await;
                0u32
            })
            .await
            .expect_err("a stalled future must be bounded out");
        assert!(matches!(
            error,
            AcceptLimitError::Timeout {
                phase: AcceptPhase::ReadFrame,
                ..
            }
        ));
        assert_eq!(error.close_code(), ACCEPT_TIMEOUT_CLOSE_CODE);
    }

    #[tokio::test(start_paused = true)]
    async fn cap_admits_up_to_the_limit_then_sheds() {
        let config = AcceptLimitConfig {
            max_in_flight: 2,
            shed_wait: Duration::from_millis(50),
            ..AcceptLimitConfig::default()
        };
        let limiter = AcceptLimiter::new(config);

        // Two permits are admitted and held.
        let permit_one = limiter.admit().await.expect("first permit admitted");
        let permit_two = limiter.admit().await.expect("second permit admitted");

        // The third sheds after the bounded wait: bounded queueing, not unbounded.
        let shed = limiter
            .admit()
            .await
            .expect_err("third is shed under saturation");
        assert!(matches!(shed, AcceptLimitError::Busy { cap: 2 }));
        assert_eq!(shed.close_code(), ACCEPT_BUSY_CLOSE_CODE);

        // Releasing a permit re-opens a slot immediately.
        drop(permit_one);
        let permit_three = limiter.admit().await.expect("slot re-opens after release");
        drop(permit_two);
        drop(permit_three);
    }

    #[test]
    fn zero_cap_is_clamped_to_one_permit() {
        let limiter = AcceptLimiter::new(AcceptLimitConfig {
            max_in_flight: 0,
            ..AcceptLimitConfig::default()
        });
        assert_eq!(limiter.semaphore.available_permits(), 1);
    }
}
