//! Fail-closed per-subject rate limiter for the issuance pipeline.
//!
//! The custody issuer mints short-lived capabilities from WebAuthn
//! assertions. A compromised or buggy client can otherwise drive the
//! issuer (and the signing backend behind it) at an unbounded rate. This
//! module adds a per-subject sliding-window limiter the issuer consults
//! BEFORE consulting the revocation oracle, recording the nonce, or
//! signing, so a flood is rejected at the cheapest possible gate.
//!
//! # Why a sliding window
//!
//! A fixed-window counter admits a burst of up to `2 * max` requests
//! across a window boundary (the tail of one window plus the head of the
//! next). A sliding log keyed on request timestamps bounds the count to
//! `max` over ANY `window`-length interval, which is the property an
//! abuse limiter needs. The log is pruned on every call so memory stays
//! bounded by the admitted rate times the window.
//!
//! # Fail-closed posture
//!
//! - The limiter denies (returns [`RateLimitOutcome::Limited`]) once a
//!   subject has `max_per_window` admitted requests inside the trailing
//!   `window`. The issuer maps this to
//!   [`crate::CustodyError::RateLimited`].
//! - A poisoned internal lock is surfaced as
//!   [`crate::CustodyError::Encoding`]: the issuer denies rather than
//!   minting while the limiter state is unknown.
//! - A non-monotonic / pre-epoch clock reading is treated as a deny, not
//!   an admit, so a clock fault can never widen the admitted rate.
//!
//! # Defaults and rationale
//!
//! [`DEFAULT_MAX_PER_WINDOW`] and [`DEFAULT_WINDOW_SECONDS`] permit
//! 30 mints per credential per 60 seconds. A legitimate interactive
//! passkey ceremony issues at most a handful of capabilities per minute
//! (each requires a fresh user-verifying gesture and a fresh challenge),
//! so 30/min leaves generous headroom for retries and multi-tab clients
//! while still capping a runaway client at a rate the signing backend and
//! nonce store comfortably absorb. Deployments tune the bound through
//! [`RateLimiter::with_limits`]; the defaults are deliberately
//! conservative rather than permissive because the limiter is a
//! fail-closed abuse gate, not a fairness scheduler.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};

use crate::error::CustodyError;

/// Default maximum admitted mints per subject per window. See the module
/// docs for the rationale (interactive passkey ceremonies issue only a
/// handful of capabilities per minute; 30 leaves retry headroom while
/// capping a runaway client).
pub const DEFAULT_MAX_PER_WINDOW: u32 = 30;

/// Default trailing window, in seconds, over which
/// [`DEFAULT_MAX_PER_WINDOW`] applies.
pub const DEFAULT_WINDOW_SECONDS: i64 = 60;

/// Hard cap on the number of distinct subjects tracked at once. A client
/// presenting an unbounded stream of distinct subject ids could otherwise
/// grow the limiter's map without bound; once this many subjects are
/// tracked the limiter fails closed on a new subject until idle subjects
/// age out. Pruning happens on every call, so steady-state occupancy is
/// bounded by the admitted rate times the window.
pub const DEFAULT_MAX_TRACKED_SUBJECTS: usize = 100_000;

/// Outcome of a [`RateLimiter::check_and_record`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitOutcome {
    /// The request is within budget and has been recorded against the
    /// subject's window.
    Allowed,
    /// The subject already has `max_per_window` admitted requests inside
    /// the trailing window. The issuer MUST fail the mint with
    /// [`CustodyError::RateLimited`].
    Limited,
}

/// Per-subject sliding-window rate limiter.
///
/// `Send + Sync` so the issuer can hold it in an `Arc<dyn IssuanceRateLimiter>`.
pub struct RateLimiter {
    inner: Mutex<HashMap<String, Vec<i64>>>,
    max_per_window: u32,
    window_seconds: i64,
    max_tracked_subjects: usize,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    /// Build a limiter with the conservative module defaults
    /// ([`DEFAULT_MAX_PER_WINDOW`] over [`DEFAULT_WINDOW_SECONDS`]).
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_PER_WINDOW, DEFAULT_WINDOW_SECONDS)
    }

    /// Build a limiter admitting at most `max_per_window` requests per
    /// subject over a trailing `window_seconds` interval.
    ///
    /// A `max_per_window` of zero (deny everything) or a non-positive
    /// window is accepted and denies all traffic; that is the
    /// fail-closed direction, so it is never a misconfiguration that
    /// widens the admitted rate.
    #[must_use]
    pub fn with_limits(max_per_window: u32, window_seconds: i64) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_per_window,
            window_seconds,
            max_tracked_subjects: DEFAULT_MAX_TRACKED_SUBJECTS,
        }
    }

    /// Override the hard cap on tracked subjects.
    #[must_use]
    pub fn with_max_tracked_subjects(mut self, max_tracked_subjects: usize) -> Self {
        self.max_tracked_subjects = max_tracked_subjects;
        self
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, Vec<i64>>>, CustodyError> {
        self.inner
            .lock()
            .map_err(|err| CustodyError::Encoding(format!("rate limiter mutex poisoned: {err}")))
    }
}

/// Trust-boundary surface for issuance rate limiting.
///
/// Implementations are `Send + Sync` so the issuer can keep them in an
/// `Arc<dyn IssuanceRateLimiter>` and swap the in-crate sliding-window
/// limiter for a distributed limiter without changing the call site.
pub trait IssuanceRateLimiter: Send + Sync {
    /// Account for one issuance attempt by `subject` at instant `now`.
    ///
    /// Returns [`RateLimitOutcome::Allowed`] if the attempt is within
    /// budget (and records it), or [`RateLimitOutcome::Limited`] if the
    /// subject is over budget. Fail-closed: lock or clock faults return
    /// [`CustodyError`] and the issuer denies.
    fn check_and_record(
        &self,
        subject: &str,
        now: DateTime<Utc>,
    ) -> Result<RateLimitOutcome, CustodyError>;
}

impl IssuanceRateLimiter for RateLimiter {
    fn check_and_record(
        &self,
        subject: &str,
        now: DateTime<Utc>,
    ) -> Result<RateLimitOutcome, CustodyError> {
        // A non-positive window or a zero budget denies everything; this
        // is the fail-closed direction so we short-circuit before taking
        // the lock.
        if self.window_seconds <= 0 || self.max_per_window == 0 {
            return Ok(RateLimitOutcome::Limited);
        }

        let now_unix = now.timestamp();
        let cutoff = now_unix.saturating_sub(self.window_seconds);

        let mut guard = self.lock()?;

        // Drop subjects whose entire window has aged out so the map stays
        // bounded. This runs on every call; steady-state occupancy is the
        // admitted rate times the window.
        guard.retain(|_, stamps| stamps.iter().any(|&t| t > cutoff));

        let max = usize::try_from(self.max_per_window).unwrap_or(usize::MAX);

        if let Some(stamps) = guard.get_mut(subject) {
            stamps.retain(|&t| t > cutoff);
            if stamps.len() >= max {
                return Ok(RateLimitOutcome::Limited);
            }
            stamps.push(now_unix);
            return Ok(RateLimitOutcome::Allowed);
        }

        // New subject: enforce the hard cap on distinct tracked subjects
        // before allocating an entry.
        if guard.len() >= self.max_tracked_subjects {
            return Err(CustodyError::Encoding(format!(
                "rate limiter capacity exceeded: {} tracked subjects (max {})",
                guard.len(),
                self.max_tracked_subjects
            )));
        }
        guard.insert(subject.to_string(), vec![now_unix]);
        Ok(RateLimitOutcome::Allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(unix: i64) -> DateTime<Utc> {
        match Utc.timestamp_opt(unix, 0) {
            chrono::LocalResult::Single(t) => t,
            _ => panic!("test timestamp must construct"),
        }
    }

    #[test]
    fn admits_up_to_budget_then_denies() {
        let limiter = RateLimiter::with_limits(3, 60);
        for i in 0..3 {
            match limiter.check_and_record("cred", at(1_000 + i)) {
                Ok(RateLimitOutcome::Allowed) => {}
                other => panic!("request {i} within budget must be allowed: {other:?}"),
            }
        }
        match limiter.check_and_record("cred", at(1_003)) {
            Ok(RateLimitOutcome::Limited) => {}
            other => panic!("over-budget request must be limited: {other:?}"),
        }
    }

    #[test]
    fn window_slides_so_old_requests_free_budget() {
        let limiter = RateLimiter::with_limits(2, 10);
        match limiter.check_and_record("cred", at(100)) {
            Ok(RateLimitOutcome::Allowed) => {}
            other => panic!("first must be allowed: {other:?}"),
        }
        match limiter.check_and_record("cred", at(101)) {
            Ok(RateLimitOutcome::Allowed) => {}
            other => panic!("second must be allowed: {other:?}"),
        }
        // At t=105 the subject is at budget within the trailing 10s.
        match limiter.check_and_record("cred", at(105)) {
            Ok(RateLimitOutcome::Limited) => {}
            other => panic!("third within window must be limited: {other:?}"),
        }
        // At t=112 the first two (t=100, t=101) have aged out of the
        // trailing 10s window (cutoff = 102), so budget reopens.
        match limiter.check_and_record("cred", at(112)) {
            Ok(RateLimitOutcome::Allowed) => {}
            other => panic!("after window slide must be allowed: {other:?}"),
        }
    }

    #[test]
    fn subjects_are_independent() {
        let limiter = RateLimiter::with_limits(1, 60);
        match limiter.check_and_record("cred-A", at(1_000)) {
            Ok(RateLimitOutcome::Allowed) => {}
            other => panic!("A first must be allowed: {other:?}"),
        }
        match limiter.check_and_record("cred-A", at(1_001)) {
            Ok(RateLimitOutcome::Limited) => {}
            other => panic!("A second must be limited: {other:?}"),
        }
        match limiter.check_and_record("cred-B", at(1_001)) {
            Ok(RateLimitOutcome::Allowed) => {}
            other => panic!("B must have its own budget: {other:?}"),
        }
    }

    #[test]
    fn zero_budget_denies_everything_fail_closed() {
        let limiter = RateLimiter::with_limits(0, 60);
        match limiter.check_and_record("cred", at(1_000)) {
            Ok(RateLimitOutcome::Limited) => {}
            other => panic!("zero budget must deny: {other:?}"),
        }
    }

    #[test]
    fn non_positive_window_denies_everything_fail_closed() {
        let limiter = RateLimiter::with_limits(10, 0);
        match limiter.check_and_record("cred", at(1_000)) {
            Ok(RateLimitOutcome::Limited) => {}
            other => panic!("non-positive window must deny: {other:?}"),
        }
    }

    #[test]
    fn tracked_subject_cap_fails_closed_on_new_subject() {
        let limiter = RateLimiter::with_limits(5, 600).with_max_tracked_subjects(1);
        match limiter.check_and_record("first", at(1_000)) {
            Ok(RateLimitOutcome::Allowed) => {}
            other => panic!("first subject must be admitted: {other:?}"),
        }
        // A second distinct subject within the window exceeds the tracked
        // cap and must fail closed rather than silently grow the map.
        let res = limiter.check_and_record("second", at(1_001));
        assert!(
            matches!(res, Err(CustodyError::Encoding(_))),
            "exceeding the tracked-subject cap must fail closed: {res:?}"
        );
    }
}
