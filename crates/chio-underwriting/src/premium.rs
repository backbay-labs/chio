//! Agent insurance premium pricing.
//!
//! `price_premium` turns a 0..=1000 compliance score and optional behavioral
//! anomaly signal into a deterministic insurance premium quote. The formula
//! is:
//!
//! ```text
//! quoted_cents = base_rate_cents * (1 + risk_multiplier(score))
//! ```
//!
//! where `risk_multiplier` is a stepwise function of the combined score:
//!
//! | Score band  | Multiplier | Disposition |
//! |-------------|-----------:|-------------|
//! | `> 900`     |        1.0 | quoted      |
//! | `700..=900` |        2.0 | quoted      |
//! | `500..700`  |        5.0 | quoted      |
//! | `< 500`     |          - | declined    |
//!
//! The combined score is derived from a compliance score and, when supplied,
//! a behavioral anomaly penalty. Both inputs are expected to have already
//! been materialised from `chio_kernel::compliance_score` and
//! `chio_kernel::behavioral_anomaly_score` by the caller (chio-underwriting
//! does not depend on chio-kernel in order to preserve the directed crate
//! graph). Callers that cannot supply a compliance score fail closed to
//! [`PremiumQuote::Declined`] rather than silently approve.
//!
//! The formula is deterministic: given the same `PremiumInputs`, every call
//! produces the same [`PremiumQuote`]. No wall-clock or randomness is used.

use serde::{Deserialize, Serialize};

/// Minimum score required to quote any premium. Below this threshold the
/// agent is declined for insurance coverage.
pub const PREMIUM_DECLINE_FLOOR: u32 = 500;
/// Upper bound of the highest-risk quotable band (exclusive, matches the
/// decline floor).
pub const PREMIUM_HIGH_RISK_FLOOR: u32 = 500;
/// Lower bound of the medium-risk band (inclusive).
pub const PREMIUM_MEDIUM_RISK_FLOOR: u32 = 700;
/// Lower bound of the low-risk band (exclusive: `> 900` earns the best rate).
pub const PREMIUM_LOW_RISK_FLOOR: u32 = 900;

/// Penalty applied to the compliance score for each sigma-multiple of
/// behavioral-anomaly z-score beyond the provided threshold. Tunable via
/// [`PremiumInputs::behavioral_penalty_per_sigma`].
pub const DEFAULT_BEHAVIORAL_PENALTY_PER_SIGMA: u32 = 50;
/// Hard cap on the behavioral deduction so a single runaway z-score cannot
/// synthesise an arbitrary decline on top of an otherwise clean history.
pub const DEFAULT_BEHAVIORAL_PENALTY_CAP: u32 = 250;

/// Lookback window for the compliance / behavioral inputs used by the
/// premium. Recorded in the justification so operators can audit the
/// evidence basis.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LookbackWindow {
    /// Beginning of the window (unix seconds, inclusive).
    pub since: u64,
    /// End of the window (unix seconds, inclusive).
    pub until: u64,
}

impl LookbackWindow {
    /// Construct a lookback window, returning an error when `since > until`.
    pub fn new(since: u64, until: u64) -> Result<Self, String> {
        if since > until {
            return Err(format!(
                "premium lookback window requires since <= until, got since={since} until={until}"
            ));
        }
        Ok(Self { since, until })
    }

    /// Width of the window in seconds.
    #[must_use]
    pub fn width_secs(&self) -> u64 {
        self.until.saturating_sub(self.since)
    }
}

/// Inputs for the premium pricing formula.
///
/// Callers populate this from `chio_kernel::compliance_score` and
/// `chio_kernel::behavioral_anomaly_score` over the kernel's receipt store
/// for the target agent and scope. A missing compliance score is treated
/// as fail-closed (the quote is declined).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PremiumInputs {
    /// Compliance score in `0..=1000`, as produced by
    /// `chio_kernel::compliance_score`. `None` forces a decline (fail-closed
    /// when the kernel API is unavailable).
    pub compliance_score: Option<u32>,
    /// Optional behavioral anomaly z-score (signed). When `Some`, the
    /// absolute value above `behavioral_threshold` erodes the compliance
    /// score before the band is chosen.
    pub behavioral_z_score: Option<f64>,
    /// Absolute z-score threshold above which the behavioral penalty is
    /// activated. Defaults to 3 sigma.
    pub behavioral_threshold: f64,
    /// Per-sigma penalty points subtracted from the compliance score.
    pub behavioral_penalty_per_sigma: u32,
    /// Maximum cumulative behavioral penalty points.
    pub behavioral_penalty_cap: u32,
    /// Base rate expressed in the smallest currency unit (e.g. USD cents).
    pub base_rate_cents: u64,
    /// ISO 4217 three-letter uppercase currency code.
    pub currency: String,
}

impl PremiumInputs {
    /// Convenience constructor with sensible defaults for the optional
    /// behavioral-penalty tuning.
    #[must_use]
    pub fn new(
        compliance_score: Option<u32>,
        behavioral_z_score: Option<f64>,
        base_rate_cents: u64,
        currency: impl Into<String>,
    ) -> Self {
        Self {
            compliance_score,
            behavioral_z_score,
            behavioral_threshold: 3.0,
            behavioral_penalty_per_sigma: DEFAULT_BEHAVIORAL_PENALTY_PER_SIGMA,
            behavioral_penalty_cap: DEFAULT_BEHAVIORAL_PENALTY_CAP,
            base_rate_cents,
            currency: currency.into(),
        }
    }

    /// Validate input sanity. Used by `price_premium` to short-circuit on
    /// malformed configuration. Fail-closed: an invalid configuration
    /// produces a decline rather than a silent approval.
    pub fn validate(&self) -> Result<(), String> {
        if self.base_rate_cents == 0 {
            return Err("premium base_rate_cents must be greater than zero".to_string());
        }
        let currency = self.currency.trim();
        if currency.len() != 3
            || !currency
                .chars()
                .all(|character| character.is_ascii_uppercase())
        {
            return Err(format!(
                "premium currency must be a three-letter uppercase ISO-style code, got `{}`",
                self.currency
            ));
        }
        if !self.behavioral_threshold.is_finite() || self.behavioral_threshold < 0.0 {
            return Err(
                "premium behavioral_threshold must be a finite non-negative number".to_string(),
            );
        }
        if let Some(score) = self.compliance_score {
            if score > 1000 {
                return Err(format!(
                    "premium compliance_score must be in 0..=1000, got {score}"
                ));
            }
        }
        if let Some(z) = self.behavioral_z_score {
            if z.is_nan() || z.is_infinite() {
                return Err("premium behavioral_z_score must be finite".to_string());
            }
        }
        Ok(())
    }
}

/// Result of premium pricing: either a concrete quote or a deterministic
/// decline explaining which floor the agent failed to clear.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum PremiumQuote {
    /// The agent cleared the decline floor and receives a numeric quote.
    Quoted {
        /// Agent the quote applies to.
        agent_id: String,
        /// Scope / coverage identifier the quote applies to.
        scope: String,
        /// Lookback window the risk signals were drawn from.
        lookback_window: LookbackWindow,
        /// Combined score (compliance, penalised by behavioral signal) in
        /// `0..=1000`.
        combined_score: u32,
        /// Base rate in the smallest currency unit.
        base_rate_cents: u64,
        /// Additive risk multiplier applied to the base rate. The final
        /// quoted amount is `base_rate_cents * (1 + score_adjustment)`.
        score_adjustment: f64,
        /// Final quoted premium in the smallest currency unit.
        quoted_cents: u64,
        /// ISO 4217 three-letter uppercase currency code.
        currency: String,
        /// Human-readable justification summarising the inputs used.
        justification: String,
    },
    /// The agent fell below the decline floor (or was otherwise fail-closed).
    Declined {
        /// Agent the decline applies to.
        agent_id: String,
        /// Scope / coverage identifier that was declined.
        scope: String,
        /// Lookback window the risk signals were drawn from.
        lookback_window: LookbackWindow,
        /// Combined score that triggered the decline. `None` when the
        /// compliance score was unavailable (fail-closed).
        combined_score: Option<u32>,
        /// Machine-readable decline reason.
        reason: PremiumDeclineReason,
        /// Human-readable justification summarising the inputs used.
        justification: String,
    },
}

impl PremiumQuote {
    /// Return the agent id this quote/decline refers to.
    #[must_use]
    pub fn agent_id(&self) -> &str {
        match self {
            PremiumQuote::Quoted { agent_id, .. } | PremiumQuote::Declined { agent_id, .. } => {
                agent_id
            }
        }
    }

    /// Return the scope this quote/decline refers to.
    #[must_use]
    pub fn scope(&self) -> &str {
        match self {
            PremiumQuote::Quoted { scope, .. } | PremiumQuote::Declined { scope, .. } => scope,
        }
    }

    /// Return the lookback window this quote/decline refers to.
    #[must_use]
    pub fn lookback_window(&self) -> LookbackWindow {
        match self {
            PremiumQuote::Quoted {
                lookback_window, ..
            }
            | PremiumQuote::Declined {
                lookback_window, ..
            } => *lookback_window,
        }
    }

    /// `true` when the quote was approved (a numeric premium is available).
    #[must_use]
    pub fn is_quoted(&self) -> bool {
        matches!(self, PremiumQuote::Quoted { .. })
    }

    /// `true` when the quote was declined.
    #[must_use]
    pub fn is_declined(&self) -> bool {
        matches!(self, PremiumQuote::Declined { .. })
    }

    /// Return the quoted premium in cents when approved.
    #[must_use]
    pub fn quoted_cents(&self) -> Option<u64> {
        match self {
            PremiumQuote::Quoted { quoted_cents, .. } => Some(*quoted_cents),
            PremiumQuote::Declined { .. } => None,
        }
    }

    /// Return the combined score, if one was computed.
    #[must_use]
    pub fn combined_score(&self) -> Option<u32> {
        match self {
            PremiumQuote::Quoted { combined_score, .. } => Some(*combined_score),
            PremiumQuote::Declined { combined_score, .. } => *combined_score,
        }
    }
}

/// Machine-readable decline reason.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PremiumDeclineReason {
    /// Score fell below the decline floor.
    ScoreBelowFloor,
    /// The kernel did not return a compliance score (fail-closed).
    MissingComplianceScore,
    /// Inputs were malformed (for example currency or base rate).
    InvalidInputs,
}

/// Price a premium for `agent_id` against `scope` over `lookback_window`.
///
/// Deterministic: the same `inputs` always produce the same `PremiumQuote`.
/// Fail-closed: if `inputs.compliance_score` is `None` or the inputs fail
/// validation, the quote is declined rather than silently approved.
#[must_use]
pub fn price_premium(
    agent_id: &str,
    scope: &str,
    lookback_window: LookbackWindow,
    inputs: &PremiumInputs,
) -> PremiumQuote {
    if let Err(error) = inputs.validate() {
        return PremiumQuote::Declined {
            agent_id: agent_id.to_string(),
            scope: scope.to_string(),
            lookback_window,
            combined_score: None,
            reason: PremiumDeclineReason::InvalidInputs,
            justification: format!("premium inputs failed validation: {error}"),
        };
    }

    let Some(compliance_score) = inputs.compliance_score else {
        return PremiumQuote::Declined {
            agent_id: agent_id.to_string(),
            scope: scope.to_string(),
            lookback_window,
            combined_score: None,
            reason: PremiumDeclineReason::MissingComplianceScore,
            justification: "compliance score unavailable for agent; premium declined fail-closed"
                .to_string(),
        };
    };

    let (behavioral_penalty, behavioral_note) =
        behavioral_penalty(inputs.behavioral_z_score, inputs);
    let combined_score = compliance_score.saturating_sub(behavioral_penalty);

    if combined_score < PREMIUM_DECLINE_FLOOR {
        return PremiumQuote::Declined {
            agent_id: agent_id.to_string(),
            scope: scope.to_string(),
            lookback_window,
            combined_score: Some(combined_score),
            reason: PremiumDeclineReason::ScoreBelowFloor,
            justification: format!(
                "combined score {combined_score} is below the decline floor {PREMIUM_DECLINE_FLOOR} \
                 (compliance_score={compliance_score}, behavioral_penalty={behavioral_penalty}{behavioral_note})",
            ),
        };
    }

    let score_adjustment = risk_multiplier(combined_score);
    let quoted_cents = compute_quoted_cents(inputs.base_rate_cents, score_adjustment);

    PremiumQuote::Quoted {
        agent_id: agent_id.to_string(),
        scope: scope.to_string(),
        lookback_window,
        combined_score,
        base_rate_cents: inputs.base_rate_cents,
        score_adjustment,
        quoted_cents,
        currency: inputs.currency.trim().to_ascii_uppercase(),
        justification: format!(
            "compliance_score={compliance_score}, behavioral_penalty={behavioral_penalty}{behavioral_note}, \
             combined_score={combined_score}, risk_multiplier={score_adjustment}, \
             quoted_cents = base_rate_cents({}) * (1 + risk_multiplier({score_adjustment})) = {quoted_cents}",
            inputs.base_rate_cents
        ),
    }
}

/// Compute the additive risk multiplier for a combined score.
///
/// See module docs for the band table.
#[must_use]
pub fn risk_multiplier(score: u32) -> f64 {
    if score > PREMIUM_LOW_RISK_FLOOR {
        1.0
    } else if score >= PREMIUM_MEDIUM_RISK_FLOOR {
        2.0
    } else if score >= PREMIUM_HIGH_RISK_FLOOR {
        5.0
    } else {
        // Caller should have declined before reaching this branch. The
        // default is conservative so out-of-band use also fails closed.
        f64::INFINITY
    }
}

fn behavioral_penalty(z: Option<f64>, inputs: &PremiumInputs) -> (u32, String) {
    match z {
        None => (0, String::new()),
        Some(z) => {
            let magnitude = z.abs();
            if magnitude <= inputs.behavioral_threshold {
                (
                    0,
                    format!(
                        ", behavioral_z={:.3} under threshold {:.3}",
                        magnitude, inputs.behavioral_threshold
                    ),
                )
            } else {
                let sigma_over = magnitude - inputs.behavioral_threshold;
                let raw = sigma_over * f64::from(inputs.behavioral_penalty_per_sigma);
                // Round half away from zero to keep the penalty deterministic.
                let raw_points = raw.round().clamp(0.0, f64::from(u32::MAX)) as u32;
                let penalty = raw_points.min(inputs.behavioral_penalty_cap);
                (
                    penalty,
                    format!(
                        ", behavioral_z={:.3} over threshold {:.3} (capped at {})",
                        magnitude, inputs.behavioral_threshold, inputs.behavioral_penalty_cap
                    ),
                )
            }
        }
    }
}

fn compute_quoted_cents(base: u64, multiplier: f64) -> u64 {
    // `base * (1 + multiplier)` on integer cents, with saturating fallback
    // so an absurd multiplier never overflows silently.
    if !multiplier.is_finite() || multiplier < 0.0 {
        return u64::MAX;
    }
    let factor = 1.0 + multiplier;
    let product = (base as f64) * factor;
    if !product.is_finite() || product < 0.0 {
        return u64::MAX;
    }
    // Round to nearest cent to keep the formula deterministic regardless of
    // fp noise; clamp into u64 range.
    let rounded = product.round();
    if rounded >= (u64::MAX as f64) {
        return u64::MAX;
    }
    rounded as u64
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn window() -> LookbackWindow {
        LookbackWindow::new(1_000_000, 1_000_600).unwrap()
    }

    fn inputs(score: Option<u32>, z: Option<f64>) -> PremiumInputs {
        PremiumInputs::new(score, z, 1_000, "USD")
    }

    #[test]
    fn clean_history_quotes_lowest_band() {
        let quote = price_premium(
            "agent-clean",
            "tool:exec",
            window(),
            &inputs(Some(950), None),
        );
        match quote {
            PremiumQuote::Quoted {
                score_adjustment,
                quoted_cents,
                combined_score,
                ..
            } => {
                assert_eq!(combined_score, 950);
                assert!((score_adjustment - 1.0).abs() < f64::EPSILON);
                assert_eq!(quoted_cents, 2_000);
            }
            other => panic!("expected Quoted, got {other:?}"),
        }
    }

    #[test]
    fn medium_band_multiplies_base_rate_by_three() {
        let quote = price_premium("agent-med", "tool:exec", window(), &inputs(Some(750), None));
        match quote {
            PremiumQuote::Quoted {
                score_adjustment,
                quoted_cents,
                ..
            } => {
                assert!((score_adjustment - 2.0).abs() < f64::EPSILON);
                assert_eq!(quoted_cents, 3_000);
            }
            other => panic!("expected Quoted, got {other:?}"),
        }
    }

    #[test]
    fn high_risk_band_multiplies_base_rate_by_six() {
        let quote = price_premium(
            "agent-risk",
            "tool:exec",
            window(),
            &inputs(Some(550), None),
        );
        match quote {
            PremiumQuote::Quoted {
                score_adjustment,
                quoted_cents,
                ..
            } => {
                assert!((score_adjustment - 5.0).abs() < f64::EPSILON);
                assert_eq!(quoted_cents, 6_000);
            }
            other => panic!("expected Quoted, got {other:?}"),
        }
    }

    #[test]
    fn score_below_floor_declines() {
        let quote = price_premium("agent-bad", "tool:exec", window(), &inputs(Some(200), None));
        match quote {
            PremiumQuote::Declined {
                reason,
                combined_score,
                ..
            } => {
                assert_eq!(reason, PremiumDeclineReason::ScoreBelowFloor);
                assert_eq!(combined_score, Some(200));
            }
            other => panic!("expected Declined, got {other:?}"),
        }
    }

    #[test]
    fn missing_compliance_score_declines_fail_closed() {
        let quote = price_premium("agent-?", "tool:exec", window(), &inputs(None, None));
        match quote {
            PremiumQuote::Declined { reason, .. } => {
                assert_eq!(reason, PremiumDeclineReason::MissingComplianceScore);
            }
            other => panic!("expected Declined, got {other:?}"),
        }
    }

    #[test]
    fn behavioral_anomaly_pushes_score_down() {
        // compliance 920 (low-risk band) with a moderate behavioral z-score
        // should erode the combined score into the medium-risk band.
        // sigma_over = 5 - 3 = 2; penalty = 2 * 50 = 100; combined = 820.
        let bump = inputs(Some(920), Some(5.0));
        let quote = price_premium("agent-anom", "tool:exec", window(), &bump);
        match quote {
            PremiumQuote::Quoted {
                combined_score,
                score_adjustment,
                ..
            } => {
                assert_eq!(combined_score, 820);
                assert!((score_adjustment - 2.0).abs() < f64::EPSILON);
            }
            other => panic!("expected Quoted with penalty applied, got {other:?}"),
        }
    }

    #[test]
    fn behavioral_anomaly_can_force_decline() {
        // A very large z-score with an aggressive penalty erodes a medium-band
        // compliance score into the decline zone.
        let mut bump = inputs(Some(720), Some(10.0));
        bump.behavioral_penalty_per_sigma = 80;
        bump.behavioral_penalty_cap = 500;
        let quote = price_premium("agent-anom-decline", "tool:exec", window(), &bump);
        assert!(matches!(
            quote,
            PremiumQuote::Declined {
                reason: PremiumDeclineReason::ScoreBelowFloor,
                ..
            }
        ));
    }

    #[test]
    fn formula_is_deterministic_for_equal_inputs() {
        let a = price_premium("agent-x", "scope", window(), &inputs(Some(800), Some(1.5)));
        let b = price_premium("agent-x", "scope", window(), &inputs(Some(800), Some(1.5)));
        assert_eq!(a, b);
    }

    #[test]
    fn invalid_inputs_decline() {
        let mut bad = inputs(Some(950), None);
        bad.base_rate_cents = 0;
        let quote = price_premium("agent-x", "scope", window(), &bad);
        assert!(matches!(
            quote,
            PremiumQuote::Declined {
                reason: PremiumDeclineReason::InvalidInputs,
                ..
            }
        ));
    }

    #[test]
    fn non_finite_behavioral_threshold_declines() {
        let mut bad = inputs(Some(950), Some(8.0));
        bad.behavioral_threshold = f64::INFINITY;
        let quote = price_premium("agent-x", "scope", window(), &bad);
        assert!(matches!(
            quote,
            PremiumQuote::Declined {
                reason: PremiumDeclineReason::InvalidInputs,
                ..
            }
        ));
    }

    #[test]
    fn clean_quote_is_less_than_denial_heavy_quote() {
        // Roadmap acceptance: clean-history quote < denial-heavy quote.
        let clean = price_premium("clean", "scope", window(), &inputs(Some(980), None));
        let denied = price_premium("denials", "scope", window(), &inputs(Some(560), None));
        let clean_cents = clean.quoted_cents().unwrap();
        let denied_cents = denied.quoted_cents().unwrap();
        assert!(
            clean_cents < denied_cents,
            "expected clean ({clean_cents}) < denials ({denied_cents})"
        );
    }

    #[test]
    fn lookback_window_rejects_inverted_range() {
        let err = LookbackWindow::new(100, 50).unwrap_err();
        assert!(err.contains("since <= until"));
    }
}
