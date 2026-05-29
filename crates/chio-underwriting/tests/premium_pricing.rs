//! Acceptance tests for premium pricing.
//!
//! Acceptance: *An agent with a clean receipt history gets a lower
//! premium quote than one with denials.* and *decline below score
//! floor.*

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_underwriting::{
    price_premium, LookbackWindow, PremiumDeclineReason, PremiumInputs, PremiumQuote,
};

fn window() -> LookbackWindow {
    LookbackWindow::new(1_000_000, 1_000_600).expect("valid lookback window")
}

fn inputs(score: Option<u32>) -> PremiumInputs {
    PremiumInputs::new(score, None, 1_000, "USD")
}

#[test]
fn clean_receipt_history_quote_is_lower_than_denial_heavy_quote() {
    let clean = price_premium("agent-clean", "tool:exec", window(), &inputs(Some(950)));
    let dirty = price_premium("agent-denials", "tool:exec", window(), &inputs(Some(560)));

    let clean_cents = match &clean {
        PremiumQuote::Quoted { quoted_cents, .. } => *quoted_cents,
        PremiumQuote::Declined { .. } => {
            panic!("clean agent should receive a quote, got {clean:?}")
        }
    };
    let dirty_cents = match &dirty {
        PremiumQuote::Quoted { quoted_cents, .. } => *quoted_cents,
        PremiumQuote::Declined { .. } => {
            panic!("denial-heavy but above-floor agent should still be quoted, got {dirty:?}")
        }
    };

    assert!(
        clean_cents < dirty_cents,
        "clean quote ({clean_cents}) should be cheaper than denial-heavy quote ({dirty_cents})"
    );
    // Low-risk band should be 2x, high-risk band should be 6x base rate.
    assert_eq!(clean_cents, 2_000);
    assert_eq!(dirty_cents, 6_000);
}

#[test]
fn score_below_500_is_declined() {
    let quote = price_premium(
        "agent-below-floor",
        "tool:exec",
        window(),
        &inputs(Some(420)),
    );
    match quote {
        PremiumQuote::Declined {
            reason,
            combined_score,
            ..
        } => {
            assert_eq!(reason, PremiumDeclineReason::ScoreBelowFloor);
            assert_eq!(combined_score, Some(420));
        }
        PremiumQuote::Quoted { .. } => panic!("expected decline for score < 500, got {quote:?}"),
    }
}

#[test]
fn missing_compliance_score_is_declined_fail_closed() {
    let quote = price_premium("agent-no-score", "tool:exec", window(), &inputs(None));
    match quote {
        PremiumQuote::Declined { reason, .. } => {
            assert_eq!(reason, PremiumDeclineReason::MissingComplianceScore);
        }
        PremiumQuote::Quoted { .. } => panic!("expected fail-closed decline, got {quote:?}"),
    }
}

#[test]
fn premium_formula_is_deterministic() {
    let first = price_premium("agent-det", "tool:exec", window(), &inputs(Some(830)));
    let second = price_premium("agent-det", "tool:exec", window(), &inputs(Some(830)));
    assert_eq!(first, second);
}
