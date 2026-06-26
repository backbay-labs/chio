use alloc::format;

use crate::error::{Error, Result};

/// Absolute basis-point ceiling for a budget share. 10000 bps == 100%.
pub(crate) const MAX_BUDGET_SHARE_BPS: u16 = 10_000;

/// Validate a `budget_share_bps` value against the absolute 100% ceiling.
///
/// This is the context-free check applied at token-signing time: a share is
/// expressed in basis points and can never exceed 100% (10000 bps) of *some*
/// budget. It does NOT prove the share is sound relative to a parent
/// capability; delegation must additionally enforce
/// [`validate_parent_relative_budget_share_bps`].
pub(crate) fn validate_budget_share_bps(share: u16) -> Result<()> {
    if share > MAX_BUDGET_SHARE_BPS {
        return Err(Error::AttenuationViolation {
            reason: format!(
                "budget_share_bps {share} exceeds the {MAX_BUDGET_SHARE_BPS} bps parent budget ceiling"
            ),
        });
    }
    Ok(())
}

/// Validate a child `budget_share_bps` parent-relative, fail-closed.
///
/// `budget_share_bps` is a *fraction of the parent's* remaining/granted
/// budget, not an absolute amount. A child can therefore never claim a larger
/// fraction than the parent itself holds:
///
/// * The absolute ceiling still applies (`child <= 10000`).
/// * When the parent already carries an explicit `budget_share_bps`, the
///   child's share must be `<=` the parent's. A parent that holds, say, 30%
///   (3000 bps) of the root budget cannot mint a child holding 50% (5000 bps):
///   the child's effective authority would exceed the parent's.
/// * When the parent carries no `budget_share_bps`, it holds the full granted
///   budget (an implicit 100% / 10000 bps), so any child share within the
///   absolute ceiling is a valid narrowing.
///
/// Returns an [`Error::AttenuationViolation`] when the child would widen the
/// parent's share.
pub(crate) fn validate_parent_relative_budget_share_bps(
    parent_share_bps: Option<u16>,
    child_share_bps: u16,
) -> Result<()> {
    // The absolute ceiling is a prerequisite for any share.
    validate_budget_share_bps(child_share_bps)?;

    // A parent with no explicit share holds the full granted budget (100%).
    let parent_share_bps = parent_share_bps.unwrap_or(MAX_BUDGET_SHARE_BPS);

    if child_share_bps > parent_share_bps {
        return Err(Error::AttenuationViolation {
            reason: format!(
                "child budget_share_bps {child_share_bps} exceeds parent budget_share_bps {parent_share_bps}; \
                 a delegated share cannot widen the parent's remaining budget"
            ),
        });
    }
    Ok(())
}
