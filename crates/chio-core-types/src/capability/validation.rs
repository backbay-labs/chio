use alloc::format;

use crate::error::{Error, Result};

pub(crate) fn validate_budget_share_bps(share: u16) -> Result<()> {
    if share > 10_000 {
        return Err(Error::AttenuationViolation {
            reason: format!("budget_share_bps {share} exceeds the 10000 bps parent budget ceiling"),
        });
    }
    Ok(())
}
