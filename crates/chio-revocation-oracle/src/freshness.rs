use crate::{EpochRoot, Result, RevocationOracleError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessConfig {
    pub max_staleness_ms: u64,
    pub offline_grace_ms: u64,
}

impl Default for FreshnessConfig {
    fn default() -> Self {
        Self::fail_closed()
    }
}

impl FreshnessConfig {
    #[must_use]
    pub fn fail_closed() -> Self {
        Self {
            max_staleness_ms: 0,
            offline_grace_ms: 0,
        }
    }

    #[must_use]
    pub fn with_offline_grace(max_staleness_ms: u64, offline_grace_ms: u64) -> Self {
        Self {
            max_staleness_ms,
            offline_grace_ms,
        }
    }

    #[must_use]
    fn allowed_age_ms(self) -> u64 {
        self.max_staleness_ms.saturating_add(self.offline_grace_ms)
    }
}

pub fn verify_fresh_epoch_root(
    root: &EpochRoot,
    now_unix_ms: u64,
    config: FreshnessConfig,
) -> Result<()> {
    if now_unix_ms < root.issued_at_unix_ms {
        return Err(RevocationOracleError::InvalidEpochTransition);
    }

    let age = now_unix_ms.saturating_sub(root.issued_at_unix_ms);
    if age <= config.allowed_age_ms() {
        Ok(())
    } else {
        Err(RevocationOracleError::StaleRoot)
    }
}
