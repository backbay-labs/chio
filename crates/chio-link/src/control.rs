use chio_core::web3::settlement::{CHIO_LINK_CONTROL_STATE_SCHEMA, CHIO_LINK_CONTROL_TRACE_SCHEMA};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::{OperatorConfig, PairRuntimeOverride};
use crate::PriceOracleError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChioLinkControlChangeKind {
    GlobalPause,
    ChainEnabled,
    PairOverride,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioLinkControlChangeRecord {
    pub schema: String,
    pub kind: ChioLinkControlChangeKind,
    pub actor: String,
    pub source: String,
    pub changed_at: u64,
    pub note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair: Option<String>,
    pub before: Value,
    pub after: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioLinkControlState {
    pub schema: String,
    pub updated_at: u64,
    pub operator: OperatorConfig,
    pub history: Vec<ChioLinkControlChangeRecord>,
}

impl ChioLinkControlState {
    #[must_use]
    pub fn new(updated_at: u64, operator: OperatorConfig) -> Self {
        Self {
            schema: CHIO_LINK_CONTROL_STATE_SCHEMA.to_string(),
            updated_at,
            operator,
            history: Vec::new(),
        }
    }

    pub fn record_global_pause(
        &mut self,
        paused: bool,
        reason: Option<String>,
        actor: impl Into<String>,
        source: impl Into<String>,
        changed_at: u64,
        note: impl Into<String>,
    ) {
        let before = json!({
            "globalPause": self.operator.global_pause,
            "pauseReason": self.operator.pause_reason
        });
        self.operator.global_pause = paused;
        self.operator.pause_reason = reason;
        let after = json!({
            "globalPause": self.operator.global_pause,
            "pauseReason": self.operator.pause_reason
        });
        self.updated_at = changed_at;
        self.history.push(ChioLinkControlChangeRecord {
            schema: CHIO_LINK_CONTROL_TRACE_SCHEMA.to_string(),
            kind: ChioLinkControlChangeKind::GlobalPause,
            actor: actor.into(),
            source: source.into(),
            changed_at,
            note: note.into(),
            chain_id: None,
            pair: None,
            before,
            after,
        });
    }

    pub fn record_chain_enabled(
        &mut self,
        chain_id: u64,
        enabled: bool,
        actor: impl Into<String>,
        source: impl Into<String>,
        changed_at: u64,
        note: impl Into<String>,
    ) -> Result<(), PriceOracleError> {
        let index = self
            .operator
            .chains
            .iter()
            .position(|chain| chain.chain_id == chain_id)
            .ok_or_else(|| {
                PriceOracleError::InvalidConfiguration(format!(
                    "cannot persist unknown operator chain_id {}",
                    chain_id
                ))
            })?;
        let before = serde_json::to_value(&self.operator.chains[index]).map_err(|error| {
            PriceOracleError::InvalidConfiguration(format!(
                "failed to serialize prior chain state for {}: {error}",
                chain_id
            ))
        })?;
        self.operator.chains[index].enabled = enabled;
        let after = serde_json::to_value(&self.operator.chains[index]).map_err(|error| {
            PriceOracleError::InvalidConfiguration(format!(
                "failed to serialize updated chain state for {}: {error}",
                chain_id
            ))
        })?;
        self.updated_at = changed_at;
        self.history.push(ChioLinkControlChangeRecord {
            schema: CHIO_LINK_CONTROL_TRACE_SCHEMA.to_string(),
            kind: ChioLinkControlChangeKind::ChainEnabled,
            actor: actor.into(),
            source: source.into(),
            changed_at,
            note: note.into(),
            chain_id: Some(chain_id),
            pair: None,
            before,
            after,
        });
        Ok(())
    }

    pub fn record_pair_override(
        &mut self,
        pair_override: PairRuntimeOverride,
        actor: impl Into<String>,
        source: impl Into<String>,
        changed_at: u64,
        note: impl Into<String>,
    ) -> Result<(), PriceOracleError> {
        let pair = pair_override.pair();
        let existing_index = self
            .operator
            .pair_overrides
            .iter()
            .position(|current| current.pair() == pair);
        let before =
            serde_json::to_value(existing_index.map(|index| &self.operator.pair_overrides[index]))
                .map_err(|error| {
                    PriceOracleError::InvalidConfiguration(format!(
                        "failed to serialize prior pair override for {pair}: {error}"
                    ))
                })?;
        if let Some(index) = existing_index {
            self.operator.pair_overrides[index] = pair_override;
        } else {
            self.operator.pair_overrides.push(pair_override);
        }
        let after = serde_json::to_value(
            self.operator
                .pair_overrides
                .iter()
                .find(|current| current.pair() == pair),
        )
        .map_err(|error| {
            PriceOracleError::InvalidConfiguration(format!(
                "failed to serialize updated pair override for {pair}: {error}"
            ))
        })?;
        self.updated_at = changed_at;
        self.history.push(ChioLinkControlChangeRecord {
            schema: CHIO_LINK_CONTROL_TRACE_SCHEMA.to_string(),
            kind: ChioLinkControlChangeKind::PairOverride,
            actor: actor.into(),
            source: source.into(),
            changed_at,
            note: note.into(),
            chain_id: None,
            pair: Some(pair),
            before,
            after,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ChioLinkControlState;
    use crate::config::{PairRuntimeOverride, PriceOracleConfig};
    use crate::test_support::TestUnwrap;

    #[test]
    fn control_state_tracks_pause_chain_and_pair_changes() {
        let mut config = PriceOracleConfig::base_mainnet_default("https://example.invalid");
        for chain in &mut config.operator.chains {
            chain.sequencer_uptime_feed = None;
        }

        let btc_pair = config
            .pairs
            .iter()
            .find(|pair| pair.base == "BTC" && pair.quote == "USD")
            .test_unwrap("btc/usd pair")
            .clone();
        let mut state = ChioLinkControlState::new(1_764_825_600, config.operator);
        state.record_global_pause(
            true,
            Some("manual stop".to_string()),
            "test-operator",
            "unit_test",
            1_764_825_610,
            "pause all conversions",
        );
        state
            .record_chain_enabled(
                42_161,
                false,
                "test-operator",
                "unit_test",
                1_764_825_620,
                "leave standby chain disabled",
            )
            .test_unwrap("chain update");
        state
            .record_pair_override(
                PairRuntimeOverride {
                    enabled: false,
                    ..PairRuntimeOverride::from_pair(&btc_pair)
                },
                "test-operator",
                "unit_test",
                1_764_825_630,
                "disable pair",
            )
            .test_unwrap("pair override");
        assert_eq!(state.history.len(), 3);
        assert!(state.operator.global_pause);
        assert!(
            state
                .operator
                .pair_overrides
                .iter()
                .any(|override_config| override_config.pair() == "BTC/USD"
                    && !override_config.enabled)
        );
    }
}
