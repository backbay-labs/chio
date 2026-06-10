use chio_egress_contract::HttpEgressContract;

use crate::config::ChainlinkNetworkConfig;
use crate::PriceOracleError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequencerAvailability {
    Up,
    Down,
    Recovering,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencerStatus {
    pub chain_id: u64,
    pub feed_address: String,
    pub checked_at: u64,
    pub status_started_at: u64,
    pub availability: SequencerAvailability,
}

pub async fn read_sequencer_status(
    chain: &ChainlinkNetworkConfig,
    _now: u64,
    _egress_contract: &HttpEgressContract,
) -> Result<Option<SequencerStatus>, PriceOracleError> {
    if chain.sequencer_uptime_feed.is_some() {
        return Err(PriceOracleError::UnsupportedBackend(
            "sequencer monitoring requires the `web3` feature".to_string(),
        ));
    }
    Ok(None)
}
