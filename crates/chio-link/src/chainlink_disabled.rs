use chio_egress_contract::HttpEgressContract;

use crate::config::{ChainlinkNetworkConfig, PairConfig};
use crate::{OracleBackend, OracleBackendKind, OracleFuture, PriceOracleError};

pub struct ChainlinkFeedReader {
    _networks: Vec<ChainlinkNetworkConfig>,
    _egress_contract: HttpEgressContract,
}

impl ChainlinkFeedReader {
    #[must_use]
    pub fn new(networks: Vec<ChainlinkNetworkConfig>, egress_contract: HttpEgressContract) -> Self {
        Self {
            _networks: networks,
            _egress_contract: egress_contract,
        }
    }
}

impl OracleBackend for ChainlinkFeedReader {
    fn kind(&self) -> OracleBackendKind {
        OracleBackendKind::Chainlink
    }

    fn read_rate<'a>(&'a self, _pair: &'a PairConfig, _now: u64) -> OracleFuture<'a> {
        Box::pin(async {
            Err(PriceOracleError::UnsupportedBackend(
                "Chainlink backend requires the `web3` feature".to_string(),
            ))
        })
    }
}
