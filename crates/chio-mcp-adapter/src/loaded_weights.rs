use std::borrow::Cow;

use chio_core::{LoadedWeights, LoadedWeightsUnavailable};

use crate::McpAdapter;

const PROVIDER_NAME: &str = "mcp";
const UNAVAILABLE_REASON: &str = "MCP protocol bridge does not expose native loaded model bytes";

pub fn loaded_weights_unavailable() -> LoadedWeightsUnavailable {
    LoadedWeightsUnavailable::new(PROVIDER_NAME, UNAVAILABLE_REASON)
}

impl LoadedWeights for McpAdapter {
    fn provider_name(&self) -> &'static str {
        PROVIDER_NAME
    }

    fn loaded_weights_bytes(&self) -> Result<Cow<'_, [u8]>, LoadedWeightsUnavailable> {
        Err(loaded_weights_unavailable())
    }
}
