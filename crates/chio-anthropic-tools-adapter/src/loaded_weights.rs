use std::borrow::Cow;

use chio_core::{LoadedWeights, LoadedWeightsUnavailable};

use crate::AnthropicAdapter;

const PROVIDER_NAME: &str = "anthropic";
const UNAVAILABLE_REASON: &str =
    "Anthropic Messages API does not expose runtime loaded model bytes";

pub fn loaded_weights_unavailable() -> LoadedWeightsUnavailable {
    LoadedWeightsUnavailable::new(PROVIDER_NAME, UNAVAILABLE_REASON)
}

impl LoadedWeights for AnthropicAdapter {
    fn provider_name(&self) -> &'static str {
        PROVIDER_NAME
    }

    fn loaded_weights_bytes(&self) -> Result<Cow<'_, [u8]>, LoadedWeightsUnavailable> {
        Err(loaded_weights_unavailable())
    }
}
