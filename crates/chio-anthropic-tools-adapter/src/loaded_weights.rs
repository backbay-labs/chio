use chio_core::LoadedWeightsUnavailable;
use chio_provider_adapter_core::impl_unavailable_loaded_weights;

use crate::AnthropicAdapter;

const PROVIDER_NAME: &str = "anthropic";
const UNAVAILABLE_REASON: &str =
    "Anthropic Messages API does not expose runtime loaded model bytes";

pub fn loaded_weights_unavailable() -> LoadedWeightsUnavailable {
    chio_provider_adapter_core::loaded_weights_unavailable(PROVIDER_NAME, UNAVAILABLE_REASON)
}

impl_unavailable_loaded_weights!(AnthropicAdapter, PROVIDER_NAME, UNAVAILABLE_REASON);
