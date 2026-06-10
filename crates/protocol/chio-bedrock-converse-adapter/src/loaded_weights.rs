use chio_core::LoadedWeightsUnavailable;
use chio_provider_adapter_core::impl_unavailable_loaded_weights;

use crate::BedrockAdapter;

const PROVIDER_NAME: &str = "bedrock";
const UNAVAILABLE_REASON: &str =
    "Amazon Bedrock Converse does not expose runtime loaded model bytes";

pub fn loaded_weights_unavailable() -> LoadedWeightsUnavailable {
    chio_provider_adapter_core::loaded_weights_unavailable(PROVIDER_NAME, UNAVAILABLE_REASON)
}

impl_unavailable_loaded_weights!(BedrockAdapter, PROVIDER_NAME, UNAVAILABLE_REASON);
