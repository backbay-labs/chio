use chio_provider_adapter_core::impl_unavailable_loaded_weights;

use crate::BedrockAdapter;

const PROVIDER_NAME: &str = "bedrock";
const UNAVAILABLE_REASON: &str =
    "Amazon Bedrock Converse does not expose runtime loaded model bytes";

impl_unavailable_loaded_weights!(BedrockAdapter, PROVIDER_NAME, UNAVAILABLE_REASON);
