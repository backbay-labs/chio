use chio_provider_adapter_core::impl_unavailable_loaded_weights;

use crate::AnthropicAdapter;

const PROVIDER_NAME: &str = "anthropic";
const UNAVAILABLE_REASON: &str =
    "Anthropic Messages API does not expose runtime loaded model bytes";

impl_unavailable_loaded_weights!(AnthropicAdapter, PROVIDER_NAME, UNAVAILABLE_REASON);
