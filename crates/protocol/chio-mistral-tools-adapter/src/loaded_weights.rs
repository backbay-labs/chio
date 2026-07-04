use chio_provider_adapter_core::impl_unavailable_loaded_weights;

use crate::MistralAdapter;

const PROVIDER_NAME: &str = "mistral";
const UNAVAILABLE_REASON: &str =
    "Mistral chat/completions API does not expose runtime loaded model bytes";

impl_unavailable_loaded_weights!(MistralAdapter, PROVIDER_NAME, UNAVAILABLE_REASON);
