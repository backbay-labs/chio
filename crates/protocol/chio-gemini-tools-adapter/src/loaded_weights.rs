use chio_provider_adapter_core::impl_unavailable_loaded_weights;

use crate::GeminiAdapter;

const PROVIDER_NAME: &str = "gemini";
const UNAVAILABLE_REASON: &str =
    "Gemini generateContent API does not expose runtime loaded model bytes";

impl_unavailable_loaded_weights!(GeminiAdapter, PROVIDER_NAME, UNAVAILABLE_REASON);
