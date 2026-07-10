use chio_provider_adapter_core::impl_unavailable_loaded_weights;

use crate::CohereAdapter;

const PROVIDER_NAME: &str = "cohere";
const UNAVAILABLE_REASON: &str = "Cohere Chat API does not expose runtime loaded model bytes";

impl_unavailable_loaded_weights!(CohereAdapter, PROVIDER_NAME, UNAVAILABLE_REASON);
