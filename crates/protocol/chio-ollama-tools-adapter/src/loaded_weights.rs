use std::borrow::Cow;

use chio_core::{loaded_weights_hash_of, LoadedWeights, LoadedWeightsUnavailable};
use chio_provider_adapter_core::impl_unavailable_loaded_weights;

use crate::OllamaAdapter;

const PROVIDER_NAME: &str = "ollama";
const ADAPTER_UNAVAILABLE_REASON: &str =
    "Ollama adapter handle does not own the local loaded model bytes";

impl_unavailable_loaded_weights!(OllamaAdapter, PROVIDER_NAME, ADAPTER_UNAVAILABLE_REASON);

#[derive(Debug, Clone)]
pub struct OllamaLoadedWeights<'a> {
    model: &'a str,
    bytes: Cow<'a, [u8]>,
}

impl<'a> OllamaLoadedWeights<'a> {
    pub fn borrowed(model: &'a str, bytes: &'a [u8]) -> Self {
        Self {
            model,
            bytes: Cow::Borrowed(bytes),
        }
    }

    pub fn owned(model: &'a str, bytes: Vec<u8>) -> Self {
        Self {
            model,
            bytes: Cow::Owned(bytes),
        }
    }

    pub fn model(&self) -> &str {
        self.model
    }
}

impl LoadedWeights for OllamaLoadedWeights<'_> {
    fn provider_name(&self) -> &'static str {
        PROVIDER_NAME
    }

    fn loaded_weights_bytes(&self) -> Result<Cow<'_, [u8]>, LoadedWeightsUnavailable> {
        Ok(Cow::Borrowed(self.bytes.as_ref()))
    }
}

pub fn loaded_weights_hash_from_bytes(bytes: &[u8]) -> String {
    loaded_weights_hash_of(bytes)
}
