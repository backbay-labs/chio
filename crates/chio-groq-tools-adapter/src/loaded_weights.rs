use std::borrow::Cow;

use chio_core::{LoadedWeights, LoadedWeightsUnavailable};

use crate::GroqAdapter;

const PROVIDER_NAME: &str = "groq";
const UNAVAILABLE_REASON: &str =
    "Groq chat/completions API does not expose runtime loaded model bytes";

pub fn loaded_weights_unavailable() -> LoadedWeightsUnavailable {
    LoadedWeightsUnavailable::new(PROVIDER_NAME, UNAVAILABLE_REASON)
}

impl LoadedWeights for GroqAdapter {
    fn provider_name(&self) -> &'static str {
        PROVIDER_NAME
    }

    fn loaded_weights_bytes(&self) -> Result<Cow<'_, [u8]>, LoadedWeightsUnavailable> {
        Err(loaded_weights_unavailable())
    }
}
