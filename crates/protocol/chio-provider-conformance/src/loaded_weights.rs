//! Provider-conformance re-export for loaded-weight digest contracts.
//!
//! The canonical trait lives in `chio-core-types` so adapters can implement it
//! without depending back on this replay harness.

pub use chio_core::{
    loaded_weights_hash_of, loaded_weights_hash_of_chunks, LoadedWeights, LoadedWeightsUnavailable,
};
