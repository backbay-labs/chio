//! In-process arena transport between kernel endpoints.

mod transport;

pub use transport::{KernelEndpoint, KernelLink, LinkEnvelope, LinkError};
