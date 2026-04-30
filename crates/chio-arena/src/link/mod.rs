//! In-process arena transport between kernel endpoints.

mod multiplex;
mod transport;

pub use multiplex::{KernelMultiplexer, MultiplexError};
pub use transport::{KernelEndpoint, KernelLink, LinkEnvelope, LinkError};
