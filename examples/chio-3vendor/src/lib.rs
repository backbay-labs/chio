//! Example-facing fixture command library for the Chio three-vendor corpus.

mod commands;

pub use chio_attest_loopback::*;
pub use commands::{run_from_env, run_with_args};
