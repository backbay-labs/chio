//! Graceful shutdown, connection drain, and server hygiene for Chio HTTP
//! services.
//!
//! Every Chio process that binds an `axum::serve` listener shares the same three
//! obligations when the platform stops it (SIGTERM on a deploy, scale event, or
//! node rotation):
//!
//! 1. Notice the stop signal instead of dying on the runtime default action.
//! 2. Stop accepting, let in-flight requests finish, then exit, all inside a
//!    bounded window so a stuck request cannot hold the process open forever.
//! 3. Refuse abusive load (oversized bodies, slow requests, connection floods)
//!    with an explicit denial rather than unbounded resource growth.
//!
//! This crate centralizes those obligations so the serve sites converge on one
//! implementation instead of drifting apart:
//!
//! - [`ShutdownController`] installs a single signal handler and fans the result
//!   out over a [`tokio::sync::watch`] channel that the serve loop and every
//!   cooperating background task observe.
//! - [`apply_server_hygiene`] wraps a [`Router`](axum::Router) with a request
//!   timeout, a global concurrency limit fronted by load shedding, and an
//!   optional body-size cap.
//! - [`MaxConnListener`] caps the number of simultaneously accepted connections
//!   with back-pressure at the accept loop.
//! - [`run_until_drained`] runs the serve future, bounds only the post-signal
//!   drain (never the healthy uptime), and then runs a flush hook so a store
//!   with a queued write is either made durable or surfaced as a loud error.
//!
//! The posture is fail-closed throughout. A signal handler that cannot be
//! installed logs and degrades to the platform default rather than crash-looping
//! at startup, and each hygiene limit denies (413 / 408 / 503) rather than
//! accepting work it cannot bound.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod drain;
mod hygiene;
mod listener;
mod signal;

pub use drain::{run_until_drained, DrainOutcome, ServeError};
pub use hygiene::{
    apply_server_hygiene, ServeHygieneConfig, DEFAULT_DRAIN_TIMEOUT,
    DEFAULT_MAX_CONCURRENT_REQUESTS, DEFAULT_MAX_CONNECTIONS, DEFAULT_REQUEST_TIMEOUT,
};
pub use listener::{CappedPeerAddr, MaxConnListener, PermittedIo};
pub use signal::{shutdown_signal, ShutdownController};

#[cfg(test)]
mod tests;
