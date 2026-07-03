//! Iroh federation-transport adapter (foundation phase).
//!
//! This crate sits strictly underneath `chio-federation` as a transport and
//! replaces no trust logic (ADR-0014, ADAPTER-SPEC section 1). iroh
//! authenticates the peer key (a completed QUIC/TLS handshake proves the remote
//! holds the private key for a given `EndpointId`); Chio authorizes above it.
//!
//! Foundation scope implements two modules:
//! - [`identity`]: the issuer-signed directory + `EndpointId -> kernel_id`
//!   binding, verified at load time with the five fail-closed checks.
//! - [`admission`]: the accept-time `EndpointHooks` gate over a load-time
//!   verified directory, rejecting any `EndpointId` not bound to an admitted,
//!   non-removed `kernel_id`.
//!
//! The [`lanes`] and [`catchup`] modules are stubs reserved for the lanes phase
//! (ADAPTER-SPEC sections 3.3, 3.4, and 4).

pub mod admission;
pub mod catchup;
pub mod identity;
pub mod lanes;
