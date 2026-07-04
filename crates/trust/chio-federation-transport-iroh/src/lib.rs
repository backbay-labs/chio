//! Iroh federation-transport adapter.
//!
//! This crate sits strictly underneath `chio-federation` as a transport and
//! replaces no trust logic (ADR-0014, ADAPTER-SPEC section 1). iroh
//! authenticates the peer key (a completed QUIC/TLS handshake proves the remote
//! holds the private key for a given `EndpointId`); Chio authorizes above it.
//!
//! Seam:
//! - [`identity`]: the issuer-signed directory + `EndpointId -> kernel_id`
//!   binding, verified at load time with the fail-closed checks (incl. the
//!   Option-B passport-over-transport endorsement).
//! - [`admission`]: the accept-time `EndpointHooks` gate over a load-time
//!   verified directory, rejecting any `EndpointId` not bound to an admitted,
//!   non-removed `kernel_id` before any handler runs.
//!
//! Lanes (each on a distinct ALPN, all sharing the gate; ADAPTER-SPEC 3.3/3.4/4):
//! - [`lanes::pheromone`]: directed batches over a direct per-peer QUIC stream
//!   (the one-hop seam swap onto the unchanged per-frame verifier).
//! - [`lanes::revocation`] + [`catchup`]: signed epoch roots over direct QUIC
//!   plus iroh-blobs content-addressed catch-up.
//! - [`lanes::fanout`]: cross-operator fan-out over iroh-gossip per-treaty topics.
//! - [`lanes::bilateral`]: DSSE co-sign over a bidirectional QUIC RPC.

pub mod admission;
pub mod catchup;
pub mod identity;
pub mod lanes;
pub mod metrics;
pub mod observability;
