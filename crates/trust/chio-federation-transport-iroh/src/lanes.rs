//! Per-lane transports (ADAPTER-SPEC section 3.3 + 4).
//!
//! Each lane mounts on a `Router` keyed by a distinct ALPN and builds on the
//! `admission::DirectoryGate` seam: the accept-time gate resolves the peer
//! `EndpointId` to a `kernel_id`, which each lane uses as the
//! `authenticated_sender_kernel_id` fed to the per-frame `chio-federation`
//! verifier (which stays ABOVE the transport, unchanged).
//!
//! - `pheromone`: directed per-recipient batches over a direct per-peer QUIC stream (lane a).
//! - `revocation`: revocation epoch roots over a direct per-peer QUIC stream (lane b).
//! - `fanout`: cross-operator fan-out over iroh-gossip per-treaty topics (lane c).
//! - `bilateral`: DSSE co-sign over a dedicated-ALPN bidirectional QUIC RPC (lane d).

pub mod bilateral;
pub mod fanout;
pub mod limits;
pub mod pheromone;
pub mod revocation;

/// Nightly loom concurrency models. Cfg-gated behind `chio_iroh_transport_loom`,
/// so off by default.
#[cfg(all(test, chio_iroh_transport_loom))]
mod limits_loom;
