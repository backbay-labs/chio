//! Per-lane transports (ADAPTER-SPEC section 3.3 + 4).
//!
// TODO(phase 2): implement the per-lane transports on a `Router` keyed by a
// distinct ALPN per surface: pheromone directed batches and revocation epoch
// roots over direct per-peer QUIC streams (lanes a/b), cross-operator fan-out
// over iroh-gossip per-treaty topics (lane c), and bilateral DSSE co-sign over a
// dedicated-ALPN bidirectional QUIC RPC (lane d). Not built in the foundation
// phase; this stub only keeps the crate module tree complete.

/// Reserved for the lanes phase. Present so the module tree is stable for the
/// lanes-phase build to grow against; performs no transport work yet.
pub fn reserved() {}
