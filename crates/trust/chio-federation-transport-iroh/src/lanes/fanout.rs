//! Lane c: cross-operator fan-out over iroh-gossip per-treaty topics.
//! ADAPTER-SPEC section 4 row (c) + 4.1. TopicId = blake3("chio-<lane>/v1\x00" ||
//! treaty_id). Payloads MUST be self-signed and origin-verified from the payload
//! alone (gossip `delivered_from` is the forwarding NEIGHBOR, not the author).
//!
// TODO(phase 2, lane c): implement.

/// Reserved for lane c. Present so the module tree compiles while the lane team builds.
pub fn reserved() {}
