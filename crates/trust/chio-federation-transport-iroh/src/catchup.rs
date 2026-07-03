//! Content-addressed anti-entropy catch-up (ADAPTER-SPEC section 3.4 + lane e).
//!
// TODO(phase 2): back `RevocationCatchupHistory` with iroh-blobs content-addressed
// fetch, gated behind the `admission` `EndpointHooks` gate so only an admitted,
// directory-bound, non-removed follower can pull catch-up roots. Each blob is a
// `SignedEpochRoot` verified against the pinned signer with strict monotone epoch
// ordering (`CatchupGap` on holes) on a durable `FsStore`. Not built in the
// foundation phase; this stub only keeps the crate module tree complete.

/// Reserved for the catch-up phase. Present so the module tree is stable for the
/// lanes-phase build to grow against; performs no transfer work yet.
pub fn reserved() {}
