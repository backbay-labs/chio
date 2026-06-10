use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};

use crate::{
    signer::{EpochRootSigner, EpochRootVerifier},
    EpochRoot, Result, RevocationOracleError, RootSignature,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEpochRoot {
    pub root: EpochRoot,
    pub signature: RootSignature,
}

impl SignedEpochRoot {
    /// Sign `root` with the oracle's [`EpochRootSigner`], pairing the resulting
    /// [`RootSignature`] with the root.
    pub fn sign(root: EpochRoot, signer: &impl EpochRootSigner) -> Result<Self> {
        let signature = signer.sign_epoch_root(&root)?;
        Ok(Self { root, signature })
    }

    /// Verify the carried signature against a pinned [`EpochRootVerifier`].
    ///
    /// This is the trust-anchor check a federation receiver runs before merging
    /// the carried [`EpochRoot`]. The verifier holds only the signer's public
    /// key, so a successful verification never implies the ability to forge the
    /// root. Any mismatch or decode failure denies fail-closed.
    pub fn verify(&self, verifier: &impl EpochRootVerifier) -> Result<()> {
        verifier.verify_epoch_root(&self.root, &self.signature)
    }
}

/// Default oracle epoch tick used by the bilateral push path. Two hundred
/// and fifty milliseconds is the trade-off between gossip storm avoidance
/// under high revoke rates and the 500ms median end-to-end latency budget.
pub const DEFAULT_EPOCH_TICK_MS: u64 = 250;

/// Sink for signed epoch roots produced by an oracle on every epoch tick.
///
/// Implementations push the carried [`SignedEpochRoot`] down whatever
/// transport the federation layer owns (in tests, an in-memory queue; in
/// production, a bilateral RPC channel). Failures are reported back to the
/// oracle so the tick driver can decide whether to retry, drop, or escalate.
pub trait EpochBroadcaster {
    fn publish(&self, root: SignedEpochRoot) -> Result<()>;
}

/// Bounded in-memory broadcaster used by the oracle's default tick driver
/// when no real transport is plugged in. The queue is FIFO and drops the
/// oldest entry when full, which matches the bilateral push contract: the
/// gossip layer is best-effort and the catch-up path covers any peer that
/// fell behind.
#[derive(Debug)]
pub struct InMemoryEpochBroadcaster {
    capacity: usize,
    queue: Mutex<VecDeque<SignedEpochRoot>>,
}

impl InMemoryEpochBroadcaster {
    /// Create a new broadcaster with the supplied bounded capacity.
    ///
    /// A `capacity` of zero is rejected fail-closed so callers cannot
    /// accidentally configure a sink that silently drops every root.
    pub fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 {
            return Err(RevocationOracleError::SignerRejected);
        }
        Ok(Self {
            capacity,
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
        })
    }

    /// Drain every queued signed root in FIFO order. Used by the federation
    /// side's push tick to assemble a batched gossip frame.
    pub fn drain(&self) -> Result<Vec<SignedEpochRoot>> {
        let mut guard = self
            .queue
            .lock()
            .map_err(|err: PoisonError<_>| RevocationOracleError::Serialization(err.to_string()))?;
        Ok(guard.drain(..).collect())
    }

    /// Number of signed roots currently queued. Primarily a test affordance.
    pub fn pending(&self) -> Result<usize> {
        let guard = self
            .queue
            .lock()
            .map_err(|err: PoisonError<_>| RevocationOracleError::Serialization(err.to_string()))?;
        Ok(guard.len())
    }
}

impl EpochBroadcaster for InMemoryEpochBroadcaster {
    fn publish(&self, root: SignedEpochRoot) -> Result<()> {
        let mut guard = self
            .queue
            .lock()
            .map_err(|err: PoisonError<_>| RevocationOracleError::Serialization(err.to_string()))?;
        if guard.len() == self.capacity {
            // Drop oldest to make room. Catch-up path covers slow peers.
            guard.pop_front();
        }
        guard.push_back(root);
        Ok(())
    }
}

/// Drives the oracle's epoch tick. Each call signs the oracle's current
/// [`EpochRoot`] and publishes it via every registered broadcaster. The tick
/// is fail-closed at the broadcaster boundary: if a broadcaster rejects the
/// root, the tick returns the first error so the kernel can escalate.
pub fn tick_and_broadcast<S>(
    root: EpochRoot,
    signer: &S,
    broadcasters: &[&dyn EpochBroadcaster],
) -> Result<SignedEpochRoot>
where
    S: EpochRootSigner,
{
    let signed = SignedEpochRoot::sign(root, signer)?;
    for broadcaster in broadcasters {
        broadcaster.publish(signed.clone())?;
    }
    Ok(signed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{Ed25519RootSigner, EpochRoot};

    const SIGNER_SEED: &str = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";

    fn signer(signer_id: &str) -> Ed25519RootSigner {
        Ed25519RootSigner::from_signing_key(signer_id, SIGNER_SEED)
            .expect("fixed seed is valid Ed25519 material")
    }

    fn epoch_root(epoch: u64) -> EpochRoot {
        EpochRoot {
            epoch,
            root_hash: [(epoch as u8); 32],
            leaf_count: epoch as usize,
            issued_at_unix_ms: 1_700_000_000_000 + epoch,
        }
    }

    #[test]
    fn in_memory_broadcaster_zero_capacity_rejected() {
        let err = InMemoryEpochBroadcaster::new(0).expect_err("zero capacity must fail closed");
        assert_eq!(err, RevocationOracleError::SignerRejected);
    }

    #[test]
    fn in_memory_broadcaster_drains_in_fifo_order() {
        let broadcaster = InMemoryEpochBroadcaster::new(4).unwrap();
        let signer = signer("oracle-a");
        for epoch in 1..=3 {
            broadcaster
                .publish(SignedEpochRoot::sign(epoch_root(epoch), &signer).unwrap())
                .unwrap();
        }
        assert_eq!(broadcaster.pending().unwrap(), 3);
        let drained = broadcaster.drain().unwrap();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].root.epoch, 1);
        assert_eq!(drained[2].root.epoch, 3);
        assert_eq!(broadcaster.pending().unwrap(), 0);
    }

    #[test]
    fn in_memory_broadcaster_drops_oldest_when_full() {
        let broadcaster = InMemoryEpochBroadcaster::new(2).unwrap();
        let signer = signer("oracle-a");
        for epoch in 1..=4 {
            broadcaster
                .publish(SignedEpochRoot::sign(epoch_root(epoch), &signer).unwrap())
                .unwrap();
        }
        let drained = broadcaster.drain().unwrap();
        assert_eq!(drained.len(), 2);
        // Oldest entries (1, 2) dropped; 3 and 4 retained.
        assert_eq!(drained[0].root.epoch, 3);
        assert_eq!(drained[1].root.epoch, 4);
    }

    #[test]
    fn tick_and_broadcast_publishes_to_every_subscriber() {
        let broadcaster_a = InMemoryEpochBroadcaster::new(8).unwrap();
        let broadcaster_b = InMemoryEpochBroadcaster::new(8).unwrap();
        let signer = signer("oracle-a");
        let signed =
            tick_and_broadcast(epoch_root(7), &signer, &[&broadcaster_a, &broadcaster_b]).unwrap();
        assert_eq!(signed.root.epoch, 7);
        assert_eq!(broadcaster_a.pending().unwrap(), 1);
        assert_eq!(broadcaster_b.pending().unwrap(), 1);
        let drained_a = broadcaster_a.drain().unwrap();
        let drained_b = broadcaster_b.drain().unwrap();
        assert_eq!(drained_a, drained_b);
        assert_eq!(drained_a[0], signed);
    }

    #[test]
    fn tick_and_broadcast_propagates_signer_failure_fail_closed() {
        struct AlwaysFail;
        impl EpochBroadcaster for AlwaysFail {
            fn publish(&self, _root: SignedEpochRoot) -> Result<()> {
                Err(RevocationOracleError::SignerRejected)
            }
        }
        let signer = signer("oracle-a");
        let result = tick_and_broadcast(epoch_root(1), &signer, &[&AlwaysFail]);
        assert_eq!(result, Err(RevocationOracleError::SignerRejected));
    }

    #[test]
    fn default_epoch_tick_is_250ms() {
        assert_eq!(DEFAULT_EPOCH_TICK_MS, 250);
    }
}
