//! Seeded RNG plumbing for the arena.
//!
//! All randomness consumed by the arena (and the adversary populations)
//! is keyed by the scenario's `rng_seed`. The root
//! [`ChaCha20Rng`] is seeded from the scenario value; per-agent sub-streams are
//! derived through `SeedableRng::seed_from_u64` over a stable hash of the
//! agent id so two runs of the same scenario observe the same byte sequence.
//!
//! `rand_chacha::ChaCha20Rng` is platform-independent and seedable from a
//! single 256-bit seed; it is the standard cross-platform deterministic RNG in
//! the Rust ecosystem and matches the determinism gate's reproducibility
//! contract.

use std::collections::BTreeMap;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use thiserror::Error;

/// Deterministic arena RNG.
///
/// Holds the scenario root stream plus per-agent sub-streams. The struct is
/// cloneable so adversary populations can fork independent views without
/// disturbing the canonical agent streams.
#[derive(Debug, Clone)]
pub struct ArenaRng {
    seed: u64,
    root: ChaCha20Rng,
    agent_streams: BTreeMap<String, ChaCha20Rng>,
}

impl ArenaRng {
    /// Build the root RNG from the scenario seed.
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            root: ChaCha20Rng::seed_from_u64(seed),
            agent_streams: BTreeMap::new(),
        }
    }

    /// Returns the scenario seed used to bootstrap the RNG.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Mutable access to the scenario root stream. Used by the scheduler to
    /// resolve tiebreaks deterministically.
    pub fn root_mut(&mut self) -> &mut ChaCha20Rng {
        &mut self.root
    }

    /// Register every agent in `agent_ids`, deriving an independent
    /// sub-stream per id.
    pub fn register_agents<'a, I>(&mut self, agent_ids: I) -> Result<(), RngError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        for id in agent_ids {
            self.register_agent(id)?;
        }
        Ok(())
    }

    /// Register a single agent. Returns an error if the id collides with an
    /// existing sub-stream.
    pub fn register_agent(&mut self, agent_id: &str) -> Result<(), RngError> {
        if self.agent_streams.contains_key(agent_id) {
            return Err(RngError::DuplicateAgent(agent_id.to_string()));
        }
        let sub_seed = derive_agent_seed(self.seed, agent_id);
        self.agent_streams
            .insert(agent_id.to_string(), ChaCha20Rng::seed_from_u64(sub_seed));
        Ok(())
    }

    /// Returns a mutable reference to the per-agent sub-stream.
    pub fn agent_stream_mut(&mut self, agent_id: &str) -> Result<&mut ChaCha20Rng, RngError> {
        self.agent_streams
            .get_mut(agent_id)
            .ok_or_else(|| RngError::UnknownAgent(agent_id.to_string()))
    }

    /// Snapshot the current 64-bit values of every registered sub-stream
    /// without disturbing them. Used by determinism tests.
    pub fn snapshot_next_u64s(&mut self) -> BTreeMap<String, u64> {
        let mut snapshot = BTreeMap::new();
        for (agent_id, stream) in self.agent_streams.iter_mut() {
            snapshot.insert(agent_id.clone(), stream.next_u64());
        }
        snapshot
    }
}

/// Errors raised by [`ArenaRng`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RngError {
    /// Duplicate agent registration.
    #[error("agent {0} already registered with the arena RNG")]
    DuplicateAgent(String),
    /// Unknown agent.
    #[error("agent {0} has no registered RNG sub-stream")]
    UnknownAgent(String),
}

/// Derive the per-agent seed from the scenario seed and agent id.
///
/// Uses FNV-1a 64-bit so the calculation is platform-independent (no
/// `std::hash::Hasher` randomization, no SipHash key) and stable over time.
fn derive_agent_seed(scenario_seed: u64, agent_id: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for byte in scenario_seed.to_be_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    // Domain separator between the seed prefix and agent id.
    hash ^= b':' as u64;
    hash = hash.wrapping_mul(FNV_PRIME);
    for byte in agent_id.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_stream_is_deterministic() {
        let mut a = ArenaRng::new(42);
        let mut b = ArenaRng::new(42);
        let a_seq: Vec<u64> = (0..16).map(|_| a.root_mut().next_u64()).collect();
        let b_seq: Vec<u64> = (0..16).map(|_| b.root_mut().next_u64()).collect();
        assert_eq!(a_seq, b_seq);
    }

    #[test]
    fn distinct_seeds_diverge() {
        let mut a = ArenaRng::new(42);
        let mut b = ArenaRng::new(43);
        assert_ne!(a.root_mut().next_u64(), b.root_mut().next_u64());
    }

    #[test]
    fn agent_streams_are_distinct_and_stable() -> Result<(), RngError> {
        let mut rng = ArenaRng::new(42);
        rng.register_agents(["agent-a", "agent-b"])?;
        let a_first = rng.agent_stream_mut("agent-a")?.next_u64();
        let b_first = rng.agent_stream_mut("agent-b")?.next_u64();
        assert_ne!(a_first, b_first);

        let mut rng2 = ArenaRng::new(42);
        rng2.register_agents(["agent-a", "agent-b"])?;
        assert_eq!(a_first, rng2.agent_stream_mut("agent-a")?.next_u64());
        assert_eq!(b_first, rng2.agent_stream_mut("agent-b")?.next_u64());
        Ok(())
    }

    #[test]
    fn duplicate_agent_registration_fails() -> Result<(), RngError> {
        let mut rng = ArenaRng::new(42);
        rng.register_agent("agent-a")?;
        assert!(matches!(
            rng.register_agent("agent-a"),
            Err(RngError::DuplicateAgent(_))
        ));
        Ok(())
    }
}
