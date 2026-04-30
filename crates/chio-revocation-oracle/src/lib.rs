//! Revocation oracle primitives for Chio.

pub mod api;
pub mod epoch;
pub mod freshness;
pub mod signer;
pub mod sparse_merkle;

pub use api::{
    EpochNonce, EpochRoot, InclusionProof, NonInclusionProof, Result, RevocationKey,
    RevocationOracle, RevocationOracleError, RootSignature, SubjectId,
};
pub use epoch::{
    tick_and_broadcast, EpochBroadcaster, InMemoryEpochBroadcaster, SignedEpochRoot,
    DEFAULT_EPOCH_TICK_MS,
};
pub use freshness::{verify_fresh_epoch_root, FreshnessConfig};
pub use signer::{DigestRootSigner, EpochRootSigner};
pub use sparse_merkle::InMemoryRevocationOracle;
