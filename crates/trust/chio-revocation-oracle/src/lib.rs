//! Revocation oracle primitives for Chio.

#![forbid(unsafe_code)]

pub mod api;
pub mod epoch;
pub mod freshness;
pub mod passport_bridge;
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
pub use passport_bridge::{
    apply_passport_revocation, PassportRevocationBridgeError, PassportRevocationEvent,
};
pub use signer::{
    Ed25519RootSigner, Ed25519RootVerifier, EpochRootSigner, EpochRootVerifier, ALGORITHM_ED25519,
    DOMAIN_SEPARATION_CONTEXT,
};
pub use sparse_merkle::InMemoryRevocationOracle;
