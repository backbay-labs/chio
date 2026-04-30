//! Revocation oracle primitives for Chio.

pub mod api;
pub mod sparse_merkle;

pub use api::{
    EpochNonce, EpochRoot, InclusionProof, NonInclusionProof, Result, RevocationKey,
    RevocationOracle, RevocationOracleError, SubjectId,
};
pub use sparse_merkle::InMemoryRevocationOracle;
