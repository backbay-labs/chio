//! Revocation oracle primitives for Chio.

pub mod api;

pub use api::{
    EpochNonce, EpochRoot, InclusionProof, NonInclusionProof, Result, RevocationKey,
    RevocationOracle, RevocationOracleError, SubjectId,
};
