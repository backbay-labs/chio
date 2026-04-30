//! Revocation oracle primitives for Chio.

pub mod api;
pub mod epoch;
pub mod signer;
pub mod sparse_merkle;

pub use api::{
    EpochNonce, EpochRoot, InclusionProof, NonInclusionProof, Result, RevocationKey,
    RevocationOracle, RevocationOracleError, RootSignature, SubjectId,
};
pub use epoch::SignedEpochRoot;
pub use signer::{DigestRootSigner, EpochRootSigner};
pub use sparse_merkle::InMemoryRevocationOracle;
