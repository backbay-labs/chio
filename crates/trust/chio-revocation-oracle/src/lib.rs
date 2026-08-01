//! Revocation oracle primitives for Chio.

#![forbid(unsafe_code)]

pub mod api;
pub mod epoch;
pub mod finding_status_sparse;
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
pub use finding_status_sparse::{
    finding_status_empty_leaf_hash, finding_status_key_hash, verify_finding_status_inclusion,
    verify_finding_status_non_inclusion, FindingStatusSparseLeaf, FindingStatusSparseMap,
    FindingStatusSparseProof, FindingStatusSparseRoot, FINDING_STATUS_BRANCH_DOMAIN,
    FINDING_STATUS_EMPTY_LEAF_DOMAIN, FINDING_STATUS_HASH_ALGORITHM,
    FINDING_STATUS_KEY_DOMAIN_NONCE, FINDING_STATUS_KEY_HASH_DOMAIN, FINDING_STATUS_MAP_VERSION,
    FINDING_STATUS_OCCUPIED_LEAF_DOMAIN, FINDING_STATUS_PROOF_SEMANTICS,
    FINDING_STATUS_SPARSE_DEPTH,
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
