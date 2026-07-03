//! Chio public identity and wallet network contracts.
//!
//! These contracts widen Chio's outward-facing identity claim without replacing
//! Chio's native `did:chio` provenance anchor. Broader DID methods, credential
//! families, wallet directory entries, and routing manifests remain explicit
//! and fail closed.

mod error;
mod types;
mod validation;
mod validators;

#[cfg(test)]
mod tests;

pub use error::IdentityNetworkContractError;
pub use types::{
    IdentityArtifactKind, IdentityArtifactReference, IdentityBindingPolicy,
    IdentityCredentialFamily, IdentityDidMethod, IdentityInteropQualificationCase,
    IdentityInteropQualificationMatrix, IdentityInteropScenarioKind, IdentityProofFamily,
    IdentityQualificationOutcome, PublicIdentityProfileArtifact,
    PublicWalletDirectoryEntryArtifact, PublicWalletRoutingManifestArtifact,
    SignedIdentityInteropQualificationMatrix, SignedPublicIdentityProfile,
    SignedPublicWalletDirectoryEntry, SignedPublicWalletRoutingManifest,
    WalletDirectoryLookupGuardrails, WalletRoutingGuardrails, WalletTransportMode,
    CHIO_IDENTITY_INTEROP_QUALIFICATION_MATRIX_SCHEMA, CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA,
    CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_SCHEMA, CHIO_PUBLIC_WALLET_ROUTING_MANIFEST_SCHEMA,
};
pub use validation::{
    validate_identity_interop_qualification_matrix, validate_public_identity_profile,
    validate_public_wallet_directory_entry, validate_public_wallet_routing_manifest,
};
