//! The `FindingEvidenceVerifier`: turns a raw finding plus an explicitly
//! resolved evidence bundle and pinned trust roots into the structured
//! 13-facet report (ARCHITECTURE 4.1.1).
//!
//! `chio_finding::verify_finding` proves artifact integrity only. This
//! crate adds the buyer/venue boundary that receipt references,
//! checkpoints, cost, recipe, and bond references must clear before a
//! facet may read `verified`. Design rules:
//!
//! - Fail closed. Empty trust inputs deny; they never widen acceptance.
//! - No loose helpers as authority boundaries: receipts verify strictly
//!   with weak-key rejection over the reconstructed signing body, and
//!   `ReceiptInclusionProof::verify` is never used without the full
//!   wrapper cross-check (checkpoint identity, sequences, range, both
//!   leaf indexes, both tree sizes, canonical leaf, signer).
//! - Facets that lack their required inputs report `unavailable`, which
//!   DENIES wherever the facet is required. Nothing upgrades one facet
//!   from another.
//!
//! The verifier is pure over its inputs: resolution (fetching receipt
//! bytes, checkpoints, recipe preimages, bond snapshots) happens at the
//! owning surface, which then binds what it resolved into the report.

#![forbid(unsafe_code)]

mod checkpoints;
mod cost;
mod receipts;
mod verify;

pub use checkpoints::{verify_checkpoint_membership, CheckpointMembershipError};
// The checkpoint and inclusion-proof types are part of this crate's
// verification contract, so a consumer can name them without taking a
// kernel dependency for two type aliases.
pub use chio_kernel::checkpoint::{KernelCheckpoint, ReceiptInclusionProof};
pub use cost::{FindingNonceResolver, NoNonceEvidence};
pub use receipts::{verify_receipt_strict, ReceiptStrictError};
pub use verify::{
    sign_finding_verifier_report, verify_finding_evidence, FindingBondSnapshot,
    FindingBondStoreSnapshot, FindingCheckpointSignerStatusTrust, FindingEvidenceBundle,
    FindingVerifierDraft, FindingVerifierError, FindingVerifierTrustRoots,
    ResolvedFindingDeliveryEvidence, ResolvedReceiptEvidence, SignedFindingBondStoreSnapshot,
    FINDING_BOND_STORE_SNAPSHOT_SCHEMA_V1, MAX_RAW_FINDING_BYTES,
};
