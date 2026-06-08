//! Implements a partial local verifier for the bilateral DSSE
//! signature-slice profile produced by
//! [`crate::bilateral_dsse::sign_dsse_envelope_full`].
//!
//! ## Partial-verifier scope
//!
//! The implementation does not yet cover the full predicate schema:
//!
//!   - `BilateralPredicate` is intentionally not the strict Chio
//!     predicate: it is missing required fields the spec
//!     enumerates (for example, `tool_args_hash` per the Chio bilateral
//!     invocation spec) and accepts
//!     internal non-schema fields that the spec does not define.
//!   - The error mapping conflates parseable-but-schema-malformed
//!     Statement JSON with `dsse.malformed` rather than the spec's
//!     `statement.malformed`.
//!
//! This verifier is labeled as a **partial local verifier**: it
//! implements the structural / cryptographic core
//! plus a meaningful subset of the §7 step list against the local
//! signature-slice profile. Strict Chio predicate completion belongs
//! in a separate predicate-profile implementation.
//!
//! Receipts that surface verifier output should NOT advertise full
//! §7 conformance based on this implementation alone.
//!
//! ## Public API summary
//!
//! * [`PeerPinSet`], [`PinnedPeer`] - verifier pin set: which kernels
//!   are trusted at which passport keys.
//! * [`ReceiptStore`] / [`InMemoryReceiptStore`] - step 7 lookup.
//! * [`CapabilityLeaseRegistry`] / [`InMemoryLeaseRegistry`] - step 14.
//! * [`GovernanceReceiptStore`] / [`InMemoryGovernanceReceiptStore`] - step 15.
//! * [`RevocationOracle`] - step 9. Demo-only
//!   [`crate::demo::DemoAllowAllRevocationOracle`] is available under
//!   `cfg(any(test, feature = "demo"))`.
//! * [`PinnedEpoch`] - verifier's wall clock + epoch height.
//! * [`VerifierConfig`] - bundles the trait objects + epoch.
//! * [`verify_bilateral_cosign_invocation`] - the canonical verifier for
//!   the local bilateral DSSE signature-slice profile. This is not full
//!   §7 conformance pending strict predicate-profile completion.
//! * [`VerifiedBilateralCoSignInvocation`] - successful verifier output
//!   (mirrors §7 step 17 for the steps this implementation covers).
//! * [`VerifierError`] - fail-closed error codes for the spec §7.1-compatible
//!   subset this partial verifier can reach (e.g. `subject.digest_mismatch`,
//!   `peer.unpinned_or_keyid_mismatch`).
//!
//! ## Usage from the local fixture helper
//!
//! [`crate::bilateral::execute_local_bilateral_invocation_fixture`] is the
//! local fixture helper that drives [`sign_dsse_envelope_full`] and
//! immediately runs this partial local verifier before returning the
//! [`crate::bilateral::BilateralCoSignArtifacts`]. Callers that want to
//! verify externally produced envelopes call
//! [`verify_bilateral_cosign_invocation`] directly.

use std::collections::{BTreeMap, HashMap, HashSet};

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::body::ChioReceipt;
use sha2::{Digest, Sha256};

use crate::bilateral::BilateralCoSigningError;
use crate::bilateral_dsse::{
    receipt_subject_name, require_policy_evaluation_allow_admission,
    verify_chio_bilateral_dsse_envelope, verify_dsse_envelope, BilateralPredicate,
    CapabilityLeaseRef, DsseEnvelope, DsseStatement, GovernanceReceiptRef, Keyid, TreatyBindingRef,
    PAYLOAD_TYPE_IN_TOTO, PREDICATE_BODY_SCHEMA, PREDICATE_TYPE_BILATERAL,
    PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION, STATEMENT_TYPE_V1, VALID_CROSS_ORG_VISIBILITY,
};
use crate::trust_establishment::LadderManifestRef;

mod config;
mod cosign;
mod error;
mod state;
mod support;
mod treaty;

pub use config::*;
pub use cosign::*;
pub use error::VerifierError;
pub use state::*;
pub use treaty::verify_treaty_bound_chio_bilateral_invocation;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
