//! ## Wire format
//!
//! ```text
//! envelope = {
//!     "payloadType": "application/vnd.in-toto+json",
//!     "payload":     base64(canonical_json(in_toto_statement)),
//!     "signatures":  [
//!         { "keyid": sha256_hex(passport_pubkey_a), "sig": base64(sig_a) },
//!         { "keyid": sha256_hex(passport_pubkey_b), "sig": base64(sig_b) },
//!     ],
//! }
//! ```
//!
//! Each signature is Ed25519 over the PAE bytes:
//!
//! ```text
//! pae = "DSSEv1" SP LEN(payloadType) SP payloadType SP
//!                 LEN(statement_bytes) SP statement_bytes
//! ```
//!
//! where `statement_bytes` is the raw canonical-JSON of the in-toto Statement
//! (NOT the base64 of it: that goes on the wire, but the signed message is the
//! pre-base64 bytes). LEN values are decimal ASCII per the DSSE v1 spec.
//!
//! ## Scope boundary
//!
//! This module emits both the DSSE signature-slice profile
//! (`chio.bilateral-signature-slice.v1`) and the strict Chio bilateral
//! invocation predicate (`chio.bilateral-cosign-invocation.v1`). The
//! signature-slice profile stays available for compatibility; strict Chio
//! conformance uses `chio.bilateral-cosign-invocation.v1` and does not
//! carry the local `receipt_canonical_json` helper field.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{Ed25519Backend, Keypair, PublicKey, Signature, SigningBackend};
use chio_core_types::receipt::body::ChioReceipt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::bilateral::{BilateralCoSigningError, BilateralCoSigningProtocol, DsseCoSigningRequest};

#[path = "bilateral_dsse/builder.rs"]
mod builder;
#[path = "bilateral_dsse/policy.rs"]
mod policy;
#[path = "bilateral_dsse/sign.rs"]
mod sign;
#[path = "bilateral_dsse/types.rs"]
mod types;
#[path = "bilateral_dsse/verify.rs"]
mod verify;

pub use self::builder::{
    build_chio_bilateral_invocation_predicate, build_chio_bilateral_invocation_statement,
    build_predicate, build_predicate_full, build_statement, pae, receipt_subject_name,
    BilateralPredicateExtensions,
};
pub use self::policy::{
    require_policy_evaluation_allow_admission, validate_policy_evaluation_summary,
};
pub use self::sign::{
    sign_chio_bilateral_dsse_envelope, sign_chio_bilateral_dsse_envelope_with_cosigner,
    sign_dsse_envelope, sign_dsse_envelope_full, sign_dsse_envelope_with_cosigner,
};
pub use self::types::{
    BilateralPredicate, CapabilityLeaseRef, DsseEnvelope, DsseSignature, DsseStatement,
    GovernanceReceiptRef, HashRecord, KernelIdentity, Keyid, PolicyEvaluationSummary,
    PolicyVerdict, StatementSubject, SubjectDigest, TreatyBindingRef,
    BILATERAL_DSSE_ENVELOPE_SCHEMA, DEFAULT_CONSISTENCY_MODEL, DEFAULT_COSIGN_MODE,
    DEFAULT_CROSS_ORG_VISIBILITY, PAYLOAD_TYPE_IN_TOTO, PREDICATE_BODY_SCHEMA,
    PREDICATE_TYPE_BILATERAL, PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION,
    RECEIPT_SUBJECT_NAME_PREFIX, STATEMENT_TYPE_V1, VALID_CROSS_ORG_VISIBILITY,
};
pub(crate) use self::verify::verify_chio_bilateral_dsse_envelope_with_frost;
pub use self::verify::{verify_chio_bilateral_dsse_envelope, verify_dsse_envelope};

use self::types::PAE_PREFIX;
use self::verify::{validate_treaty_operational_refs, validate_treaty_receipt_refs};

#[cfg(test)]
use self::verify::{receipt_body_digest_hex, receipt_canonical_digest_hex};

// ---------------------------------------------------------------------------
// Tests (encoding round-trip + happy path; negative paths live in
// chio-conformance/tests/b4_bilateral_dsse_signature_slice.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "bilateral_dsse/tests.rs"]
mod tests;
