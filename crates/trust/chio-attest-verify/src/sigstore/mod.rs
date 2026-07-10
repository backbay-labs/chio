//! Production [`AttestVerifier`] implementation backed by `sigstore-rs`.
//!
//! Three verification surfaces are exposed:
//!
//! - [`SigstoreVerifier::verify_bundle`] performs the keyless flow
//!   against a Sigstore protobuf Bundle (cert chain + signature + Rekor
//!   transparency entry). `sigstore-rs` validates the transparency entry
//!   against the signing materials, but does not currently verify Rekor
//!   Merkle inclusion or the Signed Entry Timestamp (SET). Until Chio
//!   performs those checks itself, this path marks
//!   [`VerifiedAttestation::rekor_inclusion_verified`] as `false`.
//!
//! - [`SigstoreVerifier::verify_blob`] and [`SigstoreVerifier::verify_bytes`]
//!   verify a detached `(artifact, signature, leaf-cert)` triple against
//!   the embedded Fulcio trust root. They perform certificate-chain
//!   validation, OIDC issuer match, identity SAN regex match, certificate
//!   validity-window check, and signature verification, but DO NOT consume
//!   a Rekor inclusion proof and therefore mark the resulting
//!   [`VerifiedAttestation`] with `rekor_inclusion_verified = false`.
//!
//! All paths are fail-closed: any error returns one of the [`AttestError`]
//! variants. There is no path through this module that returns
//! `Ok(VerifiedAttestation)` after a partial verification.

mod bundle_verify;
mod compat;
mod core;
mod identity;
mod parse;
mod policy;
mod validators;

#[cfg(test)]
mod tests;

use const_oid::ObjectIdentifier;

#[allow(unused_imports)]
use crate::{AttestError, AttestVerifier, VerifiedAttestation};

pub use core::SigstoreVerifier;

/// Embedded TUF trust-root materials. Checked in under `sigstore-root/` and
/// refreshed by the quarterly CODEOWNERS-reviewed re-bake job.
const EMBEDDED_TRUSTED_ROOT_JSON: &[u8] = include_bytes!("../../sigstore-root/trusted_root.json");

/// OID for the Fulcio OIDC issuer extension. Documented at
/// `https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md`.
const OIDC_ISSUER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");
/// OID for the Sigstore `OtherName` SAN entry.
const OTHERNAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.7");
/// EKU code-signing OID, required of every Fulcio-issued leaf.
const ID_KP_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

// Bring `Identity` into scope for downstream consumers that may want to
// build their own policies on top of the shared trust root. This re-export
// is intentional and stable.
#[allow(unused_imports)]
pub use sigstore::bundle::verify::policy::Identity as SigstoreIdentityPolicy;
