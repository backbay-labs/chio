//! Kernel boot path: gate the PQ signing key load on a self-quote.
//!
//! This closes the trust loop opened by the `expect_report_data` and
//! hybrid-signing paths. Boot order:
//!
//! 1. The kernel comes up with its classical Ed25519 keypair already
//!    materialized. No PQ key has been touched.
//! 2. The kernel requests its own TEE quote from the surrounding
//!    [`chio-tee`](../../../chio-tee) container and feeds the bytes into a
//!    verifier-side [`KernelSelfQuoteVerifier`]. The quote
//!    MUST commit to `expect_report_data(kernel_classical_pk,
//!    receipt_root_genesis)` where `receipt_root_genesis` is the all-zero
//!    32-byte sentinel `[0u8; 32]` representing the empty receipt-tree root
//!    at boot.
//! 3. Only after the verifier returns success does the kernel derive the
//!    [`MlDsa65Backend`](chio_core_types::pq::MlDsa65Backend) from the
//!    operator-supplied seed and compose the
//!    [`HybridBackend`](chio_core_types::pq::HybridBackend). Any failure in
//!    step 2 leaves the kernel running classical-only and the boot path
//!    returns an error: under `crypto_floor=allow_hybrid` or
//!    `crypto_floor=pq_required` the operator MUST refuse to start signing.
//!
//! ## Why a port trait rather than a hard `chio-attest-verify` dep
//!
//! `chio-kernel` does not depend on `chio-attest-verify` and this module
//! preserves that boundary. The verifier crate today carries TDX/SEV-SNP/
//! Nitro backends each pulled in behind a cargo feature; the kernel does
//! not need any of them at boot time. The port trait below is small enough
//! to implement against [`QuoteVerifier`](../../../chio-attest-verify) by a
//! one-line shim in the operator binary that wires the two crates together,
//! and small enough to implement against an in-memory mock for the
//! integration test.
//!
//! ## Trust-boundary discipline
//!
//! - Fail-closed: every error path returns
//!   [`KernelBootError`] without producing a [`HybridBackend`].
//! - The kernel signing key (the classical Ed25519 key plus the PQ
//!   composition) is never returned partially. Callers that ask for a
//!   hybrid backend either get one fully gated by a verified self-quote
//!   or they get an error.
//! - `receipt_root_genesis` is the [`RECEIPT_ROOT_GENESIS`] constant.
//!   Production callers MUST NOT thread their current receipt root in;
//!   the genesis quote binds to the empty tree so the chain has a fixed
//!   cryptographic anchor independent of the first receipt's contents.

use chio_core::crypto::{Keypair, PublicKey, SigningBackend};

use crate::receipt_support::{
    kernel_signing_backend, KernelCryptoFloor, KernelSigningBackendError,
};

/// Receipt-root sentinel used for the kernel self-quote.
///
/// The first signed receipt advances the root, but the genesis-quote
/// binds to the empty tree so the chain has a fixed cryptographic anchor
/// independent of the first receipt's contents (per the self-quote
/// boot-gate contract).
pub const RECEIPT_ROOT_GENESIS: [u8; 32] = [0u8; 32];

/// Outcome reported by a [`KernelSelfQuoteVerifier`].
///
/// The verifier carries the actual collateral chain validation and TCB
/// freshness check; the kernel boot path only inspects the boolean
/// success flag and the diagnostic message. A successful verification
/// MUST mean that:
///
/// - the quote envelope parsed and matched the configured TEE family,
/// - the collateral chained to its trusted root,
/// - the TCB status was acceptable per the verifier's policy,
/// - and the 64-byte `report_data` slot byte-matched
///   `expect_report_data(kernel_classical_pk, RECEIPT_ROOT_GENESIS)`.
///
/// Any failure produces [`KernelSelfQuoteOutcome::rejected`]. Verifiers
/// MUST NOT report success on partial verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelSelfQuoteOutcome {
    /// True when the quote verified end-to-end.
    pub verified: bool,
    /// Verifier-side diagnostic propagated into [`KernelBootError`] when
    /// `verified` is `false`. Empty on success.
    pub diagnostic: String,
}

impl KernelSelfQuoteOutcome {
    /// Verifier-friendly constructor for a successful verification.
    #[must_use]
    pub fn accepted() -> Self {
        Self {
            verified: true,
            diagnostic: String::new(),
        }
    }

    /// Verifier-friendly constructor for a failed verification.
    #[must_use]
    pub fn rejected(diagnostic: impl Into<String>) -> Self {
        Self {
            verified: false,
            diagnostic: diagnostic.into(),
        }
    }
}

/// Port the kernel boot path consults to verify its own TEE quote.
///
/// Implementations live in operator binaries (which compose
/// [`chio-attest-verify`](../../../chio-attest-verify) backends) or in
/// integration tests (which inject a mock with a captured expected
/// `report_data`). The port trait deliberately does not return the full
/// `VerifiedQuote` shape: the kernel boot path only needs a yes/no
/// answer plus a diagnostic message, and keeping the interface narrow
/// preserves the no-`chio-attest-verify`-dep boundary on `chio-kernel`.
pub trait KernelSelfQuoteVerifier: Send + Sync {
    /// Verify a kernel self-quote against the supplied classical
    /// public key and the genesis receipt root.
    ///
    /// `quote_bytes` is the raw on-the-wire envelope produced by the
    /// surrounding TEE container (chio-tee). The verifier MUST consult
    /// `expected_classical_pk` and `RECEIPT_ROOT_GENESIS` when
    /// reconstructing the expected `report_data`; any other binding is
    /// a verifier bug.
    fn verify_self_quote(
        &self,
        quote_bytes: &[u8],
        expected_classical_pk: &PublicKey,
    ) -> KernelSelfQuoteOutcome;
}

/// Errors the boot path raises while gating the PQ key load.
///
/// Distinct from [`KernelSigningBackendError`] so the operator log can
/// distinguish "the policy floor was misconfigured" from "the self-quote
/// did not bind". Both still fail the kernel start.
#[derive(Debug, thiserror::Error)]
pub enum KernelBootError {
    /// The supplied self-quote did not verify or did not bind to the
    /// classical kernel public key. The kernel MUST NOT proceed to load
    /// the PQ signing key under any non-classical floor.
    #[error("kernel self-quote did not bind to classical kernel public key: {diagnostic}")]
    SelfQuoteRejected {
        /// Verifier-supplied diagnostic message.
        diagnostic: String,
    },

    /// The boot path tried to construct a hybrid backend but the PQ
    /// seed or floor was misconfigured. Wraps the existing
    /// [`KernelSigningBackendError`] so callers can pattern-match if
    /// they need to.
    #[error(transparent)]
    SigningBackend(#[from] KernelSigningBackendError),
}

/// Load the kernel signing backend, gating the PQ half on a verified
/// self-quote.
///
/// Boot logic:
///
/// - Under [`KernelCryptoFloor::AllowClassical`] the self-quote step is
///   skipped: there is no PQ key to gate, and a classical-only deployment
///   may not even ship a TEE container. The function returns the
///   classical-only backend produced by [`kernel_signing_backend`].
/// - Under [`KernelCryptoFloor::AllowHybrid`] or
///   [`KernelCryptoFloor::PqRequired`] the function consults the
///   verifier port FIRST. Only on
///   [`KernelSelfQuoteOutcome::verified`] does it construct the hybrid
///   backend. A rejected outcome returns
///   [`KernelBootError::SelfQuoteRejected`] without ever materializing
///   the [`MlDsa65Backend`](chio_core_types::pq::MlDsa65Backend).
///
/// `quote_bytes` is the on-the-wire self-quote produced by the TEE
/// container. For tests, an empty slice combined with a mock verifier
/// is fine; for production the bytes come from `chio-tee`.
///
/// # Errors
///
/// - [`KernelBootError::SelfQuoteRejected`] when the verifier rejects
///   the self-quote and the floor mandates a PQ key.
/// - [`KernelBootError::SigningBackend`] when the floor or PQ seed is
///   misconfigured (forwarded from
///   [`KernelSigningBackendError::HybridFloorRequiresPqKey`] or
///   [`KernelSigningBackendError::PqKeyImportFailed`]).
pub fn load_kernel_signing_backend_after_self_quote(
    crypto_floor: KernelCryptoFloor,
    classical_keypair: Keypair,
    pq_seed: Option<&[u8; 32]>,
    quote_bytes: &[u8],
    verifier: &dyn KernelSelfQuoteVerifier,
) -> Result<Box<dyn SigningBackend>, KernelBootError> {
    if !crypto_floor.allows_hybrid() {
        // Classical-only deployment: no PQ key to gate. Defer to the
        // existing helper so the classical path stays byte-identical to
        // deployments that have not opted in.
        return Ok(kernel_signing_backend(
            crypto_floor,
            classical_keypair,
            pq_seed,
        )?);
    }

    // Non-classical floor: ALWAYS consult the verifier before deriving
    // any PQ material. The classical public key is the gating identity
    // every backend must commit into report_data.
    let classical_pk = classical_keypair.public_key();
    let outcome = verifier.verify_self_quote(quote_bytes, &classical_pk);
    if !outcome.verified {
        return Err(KernelBootError::SelfQuoteRejected {
            diagnostic: outcome.diagnostic,
        });
    }

    // Verifier said yes: materialize the hybrid backend through the
    // shared boot helper so the resulting backend is bit-identical to
    // the one the classical-only path already wires through.
    Ok(kernel_signing_backend(
        crypto_floor,
        classical_keypair,
        pq_seed,
    )?)
}
