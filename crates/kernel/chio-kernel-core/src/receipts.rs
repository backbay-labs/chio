//! Portable receipt signing.
//!
//! Wraps `chio_core_types::receipt::body::ChioReceipt::sign_with_backend` so the kernel core
//! can produce signed receipts without depending on the `chio-kernel` full
//! crate's keypair-based helper. Using the `SigningBackend` trait keeps
//! the FIPS-capable signing path available on every adapter.

use alloc::string::ToString;
#[cfg(kani)]
use alloc::vec::Vec;

use chio_core_types::crypto::SigningBackend;
use chio_core_types::receipt::signing::ReceiptSigningHandle;
use chio_core_types::receipt::{body::ChioReceipt, body::ChioReceiptBody};

/// Errors raised by [`sign_receipt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptSigningError {
    /// The receipt body's `kernel_key` does not match the signing backend's
    /// public key. Signing would succeed but verification against the
    /// embedded `kernel_key` would then fail; we fail early to catch
    /// config drift.
    KernelKeyMismatch,
    /// The body's claimed `content_hash` does not match the hash the signer
    /// recomputed over the bound canonical content. WYSIWYS fail-closed gate:
    /// closes render-A / sign-B forgeries. Carries the recomputed and claimed
    /// hashes for audit.
    ContentHashMismatch {
        /// Hash recomputed by the signer over the handle's canonical content.
        recomputed: alloc::string::String,
        /// `content_hash` the caller embedded in the receipt body.
        claimed: alloc::string::String,
    },
    /// The canonical-JSON signing pipeline raised an error (bubbled up
    /// from `chio-core-types::crypto::sign_canonical_with_backend`).
    SigningFailed(alloc::string::String),
}

/// WYSIWYS receipt signing at the kernel-core trust boundary. **This is the
/// production signing primitive: every signature minted from evaluated content
/// flows through here, and it never trusts the caller's `content_hash`.**
///
/// `canonical_content` is the exact byte preimage the receipt's `content_hash`
/// was derived from (for a value output the RFC 8785 canonical JSON; for a
/// stream receipt the concatenated per-chunk digest preimage; for an empty
/// output the literal `null` canonicalization). The signer recomputes
/// `sha256_hex(canonical_content)` *inside the trust boundary* and refuses to
/// sign when it disagrees with `body.content_hash` ([`ReceiptSigningError::ContentHashMismatch`],
/// fail-closed). This closes the render-A / sign-B forgery on the production
/// path: a caller can no longer render content `A` to a human while submitting
/// a body claiming the hash of content `B`.
///
/// The recompute runs **before** the kernel-key check and before any signing
/// work, so a hash mismatch can never reach the signer.
///
/// For the move-only, one-time API that binds a signature to a single evaluated
/// artifact (and cannot be replayed), see [`sign_receipt_with_handle`]; it
/// delegates here after consuming its handle. For the thin transport adapters
/// that relay an already-minted body across an FFI/WASM boundary and therefore
/// do **not** hold the content preimage, see
/// [`sign_receipt_relaying_trusted_body`].
///
/// The `body.kernel_key` must equal `backend.public_key()`; otherwise we fail
/// fast with [`ReceiptSigningError::KernelKeyMismatch`] so the caller doesn't
/// produce a receipt whose signature cannot be verified.
///
/// # Errors
///
/// - [`ReceiptSigningError::ContentHashMismatch`] when the body's claimed
///   `content_hash` does not match `sha256_hex(canonical_content)`.
/// - [`ReceiptSigningError::KernelKeyMismatch`] when `body.kernel_key` does not
///   match `backend.public_key()`.
/// - [`ReceiptSigningError::SigningFailed`] when canonical signing fails.
pub fn sign_receipt(
    body: ChioReceiptBody,
    backend: &dyn SigningBackend,
    canonical_content: &[u8],
) -> Result<ChioReceipt, ReceiptSigningError> {
    // Recompute-and-refuse FIRST, inside the trust boundary, before any
    // kernel-key or signing work, so a hash mismatch can never reach the
    // signer. The recomputed hash is the signer's own (sha256 over the bytes
    // the producer evaluated), never the caller's asserted `content_hash`.
    let recomputed = chio_core_types::crypto::sha256_hex(canonical_content);
    if recomputed != body.content_hash {
        // Capture the claimed hash for the error payload BEFORE forgetting the
        // body. Under `--cfg kani` we `mem::forget(body)` to avoid symbolically
        // executing the body's Drop, but that moves the whole `body`; reading
        // `body.content_hash` afterwards would be a use-after-move that fails to
        // type-check on the formal-verification build. Clone the claimed hash
        // into a local first so the error is built from owned data on both the
        // normal and kani cfg paths.
        let claimed = body.content_hash.clone();
        #[cfg(kani)]
        core::mem::forget(body);

        return Err(ReceiptSigningError::ContentHashMismatch {
            recomputed,
            claimed,
        });
    }

    sign_receipt_relaying_trusted_body(body, backend)
}

/// Sign a receipt body using the given [`SigningBackend`] **without**
/// recomputing `content_hash` from a content preimage.
///
/// This trusts the caller-supplied `body.content_hash`. It exists **only** for
/// the thin transport adapters (mobile FFI / browser WASM / C++ FFI) that
/// receive an already-assembled, serialized [`ChioReceiptBody`] over their
/// boundary and therefore do **not** hold the content preimage needed to
/// re-derive the hash. Those adapters relay a body minted by an upstream
/// trusted producer (the kernel), where the WYSIWYS recompute already ran
/// through [`sign_receipt`] / [`sign_receipt_with_handle`].
///
/// Every path that *does* hold the evaluated content -- i.e. the production
/// kernel signing path (`chio_kernel::kernel::responses::build_and_sign_receipt`
/// and the mpsc signing task) -- MUST instead call [`sign_receipt`] (or
/// [`sign_receipt_with_handle`]) so `content_hash` is recomputed over the
/// canonical content inside the trust boundary and signing is refused on
/// mismatch (fail-closed). Threading the content preimage across the FFI/WASM
/// boundary so these adapters can recompute too is the larger follow-up tracked
/// as ; until then this entrypoint is the explicit, auditable seam where
/// caller `content_hash` is trusted, rather than that trust being the silent
/// default of `sign_receipt`.
///
/// The `body.kernel_key` must equal `backend.public_key()`; otherwise we
/// fail fast with [`ReceiptSigningError::KernelKeyMismatch`] so the caller
/// doesn't produce a receipt whose signature cannot be verified.
///
/// # Errors
///
/// - [`ReceiptSigningError::KernelKeyMismatch`] when `body.kernel_key` does not
///   match `backend.public_key()`.
/// - [`ReceiptSigningError::SigningFailed`] when canonical signing fails.
pub fn sign_receipt_relaying_trusted_body(
    body: ChioReceiptBody,
    backend: &dyn SigningBackend,
) -> Result<ChioReceipt, ReceiptSigningError> {
    let backend_key = backend.public_key();
    if body.kernel_key.algorithm() != backend_key.algorithm() || body.kernel_key != backend_key {
        #[cfg(kani)]
        core::mem::forget(body);

        return Err(ReceiptSigningError::KernelKeyMismatch);
    }

    #[cfg(kani)]
    {
        // Kani cannot practically symbolically execute the serde/RFC 8785
        // canonicalization stack. This model still exercises the successful
        // public branch: matching kernel key, backend signing, and field
        // preservation into the returned receipt.
        let signature = backend
            .sign_bytes(b"kani-receipt-signing-model")
            .map_err(|error| ReceiptSigningError::SigningFailed(error.to_string()))?;
        return Ok(ChioReceipt {
            id: body.id,
            timestamp: body.timestamp,
            capability_id: body.capability_id,
            tool_server: body.tool_server,
            tool_name: body.tool_name,
            action: body.action,
            decision: body.decision,
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: body.content_hash,
            policy_hash: body.policy_hash,
            evidence: body.evidence,
            metadata: body.metadata,
            trust_level: body.trust_level,
            tenant_id: body.tenant_id,
            bbs_projection_version: None,
            kernel_key: body.kernel_key,
            bbs_signature: None,
            algorithm: Some(backend.algorithm()),
            signature,
        });
    }

    #[cfg(not(kani))]
    ChioReceipt::sign_with_backend(body, backend)
        .map_err(|error| ReceiptSigningError::SigningFailed(error.to_string()))
}

/// WYSIWYS receipt signing bound to a *specific* evaluated artifact via a
/// one-time [`ReceiptSigningHandle`]. **This is the strongest signing API.**
///
/// Like [`sign_receipt`], this recomputes `content_hash` over canonical content
/// inside the trust boundary and refuses to sign on mismatch (fail-closed). It
/// adds the one-time, move-only guarantee: the handle is consumed by value, so
/// a single handle backs at most one signature and cannot be replayed. The
/// handle recomputed `content_hash` over the artifact's canonical content when
/// it was constructed; here we forward that handle's canonical bytes to
/// [`sign_receipt`], which refuses to sign unless the body's claimed
/// `content_hash` equals the recomputed hash.
///
/// The kernel `build_and_sign_receipt` path and the mpsc signing task both route
/// through here, so every signature the kernel mints recomputes
/// `content_hash` inside the trust boundary and is bound to a single artifact.
/// The kernel key check from [`sign_receipt`] still applies.
///
/// # Seam note ( follow-up / )
///
/// Producers currently build the handle from canonical content they supply
/// (see [`ReceiptSigningHandle::from_content_preimage`] / [`ReceiptSigningHandle::from_content`]).
/// On the kernel path that preimage is the exact bytes
/// `receipt_content_for_output` hashed to produce `content_hash`, so the gate
/// is non-tautological there. The intended end state is for `evaluate()` to
/// return the handle so the only way to obtain one is to have actually run an
/// evaluation; threading the handle out of [`crate::evaluate`] is a larger
/// follow-up, but the recompute + refuse gate here already closes the
/// render-A / sign-B regression on the production path.
///
/// # Errors
///
/// - [`ReceiptSigningError::ContentHashMismatch`] when the body's claimed
///   `content_hash` does not match the handle's recomputed hash.
/// - [`ReceiptSigningError::KernelKeyMismatch`] when `body.kernel_key` does not
///   match `backend.public_key()`.
/// - [`ReceiptSigningError::SigningFailed`] when canonical signing fails.
pub fn sign_receipt_with_handle(
    body: ChioReceiptBody,
    backend: &dyn SigningBackend,
    handle: ReceiptSigningHandle,
) -> Result<ChioReceipt, ReceiptSigningError> {
    // Consume the handle by value (enforcing one-time use per signature) and
    // forward its immutable canonical bytes to the production recompute gate.
    // `sign_receipt` recomputes `sha256_hex(canonical_content)` and refuses on
    // mismatch with `body.content_hash`, which is exactly the handle's
    // recompute-and-refuse contract.
    let (_recomputed_hash, canonical_content) = handle.into_parts();
    sign_receipt(body, backend, &canonical_content)
}
