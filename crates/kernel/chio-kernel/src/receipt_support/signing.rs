use crate::*;

// ---------------------------------------------------------------------------
// Hybrid receipt signing path
// ---------------------------------------------------------------------------
//
// Mirrors `chio_policy::CryptoFloor` so the kernel boot path can branch on
// the configured floor without taking a circular dependency on the policy
// crate (chio-policy depends on chio-kernel). Operators that load a
// HushSpec policy with `crypto_floor` set translate it into this enum
// before constructing `KernelConfig`. Threat model row
// `pq_signature_downgrade` is enforced by validation at this boundary.

/// Minimum cryptographic posture enforced by the kernel-side signing path.
///
/// The textual encoding (`allow_classical`, `allow_hybrid`, `pq_required`)
/// matches the `chio_policy::CryptoFloor` wire form so an operator can lift
/// a parsed policy floor directly without re-encoding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum KernelCryptoFloor {
    /// Accept classical-only Ed25519/P-256/P-384 envelopes. Default.
    #[default]
    AllowClassical,
    /// Accept hybrid classical-plus-ML-DSA-65 envelopes. Requires a PQ key.
    AllowHybrid,
    /// Reject classical-only envelopes; require hybrid signing on every
    /// signed artifact. Requires a PQ key.
    PqRequired,
}

impl KernelCryptoFloor {
    /// Whether the floor permits hybrid envelopes on the wire.
    #[must_use]
    pub fn allows_hybrid(&self) -> bool {
        matches!(self, Self::AllowHybrid | Self::PqRequired)
    }

    /// Whether the floor mandates hybrid envelopes (rejects classical-only).
    #[must_use]
    pub fn requires_pq(&self) -> bool {
        matches!(self, Self::PqRequired)
    }

    /// Whether the floor permits classical-only envelopes on the wire.
    #[must_use]
    pub fn allows_classical_only(&self) -> bool {
        matches!(self, Self::AllowClassical | Self::AllowHybrid)
    }

    /// Stable wire-format identifier for diagnostics.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AllowClassical => "allow_classical",
            Self::AllowHybrid => "allow_hybrid",
            Self::PqRequired => "pq_required",
        }
    }
}

/// Sign an already-assembled [`ChioReceiptBody`] with an arbitrary
/// [`SigningBackend`] (classical, hybrid, or PQ), recomputing `content_hash`
/// inside the trust boundary (WYSIWYS).
///
/// Delegates to `chio_kernel_core::sign_receipt`, the production
/// recompute-and-refuse primitive, so the hybrid signing path is held to the
/// same WYSIWYS contract as the inline classical path and the mpsc signing
/// task. `canonical_content` is the exact byte preimage the body's
/// `content_hash` was derived from (for a value output the RFC 8785 canonical
/// JSON; for a stream receipt the concatenated per-chunk digest preimage; for an
/// empty output the literal `null` canonicalization). The signer recomputes
/// `sha256_hex(canonical_content)` and refuses to sign when it disagrees with
/// `body.content_hash`, closing the render-A / sign-B forgery on the hybrid path
/// too rather than leaving it as a caller-hash-trust seam. Receipts produced via
/// this wrapper are byte-identical to receipts produced via the inline classical
/// path when the same backend and content are used.
///
/// Callers that genuinely cannot carry the content preimage (the thin transport
/// adapters relaying an already-minted body across an FFI/WASM boundary) must
/// use `chio_kernel_core::sign_receipt_relaying_trusted_body` directly, which is
/// the explicit, auditable trusted-relay seam tracked; this
/// content-bearing kernel wrapper is not that seam.
///
/// # Errors
///
/// Returns [`KernelError::ReceiptSigningFailed`] when:
/// - the body's claimed `content_hash` does not match
///   `sha256_hex(canonical_content)` (fail-closed: render-A / sign-B refused), OR
/// - the body's `kernel_key` does not match the backend's public key
///   (fail-closed: the signing path refuses to issue a signature that would not
///   verify), OR
/// - canonical signing fails.
pub fn sign_receipt_body_with_backend(
    body: ChioReceiptBody,
    backend: &dyn chio_core::crypto::SigningBackend,
    canonical_content: &[u8],
) -> Result<ChioReceipt, KernelError> {
    chio_kernel_core::sign_receipt(body, backend, canonical_content).map_err(|error| {
        use chio_kernel_core::ReceiptSigningError;
        let message = match error {
            ReceiptSigningError::KernelKeyMismatch => {
                "kernel signing key does not match receipt body kernel_key".to_string()
            }
            // WYSIWYS mismatch: the body claimed a `content_hash` the
            // signer could not reproduce from `canonical_content`, so the
            // signature is refused fail-closed.
            ReceiptSigningError::ContentHashMismatch {
                recomputed,
                claimed,
            } => format!(
                "receipt content_hash mismatch: body claimed {claimed} but signer \
                 recomputed {recomputed} over the canonical content (WYSIWYS refused)"
            ),
            ReceiptSigningError::SigningFailed(reason) => reason,
        };
        KernelError::ReceiptSigningFailed(message)
    })
}

// ---------------------------------------------------------------------------
// CanonicalBytes consumer wiring for the hybrid signing path
// ---------------------------------------------------------------------------
//
// The `Arc<CanonicalBytes>` newtype lives at
// `chio_core_types::crypto::SharedCanonicalBytes` (already exported from
// `chio-core-types/src/canonical.rs`). The receipt-signing path under the
// hybrid backend consumes that newtype directly so the canonical JSON byte
// buffer is built once, hashed once for the classical half, and signed once
// for the ML-DSA-65 half. No byte-equivalence shim is required because the
// newtype is consumed directly rather than reserialized.
//
// The helper below returns the signed `ChioReceipt` paired with the
// `SharedCanonicalBytes` it signed, so downstream consumers (receipt store,
// federation cosign, lineage anchor) can persist or retransmit the EXACT
// bytes the signature was computed over without reserializing the body.

/// Receipt produced by the hybrid signing path together with the canonical
/// byte buffer that was signed.
///
/// Returned by [`sign_receipt_body_hybrid_canonical`] so callers can persist
/// or retransmit the exact bytes the signature was computed over without
/// reserializing the body. The buffer is wrapped in
/// [`SharedCanonicalBytes`] (which is `Arc<CanonicalBytes>`) so multiple
/// consumers downstream can share a single allocation.
#[derive(Clone, Debug)]
pub struct SignedHybridReceipt {
    /// The signed receipt envelope.
    pub receipt: ChioReceipt,
    /// The canonical JSON byte buffer that was signed. Wrapped in
    /// [`chio_core::crypto::SharedCanonicalBytes`] so multiple downstream
    /// consumers can share the allocation without copying or
    /// reserializing.
    pub canonical: chio_core::crypto::SharedCanonicalBytes,
}

/// Sign a [`ChioReceiptBody`] through a hybrid signing backend and return
/// both the signed [`ChioReceipt`] and the [`SharedCanonicalBytes`] that
/// were signed.
///
/// This is the shared-canonical-bytes entrypoint: the hybrid backend
/// (classical Ed25519 plus ML-DSA-65) is fed the `CanonicalBytes` newtype
/// directly so the canonical JSON byte buffer is built once, signed once, and
/// shared by every downstream consumer (storage, lineage anchor, federation
/// cosign).
///
/// # WYSIWYS recompute
///
/// `canonical_content` is the exact byte preimage the body's `content_hash` was
/// derived from (the same preimage the classical sibling
/// [`sign_receipt_body_with_backend`] takes). Before any cryptographic work this
/// helper recomputes `sha256_hex(canonical_content)` inside the trust boundary
/// and refuses to sign when it disagrees with `body.content_hash`
/// ([`KernelError::ReceiptSigningFailed`], fail-closed). The check reuses the
/// canonical WYSIWYS gate ([`ReceiptSigningHandle`]) so this shared-canonical
/// hybrid/PQ path is held to the same recompute-and-refuse contract as the
/// inline classical path, the mpsc signing task, and `sign_receipt_body_with_backend`.
/// This closes the render-A / sign-B forgery on the shared-canonical entrypoint
/// rather than leaving it as a caller-hash-trust seam. Callers that genuinely
/// cannot carry the content preimage must use
/// `chio_kernel_core::sign_receipt_relaying_trusted_body` (the explicit
/// trusted-relay seam); this content-bearing kernel wrapper is not that
/// seam.
///
/// # Authoritative signing input
///
/// The bytes signed are the canonical JSON encoding of the
/// [`chio_core::receipt::signing::ChioReceiptSigningBody`] wrapper, which binds
/// the content-addressed receipt id to the
/// [`chio_core::receipt::body::ChioReceiptIdInput`] that derived it. This is
/// the same byte sequence the classical sibling
/// [`sign_receipt_body_with_backend`] signs (it delegates to
/// [`chio_kernel_core::sign_receipt`] and then
/// [`chio_core::receipt::body::ChioReceipt::sign_with_backend`]). The two
/// paths produce byte-identical signed bytes for the same body and
/// backend.
///
/// # Trust-boundary discipline
///
/// - Fail-closed: if `body.kernel_key` does not match `backend.public_key()`
///   the helper returns [`KernelError::ReceiptSigningFailed`] without
///   touching the canonical buffer or producing a signature.
/// - Byte-identity: the `canonical` field of the returned
///   [`SignedHybridReceipt`] is the exact buffer the backend signed. A
///   downstream verifier MUST consume the same buffer via
///   [`chio_core::crypto::PublicKey::verify`] to keep the byte chain intact.
/// - Algorithm agnostic at the trait boundary: the helper accepts any
///   [`SigningBackend`] (Ed25519, P-256, P-384, or hybrid). When the
///   backend is the classical-only `Ed25519Backend` the canonical buffer
///   is still the exact bytes the `sign_with_backend` path signs,
///   so callers may treat this entrypoint as the canonical-bytes-aware
///   superset of the `sign_with_backend` path.
///
/// # Errors
///
/// Returns [`KernelError::ReceiptSigningFailed`] when:
/// - the body's claimed `content_hash` does not match
///   `sha256_hex(canonical_content)` (fail-closed: render-A / sign-B refused), OR
/// - `body.kernel_key` does not match the backend's public key, OR
/// - `body` fails semantic validation (see
///   [`chio_core::receipt::body::ChioReceiptBody::validate_signable_semantics`]),
///   OR
/// - canonical JSON encoding of the receipt id input or signing wrapper
///   fails, OR
/// - the signing backend itself rejects the message (for example, FIPS
///   ECDSA backends that fail to acquire OS randomness).
pub fn sign_receipt_body_hybrid_canonical(
    body: ChioReceiptBody,
    backend: &dyn chio_core::crypto::SigningBackend,
    canonical_content: &[u8],
) -> Result<SignedHybridReceipt, KernelError> {
    use chio_core::crypto::{
        canonical_json_shared_bytes, sign_shared_canonical_with_backend, PublicKey,
    };
    use chio_core::receipt::{
        body::chio_receipt_id, signing::bind_receipt_signing_nonce, signing::ChioReceiptSigningBody,
    };

    // WYSIWYS recompute-and-refuse FIRST, inside the trust boundary, before any
    // kernel-key check or cryptographic work. We recompute
    // `sha256_hex(canonical_content)` over the BORROWED preimage and refuse to
    // sign when it disagrees with the caller-supplied `body.content_hash`. This
    // is the same recompute-and-refuse gate `chio_kernel_core::sign_receipt`
    // applies (also from the borrowed slice), so the shared-canonical hybrid/PQ
    // path can no longer render content A while signing a body claiming the hash
    // of content B.
    //
    // hash the borrowed slice directly instead of
    // cloning it into a `ReceiptSigningHandle` via `to_vec()`. The preimage can
    // be up to the configured stream/output max (256 MiB); a transient clone
    // here doubled peak memory for no benefit, since the handle's only role on
    // this path is the recompute-and-compare the borrowed-slice form does
    // identically.
    let recomputed = chio_core::crypto::sha256_hex(canonical_content);
    if recomputed != body.content_hash {
        return Err(KernelError::ReceiptSigningFailed(format!(
            "receipt content_hash mismatch: body claimed {} but signer recomputed {} \
             over the canonical content (WYSIWYS refused)",
            body.content_hash, recomputed
        )));
    }

    // Fail-closed kernel-key match BEFORE any cryptographic work. Mirrors
    // `chio_kernel_core::sign_receipt` so the byte-identity contract holds
    // when callers route through either entrypoint.
    let backend_pk: PublicKey = backend.public_key();
    if body.kernel_key.algorithm() != backend_pk.algorithm() || body.kernel_key != backend_pk {
        return Err(KernelError::ReceiptSigningFailed(
            "kernel signing key does not match receipt body kernel_key".to_string(),
        ));
    }

    // Mirror the classical sibling path so the two entrypoints sign the
    // same authoritative `ChioReceiptSigningBody` wrapper (id plus
    // `ChioReceiptIdInput`). `ChioReceipt::sign_with_backend` performs
    // four steps: validate semantics, bind the canonical signing nonce
    // into metadata, compute the content-addressed id, and build the
    // wrapper. We replicate them here so the bytes the hybrid backend
    // signs are byte-identical to what the classical sibling signs for
    // the same body.
    let mut body = body;
    body.validate_signable_semantics().map_err(|error| {
        KernelError::ReceiptSigningFailed(format!(
            "receipt body failed semantic validation: {error}"
        ))
    })?;
    // Bind the signing nonce BEFORE computing the id, exactly as the
    // classical path does, so the content-addressed id (and therefore the
    // signed bytes) cover the nonce.
    bind_receipt_signing_nonce(&mut body);
    body.id = chio_receipt_id(&body).map_err(|error| {
        KernelError::ReceiptSigningFailed(format!(
            "canonical JSON encoding of receipt id input failed: {error}"
        ))
    })?;
    let signing_body = ChioReceiptSigningBody::from(&body);

    // Build the SharedCanonicalBytes once over the authoritative
    // signing wrapper. This is the byte buffer the classical half
    // hashes and the ML-DSA-65 half signs.
    let canonical = canonical_json_shared_bytes(&signing_body).map_err(|error| {
        KernelError::ReceiptSigningFailed(format!(
            "canonical JSON encoding of receipt signing body failed: {error}"
        ))
    })?;

    // Sign through the shared-bytes path so the backend is fed the EXACT
    // buffer downstream consumers will consume. `Arc::clone` keeps the
    // allocation; no second canonicalization happens.
    let signed =
        sign_shared_canonical_with_backend(backend, canonical.clone()).map_err(|error| {
            KernelError::ReceiptSigningFailed(format!("hybrid signing failed: {error}"))
        })?;
    let (signature, signed_canonical) = signed.into_parts();

    // Defence-in-depth: the buffer the backend signed MUST be the same
    // allocation we built above. `sign_shared_canonical_with_backend`
    // does not reserialize, but assert byte-equality so a future change
    // that reserializes silently fails this contract first.
    debug_assert_eq!(
        canonical.as_bytes(),
        signed_canonical.as_bytes(),
        "byte-identity drift: shared canonical bytes were re-encoded"
    );

    let receipt = ChioReceipt {
        id: body.id,
        timestamp: body.timestamp,
        capability_id: body.capability_id,
        tool_server: body.tool_server,
        tool_name: body.tool_name,
        action: body.action,
        decision: body.decision,
        receipt_kind: body.receipt_kind,
        boundary_class: body.boundary_class,
        observation_outcome: body.observation_outcome,
        tool_origin: body.tool_origin,
        redaction_mode: body.redaction_mode,
        actor_chain: body.actor_chain,
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
    };

    Ok(SignedHybridReceipt {
        receipt,
        canonical: signed_canonical,
    })
}

/// Errors raised when the kernel boot path constructs a receipt-signing
/// backend from a configured `crypto_floor` and provisioned key material.
///
/// These errors fire at signer construction time, before any receipt is
/// signed. The kernel boot path MUST surface the error and refuse to
/// start. Threat model row `pq_signature_downgrade` is the surface this
/// guards.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KernelSigningBackendError {
    /// `crypto_floor=allow_hybrid` or `crypto_floor=pq_required` was
    /// configured but no ML-DSA-65 key was provisioned. Fail-closed.
    #[error(
        "policy.crypto_floor={floor} requires a post-quantum (ML-DSA-65) signing key but \
         none was provisioned at kernel boot"
    )]
    HybridFloorRequiresPqKey {
        /// The floor that triggered the rejection.
        floor: &'static str,
    },

    /// The provisioned PQ key material could not be loaded into a
    /// signing backend.
    #[error("post-quantum signing key import failed: {reason}")]
    PqKeyImportFailed {
        /// The reason the key import failed.
        reason: String,
    },
}

/// Construct the kernel-side receipt signing backend from a configured
/// `crypto_floor` and the operator-provisioned key material.
///
/// Returns a boxed [`SigningBackend`] that the kernel calls through for
/// every receipt. Under [`KernelCryptoFloor::AllowClassical`] this is an
/// [`Ed25519Backend`] wrapping the classical [`Keypair`]; under
/// [`KernelCryptoFloor::AllowHybrid`] or [`KernelCryptoFloor::PqRequired`]
/// it is a [`HybridBackend`] composed of the same Ed25519 backend and an
/// [`MlDsa65Backend`] derived from `pq_seed`.
///
/// `pq_seed` is the 32-byte FIPS 204 keygen seed for the rolled
/// ML-DSA-65 key. Operators load it from the kernel boot environment
/// (HSM, sealed file, KMS); the seed never leaves the kernel process.
///
/// # Errors
///
/// Fails fast with [`KernelSigningBackendError::HybridFloorRequiresPqKey`]
/// if `crypto_floor` permits hybrid but `pq_seed` is `None`. This is the
/// same fail-closed behaviour that `chio_policy::CryptoFloor::validate_with_pq_key`
/// applies at policy load; checking it again at backend construction
/// catches any drift between the two enums.
#[cfg(feature = "pq")]
pub fn kernel_signing_backend(
    crypto_floor: KernelCryptoFloor,
    classical_keypair: Keypair,
    pq_seed: Option<&[u8; 32]>,
) -> Result<Box<dyn chio_core::crypto::SigningBackend>, KernelSigningBackendError> {
    use chio_core::crypto::{Ed25519Backend, HybridBackend, MlDsa65Backend};

    let classical = Ed25519Backend::new(classical_keypair);

    if !crypto_floor.allows_hybrid() {
        return Ok(Box::new(classical));
    }

    let seed = pq_seed.ok_or(KernelSigningBackendError::HybridFloorRequiresPqKey {
        floor: crypto_floor.as_str(),
    })?;
    let pq = MlDsa65Backend::from_seed(seed);
    let hybrid = HybridBackend::new(Box::new(classical), pq).map_err(|error| {
        KernelSigningBackendError::PqKeyImportFailed {
            reason: error.to_string(),
        }
    })?;
    Ok(Box::new(hybrid))
}

/// Construct the kernel-side receipt signing backend without the `pq`
/// feature.
///
/// Without the `pq` feature, only [`KernelCryptoFloor::AllowClassical`] is
/// constructible; any other floor returns
/// [`KernelSigningBackendError::HybridFloorRequiresPqKey`]. This preserves
/// the fail-closed contract for default builds.
#[cfg(not(feature = "pq"))]
pub fn kernel_signing_backend(
    crypto_floor: KernelCryptoFloor,
    classical_keypair: Keypair,
    _pq_seed: Option<&[u8; 32]>,
) -> Result<Box<dyn chio_core::crypto::SigningBackend>, KernelSigningBackendError> {
    use chio_core::crypto::Ed25519Backend;

    if crypto_floor.allows_hybrid() {
        return Err(KernelSigningBackendError::HybridFloorRequiresPqKey {
            floor: crypto_floor.as_str(),
        });
    }
    Ok(Box::new(Ed25519Backend::new(classical_keypair)))
}

#[cfg(test)]
mod borrowed_preimage_tests {
    //! the hybrid/PQ shared-canonical path recomputes
    //! `sha256_hex(canonical_content)` from the BORROWED preimage slice (no
    //! `to_vec()` clone) before any signing work, so render-A / sign-B is still
    //! refused fail-closed. These run under a classical Ed25519 backend so they
    //! exercise the borrowed-slice recompute without the `pq` feature (the
    //! helper accepts any `SigningBackend`).
    use chio_core::crypto::{Ed25519Backend, Keypair};
    use chio_core::receipt::body::ChioReceiptBody;
    use chio_core::receipt::decision::{Decision, ToolCallAction};
    use chio_core::receipt::kinds::TrustLevel;

    use super::sign_receipt_body_hybrid_canonical;
    use crate::KernelError;

    const PREIMAGE: &[u8] = br#"{"q":"borrowed-preimage"}"#;

    fn seed() -> [u8; 32] {
        let raw = b"chio-borrowed-preimage-test-seed";
        let mut out = [0u8; 32];
        out.copy_from_slice(raw);
        out
    }

    fn body_for(kernel_key: chio_core::crypto::PublicKey, content_hash: String) -> ChioReceiptBody {
        ChioReceiptBody {
            id: "rcpt-borrowed-preimage".to_string(),
            timestamp: 1_700_000_010,
            capability_id: "cap-borrowed".to_string(),
            tool_server: "audit-server".to_string(),
            tool_name: "report".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"q": "borrowed-preimage"}))
                .expect("action canonicalises"),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash,
            policy_hash: "policy-borrowed".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key,
            bbs_projection_version: None,
        }
    }

    #[test]
    fn borrowed_hash_path_signs_matching_body() {
        // A body whose claimed `content_hash` matches the borrowed preimage must
        // sign: the borrowed-slice recompute agrees, so the (previously cloned)
        // hash check still admits the legitimate receipt.
        let kp = Keypair::from_seed(&seed());
        let backend = Ed25519Backend::new(kp.clone());
        let body = body_for(kp.public_key(), chio_core::crypto::sha256_hex(PREIMAGE));

        let signed = sign_receipt_body_hybrid_canonical(body, &backend, PREIMAGE)
            .expect("matching body must sign through the borrowed-slice recompute path");
        assert!(
            signed
                .receipt
                .kernel_key
                .verify(signed.canonical.as_bytes(), &signed.receipt.signature),
            "produced signature must verify over the exact signed bytes"
        );
    }

    #[test]
    fn borrowed_hash_path_refuses_render_a_sign_b() {
        // WYSIWYS: the body binds `content_hash` to PREIMAGE but the
        // signer is handed a DIFFERENT preimage. The borrowed-slice recompute
        // must disagree and refuse, proving the clone-free hash check still
        // recomputes-and-refuses (case 4 must not weaken the gate).
        let kp = Keypair::from_seed(&seed());
        let backend = Ed25519Backend::new(kp.clone());
        let body = body_for(kp.public_key(), chio_core::crypto::sha256_hex(PREIMAGE));
        let attacker_preimage = br#"{"q":"a-different-thing"}"#;

        let err = sign_receipt_body_hybrid_canonical(body, &backend, attacker_preimage)
            .expect_err("render-A / sign-B must fail closed on the borrowed-slice path");
        match err {
            KernelError::ReceiptSigningFailed(message) => {
                assert!(
                    message.contains("content_hash mismatch")
                        && message.contains("WYSIWYS refused"),
                    "expected WYSIWYS content-hash mismatch diagnostic, got {message}"
                );
            }
            other => panic!("expected ReceiptSigningFailed, got {other:?}"),
        }
    }
}
