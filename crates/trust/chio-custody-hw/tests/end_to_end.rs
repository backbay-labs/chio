//! End-to-end issuer-to-kernel flow.
//!
//! Walks the entire custody trust boundary in one fixture:
//!
//! 1. Issuer is configured with a HybridBackend-style signer
//!    (Ed25519 under the classical-floor configuration), an
//!    InMemoryPasskeyNonceStore, and an
//!    InMemoryCredentialRevocationOracle.
//! 2. A verified WebAuthn assertion arrives; the issuer mints a signed,
//!    audience-pinned capability.
//! 3. The kernel-side verifier accepts the capability.
//! 4. Operator revokes the WebAuthn credential at the revocation oracle.
//! 5. A subsequent mint attempt for the same credential is denied
//!    fail-closed within the same oracle epoch, AND the kernel verifier
//!    keeps accepting the previously-minted (still-live) capability
//!    because the cascade is a custody-side gate, not a kernel-side
//!    gate. The kernel-side cascade is exercised by an explicit oracle
//!    consultation hook.

use std::sync::Arc;

use chio_core_types::crypto::{Ed25519Backend, Keypair, SigningBackend};
use chio_custody_hw::capability::ScopeSet;
use chio_custody_hw::error::CustodyError;
use chio_custody_hw::issuer::{IssuerService, MintRequest};
use chio_custody_hw::nonce_store::{InMemoryPasskeyNonceStore, PasskeyNonceStore};
use chio_custody_hw::revocation::{CredentialRevocationOracle, InMemoryCredentialRevocationOracle};
use chio_custody_hw::verifier::VerifiedAssertion;
use chrono::{TimeZone, Utc};

const AUDIENCE: &str = "urn:chio:audience:kernel";

fn fixed_now() -> chrono::DateTime<Utc> {
    match Utc.with_ymd_and_hms(2026, 4, 29, 12, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => panic!("fixed_now fixture must construct"),
    }
}

fn assertion(cred: &str) -> VerifiedAssertion {
    VerifiedAssertion {
        credential_id_b64: cred.into(),
        user_verified: true,
    }
}

fn request(nonce: &str) -> MintRequest {
    MintRequest {
        audience: AUDIENCE.into(),
        scope_set: ScopeSet::new(["tool:read"]),
        challenge_nonce: nonce.into(),
    }
}

/// Standalone re-implementation of the kernel verifier so the e2e test
/// can live in chio-custody-hw without taking a circular dep on
/// chio-kernel. This mirrors the four-gate behaviour exercised by
/// crates/kernel/chio-kernel/tests/passkey_capability_dispatch.rs:
///
/// - empty signatures NEVER verify,
/// - audience must match,
/// - now < exp,
/// - signature verifies under issuer public key over signing_message.
mod kernel_shim {
    use chio_core_types::crypto::{PublicKey, Signature};
    use chio_custody_hw::capability::PasskeyCapability;
    use chio_custody_hw::error::CustodyError;
    use chio_custody_hw::mint::signing_message;
    use chrono::{DateTime, Utc};

    pub struct KernelVerifier {
        pub audience: String,
        pub issuer_public_key: PublicKey,
    }

    impl KernelVerifier {
        pub fn verify(
            &self,
            cap: &PasskeyCapability,
            now: DateTime<Utc>,
        ) -> Result<(), CustodyError> {
            if cap.signature.is_empty() {
                return Err(CustodyError::AssertionRejected("empty signature".into()));
            }
            cap.require_audience(&self.audience)?;
            cap.require_live(now)?;
            let message = signing_message(cap)?;
            let signature = Signature::from_hex(&cap.signature)
                .map_err(|err| CustodyError::AssertionRejected(format!("hex decode: {err}")))?;
            if !self.issuer_public_key.verify(&message, &signature) {
                return Err(CustodyError::AssertionRejected("bad signature".into()));
            }
            Ok(())
        }
    }
}

#[test]
fn passkey_to_capability_to_kernel_call_then_revoke_within_one_epoch() {
    // Stage 1: assemble the issuer with all three security surfaces
    // (signer, replay nonce store, revocation cascade).
    let backend = Ed25519Backend::new(Keypair::from_seed(&[71u8; 32]));
    let issuer_public = backend.public_key();
    let signer: Arc<dyn SigningBackend> = Arc::new(backend);
    let nonce_store: Arc<dyn PasskeyNonceStore> = Arc::new(InMemoryPasskeyNonceStore::new());
    let oracle = Arc::new(InMemoryCredentialRevocationOracle::new());
    let oracle_dyn: Arc<dyn CredentialRevocationOracle> = oracle.clone();
    let issuer = IssuerService::with_signer(AUDIENCE, signer)
        .with_nonce_store(nonce_store)
        .with_revocation_oracle(oracle_dyn);

    let kernel = kernel_shim::KernelVerifier {
        audience: AUDIENCE.into(),
        issuer_public_key: issuer_public,
    };

    // Stage 2: passkey assertion -> capability mint.
    let cred = "cred-AAAA";
    let pre_root = match oracle.current_epoch_root() {
        Ok(r) => r,
        Err(e) => panic!("epoch root pre: {e}"),
    };
    let mint_resp = match issuer.mint_capability(&assertion(cred), &request("n-1"), fixed_now()) {
        Ok(r) => r,
        Err(e) => panic!("first mint must succeed: {e}"),
    };
    let cap = mint_resp.capability;

    // Stage 3: kernel call accepts the freshly-minted capability.
    if let Err(e) = kernel.verify(&cap, fixed_now()) {
        panic!("kernel must accept fresh capability: {e}");
    }

    // Stage 4: operator revokes the WebAuthn credential through the
    // revocation cascade.
    let post_root = match oracle.revoke_credential(cred, 1_000) {
        Ok(r) => r,
        Err(e) => panic!("revoke: {e}"),
    };
    assert!(
        post_root.epoch > pre_root.epoch,
        "revocation oracle epoch MUST advance on revocation"
    );

    // Stage 5: a subsequent mint within the new epoch is denied
    // fail-closed.
    let res = issuer.mint_capability(&assertion(cred), &request("n-2"), fixed_now());
    let err = match res {
        Ok(_) => panic!("post-revocation mint MUST fail-closed"),
        Err(e) => e,
    };
    assert!(matches!(err, CustodyError::CredentialRevoked));
    assert_eq!(err.urn(), "urn:chio:error:custody:credential-revoked");

    // Stage 6: the previously-minted capability remains
    // cryptographically valid because the kernel-side verifier does
    // NOT reach into the custody oracle (the cascade is on the issuer
    // mint path; the kernel checks the capability's own bindings).
    // This is the documented split of responsibility: revocation
    // prevents NEW capabilities, not in-flight ones whose lifetime is
    // bounded to 5 minutes.
    if let Err(e) = kernel.verify(&cap, fixed_now()) {
        panic!("kernel MUST keep accepting the previously-minted capability: {e}");
    }
}

#[test]
fn replay_of_minted_capability_is_blocked_by_nonce_store() {
    // Drives both the nonce store (replay rejection) and the kernel
    // (still-valid first-mint capability accepted) through the issuer
    // surface.
    let backend = Ed25519Backend::new(Keypair::from_seed(&[83u8; 32]));
    let issuer_public = backend.public_key();
    let signer: Arc<dyn SigningBackend> = Arc::new(backend);
    let nonce_store: Arc<dyn PasskeyNonceStore> = Arc::new(InMemoryPasskeyNonceStore::new());
    let issuer = IssuerService::with_signer(AUDIENCE, signer).with_nonce_store(nonce_store);

    let kernel = kernel_shim::KernelVerifier {
        audience: AUDIENCE.into(),
        issuer_public_key: issuer_public,
    };

    let req = request("e2e-replay");
    let mint_a = match issuer.mint_capability(&assertion("cred-r"), &req, fixed_now()) {
        Ok(r) => r,
        Err(e) => panic!("first mint must succeed: {e}"),
    };
    if let Err(e) = kernel.verify(&mint_a.capability, fixed_now()) {
        panic!("kernel must accept first capability: {e}");
    }

    let mint_b = issuer.mint_capability(&assertion("cred-r"), &req, fixed_now());
    let err = match mint_b {
        Ok(_) => panic!("second mint with same nonce MUST fail-closed as replay"),
        Err(e) => e,
    };
    assert!(matches!(err, CustodyError::ReplayDetected { .. }));
}
