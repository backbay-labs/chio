//! Revocation-cascade integration coverage.
//!
//! Invariant: revoking the WebAuthn credential at the issuer denies the
//! next call within one revocation-oracle epoch. These tests assert that
//! invariant end to end through the issuer mint surface.

use std::sync::Arc;

use chio_core_types::crypto::{Ed25519Backend, Keypair, SigningBackend};
use chio_custody_hw::capability::ScopeSet;
use chio_custody_hw::error::CustodyError;
use chio_custody_hw::issuer::{IssuerService, MintRequest};
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

fn signer() -> Arc<dyn SigningBackend> {
    Arc::new(Ed25519Backend::new(Keypair::from_seed(&[37u8; 32])))
}

fn issuer_with_oracle(oracle: Arc<dyn CredentialRevocationOracle>) -> IssuerService {
    IssuerService::with_signer(AUDIENCE, signer()).with_revocation_oracle(oracle)
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

#[test]
fn pre_revocation_mint_succeeds() {
    let oracle: Arc<dyn CredentialRevocationOracle> =
        Arc::new(InMemoryCredentialRevocationOracle::new());
    let svc = issuer_with_oracle(oracle);
    let req = request("n-pre");
    let res = svc.mint_capability(&assertion("cred-X"), &req, fixed_now());
    assert!(
        res.is_ok(),
        "pre-revocation mint must succeed under a fresh oracle"
    );
}

#[test]
fn post_revocation_next_mint_denied_within_epoch() {
    // The cascade contract: revoking the WebAuthn credential at the
    // issuer denies the next call within an oracle epoch. We assert that
    // by revoking and then attempting a new mint with a different
    // nonce (so the deny path is the cascade, not the replay store).
    let oracle = Arc::new(InMemoryCredentialRevocationOracle::new());
    let oracle_dyn: Arc<dyn CredentialRevocationOracle> = oracle.clone();
    let svc = issuer_with_oracle(oracle_dyn);

    let pre_root = match oracle.current_epoch_root() {
        Ok(r) => r,
        Err(e) => panic!("epoch root pre: {e}"),
    };
    let pre_mint = svc.mint_capability(&assertion("cred-X"), &request("n-1"), fixed_now());
    assert!(pre_mint.is_ok(), "first mint must succeed");

    // Operator revokes the credential through the cascade.
    let post_root = match oracle.revoke_credential("cred-X", 1_000) {
        Ok(r) => r,
        Err(e) => panic!("revoke must succeed: {e}"),
    };
    assert!(
        post_root.epoch > pre_root.epoch,
        "revocation oracle epoch must advance on revocation"
    );

    // Next mint within the new epoch is denied fail-closed.
    let res = svc.mint_capability(&assertion("cred-X"), &request("n-2"), fixed_now());
    let err = match res {
        Ok(_) => panic!("post-revocation mint MUST fail-closed"),
        Err(e) => e,
    };
    assert!(matches!(err, CustodyError::CredentialRevoked));
    assert_eq!(err.urn(), "urn:chio:error:custody:credential-revoked");
}

#[test]
fn revocation_does_not_cascade_across_credentials() {
    let oracle = Arc::new(InMemoryCredentialRevocationOracle::new());
    let oracle_dyn: Arc<dyn CredentialRevocationOracle> = oracle.clone();
    let svc = issuer_with_oracle(oracle_dyn);

    if let Err(e) = oracle.revoke_credential("cred-A", 1_000) {
        panic!("revoke A: {e}");
    }
    let a = svc.mint_capability(&assertion("cred-A"), &request("nA"), fixed_now());
    let b = svc.mint_capability(&assertion("cred-B"), &request("nB"), fixed_now());
    assert!(matches!(a, Err(CustodyError::CredentialRevoked)));
    assert!(
        b.is_ok(),
        "revocation must not cascade across credentials in the same oracle epoch"
    );
}

#[test]
fn revocation_check_runs_before_nonce_recording() {
    // A revoked credential must NOT consume a nonce-store slot. This
    // matters because the operator-facing UX should not see "you used
    // a nonce on a revoked credential" replay errors when the
    // credential should have been denied outright.
    use chio_custody_hw::nonce_store::{InMemoryPasskeyNonceStore, PasskeyNonceStore};
    let oracle = Arc::new(InMemoryCredentialRevocationOracle::new());
    let oracle_dyn: Arc<dyn CredentialRevocationOracle> = oracle.clone();
    let nonce_store: Arc<dyn PasskeyNonceStore> = Arc::new(InMemoryPasskeyNonceStore::new());
    let nonce_obs = nonce_store.clone();
    let svc = IssuerService::with_signer(AUDIENCE, signer())
        .with_revocation_oracle(oracle_dyn)
        .with_nonce_store(nonce_store);

    if let Err(e) = oracle.revoke_credential("cred-Z", 1_000) {
        panic!("revoke: {e}");
    }
    let res = svc.mint_capability(&assertion("cred-Z"), &request("nZ"), fixed_now());
    assert!(matches!(res, Err(CustodyError::CredentialRevoked)));
    let len = match nonce_obs.len() {
        Ok(n) => n,
        Err(e) => panic!("nonce store len: {e}"),
    };
    assert_eq!(
        len, 0,
        "revocation must short-circuit before nonce-store consumption"
    );
}

#[test]
fn double_revocation_is_idempotent_for_operator_retry() {
    let oracle = InMemoryCredentialRevocationOracle::new();
    let r1 = match oracle.revoke_credential("cred-rep", 1_000) {
        Ok(r) => r,
        Err(e) => panic!("first revoke: {e}"),
    };
    let r2 = match oracle.revoke_credential("cred-rep", 2_000) {
        Ok(r) => r,
        Err(e) => panic!("second revoke must be idempotent: {e}"),
    };
    assert_eq!(
        r1, r2,
        "operator-side retries must not advance the oracle epoch"
    );
}
