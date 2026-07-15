//! Kernel boot path: PQ signing key loads ONLY after a self-quote binds
//! to `expect_report_data(kernel_classical_pk, receipt_root_genesis)`.
//!
//! Three contracts pinned here:
//!
//! 1. **Classical-only floor skips the verifier.** Under
//!    `crypto_floor=allow_classical` the boot path must NOT consult the
//!    verifier; deployments that have not provisioned a TEE container
//!    keep working.
//! 2. **Verified self-quote unlocks the hybrid backend.** Under
//!    `crypto_floor=allow_hybrid` and `crypto_floor=pq_required` the
//!    boot path consults the verifier first and only materializes the
//!    hybrid backend on success. The resulting backend reports
//!    [`SigningAlgorithm::Hybrid`].
//! 3. **Rejected self-quote refuses the load fail-closed.** A verifier
//!    that returns `verified=false` causes
//!    [`KernelBootError::SelfQuoteRejected`] without ever deriving the
//!    PQ key. The diagnostic propagates so the operator log can carry
//!    the cause.
//!
//! Threat-model row `pq_signature_downgrade` is the surface this guards.
//! Trust boundary: PQ key load after kernel self-quote.

#![cfg(feature = "pq")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chio_core::crypto::{Keypair, PublicKey, SigningAlgorithm};
use chio_kernel::boot::{
    load_kernel_signing_backend_after_self_quote, KernelBootError, KernelSelfQuoteOutcome,
    KernelSelfQuoteVerifier, RECEIPT_ROOT_GENESIS,
};
use chio_kernel::{
    ChioKernel, HybridSigningConfig, KernelConfig, KernelCryptoFloor, KernelSigningBackendError,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};

/// Mock verifier that always accepts. Captures the classical public key
/// it was asked about so the test can assert the boot path threaded the
/// kernel identity in.
struct AcceptingVerifier {
    seen_classical_pk: Arc<std::sync::Mutex<Option<PublicKey>>>,
    seen_quote_len: Arc<AtomicUsize>,
    call_count: Arc<AtomicUsize>,
}

impl AcceptingVerifier {
    fn new() -> Self {
        Self {
            seen_classical_pk: Arc::new(std::sync::Mutex::new(None)),
            seen_quote_len: Arc::new(AtomicUsize::new(0)),
            call_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl KernelSelfQuoteVerifier for AcceptingVerifier {
    fn verify_self_quote(
        &self,
        quote_bytes: &[u8],
        expected_classical_pk: &PublicKey,
    ) -> KernelSelfQuoteOutcome {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        self.seen_quote_len
            .store(quote_bytes.len(), Ordering::SeqCst);
        let mut slot = self.seen_classical_pk.lock().unwrap();
        *slot = Some(expected_classical_pk.clone());
        KernelSelfQuoteOutcome::accepted()
    }
}

/// Mock verifier that always rejects with a fixed diagnostic.
struct RejectingVerifier {
    diagnostic: &'static str,
    call_count: Arc<AtomicUsize>,
}

impl RejectingVerifier {
    fn new(diagnostic: &'static str) -> Self {
        Self {
            diagnostic,
            call_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl KernelSelfQuoteVerifier for RejectingVerifier {
    fn verify_self_quote(
        &self,
        _quote_bytes: &[u8],
        _expected_classical_pk: &PublicKey,
    ) -> KernelSelfQuoteOutcome {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        KernelSelfQuoteOutcome::rejected(self.diagnostic)
    }
}

/// Verifier that panics if invoked. Used to prove the classical floor
/// path skips the verifier entirely.
struct PanicVerifier;

impl KernelSelfQuoteVerifier for PanicVerifier {
    fn verify_self_quote(
        &self,
        _quote_bytes: &[u8],
        _expected_classical_pk: &PublicKey,
    ) -> KernelSelfQuoteOutcome {
        panic!("classical floor must not consult the self-quote verifier");
    }
}

fn fixture_pq_seed() -> [u8; 32] {
    let raw = b"chio-bootpath-pq-self-quote-seed";
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

fn kernel_config(keypair: Keypair) -> KernelConfig {
    KernelConfig {
        keypair,
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "policy-hash".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    }
}

#[test]
fn allow_classical_skips_verifier_and_returns_classical_backend() {
    // Contract 1: the classical floor never consults the verifier.
    let kp = Keypair::generate();
    let backend = load_kernel_signing_backend_after_self_quote(
        KernelCryptoFloor::AllowClassical,
        kp.clone(),
        None,
        b"unused-quote-bytes",
        &PanicVerifier,
    )
    .expect("classical floor must succeed without a verifier call");
    assert_eq!(backend.algorithm(), SigningAlgorithm::Ed25519);
    assert_eq!(backend.public_key(), kp.public_key());
}

#[test]
fn allow_hybrid_loads_pq_only_after_verified_self_quote() {
    // Contract 2: the hybrid floor consults the verifier first and only
    // materializes the PQ key after a verified self-quote.
    let kp = Keypair::generate();
    let classical_pk = kp.public_key();
    let verifier = AcceptingVerifier::new();
    let seen_pk = verifier.seen_classical_pk.clone();
    let seen_len = verifier.seen_quote_len.clone();
    let calls = verifier.call_count.clone();
    let pq_seed = fixture_pq_seed();

    let backend = load_kernel_signing_backend_after_self_quote(
        KernelCryptoFloor::AllowHybrid,
        kp,
        Some(&pq_seed),
        b"fake-self-quote-bytes",
        &verifier,
    )
    .expect("verified self-quote must unlock the hybrid backend");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "verifier MUST be called exactly once"
    );
    assert_eq!(
        seen_len.load(Ordering::SeqCst),
        b"fake-self-quote-bytes".len()
    );
    let seen_pk_value = seen_pk.lock().unwrap();
    assert_eq!(
        seen_pk_value.as_ref().expect("verifier saw kernel pk"),
        &classical_pk,
        "boot path MUST thread the classical kernel public key into the verifier"
    );
    assert_eq!(backend.algorithm(), SigningAlgorithm::Hybrid);
}

#[test]
fn pq_required_loads_pq_only_after_verified_self_quote() {
    // Contract 2 (pq_required half): pq_required also consults the
    // verifier first and produces a hybrid backend on success.
    let kp = Keypair::generate();
    let verifier = AcceptingVerifier::new();
    let calls = verifier.call_count.clone();
    let pq_seed = fixture_pq_seed();

    let backend = load_kernel_signing_backend_after_self_quote(
        KernelCryptoFloor::PqRequired,
        kp,
        Some(&pq_seed),
        b"fake-self-quote-bytes",
        &verifier,
    )
    .expect("pq_required must unlock the hybrid backend on a verified self-quote");
    assert_eq!(backend.algorithm(), SigningAlgorithm::Hybrid);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn kernel_helper_routes_hybrid_signing_through_self_quote_gate() {
    let kp = Keypair::generate();
    let classical_pk = kp.public_key();
    let mut kernel = ChioKernel::new(kernel_config(kp));
    let verifier = AcceptingVerifier::new();
    let seen_pk = verifier.seen_classical_pk.clone();
    let calls = verifier.call_count.clone();
    let pq_seed = fixture_pq_seed();
    let hybrid = HybridSigningConfig {
        crypto_floor: KernelCryptoFloor::AllowHybrid,
        pq_signing_seed: Some(pq_seed),
    };

    let backend = kernel
        .with_hybrid_signing_backend(&hybrid, b"kernel-self-quote", &verifier)
        .expect("kernel helper must unlock hybrid backend after self-quote");

    assert_eq!(backend.algorithm(), SigningAlgorithm::Hybrid);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let seen_pk_value = seen_pk.lock().unwrap();
    assert_eq!(
        seen_pk_value.as_ref().expect("verifier saw kernel pk"),
        &classical_pk,
        "kernel helper MUST thread the classical kernel public key into the verifier"
    );
}

#[test]
fn kernel_helper_rejects_hybrid_signing_when_self_quote_rejects() {
    let kp = Keypair::generate();
    let mut kernel = ChioKernel::new(kernel_config(kp));
    let verifier = RejectingVerifier::new("self-quote-report-data-mismatch");
    let pq_seed = fixture_pq_seed();
    let hybrid = HybridSigningConfig {
        crypto_floor: KernelCryptoFloor::PqRequired,
        pq_signing_seed: Some(pq_seed),
    };

    let result = kernel.with_hybrid_signing_backend(&hybrid, b"bad-self-quote", &verifier);

    match result {
        Err(KernelBootError::SelfQuoteRejected { diagnostic }) => {
            assert_eq!(diagnostic, "self-quote-report-data-mismatch");
        }
        Ok(_) => panic!("kernel helper MUST NOT load PQ material after rejected self-quote"),
        Err(other) => panic!("expected SelfQuoteRejected, got {other:?}"),
    }
}

#[test]
fn rejected_self_quote_refuses_to_load_pq_key() {
    // Contract 3: the boot path rejects fail-closed when the verifier
    // refuses the self-quote, propagating the diagnostic for the
    // operator log.
    let kp = Keypair::generate();
    let verifier = RejectingVerifier::new("collateral-chain-stale");
    let calls = verifier.call_count.clone();
    let pq_seed = fixture_pq_seed();

    let result = load_kernel_signing_backend_after_self_quote(
        KernelCryptoFloor::AllowHybrid,
        kp,
        Some(&pq_seed),
        b"fake-self-quote-bytes",
        &verifier,
    );
    let err = match result {
        Ok(_) => panic!("rejected self-quote MUST refuse the hybrid load"),
        Err(err) => err,
    };

    match err {
        KernelBootError::SelfQuoteRejected { diagnostic } => {
            assert_eq!(diagnostic, "collateral-chain-stale");
        }
        other => panic!("expected SelfQuoteRejected, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn missing_pq_seed_fails_at_construction_after_verified_quote() {
    // Even a verified self-quote does not paper over a misconfigured
    // floor: pq_required without a PQ seed must still fail-closed at
    // backend construction.
    let kp = Keypair::generate();
    let verifier = AcceptingVerifier::new();

    let result = load_kernel_signing_backend_after_self_quote(
        KernelCryptoFloor::PqRequired,
        kp,
        None,
        b"fake-self-quote-bytes",
        &verifier,
    );
    let err = match result {
        Ok(_) => panic!("pq_required with no PQ seed MUST fail-closed"),
        Err(err) => err,
    };

    match err {
        KernelBootError::SigningBackend(KernelSigningBackendError::HybridFloorRequiresPqKey {
            floor,
        }) => {
            assert_eq!(floor, "pq_required");
        }
        other => panic!("expected SigningBackend::HybridFloorRequiresPqKey, got {other:?}"),
    }
}

#[test]
fn receipt_root_genesis_is_all_zero_sentinel() {
    // receipt_root_genesis is pinned as the all-zero 32-byte sentinel.
    // Lock the constant here so an unintentional bump fails this test
    // first.
    assert_eq!(RECEIPT_ROOT_GENESIS, [0u8; 32]);
}
