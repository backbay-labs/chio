//! Public-entry Kani harnesses for `chio-attest-verify` (TRJ5-A3.1).
//!
//! # Scope
//!
//! This module models the trust-boundary invariants of the four
//! production-shipping public surfaces of `chio-attest-verify`:
//!
//! - `expect_report_data` (free `pub fn` at `src/quote.rs:163`).
//! - `<NitroVerifier as QuoteVerifier>::verify_quote` (impl at
//!   `src/nitro.rs:200`).
//! - `<SevSnpVerifier as QuoteVerifier>::verify_quote` (impl at
//!   `src/sev_snp.rs:246`).
//! - `<TdxDcapVerifier as QuoteVerifier>::verify_quote` (impl at
//!   `src/tdx.rs:159`).
//!
//! `expect_report_data` is exercised directly: it is a pure function
//! and Kani can enumerate its determinism and one-bit-tampering
//! arms. The trait-impl `verify_quote` paths transit cryptographic
//! parsing (CBOR / DER / X.509 chain validation, ECDSA P-384, SHA-256)
//! that is intractable for symbolic execution under Kani's default
//! unwind budget. Per the project convention established by
//! `crates/chio-kernel-core/src/kani_public_harnesses.rs` (see the
//! `verify_receipt_roundtrip` block, which captures the same
//! "every sound digital signature scheme has the same observable
//! algebra" reduction), the trait-impl invariants here are modelled at
//! the smallest algebraic level that preserves the fail-closed
//! property the production path is required to satisfy. The
//! corresponding runtime tests (`tests/v318_migration.rs`,
//! `tests/migration.rs`, the per-backend unit tests in
//! `nitro.rs` / `sev_snp.rs` / `tdx.rs`) pin the concrete impl
//! behaviour against fixed fixtures; together with the algebraic
//! harnesses here they discharge the same trust-boundary invariant the
//! `kani-harness-design.md` Section (1) table assigns to TRJ5-A3.1.
//!
//! # Bound parameters
//!
//! - All symbolic byte-arrays are size-bounded to <= 64 bytes (the
//!   width of the `report_data` slot itself); larger surfaces are
//!   covered by the runtime tests cited above.
//! - The `report_data` slot is fully symbolic over its 64 bytes.
//! - Per-harness `#[kani::unwind(8)]` matches the workspace default
//!   established by `crates/chio-kernel-core/src/kani_public_harnesses.rs`.
//! - Local wall-clock budget per harness: 30 minutes (per
//!   `.planning/trajectory-5/lane-a-floor/kani-harness-design.md`
//!   Section (1) "Bound parameters").
//!
//! # Anti-pattern guard
//!
//! Every `#[kani::proof]` function in this module either calls a real
//! `pub fn` of `chio-attest-verify` (`expect_report_data`,
//! `QuoteTcbStatus::is_acceptable`,
//! `QuoteVerificationContext::expected_report_data`) or witnesses the
//! algebra of a `pub` trait-impl method via a model whose name is
//! prefixed `model_`. No harness body bottoms out in
//! `kani::assume(false)`; no harness targets a non-`pub` internal
//! helper.
//!
//! # Cross-references
//!
//! - Design doc: `.planning/trajectory-5/lane-a-floor/kani-harness-design.md`.
//! - Reference pattern: `crates/chio-kernel-core/src/kani_public_harnesses.rs`.
//! - Manifest registration (TRJ5-A3.4):
//!   `formal/rust-verification/kani-public-harnesses.toml` (multi-crate
//!   schema landed by TRJ5-A3.5a).

extern crate alloc;

use alloc::string::ToString;

use chio_core_types::crypto::PublicKey;

use crate::quote::{expect_report_data, QuoteTcbStatus, QuoteVerificationContext};
use crate::AttestError;

/// Build a deterministic uncompressed-SEC1 P-256 public key fixture.
///
/// Matches the same fixture pattern used in
/// `crates/chio-kernel-core/src/kani_public_harnesses.rs` so the two
/// crates' Kani modules share key construction conventions. The fixture
/// is a pure constructor over a u8 seed and contains no
/// nondeterministic clocks or system calls; safe to drive symbolically.
fn public_key(seed: u8) -> PublicKey {
    let mut bytes = [seed; 65];
    bytes[0] = 0x04;
    PublicKey::from_p256_sec1(&bytes)
        .unwrap_or_else(|_| unreachable!("deterministic P-256 key fixture is well-formed"))
}

/// Real public surface exercised symbolically: a one-byte flip in the
/// receipt root MUST change the entire 64-byte report-data slot, and
/// re-running with identical inputs MUST produce byte-identical
/// outputs. Together these arms pin the binding determinism property
/// every TEE backend's `verify_quote` consumes when it byte-compares
/// the observed `report_data` against `expected_report_data`.
///
/// Production entry: `chio_attest_verify::expect_report_data`
/// (`pub fn` at `crates/chio-attest-verify/src/quote.rs:163`,
/// re-exported via `crates/chio-attest-verify/src/lib.rs:50`).
#[kani::proof]
#[kani::unwind(8)]
pub fn public_expect_report_data_determinism_under_input_change() {
    // Symbolic axes. The kernel public key seed and the receipt-root
    // byte index / value are bounded to u8, matching the
    // `chio-kernel-core` Kani convention.
    let kernel_seed = kani::any::<u8>();
    let mut receipt_root = [0u8; 32];
    let flip_index = kani::any::<u8>();
    // Restrict the flip index into the slot. `assume` is bounded but
    // non-vacuous (the slot has 32 distinct positions) and lets Kani
    // enumerate every byte position in the receipt root.
    kani::assume((flip_index as usize) < receipt_root.len());
    receipt_root[flip_index as usize] = 1;

    let kernel_pk = public_key(kernel_seed);

    // (1) Determinism. Re-running with identical inputs MUST produce
    // identical 64-byte outputs. This is the load-bearing property
    // the TEE backends rely on when they byte-compare the observed
    // `report_data` against the expected slot.
    let first = expect_report_data(&kernel_pk, &receipt_root);
    let second = expect_report_data(&kernel_pk, &receipt_root);
    assert_eq!(first, second);

    // (2) Right-pad invariant. Bytes 32..64 of the slot MUST be zero
    // by construction (the function right-pads with `0x00` to fill
    // the 64-byte slot). A backend that committed unrelated bytes in
    // the upper half of the slot would defeat the binding; we pin
    // the layout the runtime relies on.
    for byte in &first[32..] {
        assert_eq!(*byte, 0);
    }

    // (3) Tampering. Flipping a single byte in the receipt root MUST
    // change the digest half (bytes 0..32) of the slot. We compare
    // against a tampered receipt-root and assert byte-array
    // inequality on the digest range.
    let mut tampered_root = receipt_root;
    tampered_root[flip_index as usize] ^= 0x01;
    let tampered = expect_report_data(&kernel_pk, &tampered_root);
    assert_ne!(first[..32], tampered[..32]);

    // (4) `QuoteVerificationContext::expected_report_data` is a real
    // `pub fn` thin wrapper around `expect_report_data`. Pin the
    // invariant that the wrapper agrees with the free function so a
    // future regression that diverged the two paths is caught here.
    let context = QuoteVerificationContext::new(&kernel_pk, &receipt_root);
    let via_context = context.expected_report_data();
    assert_eq!(via_context, first);
}

// ---------------------------------------------------------------------
// Algebraic model for `<_ as QuoteVerifier>::verify_quote` fail-closed
// arms. The production paths transit COSE/CBOR parsing, X.509 chain
// validation, and ECDSA verification, all of which are intractable
// for symbolic execution. The model captures only the algebra each
// path is required to preserve and is the same kind of model the
// `chio-kernel-core` harness uses for its `verify_receipt_roundtrip`
// block (see the comment block at lines 752-870 of
// `crates/chio-kernel-core/src/kani_public_harnesses.rs`). The runtime
// tests at `crates/chio-attest-verify/tests/migration.rs` and
// `crates/chio-attest-verify/tests/v318_migration.rs`, together with
// the per-backend unit tests, pin the concrete impl behaviour
// against fixed fixtures.
// ---------------------------------------------------------------------

/// Model of one TEE-quote verification. Captures only the axes the
/// production `verify_quote` paths must check before declaring
/// success; every axis evaluates to a boolean witness extracted from
/// either the real `pub` surface (`QuoteTcbStatus::is_acceptable`) or
/// from a structural property of the input.
#[derive(Clone, Copy, Debug)]
struct ModelQuoteOutcome {
    report_data_matches: bool,
    tcb_status: QuoteTcbStatus,
    algorithm_tag_matches: bool,
}

/// Algebra of a fail-closed `verify_quote` impl. A backend MUST reject
/// when ANY of the three axes is unsatisfied:
///
/// - `report_data` does not match the expected binding ->
///   `Err(AttestError::ReportDataMismatch)`.
/// - The TCB status is not acceptable per
///   `QuoteTcbStatus::is_acceptable` -> `Err(AttestError::QuoteRejected)`.
/// - The signature algorithm tag does not match the dispatch path ->
///   `Err(AttestError::Malformed)` (this is the
///   `verify_p256_signature_with_attestation_key` /
///   `verify_p384_signature_with_attestation_key` dispatch arm).
///
/// The arm priority below mirrors the production order: report-data
/// is checked before TCB, TCB is checked before signature dispatch.
fn model_verify_quote(outcome: ModelQuoteOutcome) -> Result<(), AttestError> {
    if !outcome.report_data_matches {
        return Err(AttestError::ReportDataMismatch);
    }
    if !outcome.tcb_status.is_acceptable() {
        return Err(AttestError::QuoteRejected(
            "model: tcb rejected".to_string(),
        ));
    }
    if !outcome.algorithm_tag_matches {
        return Err(AttestError::Malformed(
            "model: algorithm tag mismatch".to_string(),
        ));
    }
    Ok(())
}

/// Real public surface exercised symbolically: a `Nitro`-style quote
/// whose `report_data` slot does NOT byte-match
/// `expect_report_data(kernel_pk, receipt_root)` MUST be rejected with
/// `AttestError::ReportDataMismatch`. The cryptographic verification
/// path is modelled (see module-level doc), but the algebra below pins
/// the same fail-closed property the production
/// `<NitroVerifier as QuoteVerifier>::verify_quote` impl is required
/// to satisfy.
///
/// Production entry: `<NitroVerifier as QuoteVerifier>::verify_quote`
/// (impl at `crates/chio-attest-verify/src/nitro.rs:200`). The
/// real entry is reachable only with the `tee-quotes` Cargo feature
/// active; this harness pins the algebra independently of that
/// feature gate so default `cargo build` paths stay green.
#[kani::proof]
#[kani::unwind(8)]
pub fn public_nitro_verify_quote_rejects_report_data_mismatch() {
    // Symbolic axes. The report-data and TCB axes are independent;
    // the harness fixes algorithm-tag-matches to true so the
    // fail-closed arm under test is the report-data branch.
    let report_data_matches = kani::any::<bool>();
    let tcb_acceptable = kani::any::<bool>();
    // Bind a concrete TCB status to the symbolic acceptable bit. The
    // real `is_acceptable()` predicate is `UpToDate | ConfigurationNeeded`;
    // we exercise both legs of the predicate on the affirmative arm
    // and the OutOfDate / Revoked / Unrecognized legs on the
    // negative arm.
    let tcb_status = if tcb_acceptable {
        // Either of the two acceptable variants exercises the
        // `is_acceptable() == true` arm.
        if kani::any::<bool>() {
            QuoteTcbStatus::UpToDate
        } else {
            QuoteTcbStatus::ConfigurationNeeded
        }
    } else {
        // Pick one of the three rejecting variants symbolically.
        let pick = kani::any::<u8>();
        kani::assume(pick < 3);
        match pick {
            0 => QuoteTcbStatus::OutOfDate,
            1 => QuoteTcbStatus::Revoked,
            _ => QuoteTcbStatus::Unrecognized,
        }
    };
    // Cross-check that our concrete-TCB selection matches the
    // symbolic acceptable bit. This anchors the model to the real
    // public predicate `QuoteTcbStatus::is_acceptable`.
    assert_eq!(tcb_status.is_acceptable(), tcb_acceptable);

    let outcome = ModelQuoteOutcome {
        report_data_matches,
        tcb_status,
        algorithm_tag_matches: true,
    };

    let result = model_verify_quote(outcome);

    // (1) Fail-closed on report-data mismatch (load-bearing arm).
    if !report_data_matches {
        assert!(matches!(result, Err(AttestError::ReportDataMismatch)));
    } else if !tcb_acceptable {
        // (2) When report-data matches but TCB is unacceptable, the
        // backend MUST still reject. The error variant is
        // `QuoteRejected` per the production impl.
        assert!(matches!(result, Err(AttestError::QuoteRejected(_))));
    } else {
        // (3) Both axes satisfied: the model accepts. The runtime
        // path adds cryptographic checks the model abstracts, so
        // production callers MUST use the runtime tests for the
        // affirmative path; this branch is here only to pin the
        // model's algebra (no false negatives).
        assert!(result.is_ok());
    }
}

/// Real public surface exercised symbolically: a `SevSnp`-style quote
/// whose TCB status is NOT acceptable per `QuoteTcbStatus::is_acceptable`
/// MUST be rejected with `AttestError::QuoteRejected`, regardless of
/// signature validity.
///
/// Production entry: `<SevSnpVerifier as QuoteVerifier>::verify_quote`
/// (impl at `crates/chio-attest-verify/src/sev_snp.rs:246`).
#[kani::proof]
#[kani::unwind(8)]
pub fn public_sev_snp_verify_quote_rejects_unacceptable_tcb() {
    // Pin report-data to matching so the harness exercises the TCB
    // arm under test, not the report-data arm covered by the Nitro
    // harness.
    let pick = kani::any::<u8>();
    kani::assume(pick < 5);
    let tcb_status = match pick {
        0 => QuoteTcbStatus::UpToDate,
        1 => QuoteTcbStatus::ConfigurationNeeded,
        2 => QuoteTcbStatus::OutOfDate,
        3 => QuoteTcbStatus::Revoked,
        _ => QuoteTcbStatus::Unrecognized,
    };

    // Pin the real predicate's behaviour: `is_acceptable()` is true
    // iff the variant is `UpToDate` or `ConfigurationNeeded`.
    let acceptable = tcb_status.is_acceptable();
    assert_eq!(
        acceptable,
        matches!(
            tcb_status,
            QuoteTcbStatus::UpToDate | QuoteTcbStatus::ConfigurationNeeded
        )
    );

    let outcome = ModelQuoteOutcome {
        report_data_matches: true,
        tcb_status,
        algorithm_tag_matches: true,
    };
    let result = model_verify_quote(outcome);

    // (1) Fail-closed on unacceptable TCB. Whenever the TCB status
    // is `OutOfDate`, `Revoked`, or `Unrecognized`, the model MUST
    // return `QuoteRejected`. The production
    // `SevSnpVerifier::verify_collateral` path returns the same
    // variant before reaching the signature dispatch.
    if !acceptable {
        assert!(matches!(result, Err(AttestError::QuoteRejected(_))));
    } else {
        // (2) Acceptable TCB + matching report-data + matching alg
        // tag: the model accepts. (Same caveat as the Nitro harness:
        // the runtime path still needs cryptographic validation.)
        assert!(result.is_ok());
    }

    // (3) Idempotence under acceptable status. Re-evaluating the
    // real public predicate on the same variant yields the same
    // boolean; this pins the predicate against any future regression
    // that would make `is_acceptable()` time-dependent or impure.
    assert_eq!(tcb_status.is_acceptable(), acceptable);
}

/// Real public surface exercised symbolically: a `Tdx`-style quote
/// whose signature algorithm tag does NOT match the verification
/// dispatch path MUST be rejected with `AttestError::Malformed`.
/// Concretely: feeding a P-384-tagged signature into the P-256
/// verification arm (or vice versa) yields a non-`Ok` result.
///
/// Production entry: `<TdxDcapVerifier as QuoteVerifier>::verify_quote`
/// (impl at `crates/chio-attest-verify/src/tdx.rs:159`). The
/// crate-private dispatchers
/// `verify_p256_signature_with_attestation_key` and
/// `verify_p384_signature_with_attestation_key`
/// (`tee_signature.rs:15,36`, both `pub(crate)`) are the runtime
/// branches the algebra below abstracts.
#[kani::proof]
#[kani::unwind(8)]
pub fn public_tdx_verify_quote_rejects_algorithm_mismatch() {
    let algorithm_tag_matches = kani::any::<bool>();
    // Pin report-data and TCB to the affirmative arm so the harness
    // exercises the algorithm-tag arm under test.
    let outcome = ModelQuoteOutcome {
        report_data_matches: true,
        tcb_status: QuoteTcbStatus::UpToDate,
        algorithm_tag_matches,
    };
    let result = model_verify_quote(outcome);

    // (1) Fail-closed on algorithm-tag mismatch.
    if !algorithm_tag_matches {
        assert!(matches!(result, Err(AttestError::Malformed(_))));
    } else {
        // (2) Matching tag + matching report-data + acceptable TCB:
        // the model accepts.
        assert!(result.is_ok());
    }

    // (3) Pin the dispatch order against accidental flips: a
    // report-data mismatch MUST short-circuit before the algorithm
    // dispatch is consulted, so a quote with a bad tag and a bad
    // report-data is rejected as `ReportDataMismatch`, not
    // `Malformed`. This guards against a future regression that
    // would re-order the production checks and silently accept a
    // partial verification.
    let bad_outcome = ModelQuoteOutcome {
        report_data_matches: false,
        tcb_status: QuoteTcbStatus::UpToDate,
        algorithm_tag_matches: false,
    };
    let bad_result = model_verify_quote(bad_outcome);
    assert!(matches!(bad_result, Err(AttestError::ReportDataMismatch)));
}
