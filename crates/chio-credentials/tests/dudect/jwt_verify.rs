//! Timing-leak dudect harness for JWT VC signature verification.
//!
//! Gated behind the `dudect` Cargo feature so default `cargo test -p
//! chio-credentials` is unaffected; opt in via:
//!
//! ```bash
//! cargo test -p chio-credentials --features dudect --release jwt_verify
//! ```
//!
//! # What this harness measures
//!
//! Two input classes are pushed through
//! [`chio_credentials::verify_chio_passport_jwt_vc_json`]:
//!
//! - `Class::Left`: an all-zero compact byte string. The compact-JWT decoder
//!   rejects this in the very first base64url segment split, so the rejection
//!   path is short.
//! - `Class::Right`: a random ASCII byte string of the same length. Same
//!   fail-closed verdict (no arbitrary byte stream can pass the issuer
//!   signature check), but the parse path may take a different number of
//!   base64url-decode iterations or `serde_json` calls before the fail.
//!
//! Both inputs are wrong, both fail-closed; what the harness asks is whether
//! the failure path is constant-time with respect to the input contents. If
//! the runtime distributions of Left and Right are statistically
//! distinguishable (Welch's t > 4.5 in two consecutive runs), the verifier
//! has a data-dependent timing leak that an off-path attacker could exploit
//! to learn something about why a candidate JWT was rejected.
//!
//! The CI lane `.github/workflows/dudect.yml` wires this harness into
//! nightly + PR-time runs with the two-consecutive-runs `t < 4.5` pass rule.

#![cfg(feature = "dudect")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::OnceLock;

use chio_core::{Keypair, PublicKey};
use chio_credentials::verify_chio_passport_jwt_vc_json;
use dudect_bencher::rand::{Rng, RngExt};
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};

/// Deterministic 32-byte seed used to materialise the test issuer keypair.
/// Fixed across iterations so signature-mismatch noise stays out of the
/// timing distribution. Identical seed to the libFuzzer harness in
/// `crates/chio-credentials/src/fuzz.rs` for cross-tool consistency.
const DUDECT_ISSUER_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Fixed `now` clock value, identical to the libFuzzer harness for symmetry.
const DUDECT_NOW: u64 = 1_710_000_200;

/// Build the issuer public key once per process. `Keypair::from_seed` is
/// infallible for a fixed 32-byte seed.
fn issuer_public_key() -> &'static PublicKey {
    static ISSUER: OnceLock<PublicKey> = OnceLock::new();
    ISSUER.get_or_init(|| Keypair::from_seed(&DUDECT_ISSUER_SEED).public_key())
}

/// Compact-JWT-shaped string length used for both classes. Long enough to
/// exercise the base64url decode path on the header segment, short enough
/// to keep per-iteration work bounded so the t-test sample count grows
/// quickly during a 30-minute CI run.
const COMPACT_LEN: usize = 256;

/// Number of input pairs generated per harness invocation. Matches the
/// dudect-bencher upstream example; the runner re-invokes the closure
/// many times per pair so the effective sample count is larger.
const SAMPLES_PER_RUN: usize = 100_000;

/// Generate a random ASCII-printable byte string of length `COMPACT_LEN`.
/// Restricted to the printable range so the input survives the early
/// `std::str::from_utf8` check in the verifier and reaches the actual
/// compact-JWT segment-split path; otherwise non-UTF-8 inputs would be
/// rejected before the timing-sensitive code runs.
fn rand_compact_ascii(rng: &mut BenchRng) -> String {
    // Printable ASCII range 0x21..=0x7e, 94 characters.
    const ALPHABET_LEN: u8 = 0x7e - 0x21 + 1;
    let mut buf = vec![0u8; COMPACT_LEN];
    rng.fill_bytes(&mut buf);
    for byte in &mut buf {
        *byte = 0x21 + (*byte % ALPHABET_LEN);
    }
    // Safety net: every byte is in 0x21..=0x7e so the result is valid UTF-8.
    String::from_utf8(buf).unwrap_or_default()
}

/// All-zero ASCII compact string. The `0x30` byte is the digit `0`, so the
/// resulting string is valid UTF-8 and reaches the segment-split path.
fn zero_compact_ascii() -> String {
    String::from_utf8(vec![b'0'; COMPACT_LEN]).unwrap_or_default()
}

/// Dudect harness for `verify_chio_passport_jwt_vc_json`.
///
/// Class definitions:
///
/// - `Class::Left`: all-`'0'` compact string (no `.` separators, so the
///   compact-JWT decoder fails on the segment-count check immediately).
/// - `Class::Right`: random printable-ASCII compact string of the same
///   length. Most random strings also fail on segment-count, but the
///   fraction that happen to contain two `.` separators take a longer
///   path through base64url decode.
///
/// Both classes fail-closed; the t-test asks whether the *time taken to
/// fail* is data-dependent. A failing harness (max_t > 4.5 in two
/// consecutive CI runs) flags a regression in the verifier's parse path.
fn jwt_verify_bench(runner: &mut CtRunner, rng: &mut BenchRng) {
    let issuer = issuer_public_key();

    // Pre-generate inputs so the per-iteration work measured by `run_one`
    // contains only the verify call, not the input synthesis.
    let mut inputs: Vec<(Class, String)> = Vec::with_capacity(SAMPLES_PER_RUN);
    for _ in 0..SAMPLES_PER_RUN {
        if rng.random::<bool>() {
            inputs.push((Class::Left, zero_compact_ascii()));
        } else {
            inputs.push((Class::Right, rand_compact_ascii(rng)));
        }
    }

    for (class, compact) in inputs {
        runner.run_one(class, || {
            // Result intentionally discarded; we are measuring the time the
            // fail-closed path takes, not the verdict (which is always Err).
            let _ = verify_chio_passport_jwt_vc_json(&compact, issuer, DUDECT_NOW);
        });
    }
}

ctbench_main!(jwt_verify_bench);
