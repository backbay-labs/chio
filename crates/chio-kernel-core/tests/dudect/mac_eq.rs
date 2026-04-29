//! Timing-leak dudect harness for MAC (signature byte) equality compare.
//!
//! Gated behind the `dudect` Cargo feature so default `cargo test -p
//! chio-kernel-core` is unaffected; opt in via:
//!
//! ```bash
//! cargo test -p chio-kernel-core --features dudect --release mac_eq
//! ```
//!
//! # What this harness measures
//!
//! Chio kernel-core's signature-verification path returns `false` from
//! [`chio_core_types::crypto::PublicKey::verify`] when the supplied
//! signature does not match the message. The portable receipt and passport
//! verifiers compare `Signature` blobs by bytes (see
//! `chio_core_types::crypto::Signature`'s `PartialEq` impl, which uses
//! `==` on the underlying `[u8; 64]` for Ed25519). That byte-equality
//! compare is the closest in-tree analogue of an HMAC-tag compare, which
//! is the canonical "MAC eq" surface that any constant-time crypto code
//! has to keep data-independent.
//!
//! The harness drives two input classes through the byte-equality compare:
//!
//! - `Class::Left`: two signatures that differ at the **first** byte.
//!   A naive `==` short-circuits early; a constant-time compare runs
//!   through every byte.
//! - `Class::Right`: two signatures that differ at the **last** byte.
//!   A naive `==` runs through almost every byte before short-circuiting.
//!
//! If the runtime distributions are statistically distinguishable
//! (Welch's t > 4.5 in two consecutive runs), the compare path is a
//! variable-time short-circuit. The CI lane `.github/workflows/dudect.yml`
//! wires this harness into nightly + PR-time runs with the
//! two-consecutive-runs `t < 4.5` pass rule.
//!
//! # Why the trust-boundary surface, not the wrapper
//!
//! `chio-kernel-core` does not expose its own `mac_eq` symbol; the kernel
//! delegates byte-equality to the `Signature` type from `chio-core-types`,
//! which is part of the same trust boundary set. Measuring the underlying
//! `==` directly catches the leak at its source rather than smearing it
//! through a wrapper that would dilute the signal.

#![cfg(feature = "dudect")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core_types::crypto::Signature;
use dudect_bencher::rand::{Rng, RngExt};
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};

/// Number of input pairs generated per harness invocation.
const SAMPLES_PER_RUN: usize = 100_000;

/// Build a `Signature` from a raw 64-byte array. Helper around
/// [`Signature::from_bytes`] kept local so the harness logic reads cleanly.
fn signature_from_bytes(bytes: &[u8; 64]) -> Signature {
    Signature::from_bytes(bytes)
}

/// Build a `(left, right)` pair of signatures whose underlying byte arrays
/// differ at exactly `flip_position`. The base bytes are random (filled
/// from `rng`); the right-hand byte at `flip_position` is XOR'd with `0xff`
/// so the pair is guaranteed unequal regardless of what `rng` produced.
fn signature_pair_differing_at(rng: &mut BenchRng, flip_position: usize) -> (Signature, Signature) {
    let mut left_bytes = [0u8; 64];
    rng.fill_bytes(&mut left_bytes);
    let mut right_bytes = left_bytes;
    let pos = flip_position.min(63);
    right_bytes[pos] ^= 0xff;
    (
        signature_from_bytes(&left_bytes),
        signature_from_bytes(&right_bytes),
    )
}

/// Dudect harness for `Signature` byte equality.
///
/// Class definitions:
///
/// - `Class::Left`: pair `(a, b)` where `b` differs from `a` at byte 0.
///   A short-circuiting `==` returns after the first byte compare.
/// - `Class::Right`: pair `(a, b)` where `b` differs from `a` at byte 63.
///   A short-circuiting `==` returns only after 63 byte compares.
///
/// The two classes have identical input shapes (random 64-byte blobs);
/// the only difference is which byte position carries the inequality.
fn mac_eq_bench(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs: Vec<(Class, Signature, Signature)> = Vec::with_capacity(SAMPLES_PER_RUN);
    for _ in 0..SAMPLES_PER_RUN {
        if rng.random::<bool>() {
            let (a, b) = signature_pair_differing_at(rng, 0);
            inputs.push((Class::Left, a, b));
        } else {
            let (a, b) = signature_pair_differing_at(rng, 63);
            inputs.push((Class::Right, a, b));
        }
    }

    for (class, a, b) in inputs {
        runner.run_one(class, || {
            // The verdict is always `false` because the inputs differ by
            // construction; we only care about the time the compare takes.
            // Return the comparison result so `run_one`'s `black_box` keeps
            // the compare in the optimized binary; assigning to `_` would
            // let `--release` LLVM eliminate the comparison and leave the
            // harness measuring runner overhead instead of byte equality.
            a == b
        });
    }
}

ctbench_main!(mac_eq_bench);
