//! Scenario driver for the M04 deterministic-replay gate.
//!
//! This module defines the two primitives that all replay-gate fixtures
//! flow through:
//!
//! - [`Scenario`]: a simple value object describing where a fixture lives
//!   on disk (manifest path, inputs directory, expected-goldens
//!   directory, and a human-readable name).
//! - [`ScenarioDriver`]: the deterministic execution context that wraps
//!   the kernel surface used in `tests/e2e/tests/full_flow.rs`. It
//!   loads a fixed Ed25519 signing key from `tests/replay/test-key.seed`,
//!   exposes a fixed clock anchored at `2026-01-01T00:00:00Z`, and emits
//!   strictly monotonic 16-byte nonces from an in-memory counter. Every
//!   source of nondeterminism that would otherwise leak into receipts
//!   (wall-clock time, OS RNG, ambient signing keys) is replaced by one
//!   of these knobs so that replay output is byte-identical across
//!   machines and OSes.
//!
//! T2 lands the driver primitives only. T3 wires `ScenarioDriver` into
//! the kernel + `InMemoryReceiptStore` to actually drive a fixture
//! through the pipeline; T4 adds the byte-comparison harness that reads
//! the goldens back as raw `Vec<u8>` and compares them without serde
//! round-tripping.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

use crate::fs_iter::{self, FsIterError};

/// Length, in bytes, of an Ed25519 signing seed.
const SEED_LEN: usize = 32;

/// Length, in bytes, of a deterministic replay-gate nonce.
const NONCE_LEN: usize = 16;

/// Path of the test seed relative to the crate's `CARGO_MANIFEST_DIR`.
const TEST_KEY_SEED_PATH: &str = "test-key.seed";

/// Fixed clock used by [`ScenarioDriver::now`].
///
/// Anchored at the UTC midnight starting 2026-01-01 so the driver's
/// notion of "now" is independent of wall-clock time and is far enough
/// in the future to avoid colliding with historical fixture data.
const FIXED_CLOCK_YEAR: i32 = 2026;
const FIXED_CLOCK_MONTH: u32 = 1;
const FIXED_CLOCK_DAY: u32 = 1;
const FIXED_CLOCK_HOUR: u32 = 0;
const FIXED_CLOCK_MIN: u32 = 0;
const FIXED_CLOCK_SEC: u32 = 0;

/// Errors produced while constructing a [`ScenarioDriver`].
#[derive(Debug, Error)]
pub enum DriverError {
    /// Reading `test-key.seed` from disk failed.
    #[error("failed to read test-key.seed at {path}: {source}")]
    SeedRead {
        /// Path that was attempted.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The seed file was the wrong length (must be exactly 32 bytes).
    #[error("test-key.seed has wrong size: expected {expected} bytes, got {actual}")]
    SeedSize {
        /// Expected seed length (32).
        expected: usize,
        /// Observed seed length.
        actual: usize,
    },

    /// The fixed-clock constants do not represent a valid UTC instant.
    /// Should be unreachable for the hard-coded constants above; kept
    /// fail-closed so any future edit that breaks them is rejected at
    /// load time rather than silently producing a different clock.
    #[error("fixed clock constants do not form a valid UTC instant")]
    InvalidFixedClock,
}

/// On-disk layout of a single replay-gate fixture.
///
/// The replay corpus lives under `tests/replay/fixtures/<name>/` with
/// one subdirectory per scenario and one matching subdirectory under
/// `tests/replay/goldens/<name>/`. T5 lands the fixture corpus; T2
/// only defines the value type so later tickets can reference it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scenario {
    /// Human-readable scenario name (also the directory leaf).
    pub name: String,
    /// Path to the YAML manifest describing the scenario.
    pub manifest_path: PathBuf,
    /// Directory containing the scenario's inputs (capability tokens,
    /// guard configs, tool-call requests, etc.).
    pub inputs_dir: PathBuf,
    /// Directory containing the expected golden outputs (NDJSON
    /// receipts, JSON checkpoint, hex Merkle root).
    pub expected_dir: PathBuf,
}

/// Deterministic execution context for a replay-gate scenario.
///
/// Constructed via [`ScenarioDriver::new`] (which loads the test seed
/// from `tests/replay/test-key.seed` relative to this crate's
/// `CARGO_MANIFEST_DIR`). All sources of nondeterminism are replaced by
/// fixed values:
///
/// - Clock: `now()` always returns `FIXED_CLOCK`.
/// - Nonces: `next_nonce()` returns `epoch_ms_be (8 bytes) || counter_be
///   (8 bytes)`, where `epoch_ms_be` is computed from the fixed clock
///   and `counter` increments by 1 on each call. This means nonce
///   uniqueness is preserved across calls within a single driver, while
///   the time prefix stays constant (so cross-call diffing reveals only
///   the counter, which keeps replay byte-stable).
/// - Signing: `sign()` uses an `ed25519_dalek::SigningKey` derived from
///   the test seed. Ed25519 signatures are deterministic by spec, so
///   the same `(key, message)` pair always produces the same signature.
pub struct ScenarioDriver {
    fixed_now: DateTime<Utc>,
    nonce_counter: u64,
    signing_key: SigningKey,
}

impl ScenarioDriver {
    /// Construct a [`ScenarioDriver`] by loading `test-key.seed` from
    /// `<CARGO_MANIFEST_DIR>/test-key.seed` (i.e.
    /// `tests/replay/test-key.seed`).
    ///
    /// Fails closed: any I/O error, wrong-sized seed, or invalid fixed
    /// clock constant returns `Err(DriverError::...)` so a broken test
    /// fixture cannot silently fall back to nondeterministic defaults.
    pub fn new() -> Result<Self, DriverError> {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let seed_path = Path::new(manifest_dir).join(TEST_KEY_SEED_PATH);
        let bytes = match fs::read(&seed_path) {
            Ok(b) => b,
            Err(source) => {
                return Err(DriverError::SeedRead {
                    path: seed_path,
                    source,
                });
            }
        };
        if bytes.len() != SEED_LEN {
            return Err(DriverError::SeedSize {
                expected: SEED_LEN,
                actual: bytes.len(),
            });
        }
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(&bytes);
        let signing_key = SigningKey::from_bytes(&seed);

        let fixed_now = match Utc.with_ymd_and_hms(
            FIXED_CLOCK_YEAR,
            FIXED_CLOCK_MONTH,
            FIXED_CLOCK_DAY,
            FIXED_CLOCK_HOUR,
            FIXED_CLOCK_MIN,
            FIXED_CLOCK_SEC,
        ) {
            chrono::LocalResult::Single(t) => t,
            _ => return Err(DriverError::InvalidFixedClock),
        };

        Ok(Self {
            fixed_now,
            nonce_counter: 0,
            signing_key,
        })
    }

    /// Returns the fixed clock instant. Always equal across calls.
    pub fn now(&self) -> DateTime<Utc> {
        self.fixed_now
    }

    /// Returns the next deterministic 16-byte nonce.
    ///
    /// Layout: `nonce[0..8]` is the fixed clock encoded as big-endian
    /// milliseconds since the Unix epoch; `nonce[8..16]` is the
    /// in-memory counter encoded big-endian. The counter is incremented
    /// after the nonce is constructed so the very first call returns
    /// `counter == 0`.
    pub fn next_nonce(&mut self) -> [u8; NONCE_LEN] {
        let epoch_ms = self.fixed_now.timestamp_millis() as u64;
        let counter = self.nonce_counter;
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        let mut out = [0u8; NONCE_LEN];
        out[0..8].copy_from_slice(&epoch_ms.to_be_bytes());
        out[8..16].copy_from_slice(&counter.to_be_bytes());
        out
    }

    /// Signs `message` with the fixed Ed25519 signing key. Ed25519 is
    /// deterministic by spec, so the same `(driver, message)` pair
    /// produces byte-identical signatures across calls and machines.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Returns a borrow of the underlying signing key for callers that
    /// need to hand it to APIs requiring an owned `&SigningKey` (for
    /// example, capability-token issuance in T3).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Returns the verifying (public) key associated with the fixed
    /// signing seed. Useful for tests and for documenting the trust
    /// root that future replay-gate goldens were produced against.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

/// List the inputs directory for `scenario` in deterministic
/// `LC_ALL=C`-equivalent byte order.
///
/// This is the load-bearing wire-up for T7: every replay-gate code
/// path that enumerates a scenario's input directory MUST go through
/// this function (or [`crate::fs_iter::read_dir_sorted`] /
/// [`crate::fs_iter::walk_files_sorted`]) rather than calling
/// `fs::read_dir` directly. Native `read_dir` order varies across
/// hosts (HFS+/APFS case-insensitive normalization, ext4 inode order,
/// NTFS case-insensitive), which would silently desync the corpus
/// between developer machines and CI; the byte-order pass through
/// `fs_iter` is what makes the corpus byte-equivalent across hosts.
///
/// # Errors
///
/// - [`FsIterError::Io`] if `scenario.inputs_dir` cannot be opened or
///   any directory entry cannot be read.
/// - [`FsIterError::NonUtf8Path`] on non-Unix targets only, if any
///   child name is not valid UTF-8.
pub fn list_scenario_inputs(scenario: &Scenario) -> Result<Vec<PathBuf>, FsIterError> {
    fs_iter::read_dir_sorted(&scenario.inputs_dir)
}

#[cfg(test)]
mod tests {
    //! Driver-level unit tests. The expected verifying-key and signature
    //! constants below were precomputed from
    //! `SHA-256("chio-replay-gate-non-production-test-seed-v1")` using
    //! `ed25519-dalek` 2.x. They are part of the replay-gate's trust
    //! root: any change to the seed-derivation rule MUST update them.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use ed25519_dalek::Verifier;

    /// Hex of the Ed25519 verifying key derived from the test seed.
    const EXPECTED_VERIFYING_KEY_HEX: &str =
        "801e0fd63c1b9903dac8a19a6390321e571872eca0d049329baccdc6fe8e9c36";

    /// Hex of `sign(b"chio-replay-gate-test")` under the test seed.
    const EXPECTED_SIGNATURE_HEX: &str = "18846af815c63d5e1648f2fa4ef6f112eea217b9c559707381826fb283dfc3395a61670159ce6101038438064e26047ef9621602c97f419e519c0340f33ead05";

    fn driver() -> ScenarioDriver {
        ScenarioDriver::new().expect("ScenarioDriver::new must succeed in tests")
    }

    #[test]
    fn fixed_clock_returns_same_time() {
        let d = driver();
        let a = d.now();
        let b = d.now();
        assert_eq!(a, b, "fixed clock must be stable across calls");
        // Spot-check the anchor instant so any accidental change to the
        // FIXED_CLOCK_* constants is caught here, not at byte-diff
        // time three tickets later.
        let expected = Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("anchor instant must be valid");
        assert_eq!(a, expected, "fixed clock must equal 2026-01-01T00:00:00Z");
    }

    #[test]
    fn next_nonce_is_monotonic_and_unique() {
        let mut d = driver();
        let nonces: Vec<[u8; NONCE_LEN]> = (0..8).map(|_| d.next_nonce()).collect();

        // All nonces must be distinct.
        for i in 0..nonces.len() {
            for j in (i + 1)..nonces.len() {
                assert_ne!(nonces[i], nonces[j], "nonce {i} and nonce {j} must differ");
            }
        }

        // The first 8 bytes (time prefix) must be identical across all
        // nonces because the clock is fixed; only the counter half
        // changes.
        let prefix0 = &nonces[0][0..8];
        for (i, n) in nonces.iter().enumerate() {
            assert_eq!(
                &n[0..8],
                prefix0,
                "nonce {i} time-prefix must match nonce 0"
            );
        }

        // Counter must walk 0, 1, 2, ... in big-endian.
        for (i, n) in nonces.iter().enumerate() {
            let mut want = [0u8; 8];
            want.copy_from_slice(&(i as u64).to_be_bytes());
            assert_eq!(&n[8..16], &want, "nonce {i} counter half must match");
        }
    }

    #[test]
    fn signer_seed_loads_to_expected_pubkey() {
        let d = driver();
        let vk = d.verifying_key();
        let got_hex = hex::encode(vk.to_bytes());
        assert_eq!(
            got_hex, EXPECTED_VERIFYING_KEY_HEX,
            "verifying key derived from test seed must match the recorded golden"
        );
    }

    #[test]
    fn signing_is_deterministic() {
        let d = driver();
        let msg: &[u8] = b"chio-replay-gate-test";
        let sig_a = d.sign(msg);
        let sig_b = d.sign(msg);
        assert_eq!(
            sig_a.to_bytes(),
            sig_b.to_bytes(),
            "Ed25519 signing must be deterministic across calls"
        );
        let got_hex = hex::encode(sig_a.to_bytes());
        assert_eq!(
            got_hex, EXPECTED_SIGNATURE_HEX,
            "signature over the canonical test message must match the recorded golden"
        );
        // And the signature must verify under the verifying key.
        let vk = d.verifying_key();
        vk.verify(msg, &sig_a)
            .expect("signature must verify under the driver's verifying key");
    }
}
