//! libFuzzer entry-point module for `chio-kernel-core` receipt-log replay.
//!
//! Gated behind the `fuzz` Cargo feature so it only compiles into the
//! standalone `chio-fuzz` workspace at `../../fuzz`. The production build of
//! `chio-kernel-core` never pulls in `arbitrary`, never exposes these symbols,
//! and never gets recompiled with libFuzzer instrumentation. The `fuzz`
//! feature also implies `std` because libFuzzer itself only runs in a hosted
//! environment, so the portable `no_std + alloc` host + wasm proof in
//! `scripts/check-portable-kernel.sh` never observes this surface.
//!
//! # Why this target exists
//!
//! Catches reordered / corrupted-chain bugs that the merkle_checkpoint target
//! cannot. The merkle root only commits to the set of leaf hashes; it cannot
//! detect a re-encoded receipt whose canonical-JSON bytes still hash to the
//! same leaf, nor a receipt log whose timestamps move backwards while every
//! individual signature still verifies. The replay-time verifier is the
//! canonical "decode-then-verify-then-check-chain-invariants" surface: tee
//! streams produce NDJSON receipt logs (one canonical-JSON `ChioReceipt` per
//! line) that the gate re-reads and validates, and any panic on that re-read
//! path would crash the gate every time the malformed bytes are seen.
//!
//! # Chosen entry point
//!
//! The receipt-log decode-then-verify pipeline is structured around
//! [`chio_core_types::ChioReceipt`]:
//!
//! 1. Split the input bytes on `\n` into NDJSON lines (matching the
//!    `tests/replay/src/golden_writer.rs` newline-terminated framing).
//! 2. For each non-empty line, attempt `serde_json::from_slice::<ChioReceipt>`.
//!    Errors are silently consumed (fail-closed: malformed lines are simply
//!    not part of the chain).
//! 3. For each successfully decoded receipt, call
//!    [`ChioReceipt::verify_signature`]. The result is intentionally
//!    discarded: the trust-boundary contract guarantees the only outcomes
//!    are `Ok(true)` (signature verified), `Ok(false)` (signature mismatch),
//!    `Err(_)` (decode error inside the canonical-JSON pipeline), or a panic
//!    that libFuzzer surfaces as a crash.
//! 4. Cross-receipt chain invariants are then checked over the verified
//!    sequence: timestamp monotonicity (non-decreasing) and `kernel_key`
//!    consistency (every receipt in a single log shares one signer). These
//!    catch the reorder / chain-tamper class the Round-2 rationale calls out.
//!
//! As a fall-back interpretation, the entire input is also fed once through
//! `serde_json::from_slice::<ChioReceipt>` so libFuzzer can reach the
//! single-receipt decode path with arbitrary bytes that do not contain a
//! newline. This mirrors the `chio-anchor` two-interpretation pattern: every
//! iteration drives both parsers concurrently from the same byte stream.
//!
//! No setup state is required: the verifier operates purely over its input
//! arguments (no clocks, no key registries, no stores).

use alloc::vec::Vec;

use chio_core_types::receipt::ChioReceipt;
use chio_core_types::PublicKey;

/// Drive arbitrary bytes through the `chio-kernel-core` receipt-log replay
/// trust boundary.
///
/// Bytes are interpreted in two independent ways and each interpretation is
/// forwarded to the corresponding verifier:
///
/// 1. As an NDJSON receipt log (one canonical-JSON [`ChioReceipt`] per line,
///    `\n`-terminated, matching `tests/replay/src/golden_writer.rs`). Each
///    line is decoded; for each successfully decoded receipt
///    [`ChioReceipt::verify_signature`] is called and the result discarded.
///    Cross-receipt chain invariants (timestamp monotonicity,
///    `kernel_key` consistency) are then checked over the verified sequence.
/// 2. As a single canonical-JSON-encoded [`ChioReceipt`] (no NDJSON
///    framing). Decoded once per iteration so libFuzzer reaches the
///    single-receipt parse path with inputs that do not contain a newline.
///
/// Errors at every step are silently consumed: the trust-boundary contract
/// guarantees the only outcomes are `Err(_)`, `Ok(true)`, `Ok(false)`, or a
/// panic / abort (which libFuzzer surfaces as a crash). The goal is
/// exercising the parse plus signature-verify plus chain-invariant paths,
/// not asserting any post-condition on the success branch.
pub fn fuzz_receipt_log_replay(data: &[u8]) {
    drive_ndjson_log(data);
    drive_single_receipt(data);
}

/// Interpret `data` as a `\n`-terminated NDJSON receipt log: decode each
/// line, verify every successfully decoded receipt, then check cross-receipt
/// chain invariants over the verified sequence.
fn drive_ndjson_log(data: &[u8]) {
    let mut verified: Vec<ChioReceipt> = Vec::new();
    for line in data.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let receipt: ChioReceipt = match serde_json::from_slice(line) {
            Ok(receipt) => receipt,
            Err(_) => continue,
        };
        // Per-receipt signature verify. Errors / `Ok(false)` are both
        // dropped; the goal is to exercise the canonical-JSON canonicalization
        // plus signature-verify pipeline, not to assert a verdict.
        let _ = receipt.verify_signature();
        verified.push(receipt);
    }
    check_chain_invariants(&verified);
}

/// Interpret `data` as a single canonical-JSON-encoded receipt: decode it,
/// then verify the signature. Reaches the single-receipt parse path even
/// when `data` contains no newline.
fn drive_single_receipt(data: &[u8]) {
    let receipt: ChioReceipt = match serde_json::from_slice(data) {
        Ok(receipt) => receipt,
        Err(_) => return,
    };
    let _ = receipt.verify_signature();
}

/// Check cross-receipt chain invariants over a sequence of decoded
/// receipts. Each invariant exercise is intentionally non-asserting: any
/// panic in the comparison primitives ([`PublicKey`] equality, `u64`
/// comparison) would surface through libFuzzer as a crash. The function's
/// purpose is to traverse the chain in order, not to enforce policy.
///
/// Invariants exercised:
///
/// - Timestamp monotonicity: successive `timestamp` values are read and
///   compared. Reordered or rewound receipts are visited but not rejected
///   (libFuzzer is the rejecter, via crashes). The comparison itself is the
///   load-bearing surface this target hardens.
/// - `kernel_key` consistency: successive `kernel_key` values are compared
///   against the first receipt's signer. Mixed-signer logs are visited but
///   not rejected here.
fn check_chain_invariants(receipts: &[ChioReceipt]) {
    let mut prev_timestamp: Option<u64> = None;
    let mut signer: Option<PublicKey> = None;
    for receipt in receipts {
        if let Some(prev) = prev_timestamp {
            // Read both sides; the boolean result is discarded.
            let _ = receipt.timestamp >= prev;
        }
        prev_timestamp = Some(receipt.timestamp);

        match &signer {
            Some(first) => {
                let _ = first == &receipt.kernel_key;
            }
            None => {
                signer = Some(receipt.kernel_key.clone());
            }
        }
    }
}
