// Property-based replay-invariance suite for the Chio kernel.
//
// Three properties over arbitrary `(decision, payload, clock, nonce)` receipt
// tuples:
//
//   1. Signing is a function (same canonical body, same signed bytes).
//   2. Replaying the receipt log twice yields the same anchored Merkle root.
//   3. Shuffling independent receipts (no shared nonce) does not change the
//      per-receipt canonical signing bytes.
//
// CI budget: 30 seconds (enforced at the workflow level via timeout-minutes
// and PROPTEST_CASES). Failed shrinks persist under
// `tests/replay/proptest-regressions/` so future runs replay the seed.
//
// `unwrap_used` / `expect_used` are denied workspace-wide; we allow them
// inside this file because the proptest harness constructs ad-hoc fixtures
// whose invariants are checked locally.
//
// Each named property (`signing_is_a_function`, `replay_root_is_idempotent`,
// `shuffle_independent_receipts_preserves_bytes`) lives in its own
// `proptest! { ... }` block so the case count can be tuned per-property;
// `proptest!` only honours `#![proptest_config(...)]` at block scope.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::merkle::MerkleTree;
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence};
use serde_json::json;

// Deterministic test signing key. The kernel verifies receipts off the
// embedded `kernel_key`, so a fixed seed keeps the fixture reproducible
// across machines without coupling to the production key-rotation runbook.
const KERNEL_SEED: [u8; 32] = [
    0xC4, 0x10, 0x73, 0x29, 0xA6, 0xB2, 0x4D, 0x5F, 0x91, 0x08, 0x42, 0x6E, 0xD7, 0xCB, 0x33, 0x80,
    0x1E, 0x55, 0xAA, 0x77, 0x16, 0x9C, 0x3B, 0xE0, 0x4F, 0x82, 0x69, 0x12, 0xBD, 0x05, 0x2A, 0xCC,
];

/// Higher case count for `signing_is_a_function`. Signing is the cheapest
/// property to evaluate (one body, one keypair, no Merkle anchoring) so we
/// can afford a denser sweep without breaching the 30s CI budget.
const SIGNING_FUNCTION_CASES: u32 = 256;

/// Higher case count for `replay_root_is_idempotent`. Each case builds two
/// Merkle trees over up to 32 leaves and asserts byte equality on the root.
/// 256 cases stays inside the 30s CI budget because the per-case work (two
/// anchors, no signature verification) is cheap.
const REPLAY_ROOT_CASES: u32 = 256;

/// Higher case count for `shuffle_independent_receipts_preserves_bytes`. Each
/// case signs up to 16 receipts and compares per-receipt canonical bytes
/// across a deterministic permutation; 256 cases stays inside the 30s CI
/// budget because the per-case work (signatures only, no Merkle anchoring) is
/// bounded.
const SHUFFLE_INDEPENDENCE_CASES: u32 = 256;

/// Maximum batch size for the independence shuffle property. Capped at 16 so
/// the shuffle exercises both small degenerate cases (2-3 receipts) and a
/// non-trivial mid-range batch.
const SHUFFLE_INDEPENDENCE_MAX: usize = 16;

/// Maximum batch size for the random arm of `replay_sequence()`. Upper bound
/// of 32 receipts exercises the next power-of-two RFC 6962 padding boundary.
const REPLAY_RANDOM_MAX: usize = 32;

fn kernel_keypair() -> Keypair {
    Keypair::from_seed(&KERNEL_SEED)
}

/// One element of the strategy: `(decision, payload, clock, nonce)`.
#[derive(Debug, Clone)]
struct ReceiptTuple {
    decision: Decision,
    payload: serde_json::Value,
    clock: u64,
    nonce: String,
}

fn arbitrary_decision() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Allow),
        ("[a-z]{3,16}", "[a-z]{3,16}").prop_map(|(reason, guard)| Decision::Deny { reason, guard }),
        "[a-z]{3,16}".prop_map(|reason| Decision::Cancelled { reason }),
        "[a-z]{3,16}".prop_map(|reason| Decision::Incomplete { reason }),
    ]
}

fn arbitrary_payload() -> impl Strategy<Value = serde_json::Value> {
    // Bound payload size so the strategy is shrink-friendly and the 30s CI
    // budget is reachable. Real-world receipts carry larger payloads, but the
    // properties under test are agnostic to payload contents.
    (
        "[a-z]{1,12}",
        proptest::collection::vec(0u8..=255, 0..16),
        any::<i32>(),
    )
        .prop_map(|(method, bytes, magnitude)| {
            json!({
                "method": method,
                "bytes": bytes,
                "magnitude": magnitude,
            })
        })
}

/// `arbitrary_receipt_tuple()`: produces `(decision, payload, clock, nonce)`.
fn arbitrary_receipt_tuple() -> impl Strategy<Value = ReceiptTuple> {
    (
        arbitrary_decision(),
        arbitrary_payload(),
        any::<u64>(),
        "[a-z0-9]{8,32}",
    )
        .prop_map(|(decision, payload, clock, nonce)| ReceiptTuple {
            decision,
            payload,
            clock,
            nonce,
        })
}

/// Edge-case payload strategy biased toward boundary shapes that have caused
/// canonical-bytes regressions in the past: empty maps, all-zero byte vectors,
/// extreme integer magnitudes, and unicode-free single-character methods.
fn edge_case_payload() -> impl Strategy<Value = serde_json::Value> {
    prop_oneof![
        // Empty payload (no fields).
        Just(json!({})),
        // All-zero byte vector at maximum bounded size.
        Just(json!({
            "method": "z",
            "bytes": vec![0u8; 16],
            "magnitude": 0,
        })),
        // Maximum-magnitude i32 (positive and negative).
        Just(json!({
            "method": "max",
            "bytes": Vec::<u8>::new(),
            "magnitude": i32::MAX,
        })),
        Just(json!({
            "method": "min",
            "bytes": Vec::<u8>::new(),
            "magnitude": i32::MIN,
        })),
        // Single-element byte vector with the high bit set (canonical-JSON
        // numeric encoding has previously regressed on values >= 128).
        Just(json!({
            "method": "h",
            "bytes": vec![0xFFu8],
            "magnitude": 1,
        })),
    ]
}

/// `signing_edge_tuple()`: tuples that exercise boundary conditions of the
/// signing surface area. The strategy mixes random tuples with a curated set
/// of edge cases (zero clock, max-u64 clock, empty/min-length nonce,
/// max-length nonce, and the edge-case payload shapes above).
fn signing_edge_tuple() -> impl Strategy<Value = ReceiptTuple> {
    prop_oneof![
        // 60% of the budget: random tuples (the original strategy).
        6 => arbitrary_receipt_tuple(),
        // Zero clock + minimal nonce.
        1 => (arbitrary_decision(), edge_case_payload(), Just(0u64), "[a-z]{1}").prop_map(
            |(decision, payload, clock, nonce)| ReceiptTuple { decision, payload, clock, nonce },
        ),
        // Max u64 clock + maximum-length nonce.
        1 => (
            arbitrary_decision(),
            edge_case_payload(),
            Just(u64::MAX),
            "[a-z0-9]{32}",
        )
            .prop_map(|(decision, payload, clock, nonce)| ReceiptTuple {
                decision,
                payload,
                clock,
                nonce,
            }),
        // Boundary clocks: 1, i64::MAX as u64, u64::MAX - 1.
        1 => (
            arbitrary_decision(),
            arbitrary_payload(),
            prop_oneof![Just(1u64), Just(i64::MAX as u64), Just(u64::MAX - 1)],
            "[a-z0-9]{8,32}",
        )
            .prop_map(|(decision, payload, clock, nonce)| ReceiptTuple {
                decision,
                payload,
                clock,
                nonce,
            }),
        // Edge payloads paired with random clocks/nonces.
        1 => (arbitrary_decision(), edge_case_payload(), any::<u64>(), "[a-z0-9]{8,32}").prop_map(
            |(decision, payload, clock, nonce)| ReceiptTuple { decision, payload, clock, nonce },
        ),
    ]
}

/// `replay_sequence()`: produces sequences of receipt tuples covering the
/// boundary shapes that have caused replay-root regressions in the past:
///
/// - `0` receipts: empty sequence. `MerkleTree::from_leaves` returns
///   `Err(Error::EmptyTree)` for this input; the idempotence property still
///   holds (both replays must produce the same error variant), and the
///   property handler exercises that path explicitly.
/// - `1` receipt: degenerate single-leaf tree (root is the leaf hash).
/// - `2` receipts: smallest non-trivial RFC 6962 tree (one internal node,
///   no padding).
/// - `3..=REPLAY_RANDOM_MAX` receipts: random batch sizes spanning every
///   power-of-two padding boundary up to 32 leaves.
///
/// Nonces are filtered for uniqueness per batch; this guarantees each tuple
/// produces distinct canonical bytes (the nonce is woven into the receipt id,
/// capability id, and policy hash by `body_from_tuple`).
fn replay_sequence() -> impl Strategy<Value = Vec<ReceiptTuple>> {
    prop_oneof![
        // Empty sequence: idempotent failure mode (both replays must yield
        // the same `EmptyTree` error).
        1 => Just(Vec::<ReceiptTuple>::new()),
        // Single-receipt sequence: degenerate leaf-as-root case.
        1 => proptest::collection::vec(arbitrary_receipt_tuple(), 1..=1),
        // Two-receipt sequence: smallest non-trivial tree.
        1 => proptest::collection::vec(arbitrary_receipt_tuple(), 2..=2),
        // Random N-receipt sequence: covers padding boundaries through 32.
        4 => proptest::collection::vec(arbitrary_receipt_tuple(), 3..=REPLAY_RANDOM_MAX),
    ]
    .prop_filter("receipt nonces must be unique per batch", |ts| {
        let mut seen = std::collections::HashSet::new();
        ts.iter().all(|t| seen.insert(t.nonce.clone()))
    })
}

/// Build a `ChioReceiptBody` from a tuple. The `nonce` is woven into the
/// receipt id, the capability id, and the policy hash so two tuples with
/// distinct nonces produce different canonical bytes.
fn body_from_tuple(tuple: &ReceiptTuple, kernel_key: &Keypair) -> ChioReceiptBody {
    let action =
        ToolCallAction::from_parameters(tuple.payload.clone()).expect("payload canonicalises");
    let content_hash = sha256_hex(action.parameter_hash.as_bytes());
    let policy_hash = sha256_hex(format!("policy:{}", tuple.nonce).as_bytes());
    ChioReceiptBody {
        id: format!("rcpt-{}", tuple.nonce),
        timestamp: tuple.clock,
        capability_id: format!("cap-{}", tuple.nonce),
        tool_server: "tool.example".to_string(),
        tool_name: "echo".to_string(),
        action,
        decision: tuple.decision.clone(),
        content_hash,
        policy_hash,
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kernel_key.public_key(),
    }
}

fn sign_body(body: &ChioReceiptBody, kernel_key: &Keypair) -> ChioReceipt {
    ChioReceipt::sign(body.clone(), kernel_key).expect("signing succeeds")
}

fn canonical_body_bytes(body: &ChioReceiptBody) -> Vec<u8> {
    canonical_json_bytes(body).expect("body canonicalises")
}

/// Outcome of anchoring a (possibly empty) receipt batch. The empty-batch
/// case is a documented failure mode of `MerkleTree::from_leaves`; the
/// idempotence property treats it as a value to compare across replays.
#[derive(Debug, PartialEq, Eq)]
enum AnchorOutcome {
    /// Successful anchor: the 32-byte root hash.
    Root([u8; 32]),
    /// Documented failure mode: the empty-tree error string. We compare the
    /// `Display` form rather than the typed variant because `chio_core`'s
    /// `Error` does not derive `PartialEq`; the `Display` impl is the stable
    /// surface that callers (including replay tooling) rely on.
    EmptyTree(String),
}

/// Anchor a (possibly empty) receipt batch. Used by `replay_root_is_idempotent`
/// so the empty-sequence boundary is exercised as a first-class case rather
/// than panicking via `expect`.
fn try_anchor_root(receipts: &[ChioReceipt]) -> AnchorOutcome {
    let leaves: Vec<Vec<u8>> = receipts
        .iter()
        .map(|r| canonical_body_bytes(&r.body()))
        .collect();
    match MerkleTree::from_leaves(&leaves) {
        Ok(tree) => AnchorOutcome::Root(*tree.root().as_bytes()),
        Err(err) => AnchorOutcome::EmptyTree(err.to_string()),
    }
}

/// Path to the regression archive directory required by the source-of-truth
/// doc (`tests/replay/proptest-regressions/`). We point proptest at a file
/// inside this directory so failed shrinks are committed alongside other
/// replay-test artefacts.
fn regression_persistence() -> Box<FileFailurePersistence> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // CARGO_MANIFEST_DIR is `crates/chio-kernel`; the archive lives at the
    // repo root under `tests/replay/proptest-regressions/`.
    path.pop(); // crates/
    path.pop(); // repo root
    path.push("tests");
    path.push("replay");
    path.push("proptest-regressions");
    path.push("replay_proptest.txt");
    Box::new(FileFailurePersistence::Direct(Box::leak(
        path.to_string_lossy().into_owned().into_boxed_str(),
    )))
}

// Property 1 lives in its own `proptest!` block so we can dial up the case
// count specifically for `signing_is_a_function` without slowing the other
// two properties (which build full Merkle trees per case).
proptest! {
    #![proptest_config(ProptestConfig {
        cases: SIGNING_FUNCTION_CASES,
        failure_persistence: Some(regression_persistence()),
        .. ProptestConfig::default()
    })]

    /// Property 1 (named exit-criterion test):
    /// signing is a pure function: same canonical body, same signed bytes.
    /// We sign the same body three times across two independently-derived
    /// keypair instances and assert byte equality across every pairing.
    /// The strategy is biased toward edge cases (boundary clocks, empty and
    /// all-zero payloads, min and max nonce lengths) on top of the random
    /// `arbitrary_receipt_tuple` baseline.
    #[test]
    fn signing_is_a_function(tuple in signing_edge_tuple()) {
        // Two keypair instances from the same seed must behave identically.
        // This catches regressions where signer state (e.g. RNG) leaks into
        // the signature bytes.
        let kp = kernel_keypair();
        let kp_twin = kernel_keypair();
        prop_assert_eq!(kp.public_key(), kp_twin.public_key());

        let body = body_from_tuple(&tuple, &kp);

        // Triple-sign across both keypair instances. Three signatures over
        // the same body must produce identical bytes; if any pair drifts,
        // signing is not a pure function of (body, key).
        let receipt_a = sign_body(&body, &kp);
        let receipt_b = sign_body(&body, &kp);
        let receipt_c = sign_body(&body, &kp_twin);

        let bytes_a = canonical_json_bytes(&receipt_a).expect("receipt a canonicalises");
        let bytes_b = canonical_json_bytes(&receipt_b).expect("receipt b canonicalises");
        let bytes_c = canonical_json_bytes(&receipt_c).expect("receipt c canonicalises");
        prop_assert_eq!(&bytes_a, &bytes_b);
        prop_assert_eq!(&bytes_a, &bytes_c);

        // Raw signature bytes must agree exactly. We compare both the
        // canonical-JSON encoding of the signature container and the
        // structural equality of the signature itself, so a bug that
        // reordered hex chars or changed the encoding would still fail.
        let sig_a = canonical_json_bytes(&receipt_a.signature)
            .expect("signature a canonicalises");
        let sig_b = canonical_json_bytes(&receipt_b.signature)
            .expect("signature b canonicalises");
        let sig_c = canonical_json_bytes(&receipt_c.signature)
            .expect("signature c canonicalises");
        prop_assert_eq!(&sig_a, &sig_b);
        prop_assert_eq!(&sig_a, &sig_c);

        // Verification must succeed for every signed copy.
        prop_assert!(receipt_a.verify_signature().expect("verify a"));
        prop_assert!(receipt_b.verify_signature().expect("verify b"));
        prop_assert!(receipt_c.verify_signature().expect("verify c"));

        // Canonical body bytes must round-trip independent of which receipt
        // we project from: the body is the input to signing and must remain
        // a fixed point.
        let body_bytes_a = canonical_body_bytes(&receipt_a.body());
        let body_bytes_b = canonical_body_bytes(&receipt_b.body());
        let body_bytes_direct = canonical_body_bytes(&body);
        prop_assert_eq!(&body_bytes_a, &body_bytes_b);
        prop_assert_eq!(&body_bytes_a, &body_bytes_direct);

        // The action's parameter hash must verify against its own canonical
        // bytes. This guards against a regression where signing accepted a
        // body with a stale `parameter_hash`.
        prop_assert!(
            receipt_a
                .body()
                .action
                .verify_hash()
                .expect("parameter hash verifies")
        );
    }
}

// Property 2 lives in its own `proptest!` block so we can dial up the case
// count to 256 without slowing Property 3. The strategy (`replay_sequence()`)
// covers the boundary shapes: empty, single-receipt, two-receipt, and random
// N up to 32.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: REPLAY_ROOT_CASES,
        failure_persistence: Some(regression_persistence()),
        .. ProptestConfig::default()
    })]

    /// Property 2 (named exit-criterion test):
    /// replaying the receipt log twice yields the same anchored root. We
    /// build the same receipt batch twice and assert byte equality on the
    /// computed Merkle root. The strategy covers four boundary shapes:
    /// empty (idempotent `EmptyTree` error), single-receipt (leaf-as-root),
    /// two-receipt (smallest non-trivial RFC 6962 tree), and random N-receipt
    /// up to 32 leaves (every padding boundary through `2^5`).
    #[test]
    fn replay_root_is_idempotent(tuples in replay_sequence()) {
        let kp = kernel_keypair();

        let receipts_a: Vec<ChioReceipt> = tuples
            .iter()
            .map(|t| sign_body(&body_from_tuple(t, &kp), &kp))
            .collect();
        let receipts_b: Vec<ChioReceipt> = tuples
            .iter()
            .map(|t| sign_body(&body_from_tuple(t, &kp), &kp))
            .collect();

        let outcome_a = try_anchor_root(&receipts_a);
        let outcome_b = try_anchor_root(&receipts_b);
        prop_assert_eq!(&outcome_a, &outcome_b);

        // Empty input must take the documented failure path on both replays.
        // Non-empty input must produce a 32-byte root on both replays. This
        // pins the strategy's empty-arm to its expected branch and stops a
        // future regression that silently swallows the empty case.
        match (&outcome_a, tuples.is_empty()) {
            (AnchorOutcome::EmptyTree(_), true) => {}
            (AnchorOutcome::Root(_), false) => {}
            (AnchorOutcome::EmptyTree(_), false) => {
                prop_assert!(
                    false,
                    "non-empty receipt batch produced EmptyTree outcome"
                );
            }
            (AnchorOutcome::Root(_), true) => {
                prop_assert!(
                    false,
                    "empty receipt batch produced a Merkle root"
                );
            }
        }
    }
}

/// `independent_tuple_batch()`: produces 2..=`SHUFFLE_INDEPENDENCE_MAX`
/// "independent" receipt tuples whose **nonces are pairwise distinct** AND
/// whose **payloads are pairwise distinct** (which forces pairwise distinct
/// `content_hash` values, since `content_hash` is derived from the canonical
/// bytes of the payload via `ToolCallAction::from_parameters`).
///
/// Independence here means no cross-reference: each tuple is signed in
/// isolation and shares no fields with any other tuple in the batch. This is
/// the precondition the shuffle-invariance property depends on; the property
/// body re-asserts it (see the `independence_*` checks) so a future strategy
/// regression cannot silently weaken the guarantee.
///
/// Implementation notes:
/// - The strategy stamps the nonce into the payload's `method` field so a
///   distinct nonce mechanically produces a distinct payload, which in turn
///   produces a distinct `content_hash`. This avoids a `prop_filter` rejection
///   loop on the (nonce x payload) cross-product.
/// - Nonce uniqueness is enforced by a `prop_filter` HashSet check; the regex
///   alphabet (`[a-z0-9]{8,32}`) keeps the rejection rate low at our batch
///   sizes (max 16 entries from a >36^8 alphabet).
fn independent_tuple_batch() -> impl Strategy<Value = Vec<ReceiptTuple>> {
    proptest::collection::vec(arbitrary_receipt_tuple(), 2..=SHUFFLE_INDEPENDENCE_MAX)
        .prop_filter("receipt nonces must be unique per batch", |ts| {
            let mut seen = std::collections::HashSet::new();
            ts.iter().all(|t| seen.insert(t.nonce.clone()))
        })
        .prop_map(|ts| {
            // Fold the nonce into each payload's `method` field. Distinct
            // nonces (already enforced above) now guarantee distinct payloads
            // and therefore distinct content_hashes, which is the explicit
            // independence guarantee the shuffle property relies on.
            ts.into_iter()
                .map(|mut t| {
                    if let Some(obj) = t.payload.as_object_mut() {
                        obj.insert(
                            "method".to_string(),
                            serde_json::Value::String(format!("m-{}", t.nonce)),
                        );
                    } else {
                        t.payload = json!({
                            "method": format!("m-{}", t.nonce),
                            "bytes": Vec::<u8>::new(),
                            "magnitude": 0,
                        });
                    }
                    t
                })
                .collect()
        })
}

// Property 3 lives in its own `proptest!` block at 256 cases. Each case signs
// up to 16 receipts and compares per-receipt canonical bytes across a
// deterministic permutation.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: SHUFFLE_INDEPENDENCE_CASES,
        failure_persistence: Some(regression_persistence()),
        .. ProptestConfig::default()
    })]

    /// Property 3:
    /// shuffling **independent** receipts (no shared nonce, no shared
    /// content_hash, no cross-reference) does not change any individual
    /// receipt's canonical body bytes. The anchored Merkle root WILL change
    /// when the receipt order changes (RFC 6962 trees are order-sensitive),
    /// but each receipt's individual signing payload is invariant under
    /// reordering of the surrounding batch.
    ///
    /// The "independent" qualifier is the load-bearing precondition: this
    /// property does NOT claim invariance for receipts that share a nonce or
    /// reference each other. The strategy (`independent_tuple_batch`)
    /// guarantees pairwise-distinct nonces and pairwise-distinct payloads, and
    /// the property body re-asserts both invariants up front so a strategy
    /// regression that silently weakens the guarantee fails the test.
    #[test]
    fn shuffle_independent_receipts_preserves_bytes(
        tuples in independent_tuple_batch(),
        seed in any::<u64>(),
    ) {
        let kp = kernel_keypair();

        let receipts: Vec<ChioReceipt> = tuples
            .iter()
            .map(|t| sign_body(&body_from_tuple(t, &kp), &kp))
            .collect();
        let baseline_bytes: Vec<Vec<u8>> = receipts
            .iter()
            .map(|r| canonical_body_bytes(&r.body()))
            .collect();

        // Independence guarantee 1: pairwise-distinct nonces. Re-asserted
        // here so a future strategy regression that drops the uniqueness
        // filter is caught by the property itself, not just by code review.
        let nonces: std::collections::HashSet<&str> =
            tuples.iter().map(|t| t.nonce.as_str()).collect();
        prop_assert_eq!(nonces.len(), tuples.len());

        // Independence guarantee 2: pairwise-distinct content hashes. The
        // strategy stamps the nonce into each payload's `method` field, so
        // distinct nonces mechanically produce distinct content_hashes; this
        // assertion pins that invariant to the property surface.
        let content_hashes: std::collections::HashSet<String> = receipts
            .iter()
            .map(|r| r.body().content_hash.clone())
            .collect();
        prop_assert_eq!(content_hashes.len(), receipts.len());

        // Independence guarantee 3: every baseline byte vector is unique
        // (no two receipts canonicalize to the same bytes). This is the
        // strongest cross-reference guard: if two receipts produced
        // identical bytes, the shuffle would trivially preserve "per-receipt
        // bytes" by aliasing, which is not what the property asserts.
        let baseline_set: std::collections::HashSet<Vec<u8>> =
            baseline_bytes.iter().cloned().collect();
        prop_assert_eq!(baseline_set.len(), baseline_bytes.len());

        // Deterministic Fisher-Yates permutation seeded by the proptest
        // input. We avoid pulling in `rand` here: a linear congruential
        // step over `seed` is sufficient to produce a non-trivial
        // permutation while keeping the property reproducible.
        let mut indices: Vec<usize> = (0..receipts.len()).collect();
        let mut state = seed | 1;
        for i in (1..indices.len()).rev() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let j = (state as usize) % (i + 1);
            indices.swap(i, j);
        }
        let shuffled: Vec<ChioReceipt> =
            indices.iter().map(|&i| receipts[i].clone()).collect();
        let shuffled_bytes: Vec<Vec<u8>> = shuffled
            .iter()
            .map(|r| canonical_body_bytes(&r.body()))
            .collect();

        // Per-receipt assertion (strongest form): the receipt at position
        // `j` of the shuffled batch maps back to original index
        // `indices[j]`, and its canonical bytes must equal the baseline
        // bytes at that original index exactly. This is stronger than the
        // multiset comparison below: it pins the byte-identity of each
        // logical receipt across the permutation rather than just the
        // multiset of byte vectors.
        for (j, &original_index) in indices.iter().enumerate() {
            prop_assert_eq!(
                &shuffled_bytes[j],
                &baseline_bytes[original_index],
            );
        }

        // Multiset assertion (set-of-bytes regardless of order): every
        // shuffled entry must match exactly one baseline entry, with
        // multiplicities. This is a weaker check than the per-receipt
        // assertion above, but it pins the strategy's "no duplicate bytes"
        // invariant and catches a regression that would corrupt the receipt
        // body during the shuffle copy without altering positions.
        let mut baseline_sorted = baseline_bytes.clone();
        baseline_sorted.sort();
        let mut shuffled_sorted = shuffled_bytes.clone();
        shuffled_sorted.sort();
        prop_assert_eq!(baseline_sorted, shuffled_sorted);
    }
}
