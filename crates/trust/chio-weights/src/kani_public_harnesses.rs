//! # Scope
//!
//! This module models the trust-boundary invariants of the public
//! surfaces of `chio-weights` that are tractable for symbolic
//! execution under Kani's default unwind budget:
//!
//! - `weights_hash_of` (free `pub fn` at `src/card.rs:274`).
//! - `ModelCard::require_live` (`pub fn` at `src/card.rs:236`).
//! - `ModelCard::new` schema-version pinning (`pub fn` at `src/card.rs:172`).
//! - `WeightsError::urn` (`pub fn` at `src/error.rs:75`).
//!
//! # What these harnesses model and what they do not
//!
//! `weights_hash_of` is exercised directly: its body is a pure SHA-256
//! over a byte slice followed by lowercase-hex encoding. Kani can
//! verify the determinism and tampering algebra over a small
//! symbolic input (the SHA-256 implementation itself transitively
//! involves a fixed-iteration loop that fits within a bounded
//! `#[kani::unwind]` envelope). The harnesses therefore exercise the
//! real `pub fn` rather than an algebraic surrogate.
//!
//! `ModelCard::validate` and `ModelCard::from_canonical_json` build
//! arbitrary-length `String` and `BTreeSet<String>` payloads through
//! `serde_json` + `chrono`, which transit allocator paths and parser
//! state machines that are intractable under Kani's default unwind
//! budget. The same is true of `StringSet::covers`/`intersects`/
//! `contains`: even with a fixed two-element set, the symbolic
//! `BTreeSet<String>` lookup path exceeds the workspace
//! `#[kani::unwind(8)]` envelope. Per the convention in
//! `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs`, those
//! surfaces are pinned by the runtime tests in `src/card.rs::tests`,
//! `src/lineage.rs::tests`, and the integration tests under
//! `crates/trust/chio-weights/tests/`. The harnesses below cover the
//! algebraic core that fits within the unwind envelope:
//! `require_live`, the schema-version pin in `ModelCard::new`, the
//! `WeightsError::urn` mapping, and the `weights_hash_of` byte
//! algebra.
//!
//! # Bound parameters
//!
//! - Symbolic byte arrays are <= 4 bytes (the smallest size that
//!   exercises the SHA-256 length-encoding while staying within the
//!   `#[kani::unwind(8)]` envelope).
//! - `StringSet` predicates are NOT exercised here; the underlying
//!   `BTreeSet<String>` lookup exceeds the workspace
//!   `#[kani::unwind(8)]` envelope. The runtime tests in
//!   `src/card.rs::tests` pin the algebra.
//! - `ModelCard::require_live` is exercised over a symbolic `now`
//!   ordering relative to `expires_at`; the card body itself is built
//!   from constants because `ModelCard::new` calls into `chrono` and
//!   `serde` paths that are intractable for symbolic execution.
//! - Per-harness `#[kani::unwind(8)]` matches the workspace default
//!   established by `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs`.
//!
//! # Anti-pattern guard
//!
//! Every `#[kani::proof]` function in this module either calls a real
//! `pub fn` of `chio-weights` or witnesses the algebra of one over a
//! bounded symbolic envelope. No harness body bottoms out in
//! `kani::assume(false)`; no harness targets a non-`pub` internal
//! helper.
//!
//! # Cross-references

extern crate alloc;

use alloc::string::{String, ToString};

use chrono::{DateTime, TimeZone, Utc};

use crate::card::{weights_hash_of, ModelCard, StringSet, CARD_VERSION_V1};
use crate::error::WeightsError;

/// Construct a deterministic `ModelCard` fixture suitable for symbolic
/// `require_live` enumeration. The fixture is built from constants so
/// the harness body avoids the `serde_json` / `chrono` parser paths
/// that are intractable under Kani's default unwind budget.
fn fixture_card(issued_at: DateTime<Utc>, expires_at: DateTime<Utc>) -> ModelCard {
    // ModelCard::new calls validate(); both arguments here satisfy
    // every checked invariant. The lowercase-hex weights_hash, the
    // non-empty issuer/training_data_class strings, and the
    // expires_at >= issued_at ordering are pinned at construction.
    match ModelCard::new(
        "0000000000000000000000000000000000000000000000000000000000000001",
        StringSet::default(),
        StringSet::default(),
        "public-internet",
        "https://example.com/issuer",
        issued_at,
        expires_at,
    ) {
        Ok(card) => card,
        Err(_) => {
            unreachable!("fixture_card constants satisfy ModelCard::new's validate() invariants")
        }
    }
}

/// Real public surface exercised symbolically: `weights_hash_of` MUST
/// be deterministic (re-running with byte-identical input MUST
/// produce the same digest hex) AND fail-closed under one-byte
/// tampering (flipping any byte in the input MUST change the digest
/// hex). Together these arms pin the binding determinism property the
/// kernel-binding refusal path relies on when it byte-compares the
/// runtime-loaded `weights_hash` against the card's declared
/// `weights_hash`.
///
/// Production entry: `chio_weights::card::weights_hash_of`
/// (`pub fn` in `crates/trust/chio-weights/src/card.rs`,
/// re-exported via `crates/trust/chio-weights/src/lib.rs`).
#[kani::proof]
#[kani::unwind(8)]
pub fn public_weights_hash_of_determinism_and_tampering() {
    // Symbolic 4-byte input. SHA-256's compression function processes
    // a single 64-byte block here (a 4-byte payload always fits in
    // one block under the 1-bit + length padding), so the loop count
    // is bounded by `#[kani::unwind(8)]`.
    let bytes: [u8; 4] = kani::any();
    let flip_index: u8 = kani::any();
    kani::assume((flip_index as usize) < bytes.len());

    // (1) Determinism. Two calls with identical inputs MUST agree
    // byte-for-byte. The kernel binding refusal path relies on this
    // when it recomputes `weights_hash_of(loaded_bytes)` and
    // byte-compares against the card's `weights_hash`.
    let first = weights_hash_of(&bytes);
    let second = weights_hash_of(&bytes);
    assert_eq!(first, second);

    // (2) Output shape. The output is always a 64-character lowercase
    // hex string. The card's `validate()` predicate refuses any
    // candidate that does not match this shape, so a `weights_hash_of`
    // implementation that drifted to uppercase or shortened the
    // digest would silently break every binding.
    assert_eq!(first.len(), 64);
    for byte in first.as_bytes() {
        assert!(matches!(*byte, b'0'..=b'9' | b'a'..=b'f'));
    }

    // (3) Tampering. Flipping a single bit in the input MUST change
    // the digest. The kernel binding refusal path therefore cannot
    // be tricked by a runtime that loads tampered weights and hopes
    // the digest collides.
    let mut tampered = bytes;
    tampered[flip_index as usize] ^= 0x01;
    let tampered_digest = weights_hash_of(&tampered);
    assert_ne!(first, tampered_digest);
}

/// Real public surface exercised symbolically: `ModelCard::require_live`
/// MUST return `Ok(())` when `now < expires_at` and
/// `Err(WeightsError::Expired)` when `now >= expires_at`. The
/// fail-closed semantics matter for the kernel verifier path: a card
/// whose expiry has passed MUST NOT bind, even if the cosign bundle
/// itself remains valid.
///
/// Production entry: `chio_weights::card::ModelCard::require_live`
/// (`pub fn` in `crates/trust/chio-weights/src/card.rs`).
#[kani::proof]
#[kani::unwind(8)]
pub fn public_model_card_require_live_fail_closed() {
    // Fixed reference timestamps. `chrono::Utc.with_ymd_and_hms` is
    // a const-shaped path; the `LocalResult::Single` arm is taken
    // for the chosen 2026 dates, and the `unreachable!()` fallback
    // is never reached at runtime. We pin the construction outside
    // the symbolic envelope so the harness body itself stays
    // tractable.
    let issued_at = match Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => unreachable!("fixed issued_at fixture must construct"),
    };
    let expires_at = match Utc.with_ymd_and_hms(2026, 5, 30, 12, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => unreachable!("fixed expires_at fixture must construct"),
    };
    let card = fixture_card(issued_at, expires_at);

    // Symbolic axis: `now` chosen relative to `expires_at` from one
    // of three discrete buckets. We pin the bucket selector via a
    // bounded u8 rather than building a fully symbolic
    // `DateTime<Utc>` (the latter transits chrono's parser paths,
    // which are intractable here).
    let bucket: u8 = kani::any();
    kani::assume(bucket < 3);
    let now = match bucket {
        // (a) now < expires_at -- card MUST be live.
        0 => match Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0) {
            chrono::LocalResult::Single(t) => t,
            _ => unreachable!("fixed live `now` fixture must construct"),
        },
        // (b) now == expires_at -- card MUST be expired (the
        // predicate is `now < expires_at`, strict).
        1 => expires_at,
        // (c) now > expires_at -- card MUST be expired.
        _ => match Utc.with_ymd_and_hms(2026, 6, 30, 12, 0, 0) {
            chrono::LocalResult::Single(t) => t,
            _ => unreachable!("fixed expired `now` fixture must construct"),
        },
    };

    let result = card.require_live(now);
    if now < expires_at {
        // Live arm.
        assert!(result.is_ok());
    } else {
        // Expired arm. The error variant MUST be `Expired` so the
        // kernel can route the refusal to the
        // `urn:chio:error:weights:card-expired` URN; routing it as
        // any other variant would lose the registered code.
        assert!(matches!(result, Err(WeightsError::Expired { .. })));
    }
}

/// Real public surface exercised symbolically: `WeightsError::urn`
/// MUST map every error variant to a stable URN string. The kernel
/// audit-log surface and the typed-enum codegen consume these
/// URNs; a bug that reused or dropped a URN would silently merge
/// two distinct refusal classes in the audit trail.
///
/// Production entry: `chio_weights::error::WeightsError::urn`
/// (`pub fn` in `crates/trust/chio-weights/src/error.rs`).
#[kani::proof]
#[kani::unwind(8)]
pub fn public_weights_error_urn_is_stable() {
    // Symbolic axis: variant selector. Each value picks one of the
    // eight inhabitable variants (the enum is `#[non_exhaustive]`
    // for forward-compatibility, but the local `match` is
    // exhaustive over today's variants). The `tool-banned` URN is
    // pinned alongside the others to keep coverage exhaustive.
    let pick: u8 = kani::any();
    kani::assume(pick < 8);

    let err: WeightsError = match pick {
        0 => WeightsError::Encoding(String::new()),
        1 => WeightsError::MissingField("training_data_class"),
        2 => WeightsError::SchemaRejected(String::new()),
        3 => {
            // Construct two valid `DateTime<Utc>` values so the
            // `Expired` variant has live fields. The constants are
            // chosen to never fail `with_ymd_and_hms`.
            let expires_at = match Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0) {
                chrono::LocalResult::Single(t) => t,
                _ => unreachable!(),
            };
            let now = match Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0) {
                chrono::LocalResult::Single(t) => t,
                _ => unreachable!(),
            };
            WeightsError::Expired { expires_at, now }
        }
        4 => WeightsError::BundleRejected(String::new()),
        5 => WeightsError::CardMismatch {
            expected: String::new(),
            found: String::new(),
        },
        6 => WeightsError::ScopeNotSubset {
            scope: String::new(),
        },
        7 => WeightsError::ToolBanned {
            tool: String::new(),
        },
        _ => unreachable!("pick is bounded by kani::assume above"),
    };

    let urn = err.urn();

    // (1) Every URN starts with the registered prefix. The
    // error-code registry pins this; a drift would break audit-log routing.
    assert!(urn.starts_with("urn:chio:error:weights:"));

    // (2) Per-variant URN. The mapping is the registered
    // identifier; pin each one explicitly so a future regression
    // that renamed a code is caught here. `MissingField` and
    // `SchemaRejected` share a URN by design (both are schema
    // rejections); we assert the shared mapping rather than over-
    // specifying.
    let expected = match pick {
        0 => "urn:chio:error:weights:internal-encoding",
        1 => "urn:chio:error:weights:schema-rejected",
        2 => "urn:chio:error:weights:schema-rejected",
        3 => "urn:chio:error:weights:card-expired",
        4 => "urn:chio:error:weights:bundle-rejected",
        5 => "urn:chio:error:weights:card-mismatch",
        6 => "urn:chio:error:weights:scope-not-subset",
        7 => "urn:chio:error:weights:tool-banned",
        _ => unreachable!(),
    };
    assert_eq!(urn, expected);
}

/// Real public surface exercised symbolically: `ModelCard`'s
/// `card_version` field MUST equal `CARD_VERSION_V1` for every
/// successfully constructed card. This pins the schema-pinning
/// invariant that `ModelCard::new` writes the constant rather than
/// echoing a caller-supplied value.
///
/// Production entries:
/// - `chio_weights::card::ModelCard::new`
///   (`pub fn` in `crates/trust/chio-weights/src/card.rs`).
/// - `chio_weights::card::CARD_VERSION_V1` constant.
#[kani::proof]
#[kani::unwind(8)]
pub fn public_model_card_new_pins_schema_version() {
    let issued_at = match Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => unreachable!("fixed issued_at fixture must construct"),
    };
    let expires_at = match Utc.with_ymd_and_hms(2026, 5, 30, 12, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => unreachable!("fixed expires_at fixture must construct"),
    };
    let card = fixture_card(issued_at, expires_at);

    // (1) Schema version MUST equal `CARD_VERSION_V1`; `ModelCard::new` MUST NOT accept a caller-supplied schema string.
    assert_eq!(card.card_version, CARD_VERSION_V1.to_string());

    // (2) `validate()` is idempotent and accepts a freshly
    // constructed card. Re-validation after construction MUST
    // succeed; the kernel calls `validate()` on every deserialised
    // card and a non-idempotent path would reject good inputs.
    assert!(card.validate().is_ok());

    // (3) `expires_at >= issued_at` is preserved. `ModelCard::new`
    // refuses inputs that violate this; we double-check the
    // accessors agree with the constructor's contract.
    assert!(card.expires_at >= card.issued_at);
}
