//! Fail-closed and paranoid-heuristic tests for the M06 redactor pass
//! (M10 Phase 1 Task 6).
//!
//! Trajectory doc references:
//! `.planning/trajectory/10-tee-replay-harness.md` line 21 (paranoid
//! heuristic) and line 452 (fail-closed semantics).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chio_data_guards_redactors_default::PASS_ID;
use chio_tee::redact::{
    RedactClass, RedactError, RedactPass, RedactedPayload, Redactor, RedactorError,
    PARANOID_ZERO_MATCH_THRESHOLD,
};
use chio_tee::{RawPayloadBuffer, RedactionManifest};
use zeroize::ZeroizeOnDrop;

// -------------------------------------------------------------------------
// Test doubles
// -------------------------------------------------------------------------

/// Redactor that always returns `Err(_)`. Exercises Test 1.
struct AlwaysFailRedactor {
    calls: Arc<AtomicUsize>,
}

impl Redactor for AlwaysFailRedactor {
    fn redact_payload(
        &self,
        _payload: &[u8],
        _classes: RedactClass,
    ) -> Result<RedactedPayload, RedactorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(RedactorError::Failed("synthetic test failure".to_string()))
    }
}

/// Redactor that returns an `Ok(_)` whose manifest reports zero matches
/// regardless of the payload. Exercises Tests 3 and 4.
struct EmptyManifestRedactor;

impl Redactor for EmptyManifestRedactor {
    fn redact_payload(
        &self,
        payload: &[u8],
        _classes: RedactClass,
    ) -> Result<RedactedPayload, RedactorError> {
        Ok(RedactedPayload {
            bytes: payload.to_vec(),
            manifest: RedactionManifest {
                pass_id: PASS_ID.to_string(),
                matches: Vec::new(),
                elapsed_micros: 0,
            },
        })
    }
}

// -------------------------------------------------------------------------
// Test 1: redactor returns Err -> RedactPass returns Err(FailClosed).
// Trajectory doc line 452.
// -------------------------------------------------------------------------

#[test]
fn fail_closed_when_redactor_returns_err() {
    let calls = Arc::new(AtomicUsize::new(0));
    let pass = RedactPass::new(Box::new(AlwaysFailRedactor {
        calls: Arc::clone(&calls),
    }));

    let payload = RawPayloadBuffer::from_slice(b"alice@example.com");
    let result = pass.redact_or_fail_closed(payload, RedactClass::default_full(), false);

    let err = result.expect_err("redactor returned Err; pass MUST return Err");
    match err {
        RedactError::FailClosed(msg) => {
            assert!(
                msg.contains("synthetic test failure"),
                "FailClosed message should propagate the redactor error: {msg}"
            );
        }
        other => panic!("expected RedactError::FailClosed, got {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "redactor should be invoked exactly once before fail-closed"
    );
}

// -------------------------------------------------------------------------
// Test 2: redactor returns Ok with valid matches -> RedactPass returns
// Ok and the redacted bytes are present.
// -------------------------------------------------------------------------

#[test]
fn returns_ok_when_redactor_succeeds() {
    let pass = RedactPass::with_default();
    let payload = RawPayloadBuffer::from_slice(b"contact alice@example.com regarding the receipt");
    let out = pass
        .redact_or_fail_closed(payload, RedactClass::default_full(), false)
        .expect("default redactor should succeed on a payload containing an email");

    let body = String::from_utf8(out.bytes).expect("redacted bytes are utf-8");
    assert!(body.contains("[REDACTED-EMAIL]"));
    assert!(!body.contains("alice@example.com"));
    assert!(
        out.manifest.matches.iter().any(|m| m.class == "pii.email"),
        "manifest should record the email match"
    );
    assert_eq!(out.manifest.pass_id, PASS_ID);
}

// -------------------------------------------------------------------------
// Test 3: paranoid=true, payload>256 bytes, manifest has zero matches
// -> RedactError::ParanoidRefusal. Trajectory doc line 21.
// -------------------------------------------------------------------------

#[test]
fn paranoid_refuses_zero_match_on_large_payload() {
    let pass = RedactPass::new(Box::new(EmptyManifestRedactor));

    // 300 bytes of innocuous filler that the empty-manifest redactor
    // will report as zero matches.
    let bytes = vec![b'.'; 300];
    assert!(bytes.len() > PARANOID_ZERO_MATCH_THRESHOLD);
    let payload = RawPayloadBuffer::new(bytes);

    let result = pass.redact_or_fail_closed(payload, RedactClass::default_full(), true);
    let err = result.expect_err("paranoid heuristic should refuse zero-match large payload");
    match err {
        RedactError::ParanoidRefusal {
            payload_len,
            threshold,
        } => {
            assert_eq!(payload_len, 300);
            assert_eq!(threshold, PARANOID_ZERO_MATCH_THRESHOLD);
            assert_eq!(threshold, 256);
        }
        other => panic!("expected RedactError::ParanoidRefusal, got {other:?}"),
    }
}

// -------------------------------------------------------------------------
// Test 4: paranoid=false, same input -> Ok. Zero matches don't trip
// the heuristic when paranoid is disabled.
// -------------------------------------------------------------------------

#[test]
fn paranoid_off_allows_zero_match_on_large_payload() {
    let pass = RedactPass::new(Box::new(EmptyManifestRedactor));

    let bytes = vec![b'.'; 300];
    let payload = RawPayloadBuffer::new(bytes);

    let out = pass
        .redact_or_fail_closed(payload, RedactClass::default_full(), false)
        .expect("paranoid=false should pass even with zero matches");
    assert!(out.manifest.matches.is_empty());
    assert_eq!(out.bytes.len(), 300);
}

// -------------------------------------------------------------------------
// Test 4b (boundary): paranoid=true on a payload at-or-below 256 bytes
// with zero matches -> Ok. The heuristic is strictly `len > 256`.
// -------------------------------------------------------------------------

#[test]
fn paranoid_does_not_refuse_at_threshold_boundary() {
    let pass = RedactPass::new(Box::new(EmptyManifestRedactor));

    // Exactly 256 bytes: NOT greater than the threshold, so paranoid
    // must let it through.
    let bytes = vec![b'.'; PARANOID_ZERO_MATCH_THRESHOLD];
    let payload = RawPayloadBuffer::new(bytes);

    let out = pass
        .redact_or_fail_closed(payload, RedactClass::default_full(), true)
        .expect("payload at threshold should not trip paranoid heuristic");
    assert!(out.manifest.matches.is_empty());
}

// -------------------------------------------------------------------------
// Test 5: zeroize trait check. Compile-time assertion that
// RawPayloadBuffer carries the ZeroizeOnDrop bound. If the buffer were
// changed to a plain Vec or the derive removed, this test would fail
// to compile.
// -------------------------------------------------------------------------

#[test]
fn raw_payload_buffer_implements_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<RawPayloadBuffer>();
}
