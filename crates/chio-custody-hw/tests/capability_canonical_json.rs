//! Canonical-JSON encoding round-trip vectors for [`PasskeyCapability`].
//!
//! These vectors lock the byte-level shape of the audience-pinned capability
//! envelope. Any reviewer touching `PasskeyCapability` field order, default
//! values, or scope ordering must rebuild the golden bytes deliberately.

use chio_custody_hw::capability::{PasskeyCapability, ScopeSet, CAPABILITY_LIFETIME_SECONDS};
use chrono::{TimeZone, Utc};

fn fixed_iat() -> chrono::DateTime<Utc> {
    match Utc.with_ymd_and_hms(2026, 4, 29, 0, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => panic!("fixed_iat fixture must construct"),
    }
}

fn fixture_capability() -> PasskeyCapability {
    PasskeyCapability::new_stub_unsigned(
        "urn:chio:audience:kernel",
        "AAAA",
        ScopeSet::new(["tool:write", "tool:read"]), // intentionally unsorted
        "challenge-nonce-1",
        fixed_iat(),
    )
}

#[test]
fn canonical_json_round_trip_byte_identical() {
    let cap = fixture_capability();
    let bytes = match cap.to_canonical_json() {
        Ok(b) => b,
        Err(e) => panic!("canonical-json encode must succeed: {e}"),
    };
    let decoded = match PasskeyCapability::from_canonical_json(&bytes) {
        Ok(c) => c,
        Err(e) => panic!("canonical-json decode must succeed: {e}"),
    };
    let bytes2 = match decoded.to_canonical_json() {
        Ok(b) => b,
        Err(e) => panic!("re-encode must succeed: {e}"),
    };
    assert_eq!(bytes, bytes2, "canonical-json must be deterministic");
}

#[test]
fn canonical_json_field_order_locked() {
    let cap = fixture_capability();
    let bytes = match cap.to_canonical_json() {
        Ok(b) => b,
        Err(e) => panic!("encode must succeed: {e}"),
    };
    let s = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(e) => panic!("encoded bytes must be utf-8: {e}"),
    };
    // RFC 8785 sorts top-level object keys by UTF-16 code unit comparison.
    // Lexicographic order of the seven envelope keys: audience,
    // challenge_nonce, credential_id, exp, iat, scope_set, signature.
    // Locking this order keeps the issuer signature bit-stable against
    // any compliant RFC 8785 implementation.
    let audience_at = s.find("\"audience\"");
    let nonce_at = s.find("\"challenge_nonce\"");
    let credential_at = s.find("\"credential_id\"");
    let exp_at = s.find("\"exp\"");
    let iat_at = s.find("\"iat\"");
    let scope_at = s.find("\"scope_set\"");
    let sig_at = s.find("\"signature\"");
    assert!(audience_at < nonce_at, "audience before challenge_nonce");
    assert!(
        nonce_at < credential_at,
        "challenge_nonce before credential_id"
    );
    assert!(credential_at < exp_at, "credential_id before exp");
    assert!(exp_at < iat_at, "exp before iat");
    assert!(iat_at < scope_at, "iat before scope_set");
    assert!(scope_at < sig_at, "scope_set before signature");
}

#[test]
fn scope_set_serialised_in_canonical_sorted_order() {
    let cap = fixture_capability();
    let bytes = match cap.to_canonical_json() {
        Ok(b) => b,
        Err(e) => panic!("encode must succeed: {e}"),
    };
    let s = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(e) => panic!("encoded bytes must be utf-8: {e}"),
    };
    // BTreeSet ordering ensures lexicographic order: tool:read < tool:write.
    let read_at = s.find("\"tool:read\"");
    let write_at = s.find("\"tool:write\"");
    assert!(
        read_at.is_some() && write_at.is_some(),
        "both scopes encoded"
    );
    assert!(read_at < write_at, "scopes sorted lexicographically");
}

#[test]
fn unsigned_envelope_encodes_empty_signature_slot() {
    // The canonical-JSON encoding of the pre-signing envelope (signature
    // slot empty) MUST render `"signature":""`. This is the exact byte
    // sequence `sign_capability` signs over and the kernel verifier
    // reconstructs by clearing the slot, so the empty-string rendering is
    // a load-bearing canonicalisation invariant (not a claim that issued
    // capabilities are unsigned: the issuer always fills this slot).
    let cap = fixture_capability();
    let bytes = match cap.to_canonical_json() {
        Ok(b) => b,
        Err(e) => panic!("encode must succeed: {e}"),
    };
    let s = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(e) => panic!("encoded bytes must be utf-8: {e}"),
    };
    assert!(
        s.contains("\"signature\":\"\""),
        "the unsigned envelope MUST encode the signature slot as the empty string. got: {s}"
    );
}

#[test]
fn five_minute_lifetime_pinned() {
    let cap = fixture_capability();
    let delta = (cap.exp - cap.iat).num_seconds();
    assert_eq!(
        delta, CAPABILITY_LIFETIME_SECONDS,
        "lifetime must equal 5 minutes (300s)"
    );
    assert_eq!(delta, 300, "5 minutes is 300 seconds");
}

#[test]
fn audience_pin_encoded_verbatim() {
    let cap = fixture_capability();
    let bytes = match cap.to_canonical_json() {
        Ok(b) => b,
        Err(e) => panic!("encode must succeed: {e}"),
    };
    let s = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(e) => panic!("encoded bytes must be utf-8: {e}"),
    };
    assert!(s.contains("\"audience\":\"urn:chio:audience:kernel\""));
}
