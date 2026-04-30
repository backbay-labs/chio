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
    // Lock the field order so signatures over the canonical bytes survive
    // serde-version churn. Order: audience, credential_id, scope_set, iat,
    // exp, challenge_nonce, signature.
    let audience_at = s.find("\"audience\"");
    let credential_at = s.find("\"credential_id\"");
    let scope_at = s.find("\"scope_set\"");
    let iat_at = s.find("\"iat\"");
    let exp_at = s.find("\"exp\"");
    let nonce_at = s.find("\"challenge_nonce\"");
    let sig_at = s.find("\"signature\"");
    assert!(audience_at < credential_at, "audience before credential_id");
    assert!(credential_at < scope_at, "credential_id before scope_set");
    assert!(scope_at < iat_at, "scope_set before iat");
    assert!(iat_at < exp_at, "iat before exp");
    assert!(exp_at < nonce_at, "exp before challenge_nonce");
    assert!(nonce_at < sig_at, "challenge_nonce before signature");
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
fn signature_field_empty_in_p1() {
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
        "P1 capabilities are unsigned; signature MUST be the empty string. got: {s}"
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
