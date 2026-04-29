//! Round-trip property invariants for `chio-tee-frame.v1`.
//!
//! Two named invariants from `.planning/trajectory/10-tee-replay-harness.md`
//! Phase 1 task 3:
//!
//! 1. [`canonicalize_parse_round_trips`] -- `parse(canonicalize(frame)) == frame`.
//! 2. [`canonicalize_is_idempotent`]    -- `canonicalize(parse(canonicalize(frame))) == canonicalize(frame)`.
//!
//! 256 cases per invariant by default. The `PROPTEST_CASES` env var
//! overrides for tiered CI lanes (PR vs nightly), matching the convention
//! used by `chio-core-types/tests/property_capability_algebra.rs`.

#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use chio_tee_frame::{
    canonicalize, parse, Frame, Otel, Provenance, Upstream, UpstreamSystem, Verdict, SCHEMA_VERSION,
};
use proptest::prelude::*;

/// Build a `ProptestConfig` honouring `PROPTEST_CASES` so CI tiering can
/// raise the case count without code edits.
fn proptest_config_for_lane(default_cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default_cases);
    ProptestConfig::with_cases(cases)
}

// ---- Strategies --------------------------------------------------------

/// Crockford base32 alphabet (uppercase): 0-9 plus the 22 letters used by
/// ULIDs (A-H, J, K, M, N, P-T, V-Z).
const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn ulid_strategy() -> impl Strategy<Value = String> {
    proptest::collection::vec(0usize..CROCKFORD.len(), 26).prop_map(|idxs| {
        let bytes: Vec<u8> = idxs.into_iter().map(|i| CROCKFORD[i]).collect();
        String::from_utf8(bytes).unwrap_or_else(|_| "0".repeat(26))
    })
}

fn timestamp_strategy() -> impl Strategy<Value = String> {
    (
        2000u32..=2100,
        1u32..=12,
        1u32..=28, // avoid month-end rollover
        0u32..=23,
        0u32..=59,
        0u32..=59,
        0u32..=999,
    )
        .prop_map(|(yr, mo, dy, hr, mn, sc, ms)| {
            format!("{yr:04}-{mo:02}-{dy:02}T{hr:02}:{mn:02}:{sc:02}.{ms:03}Z")
        })
}

fn tee_id_strategy() -> impl Strategy<Value = String> {
    // 3..=10 chars of [a-z0-9-], head/tail constrained to alnum.
    (3usize..=10).prop_flat_map(|len| {
        proptest::collection::vec(any::<u8>(), len).prop_map(move |raw| {
            let mut s = String::with_capacity(len);
            for (idx, byte) in raw.iter().enumerate() {
                let pool: &[u8] = if idx == 0 || idx == len - 1 {
                    b"abcdefghijklmnopqrstuvwxyz0123456789"
                } else {
                    b"abcdefghijklmnopqrstuvwxyz0123456789-"
                };
                s.push(pool[(*byte as usize) % pool.len()] as char);
            }
            s
        })
    })
}

fn upstream_system_strategy() -> impl Strategy<Value = UpstreamSystem> {
    prop_oneof![
        Just(UpstreamSystem::Openai),
        Just(UpstreamSystem::Anthropic),
        Just(UpstreamSystem::AwsBedrock),
        Just(UpstreamSystem::Mcp),
        Just(UpstreamSystem::A2a),
        Just(UpstreamSystem::Acp),
    ]
}

fn operation_strategy() -> impl Strategy<Value = String> {
    // 1..=16 chars matching ^[a-z][a-z0-9_.]*$.
    (1usize..=16).prop_flat_map(|len| {
        proptest::collection::vec(any::<u8>(), len).prop_map(move |raw| {
            let mut s = String::with_capacity(len);
            for (idx, byte) in raw.iter().enumerate() {
                let pool: &[u8] = if idx == 0 {
                    b"abcdefghijklmnopqrstuvwxyz"
                } else {
                    b"abcdefghijklmnopqrstuvwxyz0123456789_."
                };
                s.push(pool[(*byte as usize) % pool.len()] as char);
            }
            s
        })
    })
}

fn api_version_strategy() -> impl Strategy<Value = String> {
    (1usize..=16).prop_map(|len| {
        let mut s = String::with_capacity(len);
        for i in 0..len {
            let c = match i % 3 {
                0 => 'v',
                1 => '1',
                _ => '.',
            };
            s.push(c);
        }
        s
    })
}

fn upstream_strategy() -> impl Strategy<Value = Upstream> {
    (
        upstream_system_strategy(),
        operation_strategy(),
        api_version_strategy(),
    )
        .prop_map(|(system, operation, api_version)| Upstream {
            system,
            operation,
            api_version,
        })
}

fn lower_hex_string(len: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(0u8..16, len).prop_map(|nibs| {
        nibs.into_iter()
            .map(|n| char::from_digit(u32::from(n), 16).unwrap_or('0'))
            .collect()
    })
}

fn invocation_strategy() -> impl Strategy<Value = serde_json::Value> {
    // Keep the invocation simple and JSON-stable. Real frames carry a
    // ToolInvocation object; for round-trip purposes any JSON value works.
    // Strings are bounded to keep canonical-JSON round trip costs small.
    let string_strategy = proptest::collection::vec(any::<char>(), 0..=8)
        .prop_map(|chars| chars.into_iter().collect::<String>())
        .prop_map(serde_json::Value::String);
    prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        (-1_000_000i64..1_000_000).prop_map(|n| serde_json::Value::Number(n.into())),
        string_strategy,
    ]
}

fn provenance_strategy() -> impl Strategy<Value = Provenance> {
    (lower_hex_string(32), lower_hex_string(16), any::<bool>()).prop_map(
        |(trace_id, span_id, has_supply_chain)| Provenance {
            otel: Otel { trace_id, span_id },
            supply_chain: if has_supply_chain {
                Some(serde_json::json!({"k":"v"}))
            } else {
                None
            },
        },
    )
}

fn redaction_pass_id_strategy() -> impl Strategy<Value = String> {
    (1usize..=32).prop_map(|len| {
        let mut s = String::with_capacity(len);
        for i in 0..len {
            let c = match i % 4 {
                0 => 'a',
                1 => '0',
                2 => '_',
                _ => '.',
            };
            s.push(c);
        }
        s
    })
}

fn deny_reason_strategy() -> impl Strategy<Value = String> {
    // Build either a single segment or two segments joined by `:`.
    prop_oneof![
        Just("guard:pii".to_string()),
        Just("rewrite:tool.shell".to_string()),
        Just("policy:denied_capability".to_string()),
        Just("kernel:budget_exceeded".to_string()),
    ]
}

fn verdict_payload_strategy() -> impl Strategy<Value = (Verdict, Option<String>)> {
    prop_oneof![
        Just((Verdict::Allow, None::<String>)),
        deny_reason_strategy().prop_map(|r| (Verdict::Deny, Some(r))),
        deny_reason_strategy().prop_map(|r| (Verdict::Rewrite, Some(r))),
    ]
}

fn tenant_sig_strategy() -> impl Strategy<Value = String> {
    (86usize..=88).prop_map(|len| format!("ed25519:{}", "A".repeat(len)))
}

fn frame_strategy() -> impl Strategy<Value = Frame> {
    (
        ulid_strategy(),
        timestamp_strategy(),
        tee_id_strategy(),
        upstream_strategy(),
        invocation_strategy(),
        provenance_strategy(),
        lower_hex_string(64),
        lower_hex_string(64),
        redaction_pass_id_strategy(),
        verdict_payload_strategy(),
        any::<bool>(),
        tenant_sig_strategy(),
    )
        .prop_map(
            |(
                event_id,
                ts,
                tee_id,
                upstream,
                invocation,
                provenance,
                request_blob_sha256,
                response_blob_sha256,
                redaction_pass_id,
                (verdict, deny_reason),
                would_have_blocked,
                tenant_sig,
            )| Frame {
                schema_version: SCHEMA_VERSION.to_string(),
                event_id,
                ts,
                tee_id,
                upstream,
                invocation,
                provenance,
                request_blob_sha256,
                response_blob_sha256,
                redaction_pass_id,
                verdict,
                deny_reason,
                would_have_blocked,
                tenant_sig,
            },
        )
}

// ---- Properties --------------------------------------------------------

proptest! {
    #![proptest_config(proptest_config_for_lane(256))]

    /// `parse(canonicalize(frame))` recovers the original frame.
    #[test]
    fn canonicalize_parse_round_trips(frame in frame_strategy()) {
        let bytes = canonicalize(&frame).map_err(|e| TestCaseError::fail(format!("canonicalize: {e}")))?;
        let parsed = parse(&bytes).map_err(|e| TestCaseError::fail(format!("parse: {e}")))?;
        prop_assert_eq!(parsed, frame);
    }

    /// Canonicalization is idempotent: re-encoding a parsed frame yields
    /// the same bytes.
    #[test]
    fn canonicalize_is_idempotent(frame in frame_strategy()) {
        let a = canonicalize(&frame).map_err(|e| TestCaseError::fail(format!("canonicalize a: {e}")))?;
        let parsed = parse(&a).map_err(|e| TestCaseError::fail(format!("parse: {e}")))?;
        let b = canonicalize(&parsed).map_err(|e| TestCaseError::fail(format!("canonicalize b: {e}")))?;
        prop_assert_eq!(a, b);
    }
}
