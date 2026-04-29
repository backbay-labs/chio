//! Property-based invariants for the Chio tool-call fabric.
//!
//! Eight named properties over arbitrary fabric values:
//!
//!   (a) `ToolInvocation` round-trips canonical JSON.
//!   (b) `ProvenanceStamp` round-trips.
//!   (c) `Principal` round-trips for all three variants.
//!   (d) lift then lower preserves invocation identity.
//!   (e) `VerdictResult::Deny` always carries a `receipt_id`.
//!   (f) `ProviderError` Display is em-dash-free.
//!   (g) `ProvenanceStamp.received_at` round-trips through canonical JSON
//!       without precision loss above ms granularity.
//!   (h) Schema subsumption (gated on the `m01-schema-subsumption` feature;
//!       runs as a structural self-check over the canonical-JSON pipeline
//!       when the schema is not present).
//!
//! Per-property budget: 64 cases (matches the doc's "8 proptest invariants"
//! sizing and keeps the suite under ~1s on CI). Failed shrinks persist under
//! `crates/chio-tool-call-fabric/proptest-regressions/` so future runs replay
//! the seed.
//!
//! House rules:
//! - No em dashes (U+2014) anywhere in code, comments, or rendered output.
//! - `unwrap_used` / `expect_used` are denied workspace-wide; we allow them
//!   inside this file because the proptest harness builds throwaway fixtures
//!   whose invariants are checked locally.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{Duration, SystemTime};

use chio_core::canonical::canonical_json_bytes;
use chio_tool_call_fabric::{
    DenyReason, Principal, ProvenanceStamp, ProviderError, ProviderId, ReceiptId, Redaction,
    ToolInvocation, VerdictResult,
};
use proptest::collection::vec as prop_vec;
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

/// Per-property budget. 64 cases per property keeps the full suite well under
/// the 30s CI budget shared with the kernel replay-invariance suite.
const PROPTEST_BUDGET_CASES: u32 = 64;

// -- arbitrary generators -------------------------------------------------

fn arb_provider_id() -> impl Strategy<Value = ProviderId> {
    prop_oneof![
        Just(ProviderId::OpenAi),
        Just(ProviderId::Anthropic),
        Just(ProviderId::Bedrock),
    ]
}

fn arb_principal() -> impl Strategy<Value = Principal> {
    prop_oneof![
        "[a-zA-Z0-9_]{1,16}".prop_map(|org_id| Principal::OpenAiOrg { org_id }),
        "[a-zA-Z0-9_]{1,16}"
            .prop_map(|workspace_id| Principal::AnthropicWorkspace { workspace_id }),
        (
            "arn:aws:iam::[0-9]{12}:role/[a-zA-Z0-9]{1,16}",
            "[0-9]{12}",
            proptest::option::of(
                "arn:aws:sts::[0-9]{12}:assumed-role/[a-zA-Z0-9]{1,16}/session-[0-9]{1,4}"
            ),
        )
            .prop_map(|(caller_arn, account_id, assumed_role_session_arn)| {
                Principal::BedrockIam {
                    caller_arn,
                    account_id,
                    assumed_role_session_arn,
                }
            }),
    ]
}

/// Generate a `SystemTime` aligned to whole milliseconds since UNIX_EPOCH.
///
/// The fabric's canonical-JSON round-trip preserves millisecond precision
/// (invariant g). Generating below-ms granularity would conflate generator
/// noise with precision loss, so we sample whole-ms timestamps.
fn arb_system_time_ms() -> impl Strategy<Value = SystemTime> {
    // 2000-01-01 .. 2100-01-01 in milliseconds.
    (946_684_800_000u64..4_102_444_800_000u64)
        .prop_map(|ms| SystemTime::UNIX_EPOCH + Duration::from_millis(ms))
}

fn arb_provenance_stamp() -> impl Strategy<Value = ProvenanceStamp> {
    (
        arb_provider_id(),
        "[a-zA-Z0-9_-]{1,32}",
        "[a-z0-9.-]{1,24}",
        arb_principal(),
        arb_system_time_ms(),
    )
        .prop_map(
            |(provider, request_id, api_version, principal, received_at)| ProvenanceStamp {
                provider,
                request_id,
                api_version,
                principal,
                received_at,
            },
        )
}

fn arb_tool_invocation() -> impl Strategy<Value = ToolInvocation> {
    (
        arb_provider_id(),
        "[a-zA-Z_][a-zA-Z0-9_]{0,31}",
        prop_vec(any::<u8>(), 0..64),
        arb_provenance_stamp(),
    )
        .prop_map(
            |(provider, tool_name, arguments, provenance)| ToolInvocation {
                provider,
                tool_name,
                arguments,
                provenance,
            },
        )
}

fn arb_deny_reason() -> impl Strategy<Value = DenyReason> {
    prop_oneof![
        "[a-zA-Z0-9_-]{1,16}".prop_map(|rule_id| DenyReason::PolicyDeny { rule_id }),
        ("[a-zA-Z0-9_-]{1,16}", "[ -~]{0,32}")
            .prop_map(|(guard_id, detail)| { DenyReason::GuardDeny { guard_id, detail } }),
        Just(DenyReason::CapabilityExpired),
        Just(DenyReason::PrincipalUnknown),
        Just(DenyReason::BudgetExceeded),
    ]
}

fn arb_redaction() -> impl Strategy<Value = Redaction> {
    ("[a-zA-Z0-9_./-]{1,32}", "[ -~]{0,16}")
        .prop_map(|(path, replacement)| Redaction { path, replacement })
}

fn arb_verdict_result() -> impl Strategy<Value = VerdictResult> {
    let allow =
        (prop_vec(arb_redaction(), 0..4), "[a-zA-Z0-9_-]{1,32}").prop_map(|(redactions, rid)| {
            VerdictResult::Allow {
                redactions,
                receipt_id: ReceiptId(rid),
            }
        });
    let deny =
        (arb_deny_reason(), "[a-zA-Z0-9_-]{1,32}").prop_map(|(reason, rid)| VerdictResult::Deny {
            reason,
            receipt_id: ReceiptId(rid),
        });
    prop_oneof![allow, deny]
}

fn arb_provider_error() -> impl Strategy<Value = ProviderError> {
    prop_oneof![
        any::<u64>().prop_map(|retry_after_ms| ProviderError::RateLimited { retry_after_ms }),
        "[ -~]{0,32}".prop_map(ProviderError::ContentPolicy),
        "[ -~]{0,32}".prop_map(ProviderError::BadToolArgs),
        (500u16..=599u16, "[ -~]{0,32}")
            .prop_map(|(status, body)| ProviderError::Upstream5xx { status, body }),
        any::<u64>().prop_map(|ms| ProviderError::TransportTimeout { ms }),
        (any::<u64>(), any::<u64>()).prop_map(|(observed_ms, budget_ms)| {
            ProviderError::VerdictBudgetExceeded {
                observed_ms,
                budget_ms,
            }
        }),
        "[ -~]{0,32}".prop_map(ProviderError::Malformed),
    ]
}

// -- properties -----------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: PROPTEST_BUDGET_CASES,
        ..ProptestConfig::default()
    })]

    /// (a) `ToolInvocation` round-trips canonical JSON.
    ///
    /// Serialize through RFC 8785 canonical bytes, deserialize back, and
    /// assert structural equality plus byte determinism on a second
    /// canonicalization pass.
    #[test]
    fn invariant_a_tool_invocation_round_trips_canonical_json(
        inv in arb_tool_invocation(),
    ) {
        let bytes = canonical_json_bytes(&inv).expect("invocation canonicalises");
        let back: ToolInvocation = serde_json::from_slice(&bytes)
            .expect("invocation deserialises from canonical bytes");
        prop_assert_eq!(&inv, &back);
        let bytes_b = canonical_json_bytes(&back).expect("re-canonicalises");
        prop_assert_eq!(bytes, bytes_b);
    }

    /// (b) `ProvenanceStamp` round-trips.
    ///
    /// Same shape as (a) but for the stamp alone; also exercises
    /// `serde_json::to_string` so the regular (non-canonical) serializer
    /// stays compatible with the canonical one for stamp values.
    #[test]
    fn invariant_b_provenance_stamp_round_trips(stamp in arb_provenance_stamp()) {
        let json = serde_json::to_string(&stamp).expect("stamp to_string");
        let back: ProvenanceStamp = serde_json::from_str(&json)
            .expect("stamp from_str");
        prop_assert_eq!(&stamp, &back);

        let canon = canonical_json_bytes(&stamp).expect("stamp canonicalises");
        let canon_back: ProvenanceStamp = serde_json::from_slice(&canon)
            .expect("stamp from canonical bytes");
        prop_assert_eq!(stamp, canon_back);
    }

    /// (c) `Principal` round-trips for all three variants.
    #[test]
    fn invariant_c_principal_round_trips_all_variants(p in arb_principal()) {
        let json = serde_json::to_string(&p).expect("principal to_string");
        let back: Principal = serde_json::from_str(&json).expect("principal from_str");
        prop_assert_eq!(&p, &back);
        let canon = canonical_json_bytes(&p).expect("principal canonicalises");
        let canon_back: Principal = serde_json::from_slice(&canon)
            .expect("principal from canonical bytes");
        prop_assert_eq!(p, canon_back);
    }

    /// (d) lift then lower preserves invocation identity.
    ///
    /// Phase 1 has no provider adapters wired yet, so we model the lift/lower
    /// pair at the fabric level: take the invocation to canonical-JSON bytes
    /// (the on-the-wire shape adapters will produce), parse those bytes back
    /// (the inverse adapters will consume), and assert byte-for-byte
    /// stability of every field including the canonicalized arguments
    /// payload. Phase 2-4 adapter conformance tests will tighten this to a
    /// real `lift(lower(x)) == x` round-trip.
    #[test]
    fn invariant_d_lift_lower_preserves_invocation_identity(
        inv in arb_tool_invocation(),
    ) {
        // Lift: serialize to canonical bytes (the wire shape).
        let lifted = canonical_json_bytes(&inv).expect("lift canonicalises");
        // Lower: parse back into a `ToolInvocation`.
        let lowered: ToolInvocation = serde_json::from_slice(&lifted)
            .expect("lower parses from canonical bytes");
        prop_assert_eq!(&inv, &lowered);

        // Identity also holds at the byte level: re-lifting yields the same
        // canonical wire bytes.
        let relifted = canonical_json_bytes(&lowered).expect("relift canonicalises");
        prop_assert_eq!(lifted, relifted);

        // Field-by-field identity (so a future struct-shape change that
        // happens to round-trip but reorders fields is still caught).
        prop_assert_eq!(&inv.provider, &lowered.provider);
        prop_assert_eq!(&inv.tool_name, &lowered.tool_name);
        prop_assert_eq!(&inv.arguments, &lowered.arguments);
        prop_assert_eq!(&inv.provenance, &lowered.provenance);
    }

    /// (e) `VerdictResult::Deny` always carries a `receipt_id`.
    ///
    /// The type system already enforces this via the `receipt_id` field on
    /// the `Deny` variant; the property guards against future schema drift
    /// (for example, making `receipt_id` `Option<ReceiptId>`) by asserting
    /// every generated `Deny` value canonicalises to JSON that contains a
    /// non-empty `receipt_id` string.
    #[test]
    fn invariant_e_verdict_deny_always_carries_receipt_id(verdict in arb_verdict_result()) {
        if let VerdictResult::Deny { receipt_id, .. } = &verdict {
            prop_assert!(!receipt_id.0.is_empty(), "deny receipt_id is empty");
            let json = canonical_json_bytes(&verdict).expect("deny canonicalises");
            let parsed: serde_json::Value = serde_json::from_slice(&json)
                .expect("deny canonical bytes parse");
            let rid = parsed
                .get("receipt_id")
                .and_then(|v| v.get("0").or(Some(v)))
                .and_then(|v| v.as_str().or_else(|| {
                    // ReceiptId is a tuple struct; serde renders it as a
                    // bare string. Accept either form so the assertion is
                    // robust to a future newtype-display change.
                    v.as_str()
                }));
            prop_assert!(rid.is_some(), "deny missing receipt_id in canonical json");
        }
    }

    /// (f) `ProviderError` Display is em-dash-free.
    ///
    /// House rule: no em dashes (U+2014) in any rendered output. Each
    /// `ProviderError` variant must satisfy this for arbitrary content.
    #[test]
    fn invariant_f_provider_error_display_is_em_dash_free(err in arb_provider_error()) {
        let rendered = err.to_string();
        prop_assert!(
            !rendered.contains('\u{2014}'),
            "em dash in provider error display: {}",
            rendered,
        );
        prop_assert!(!rendered.is_empty(), "provider error display is empty");
    }

    /// (g) `ProvenanceStamp.received_at` round-trips through canonical JSON
    ///     without precision loss above ms granularity.
    ///
    /// We sample timestamps at whole-ms granularity (see
    /// `arb_system_time_ms`) and assert that the round-tripped stamp's
    /// `received_at` matches the input within ms tolerance. This pins the
    /// wire-precision contract: M07 surfaces ms-precision timestamps; any
    /// future drift to second-only precision will fail this property.
    #[test]
    fn invariant_g_received_at_round_trips_within_ms(stamp in arb_provenance_stamp()) {
        let bytes = canonical_json_bytes(&stamp).expect("stamp canonicalises");
        let back: ProvenanceStamp = serde_json::from_slice(&bytes)
            .expect("stamp from canonical bytes");

        let original_ms = stamp
            .received_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("input timestamp is post-epoch")
            .as_millis();
        let back_ms = back
            .received_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("round-tripped timestamp is post-epoch")
            .as_millis();

        // Allow at most 1ms drift (covers any future serializer that uses
        // floating-point seconds; today serde defaults to whole-second
        // SystemTime via secs+nanos and the property still holds tightly).
        let delta = original_ms.abs_diff(back_ms);
        prop_assert!(delta <= 1, "received_at drifted {}ms (>1ms)", delta);
    }

    /// (h) Schema subsumption against the M01 capability schema.
    ///
    /// Soft-dep: the canonical `chio-tool-call-fabric.v1` schema is part of
    /// M01 and is not yet vendored into the workspace. Until it is, this
    /// property runs as a structural self-check: every arbitrary
    /// `ToolInvocation` must canonicalise to a JSON object with the four
    /// load-bearing fields (`provider`, `tool_name`, `arguments`,
    /// `provenance`), and the `provenance` sub-object must carry the five
    /// load-bearing fields (`provider`, `request_id`, `api_version`,
    /// `principal`, `received_at`). When the M01 schema lands the test will
    /// be promoted to a real jsonschema validation behind the
    /// `m01-schema-subsumption` cargo feature.
    #[test]
    fn invariant_h_schema_subsumption_self_check(inv in arb_tool_invocation()) {
        let bytes = canonical_json_bytes(&inv).expect("invocation canonicalises");
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .expect("canonical bytes parse as json");
        let obj = value.as_object().expect("invocation is a json object");
        for required in ["provider", "tool_name", "arguments", "provenance"] {
            prop_assert!(
                obj.contains_key(required),
                "invocation missing required field: {}",
                required,
            );
        }
        let prov = obj
            .get("provenance")
            .and_then(serde_json::Value::as_object)
            .expect("provenance is an object");
        for required in [
            "provider",
            "request_id",
            "api_version",
            "principal",
            "received_at",
        ] {
            prop_assert!(
                prov.contains_key(required),
                "provenance missing required field: {}",
                required,
            );
        }

        // When the M01 capability schema is vendored, this branch tightens
        // the property into a real jsonschema validation. The feature gate
        // keeps the default build green until the schema lands.
        #[cfg(feature = "m01-schema-subsumption")]
        {
            // Intentionally minimal stub: the actual schema path will be
            // wired here once `spec/schemas/chio-tool-call-fabric/v1.json`
            // exists. Until then enabling the feature is a compile-only
            // assertion that the property still type-checks.
            let _ = bytes;
        }
    }
}
