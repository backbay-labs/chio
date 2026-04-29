//! Five named proptest invariants for the portable kernel `evaluate` surface.
//!
//! Notes on the API:
//!
//! - `chio-kernel-core::evaluate` does not perform stateful revocation
//!   lookup (that lives in `chio-kernel`). The portable core models the
//!   "revoked lifecycle" property of invariant 1 via the lifecycle
//!   information it does see: a capability whose validity window has
//!   closed (`expires_at <= now`) is denied.
//! - The portable kernel does not expose public `union` or `intersect`
//!   operators on `ChioScope`. Invariants 4 and 5 are therefore expressed
//!   through `resolve_matching_grants`, which is the public matcher the
//!   evaluator already uses; intersection of a grant with a request is
//!   modelled as "the matcher reports the grant covers the request".
//!
//! Each `proptest!` block is configured via `proptest_config_for_lane()`,
//! which honours `PROPTEST_CASES` from the CI environment (PR-tier 256,
//! nightly-tier 4096) and falls back to a modest local default of 48 so
//! the default `cargo test` lane stays well under one minute.

use std::ops::Range;

use chio_core_types::capability::{
    CapabilityToken, CapabilityTokenBody, ChioScope, Operation, ToolGrant,
};
use chio_core_types::crypto::Keypair;
use chio_kernel_core::evaluate::{evaluate, EvaluateInput};
use chio_kernel_core::guard::PortableToolCallRequest;
use chio_kernel_core::scope::{resolve_matching_grants, MatchedGrant};
use chio_kernel_core::{FixedClock, Verdict};
use proptest::prelude::*;

/// Build a `ProptestConfig` whose case count honours the `PROPTEST_CASES`
/// environment variable used by the CI lanes (`256` for PR, `4096` for
/// nightly). When the variable is unset or unparseable we fall back to
/// the local default `48`. Without this helper, a per-block
/// `ProptestConfig::with_cases(...)` literal would override the env-var
/// derived default that proptest reads at startup, defeating the tiered
/// case-count gate.
fn proptest_config_for_lane(default_cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default_cases);
    ProptestConfig::with_cases(cases)
}

// --- pool-based strategies --------------------------------------------------

const SERVER_POOL: &[&str] = &["srv-a", "srv-b", "srv-c", "srv-files", "srv-net"];
const TOOL_POOL: &[&str] = &[
    "file_read",
    "file_write",
    "shell_exec",
    "http_get",
    "search",
];
const ARG_POOL: &[&str] = &["alpha", "beta", "gamma"];

fn pool_pick(pool: &[&str], idx: usize) -> String {
    pool[idx % pool.len()].to_string()
}

fn arb_pattern_for(pool: &'static [&'static str]) -> impl Strategy<Value = String> {
    // Mostly-exact patterns plus a `"*"` wildcard, matching the portable
    // matcher's two pattern forms (`exact` and `"*"`).
    prop_oneof![
        4 => (0usize..pool.len()).prop_map(|i| pool_pick(pool, i)),
        1 => Just("*".to_string()),
    ]
}

fn arb_unconstrained_invoke_grant() -> impl Strategy<Value = ToolGrant> {
    (arb_pattern_for(SERVER_POOL), arb_pattern_for(TOOL_POOL)).prop_map(|(server_id, tool_name)| {
        ToolGrant {
            server_id,
            tool_name,
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }
    })
}

fn arb_grant_vec(range: Range<usize>) -> impl Strategy<Value = Vec<ToolGrant>> {
    proptest::collection::vec(arb_unconstrained_invoke_grant(), range)
}

fn arb_arguments() -> impl Strategy<Value = serde_json::Value> {
    // Keep arguments outside the path / domain key namespace so the portable
    // matcher's leaf-key heuristics never pull a `PathPrefix` constraint out
    // of an unrelated string. All grants in this test file are unconstrained
    // anyway, but pinning the shape makes shrinking deterministic.
    (0usize..ARG_POOL.len()).prop_map(|i| serde_json::json!({ "value": pool_pick(ARG_POOL, i) }))
}

// --- capability + request builders ------------------------------------------

const ISSUED_AT: u64 = 1_700_000_000;
const VALID_UNTIL: u64 = 1_700_100_000;
const NOW: u64 = ISSUED_AT + 10;

fn signed_capability(
    issuer_kp: &Keypair,
    subject_kp: &Keypair,
    scope: ChioScope,
    issued_at: u64,
    expires_at: u64,
) -> Option<CapabilityToken> {
    let body = CapabilityTokenBody {
        id: "cap-property".to_string(),
        issuer: issuer_kp.public_key(),
        subject: subject_kp.public_key(),
        scope,
        issued_at,
        expires_at,
        delegation_chain: Vec::new(),
    };
    CapabilityToken::sign(body, issuer_kp).ok()
}

fn build_request(
    subject_kp: &Keypair,
    server_id: String,
    tool_name: String,
    arguments: serde_json::Value,
) -> PortableToolCallRequest {
    PortableToolCallRequest {
        request_id: "req-property".to_string(),
        tool_name,
        server_id,
        agent_id: subject_kp.public_key().to_hex(),
        arguments,
    }
}

fn pattern_covers(pattern: &str, candidate: &str) -> bool {
    pattern == "*" || pattern == candidate
}

// --- proptest blocks --------------------------------------------------------

proptest! {
    #![proptest_config(proptest_config_for_lane(48))]

    // Invariant 1: evaluate returns Deny when the capability is in a
    // revoked lifecycle state. The portable kernel core never reaches into
    // a revocation store, so we model "revoked" via the lifecycle signal it
    // does observe: a capability evaluated outside its validity window.
    //
    // To avoid a vacuous Deny (out-of-scope requests are denied for an
    // unrelated reason), we ensure the request matches the first generated
    // grant by reusing its server/tool when neither pattern is a wildcard.
    // For wildcard patterns we pick any concrete identifier from the pool.
    #[test]
    fn evaluate_deny_when_capability_revoked(
        grants in arb_grant_vec(1..6),
        server_idx in 0usize..SERVER_POOL.len(),
        tool_idx in 0usize..TOOL_POOL.len(),
        arguments in arb_arguments(),
    ) {
        let issuer_kp = Keypair::generate();
        let subject_kp = Keypair::generate();

        // Pick a server/tool that the first grant covers, so the verdict
        // can be attributed to lifecycle expiry rather than a missed match.
        let first = &grants[0];
        let server_id = if first.server_id == "*" {
            pool_pick(SERVER_POOL, server_idx)
        } else {
            first.server_id.clone()
        };
        let tool_name = if first.tool_name == "*" {
            pool_pick(TOOL_POOL, tool_idx)
        } else {
            first.tool_name.clone()
        };

        let scope = ChioScope { grants, ..ChioScope::default() };

        // Build a capability whose validity window has already closed at
        // NOW. This is the portable-core analog of "revoked" - the kernel
        // sees a closed lifecycle window and must fail closed.
        //
        // Signing failure under deterministic test inputs would indicate a
        // regression in canonicalization or signing, not a property case
        // we want to skip; surface it as a test failure.
        let capability = match signed_capability(
            &issuer_kp,
            &subject_kp,
            scope,
            ISSUED_AT - 100,
            ISSUED_AT - 1,
        ) {
            Some(capability) => capability,
            None => {
                prop_assert!(
                    false,
                    "signed_capability returned None on well-formed inputs"
                );
                return Ok(());
            }
        };

        let request = build_request(
            &subject_kp,
            server_id,
            tool_name,
            arguments,
        );
        let clock = FixedClock::new(NOW);
        let trusted = [issuer_kp.public_key()];
        let guards: [&dyn chio_kernel_core::Guard; 0] = [];

        let verdict = evaluate(EvaluateInput {
            request: &request,
            capability: &capability,
            trusted_issuers: &trusted,
            clock: &clock,
            guards: &guards,
            session_filesystem_roots: None,
        });

        prop_assert_eq!(verdict.verdict, Verdict::Deny);
    }
}

proptest! {
    #![proptest_config(proptest_config_for_lane(48))]

    // Invariant 2: when evaluate returns Allow, the matched grant's
    // (server, tool) pattern covers the request - i.e. the grant the
    // kernel selected genuinely subsumes the requested operation. This is
    // the no-privilege-escalation property at the matcher boundary.
    #[test]
    fn evaluate_allow_implies_grant_subset_of_request(
        grants in arb_grant_vec(1..6),
        server_idx in 0usize..SERVER_POOL.len(),
        tool_idx in 0usize..TOOL_POOL.len(),
        arguments in arb_arguments(),
    ) {
        let issuer_kp = Keypair::generate();
        let subject_kp = Keypair::generate();
        let scope = ChioScope { grants: grants.clone(), ..ChioScope::default() };

        let capability = match signed_capability(
            &issuer_kp,
            &subject_kp,
            scope,
            ISSUED_AT,
            VALID_UNTIL,
        ) {
            Some(capability) => capability,
            None => {
                prop_assert!(
                    false,
                    "signed_capability returned None on well-formed inputs"
                );
                return Ok(());
            }
        };

        let server_id = pool_pick(SERVER_POOL, server_idx);
        let tool_name = pool_pick(TOOL_POOL, tool_idx);
        let request = build_request(
            &subject_kp,
            server_id.clone(),
            tool_name.clone(),
            arguments,
        );
        let clock = FixedClock::new(NOW);
        let trusted = [issuer_kp.public_key()];
        let guards: [&dyn chio_kernel_core::Guard; 0] = [];

        let verdict = evaluate(EvaluateInput {
            request: &request,
            capability: &capability,
            trusted_issuers: &trusted,
            clock: &clock,
            guards: &guards,
            session_filesystem_roots: None,
        });

        if verdict.verdict == Verdict::Allow {
            let Some(idx) = verdict.matched_grant_index else {
                prop_assert!(false, "Allow verdict missing matched_grant_index");
                return Ok(());
            };
            prop_assert!(idx < grants.len());
            let matched = &grants[idx];
            // The matcher must have selected a grant whose patterns cover
            // the request and whose operations include Invoke; otherwise
            // the matched grant cannot be a superset of the request.
            prop_assert!(pattern_covers(&matched.server_id, &server_id));
            prop_assert!(pattern_covers(&matched.tool_name, &tool_name));
            prop_assert!(matched.operations.contains(&Operation::Invoke));
        }
    }
}

proptest! {
    #![proptest_config(proptest_config_for_lane(48))]

    // Invariant 3: the multiset of matching grants for a request is
    // invariant under the input grant-list ordering. Ranking may shift by
    // index (since indices follow the input order), but the underlying
    // multiset of matched grant identities is order-independent.
    //
    // We compare as a sorted Vec rather than a BTreeSet so duplicates with
    // identical (server, tool, operations.len()) keys are not silently
    // deduplicated; using a set would let `[A, A, B, B]` and `[A, B, B, B]`
    // compare equal even though the underlying multisets differ.
    #[test]
    fn resolve_matching_grants_order_independent(
        grants in arb_grant_vec(0..6),
        rotation in 0usize..6,
        server_idx in 0usize..SERVER_POOL.len(),
        tool_idx in 0usize..TOOL_POOL.len(),
        arguments in arb_arguments(),
    ) {
        prop_assume!(!grants.is_empty());
        let server_id = pool_pick(SERVER_POOL, server_idx);
        let tool_name = pool_pick(TOOL_POOL, tool_idx);

        let scope_a = ChioScope { grants: grants.clone(), ..ChioScope::default() };

        // Rotate the grant list to produce a permutation with stable
        // membership but a different traversal order.
        let mut rotated = grants.clone();
        let len = rotated.len();
        rotated.rotate_left(rotation % len);
        let scope_b = ChioScope { grants: rotated.clone(), ..ChioScope::default() };

        // All generated grants are unconstrained, so the matcher must
        // succeed on both scopes; treating an Err as a passing case would
        // mask matcher regressions (e.g. ConstraintError leaks).
        let matches_a = resolve_matching_grants(&scope_a, &tool_name, &server_id, &arguments)
            .map_err(|err| TestCaseError::fail(
                format!("resolve_matching_grants(scope_a) failed unexpectedly: {err:?}")
            ))?;
        let matches_b = resolve_matching_grants(&scope_b, &tool_name, &server_id, &arguments)
            .map_err(|err| TestCaseError::fail(
                format!("resolve_matching_grants(scope_b) failed unexpectedly: {err:?}")
            ))?;

        // Re-key both match results by the underlying grant identity
        // (server, tool, operations.len()). Compare as sorted multisets
        // so per-key multiplicity differences are not hidden.
        let mut keys_a: Vec<(String, String, usize)> = matches_a
            .iter()
            .map(|matched| (
                matched.grant.server_id.clone(),
                matched.grant.tool_name.clone(),
                matched.grant.operations.len(),
            ))
            .collect();
        let mut keys_b: Vec<(String, String, usize)> = matches_b
            .iter()
            .map(|matched| (
                matched.grant.server_id.clone(),
                matched.grant.tool_name.clone(),
                matched.grant.operations.len(),
            ))
            .collect();
        keys_a.sort();
        keys_b.sort();

        prop_assert_eq!(keys_a, keys_b);
        prop_assert_eq!(matches_a.len(), matches_b.len());
    }
}

proptest! {
    #![proptest_config(proptest_config_for_lane(48))]

    // Invariant 4: intersection (matcher) distributes over grant union.
    // `resolve_matching_grants(scope_a + scope_b, request)` must equal
    // `resolve_matching_grants(scope_a, request)` plus
    // `resolve_matching_grants(scope_b, request)`, where addition on
    // grants is list concatenation and addition on match sets is union by
    // grant identity.
    #[test]
    fn intersection_distributes_over_grant_union(
        grants_a in arb_grant_vec(0..4),
        grants_b in arb_grant_vec(0..4),
        server_idx in 0usize..SERVER_POOL.len(),
        tool_idx in 0usize..TOOL_POOL.len(),
        arguments in arb_arguments(),
    ) {
        let server_id = pool_pick(SERVER_POOL, server_idx);
        let tool_name = pool_pick(TOOL_POOL, tool_idx);

        let scope_a = ChioScope { grants: grants_a.clone(), ..ChioScope::default() };
        let scope_b = ChioScope { grants: grants_b.clone(), ..ChioScope::default() };
        let mut union_grants = grants_a.clone();
        union_grants.extend(grants_b.clone());
        let scope_union = ChioScope { grants: union_grants, ..ChioScope::default() };

        // All generated grants are unconstrained, so matcher errors are
        // unexpected: bubble them as test failures rather than skipping.
        let matches_a = resolve_matching_grants(&scope_a, &tool_name, &server_id, &arguments)
            .map_err(|err| TestCaseError::fail(format!("scope_a matcher failed: {err:?}")))?;
        let matches_b = resolve_matching_grants(&scope_b, &tool_name, &server_id, &arguments)
            .map_err(|err| TestCaseError::fail(format!("scope_b matcher failed: {err:?}")))?;
        let matches_union = resolve_matching_grants(&scope_union, &tool_name, &server_id, &arguments)
            .map_err(|err| TestCaseError::fail(format!("union matcher failed: {err:?}")))?;

        // Re-key by grant identity. The union side enumerates over
        // grants_a then grants_b, so multiplicity is preserved on both
        // sides; we compare as multisets via a sorted Vec.
        fn key(matched: &MatchedGrant<'_>) -> (String, String, usize) {
            (
                matched.grant.server_id.clone(),
                matched.grant.tool_name.clone(),
                matched.grant.operations.len(),
            )
        }
        let mut left: Vec<(String, String, usize)> = matches_a
            .iter()
            .chain(matches_b.iter())
            .map(key)
            .collect();
        let mut right: Vec<(String, String, usize)> = matches_union.iter().map(key).collect();
        left.sort();
        right.sort();

        prop_assert_eq!(left, right);
    }
}

proptest! {
    #![proptest_config(proptest_config_for_lane(48))]

    // Invariant 5: a wildcard scope intersected with a specific scope
    // collapses to the specific scope (wildcards are absorptive). At the
    // matcher boundary, this means: when a wildcard grant and a specific
    // grant both cover the same request, both match and the specific
    // grant ranks at least as high as the wildcard. After the matcher's
    // specificity sort, the front of the list is no less specific than
    // any wildcard tail entry.
    #[test]
    fn wildcard_subsumes_specific_under_intersection(
        server_idx in 0usize..SERVER_POOL.len(),
        tool_idx in 0usize..TOOL_POOL.len(),
        arguments in arb_arguments(),
    ) {
        let server_id = pool_pick(SERVER_POOL, server_idx);
        let tool_name = pool_pick(TOOL_POOL, tool_idx);

        let wildcard = ToolGrant {
            server_id: "*".to_string(),
            tool_name: "*".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let specific = ToolGrant {
            server_id: server_id.clone(),
            tool_name: tool_name.clone(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };

        // Place the wildcard first to give it index 0, so a naive
        // "first index wins" matcher would pick the wildcard. The
        // specificity sort must still prefer the specific grant.
        let scope = ChioScope {
            grants: vec![wildcard, specific],
            ..ChioScope::default()
        };

        let matches = resolve_matching_grants(&scope, &tool_name, &server_id, &arguments)
            .map_err(|err| TestCaseError::fail(
                format!("resolve_matching_grants failed unexpectedly: {err:?}")
            ))?;

        prop_assert_eq!(matches.len(), 2);
        // The specific grant (index 1) must come first under the
        // matcher's specificity ordering; wildcards are absorbed by the
        // narrower, exact-match grant.
        let head = &matches[0];
        prop_assert_eq!(head.index, 1);
        prop_assert_eq!(&head.grant.server_id, &server_id);
        prop_assert_eq!(&head.grant.tool_name, &tool_name);
        // The wildcard tail entry must have strictly lower specificity.
        let tail = &matches[1];
        prop_assert!(head.specificity > tail.specificity, "specific must outrank wildcard, got head={:?} tail={:?}", head.specificity, tail.specificity);
        prop_assert_eq!(format!("{}", tail.grant.server_id), "*".to_string());
        prop_assert_eq!(format!("{}", tail.grant.tool_name), "*".to_string());
    }
}
