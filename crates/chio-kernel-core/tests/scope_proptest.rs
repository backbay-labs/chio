#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use chio_core_types::capability::scope::{ChioScope, Constraint, Operation, ToolGrant};
use chio_kernel_core::scope::resolve_matching_grants;
use proptest::prelude::*;

fn proptest_config_for_lane(default_cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(default_cases);
    ProptestConfig::with_cases(cases)
}

fn ident_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_-]{0,10}".prop_map(|value| value)
}

fn domain_label_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{0,10}".prop_map(|value| value)
}

fn grant(
    server_id: &str,
    tool_name: &str,
    operations: Vec<Operation>,
    constraints: Vec<Constraint>,
) -> ToolGrant {
    ToolGrant {
        server_id: server_id.to_string(),
        tool_name: tool_name.to_string(),
        operations,
        constraints,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn scope(grants: Vec<ToolGrant>) -> ChioScope {
    ChioScope {
        grants,
        ..ChioScope::default()
    }
}

fn matching_count(scope: &ChioScope, args: serde_json::Value) -> usize {
    match resolve_matching_grants(scope, "read", "files", &args) {
        Ok(matches) => matches.len(),
        Err(error) => panic!("portable scope matcher returned unexpected error: {error:?}"),
    }
}

proptest! {
    #![proptest_config(proptest_config_for_lane(96))]

    #[test]
    fn path_prefix_allows_normalized_descendants_and_denies_siblings(
        tenant in ident_strategy(),
        leaf in ident_strategy(),
    ) {
        let prefix = format!("/tenant/{tenant}/private");
        let scope = scope(vec![grant(
            "files",
            "read",
            vec![Operation::Invoke],
            vec![Constraint::PathPrefix(prefix.clone())],
        )]);

        let allowed = serde_json::json!({
            "path": format!("{prefix}/./{leaf}.txt")
        });
        prop_assert_eq!(matching_count(&scope, allowed), 1);

        let sibling = serde_json::json!({
            "path": format!("/tenant/{tenant}/public/{leaf}.txt")
        });
        prop_assert_eq!(matching_count(&scope, sibling), 0);
    }

    #[test]
    fn domain_exact_normalizes_case_and_url_authority(
        label in domain_label_strategy(),
    ) {
        let domain = format!("api.{label}.example.com");
        let scope = scope(vec![grant(
            "files",
            "read",
            vec![Operation::Invoke],
            vec![Constraint::DomainExact(domain.to_ascii_uppercase())],
        )]);

        let allowed = serde_json::json!({
            "url": format!("https://{domain}:443/v1/events?cursor=1")
        });
        prop_assert_eq!(matching_count(&scope, allowed), 1);

        let denied = serde_json::json!({
            "url": format!("https://evil.{label}.example.com/v1/events")
        });
        prop_assert_eq!(matching_count(&scope, denied), 0);
    }

    #[test]
    fn domain_glob_matches_subdomain_but_not_base_domain(
        label in domain_label_strategy(),
    ) {
        let base = format!("{label}.example.com");
        let scope = scope(vec![grant(
            "files",
            "read",
            vec![Operation::Invoke],
            vec![Constraint::DomainGlob(format!("*.{base}"))],
        )]);

        let allowed = serde_json::json!({
            "url": format!("https://api.{base}/v1")
        });
        prop_assert_eq!(matching_count(&scope, allowed), 1);

        let denied = serde_json::json!({
            "url": format!("https://{base}/v1")
        });
        prop_assert_eq!(matching_count(&scope, denied), 0);
    }

    #[test]
    fn max_length_and_max_args_size_boundaries_are_inclusive(
        value in "[a-z]{1,24}",
    ) {
        let len = value.len();
        let exact_length_scope = scope(vec![grant(
            "files",
            "read",
            vec![Operation::Invoke],
            vec![Constraint::MaxLength(len)],
        )]);
        prop_assert_eq!(
            matching_count(&exact_length_scope, serde_json::json!({ "value": value.clone() })),
            1
        );
        prop_assert_eq!(
            matching_count(&exact_length_scope, serde_json::json!({ "value": format!("{value}x") })),
            0
        );

        let compact = serde_json::json!({ "v": value });
        let serialized_len = compact.to_string().len();
        let exact_size_scope = scope(vec![grant(
            "files",
            "read",
            vec![Operation::Invoke],
            vec![Constraint::MaxArgsSize(serialized_len)],
        )]);
        prop_assert_eq!(matching_count(&exact_size_scope, compact), 1);
    }
}

#[test]
fn exact_grants_sort_ahead_of_wildcard_fallbacks() {
    let scope = scope(vec![
        grant("*", "*", vec![Operation::Invoke], Vec::new()),
        grant("files", "read", vec![Operation::Invoke], Vec::new()),
    ]);
    let matches = match resolve_matching_grants(
        &scope,
        "read",
        "files",
        &serde_json::json!({ "path": "/tenant/a/private/report.txt" }),
    ) {
        Ok(matches) => matches,
        Err(error) => panic!("expected grant resolution: {error:?}"),
    };

    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].index, 1);
    assert_eq!(matches[0].specificity, (1, 1, 0));
    assert_eq!(matches[1].index, 0);
}
