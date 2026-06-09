use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CompatibilityReport, ResultStatus, ScenarioCategory, ScenarioDescriptor, ScenarioResult,
};

pub fn generate_markdown_report(report: &CompatibilityReport) -> String {
    let columns = matrix_columns(&report.results);
    let mut output = String::new();

    output.push_str("# Compatibility Matrix\n\n");
    output.push_str("Generated from conformance result artifacts.\n\n");

    if report.results.is_empty() {
        output.push_str("No result artifacts were loaded.\n");
        return output;
    }

    output.push_str("## Summary\n\n");
    for category in category_order() {
        let results = report
            .results
            .iter()
            .filter(|result| result.category == category)
            .collect::<Vec<_>>();
        if results.is_empty() {
            continue;
        }
        let pass = results
            .iter()
            .filter(|result| result.status == ResultStatus::Pass)
            .count();
        let xfail = results
            .iter()
            .filter(|result| result.status == ResultStatus::Xfail)
            .count();
        output.push_str(&format!(
            "- {}: {pass}/{} pass",
            category.heading(),
            results.len()
        ));
        if xfail > 0 {
            output.push_str(&format!(", {xfail} xfail"));
        }
        output.push('\n');
    }
    output.push('\n');

    for category in category_order() {
        let category_scenarios = report
            .scenarios
            .iter()
            .filter(|scenario| scenario.category == category)
            .collect::<Vec<_>>();
        if category_scenarios.is_empty() {
            continue;
        }

        output.push_str(&format!("## {}\n\n", category.heading()));
        output.push_str("| Area | Scenario |");
        for column in &columns {
            output.push_str(&format!(" {} |", column));
        }
        output.push('\n');
        output.push_str("| --- | --- |");
        for _ in &columns {
            output.push_str(" --- |");
        }
        output.push('\n');

        for scenario in category_scenarios {
            output.push_str(&format!("| {} | `{}` |", scenario.area, scenario.id));
            for column in &columns {
                let value = find_matrix_value(scenario, &report.results, column)
                    .unwrap_or("n/a".to_string());
                output.push_str(&format!(" {} |", value));
            }
            output.push('\n');
        }
        output.push('\n');
    }

    let failures = report
        .results
        .iter()
        .filter(|result| result.status == ResultStatus::Fail)
        .collect::<Vec<_>>();
    if !failures.is_empty() {
        output.push_str("## Failures\n\n");
        for failure in failures {
            output.push_str(&format!(
                "- `{}` on `{}` / `{}` / `{}`: {}\n",
                failure.scenario_id,
                failure.peer,
                failure.deployment_mode.label(),
                failure.transport.label(),
                failure
                    .failure_message
                    .as_deref()
                    .unwrap_or("scenario failed without a recorded failure message")
            ));
        }
    }

    let expected_failures = report
        .results
        .iter()
        .filter(|result| result.status == ResultStatus::Xfail)
        .collect::<Vec<_>>();
    if !expected_failures.is_empty() {
        output.push_str("\n## Expected Failures\n\n");
        for failure in expected_failures {
            output.push_str(&format!(
                "- `{}` on `{}` / `{}` / `{}`: {}\n",
                failure.scenario_id,
                failure.peer,
                failure.deployment_mode.label(),
                failure.transport.label(),
                failure
                    .failure_message
                    .as_deref()
                    .or(failure.notes.as_deref())
                    .unwrap_or("scenario is currently classified as an expected failure")
            ));
        }
    }

    output
}

fn category_order() -> [ScenarioCategory; 4] {
    [
        ScenarioCategory::McpCore,
        ScenarioCategory::McpExperimental,
        ScenarioCategory::ChioExtension,
        ScenarioCategory::Infra,
    ]
}

fn matrix_columns(results: &[ScenarioResult]) -> Vec<String> {
    let mut columns = BTreeSet::new();
    for result in results {
        columns.insert(format!(
            "{} {} {}",
            result.peer,
            result.deployment_mode.label(),
            result.transport.label()
        ));
    }
    columns.into_iter().collect()
}

fn find_matrix_value(
    scenario: &ScenarioDescriptor,
    results: &[ScenarioResult],
    column: &str,
) -> Option<String> {
    let grouped = results
        .iter()
        .filter(|result| result.scenario_id == scenario.id)
        .map(|result| {
            (
                format!(
                    "{} {} {}",
                    result.peer,
                    result.deployment_mode.label(),
                    result.transport.label()
                ),
                result.status.label().to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    grouped.get(column).cloned()
}

#[cfg(test)]
mod tests {
    use crate::{
        AssertionOutcome, AssertionResult, DeploymentMode, PeerRole, RequiredCapabilities,
        ResultStatus, ScenarioCategory, ScenarioDescriptor, ScenarioResult, Transport,
    };

    use super::*;

    #[test]
    fn generates_grouped_markdown_matrix() {
        let report = CompatibilityReport {
            scenarios: vec![
                ScenarioDescriptor {
                    id: "initialize".to_string(),
                    title: "Initialize".to_string(),
                    area: "lifecycle".to_string(),
                    category: ScenarioCategory::McpCore,
                    spec_versions: vec!["2025-11-25".to_string()],
                    transport: vec![Transport::Stdio, Transport::StreamableHttp],
                    peer_roles: vec![PeerRole::ClientToChioServer],
                    deployment_modes: vec![
                        DeploymentMode::WrappedStdio,
                        DeploymentMode::RemoteHttp,
                    ],
                    required_capabilities: RequiredCapabilities::default(),
                    tags: vec!["mcp-core".to_string()],
                    expected: ResultStatus::Pass,
                    timeout_ms: None,
                    notes: None,
                },
                ScenarioDescriptor {
                    id: "deny-receipt-emitted".to_string(),
                    title: "Deny receipt".to_string(),
                    area: "trust_extensions".to_string(),
                    category: ScenarioCategory::ChioExtension,
                    spec_versions: vec!["2026-03-19".to_string()],
                    transport: vec![Transport::Stdio],
                    peer_roles: vec![PeerRole::ClientToChioServer],
                    deployment_modes: vec![DeploymentMode::WrappedStdio],
                    required_capabilities: RequiredCapabilities::default(),
                    tags: vec!["trust".to_string(), "deny-receipts".to_string()],
                    expected: ResultStatus::Pass,
                    timeout_ms: None,
                    notes: None,
                },
            ],
            results: vec![
                ScenarioResult {
                    scenario_id: "initialize".to_string(),
                    peer: "js".to_string(),
                    peer_role: PeerRole::ClientToChioServer,
                    deployment_mode: DeploymentMode::WrappedStdio,
                    transport: Transport::Stdio,
                    spec_version: "2025-11-25".to_string(),
                    category: ScenarioCategory::McpCore,
                    status: ResultStatus::Pass,
                    duration_ms: 25,
                    assertions: vec![AssertionResult {
                        name: "initialize_succeeds".to_string(),
                        status: AssertionOutcome::Pass,
                        message: None,
                    }],
                    notes: None,
                    artifacts: BTreeMap::new(),
                    failure_kind: None,
                    failure_message: None,
                    expected_failure: None,
                },
                ScenarioResult {
                    scenario_id: "deny-receipt-emitted".to_string(),
                    peer: "chio-self".to_string(),
                    peer_role: PeerRole::ClientToChioServer,
                    deployment_mode: DeploymentMode::WrappedStdio,
                    transport: Transport::Stdio,
                    spec_version: "2026-03-19".to_string(),
                    category: ScenarioCategory::ChioExtension,
                    status: ResultStatus::Pass,
                    duration_ms: 8,
                    assertions: Vec::new(),
                    notes: None,
                    artifacts: BTreeMap::new(),
                    failure_kind: None,
                    failure_message: None,
                    expected_failure: None,
                },
            ],
        };

        let markdown = generate_markdown_report(&report);

        assert!(markdown.contains("# Compatibility Matrix"));
        assert!(markdown.contains("## MCP Core"));
        assert!(markdown.contains("## Chio Extensions"));
        assert!(markdown.contains("`initialize`"));
        assert!(markdown.contains("js wrapped-stdio stdio"));
        assert!(markdown.contains("chio-self wrapped-stdio stdio"));
    }

    #[test]
    fn report_summary_and_sections_include_xfail_results() {
        let report = CompatibilityReport {
            scenarios: vec![ScenarioDescriptor {
                id: "tasks-cancel".to_string(),
                title: "Cancel task".to_string(),
                area: "tasks".to_string(),
                category: ScenarioCategory::McpExperimental,
                spec_versions: vec!["2025-11-25".to_string()],
                transport: vec![Transport::StreamableHttp],
                peer_roles: vec![PeerRole::ClientToChioServer],
                deployment_modes: vec![DeploymentMode::RemoteHttp],
                required_capabilities: RequiredCapabilities::default(),
                tags: vec!["tasks".to_string()],
                expected: ResultStatus::Xfail,
                timeout_ms: None,
                notes: Some("known gap".to_string()),
            }],
            results: vec![ScenarioResult {
                scenario_id: "tasks-cancel".to_string(),
                peer: "js".to_string(),
                peer_role: PeerRole::ClientToChioServer,
                deployment_mode: DeploymentMode::RemoteHttp,
                transport: Transport::StreamableHttp,
                spec_version: "2025-11-25".to_string(),
                category: ScenarioCategory::McpExperimental,
                status: ResultStatus::Xfail,
                duration_ms: 1000,
                assertions: vec![AssertionResult {
                    name: "tasks_cancel_known_remote_http_gap".to_string(),
                    status: AssertionOutcome::Fail,
                    message: Some("known remote-http task cancellation gap".to_string()),
                }],
                notes: Some("known gap".to_string()),
                artifacts: BTreeMap::new(),
                failure_kind: Some("expected-failure".to_string()),
                failure_message: Some("known remote-http task cancellation gap".to_string()),
                expected_failure: Some(true),
            }],
        };

        let markdown = generate_markdown_report(&report);

        assert!(markdown.contains("## Summary"));
        assert!(markdown.contains("MCP Experimental: 0/1 pass, 1 xfail"));
        assert!(markdown.contains("| tasks | `tasks-cancel` | xfail |"));
        assert!(markdown.contains("## Expected Failures"));
        assert!(markdown.contains("known remote-http task cancellation gap"));
    }
}
