#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use chio_conformance::{run_conformance_harness, ConformanceAuthMode};

#[test]
fn tasks_harness_runs_against_live_cpp_peer() {
    if common::skip_cpp_live_conformance_unless_enabled() {
        return;
    }

    if !common::command_available("cmake") || !common::python3_supports_chio_sdk() {
        return;
    }

    let options = common::cpp_options("tasks", ConformanceAuthMode::StaticBearer);
    let summary = run_conformance_harness(&options).expect("run conformance harness");
    let report = std::fs::read_to_string(&summary.report_output).expect("read report");
    let cpp_results = std::fs::read_to_string(summary.results_dir.join("cpp-remote-http.json"))
        .expect("cpp results");

    assert!(report.contains("## MCP Experimental"));
    assert!(common::scenario_passed(
        &cpp_results,
        "tasks-call-get-result"
    ));
    assert!(common::scenario_passed(&cpp_results, "tasks-cancel"));
}
