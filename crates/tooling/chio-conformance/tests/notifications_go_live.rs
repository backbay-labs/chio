#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

use chio_conformance::{default_run_options, run_conformance_harness, unique_run_dir, PeerTarget};
use serde_json::Value;

fn command_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn python3_supports_chio_sdk() -> bool {
    let Ok(output) = Command::new("python3")
        .arg("-c")
        .arg("import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')")
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let version = String::from_utf8_lossy(&output.stdout);
    let mut parts = version.trim().split('.');
    let major = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    (major, minor) >= (3, 11)
}

fn ensure_chio_binary(repo_root: &PathBuf) {
    let chio_binary = repo_root.join("target/debug/chio");
    if chio_binary.exists() {
        return;
    }

    let chio_binary = repo_root.join("target/debug/chio");
    if chio_binary.exists() {
        return;
    }

    let status = Command::new("cargo")
        .current_dir(repo_root)
        .arg("build")
        .arg("-q")
        .arg("-p")
        .arg("chio-cli")
        .status()
        .expect("build chio-cli");
    assert!(status.success(), "cargo build -p chio-cli must succeed");
}

fn scenario_passed(results_json: &str, scenario_id: &str) -> bool {
    let Ok(results) = serde_json::from_str::<Vec<Value>>(results_json) else {
        return false;
    };
    results.iter().any(|result| {
        result["scenarioId"].as_str() == Some(scenario_id)
            && result["status"].as_str() == Some("pass")
    })
}

#[test]
fn notifications_harness_runs_against_live_go_peer() {
    if !command_available("go") || !python3_supports_chio_sdk() {
        return;
    }

    let mut options = default_run_options();
    ensure_chio_binary(&options.repo_root);
    options.peers = vec![PeerTarget::Go];
    options.scenarios_dir = options
        .repo_root
        .join("tests/conformance/scenarios/notifications");
    let run_dir = unique_run_dir("chio-conformance-notifications-go");
    options.results_dir = run_dir.join("results");
    options.report_output = run_dir.join("reports/notifications-go-live.md");

    let summary = run_conformance_harness(&options).expect("run conformance harness");
    let report = std::fs::read_to_string(&summary.report_output).expect("read report");
    let go_results = std::fs::read_to_string(summary.results_dir.join("go-remote-http.json"))
        .expect("go results");

    assert!(report.contains("## MCP Core"));
    assert!(report.contains("`resources-subscribe-updated-notification`"));
    assert!(report.contains("`catalog-list-changed-notifications`"));
    assert!(scenario_passed(
        &go_results,
        "resources-subscribe-updated-notification"
    ));
    assert!(scenario_passed(
        &go_results,
        "catalog-list-changed-notifications"
    ));
}
