#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_conformance::{
    default_repo_root, load_native_scenarios_from_dir, run_native_conformance_suite,
    NativeConformanceRunOptions, NativeScenarioCategory, NativeScenarioResult, NativeStatus,
};

fn unique_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}"))
}

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn reserve_listen_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

fn wait_for_server(listen: SocketAddr) {
    for _ in 0..50 {
        if TcpStream::connect(listen).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("fixture server did not start on {listen}");
}

#[test]
fn native_conformance_suite_runs_against_fixture() {
    let repo_root = default_repo_root();
    let output_dir = unique_dir("chio-native-conformance");
    fs::create_dir_all(&output_dir).expect("create output dir");

    let fixture_bin = PathBuf::from(env!("CARGO_BIN_EXE_chio-native-conformance-fixture"));
    let listen = reserve_listen_addr();
    let child = Command::new(&fixture_bin)
        .arg("--http-listen")
        .arg(listen.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fixture server");
    let _guard = ChildGuard { child };
    wait_for_server(listen);

    let options = NativeConformanceRunOptions {
        repo_root: repo_root.clone(),
        scenarios_dir: repo_root.join("tests/conformance/native/scenarios"),
        results_output: output_dir.join("results.json"),
        report_output: output_dir.join("report.md"),
        peer_label: "chio-self".to_string(),
        stdio_command: Some(fixture_bin),
        http_base_url: Some(format!("http://{listen}")),
        trace_output: Some(output_dir.join("trace.ndjson")),
        trace_negative_output: Some(output_dir.join("trace-negative.ndjson")),
        trace_monotone_negative_output: Some(output_dir.join("trace-monotone-negative.ndjson")),
        trace_attenuation_negative_output: Some(
            output_dir.join("trace-attenuation-negative.ndjson"),
        ),
        trace_freshness_negative_output: Some(output_dir.join("trace-freshness-negative.ndjson")),
        trace_observer_key_output: Some(output_dir.join("trace-key.txt")),
    };

    let summary = run_native_conformance_suite(&options).expect("run native suite");
    assert_eq!(summary.scenario_count, 6);

    let results: Vec<NativeScenarioResult> =
        serde_json::from_str(&fs::read_to_string(summary.results_output).expect("read results"))
            .expect("parse results");
    assert_eq!(results.len(), 6);
    assert!(results
        .iter()
        .all(|result| result.status == NativeStatus::Pass));

    let trace_path = summary.trace_output.expect("trace output");
    let trace_key_path = summary
        .trace_observer_key_output
        .expect("trace observer key output");
    let trace = fs::read(trace_path).expect("read trace");
    let trusted_key = chio_core::crypto::PublicKey::from_hex(
        fs::read_to_string(trace_key_path)
            .expect("read trace key")
            .trim(),
    )
    .expect("parse trace key");
    let observations = chio_trace_validate::decode_observations(&trace, &[trusted_key])
        .expect("decode native trace");
    let projection =
        chio_trace_validate::project_revocation_trace(&observations).expect("project native trace");
    assert_eq!(projection.action_coverage().revoke, 1);
    assert_eq!(projection.action_coverage().post_revocation_evaluate, 1);

    let report = fs::read_to_string(summary.report_output).expect("read report");
    assert!(report.contains("Chio Native Conformance Report"));
    assert!(report.contains("Capability Validation"));
    assert!(report.contains("Governed Transaction Enforcement"));
}

#[test]
fn native_standards_artifacts_cover_required_categories_and_references() {
    let repo_root = default_repo_root();
    let scenarios =
        load_native_scenarios_from_dir(repo_root.join("tests/conformance/native/scenarios"))
            .expect("load scenarios");

    let categories = scenarios
        .iter()
        .map(|scenario| scenario.category)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = std::collections::BTreeSet::from([
        NativeScenarioCategory::CapabilityValidation,
        NativeScenarioCategory::DelegationAttenuation,
        NativeScenarioCategory::ReceiptIntegrity,
        NativeScenarioCategory::RevocationPropagation,
        NativeScenarioCategory::DpopVerification,
        NativeScenarioCategory::GovernedTransactionEnforcement,
    ]);
    assert_eq!(categories, expected);

    let draft = fs::read_to_string(repo_root.join("spec/ietf/draft-chio-protocol-00.md"))
        .expect("read internet draft");
    assert!(draft.contains("Intended status: Standards Track"));
    assert!(draft.contains("Security Considerations"));

    let matrix =
        fs::read_to_string(repo_root.join("docs/standards/CHIO_PROTOCOL_ALIGNMENT_MATRIX.md"))
            .expect("read alignment matrix");
    for needle in [
        "GNAP", "SCITT", "RATS", "RFC 9449", "W3C VC", "OID4VCI", "OID4VP", "RFC 8785",
    ] {
        assert!(
            matrix.contains(needle),
            "missing standards mapping for {needle}"
        );
    }
}
