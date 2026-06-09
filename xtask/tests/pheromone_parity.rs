// Dual-run parity harness for the pheromone fixture-and-schema gate cluster.
//
// For each facet and each mode, run BOTH the legacy script and the consolidated
// `cargo xtask check fixtures <facet>` leaf and assert identical exit codes.
// This is the load-bearing proof that the consolidation is behavior-identical:
// the cluster has no `*.test.sh` meta-tests, so parity is the only behavior
// contract.
//
// Gated behind CHIO_PHEROMONE_PARITY=1 so a normal `cargo test -p xtask` does
// not trigger the multi-minute cargo and npm chains. CI runs it explicitly.

use std::path::{Path, PathBuf};
use std::process::Command;

const FACETS: [&str; 15] = [
    "directory-lifecycle",
    "relay-alert-assurance-archive-hardening",
    "relay-alert-assurance-archive-package",
    "relay-alert-assurance-archive",
    "relay-alert-assurance-export",
    "relay-alert-assurance-external-retention",
    "relay-alert-assurance",
    "relay-alert-delivery",
    "relay-alert-handoff",
    "relay-alert-routing",
    "relay-observability",
    "relay-ops",
    "relay",
    "runtime",
    "transit",
];

fn root() -> PathBuf {
    match PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent() {
        Some(parent) => parent.to_path_buf(),
        None => panic!("xtask manifest dir has no parent"),
    }
}

fn script_exit(root: &Path, facet: &str, mode: &[&str]) -> i32 {
    Command::new("bash")
        .arg(format!("scripts/check-chio-pheromone-{facet}.sh"))
        .args(mode)
        .current_dir(root)
        .status()
        .map(|status| status.code().unwrap_or(-1))
        .unwrap_or(-1)
}

fn xtask_exit(root: &Path, facet: &str, mode: &[&str]) -> i32 {
    let mut args = vec!["run", "-q", "-p", "xtask", "--", "check", "fixtures", facet];
    args.extend_from_slice(mode);
    Command::new("cargo")
        .args(&args)
        .current_dir(root)
        .status()
        .map(|status| status.code().unwrap_or(-1))
        .unwrap_or(-1)
}

#[test]
fn pheromone_dual_run_parity() {
    if std::env::var("CHIO_PHEROMONE_PARITY").ok().as_deref() != Some("1") {
        eprintln!("skipped: set CHIO_PHEROMONE_PARITY=1 to run the multi-minute parity gate");
        return;
    }
    let root = root();
    let modes: [&[&str]; 3] = [&[], &["--schema-only"], &["--negative-only"]];
    let mut mismatches = Vec::new();
    for facet in FACETS {
        for mode in modes {
            let old = script_exit(&root, facet, mode);
            let new = xtask_exit(&root, facet, mode);
            let label = if mode.is_empty() { "all" } else { mode[0] };
            eprintln!("{facet} {label}: script={old} xtask={new}");
            if old != new {
                mismatches.push(format!("{facet} {label}: script={old} xtask={new}"));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "parity mismatches:\n{}",
        mismatches.join("\n")
    );
}
