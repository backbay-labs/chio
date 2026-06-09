// Retirement guard for the pheromone fixture-and-schema gate cluster.
//
// The 15 legacy `scripts/check-chio-pheromone-*.sh` gates were consolidated into
// `cargo xtask check fixtures <facet>` and deleted after a green dual-run parity
// sweep (15 facets x 3 modes, all exit codes identical). The dual-run harness
// that proved that parity lived here and is preserved in git history; once the
// scripts are gone it can no longer dual-run, so this file now enforces that the
// scripts stay retired. A re-added script would resurrect the divergence the
// consolidation closed and would not be exercised by any workflow.

use std::path::PathBuf;

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

#[test]
fn pheromone_scripts_are_retired() {
    let root = root();
    let mut present = Vec::new();
    for facet in FACETS {
        let path = root.join(format!("scripts/check-chio-pheromone-{facet}.sh"));
        if path.exists() {
            present.push(facet);
        }
    }
    assert!(
        present.is_empty(),
        "legacy pheromone scripts must stay retired; still present: {present:?}"
    );
}
