// Retirement guard for the pheromone fixture-and-schema gate cluster.
//
// The pheromone gates live in `cargo xtask check fixtures <facet>`. The
// `scripts/check-chio-pheromone-*.sh` paths must stay absent: a re-added script
// would not be exercised by any workflow and would diverge from the live gate.
// This test fails if any of those script paths reappears.

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
