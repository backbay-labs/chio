// M05.P4.T2 test body for threat ID `audience_confusion`.
//
// Threat: audience_confusion (Audience confusion).
// Surfaces: trust_control, native_chio, hosted_mcp.
//
// Coverage strategy: M10.P2 pins passkey capability audience fields
// in the custody hardware surface and exercises cross-audience
// presentation rejection in the audience-confusion property tests.

use std::path::PathBuf;

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

#[test]
fn threat_audience_confusion_is_covered() {
    // covers: audience_confusion
    for evidence in [
        "crates/chio-custody-hw/src/capability.rs",
        "crates/chio-custody-hw/tests/audience_confusion.rs",
    ] {
        let path = repo_path(evidence);
        assert!(
            path.is_file(),
            "audience confusion evidence file {} must remain in-tree",
            path.display()
        );
    }
}
