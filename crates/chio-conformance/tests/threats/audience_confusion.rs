// M05.P4.T2 test body for threat ID `audience_confusion`.
//
// Threat: audience_confusion (Audience confusion).
// Surfaces: trust_control, native_chio, hosted_mcp.
//
// Coverage strategy: M10.P2 pins passkey capability audience fields
// in the custody hardware surface and exercises cross-audience
// presentation rejection in the audience-confusion property tests.

use std::{fs, path::PathBuf};

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

#[test]
fn threat_audience_confusion_is_covered() {
    // covers: audience_confusion
    //
    // Pin the M10.P2.T4 audience-confusion property test plus the
    // audience-pinned PasskeyCapability source surface. File
    // existence alone is not enough: the cited bit-flip regression
    // and the require_audience pinned test are the actual failure
    // exercises and must remain referenced by name.
    for (evidence, needle) in [
        (
            "crates/chio-custody-hw/src/capability.rs",
            "PasskeyCapability",
        ),
        (
            "crates/chio-custody-hw/tests/audience_confusion.rs",
            "audience_bit_flip_invalidates_signature_pinned",
        ),
    ] {
        let path = repo_path(evidence);
        assert!(
            path.is_file(),
            "audience confusion evidence file {} must remain in-tree",
            path.display()
        );
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(err) => panic!("read {}: {err}", path.display()),
        };
        assert!(
            raw.contains(needle),
            "audience confusion evidence file {} must mention {needle:?}",
            path.display()
        );
    }
}

#[test]
fn threat_audience_confusion_pins_require_audience_check() {
    // covers: audience_confusion
    //
    // The application-level fail-closed check is
    // `require_audience_fail_closed_for_mismatch_pinned`: presenting
    // a capability minted for audience A to audience B must reject
    // even before the signature surface is reached. Pin that test
    // name so a rename without coordination breaks this closure.
    let path = repo_path("crates/chio-custody-hw/tests/audience_confusion.rs");
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) => panic!("read {}: {err}", path.display()),
    };
    assert!(
        raw.contains("require_audience_fail_closed_for_mismatch_pinned"),
        "audience confusion application-level fail-closed pinned test must remain in-tree"
    );
}
