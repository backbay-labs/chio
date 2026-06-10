// Retirement guard for the bounded-chio qualification gate.
//
// The bounded-chio qualification contract lives in `cargo xtask qualify
// bounded-chio` (see xtask/src/qualify.rs). The `scripts/qualify-bounded-chio.sh`
// path must stay absent: the matrix entrypoint and the release docs point at the
// xtask leaf, so a re-added script would not be exercised by any workflow. This
// test fails if that script path reappears.

use std::path::PathBuf;

fn root() -> PathBuf {
    match PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent() {
        Some(parent) => parent.to_path_buf(),
        None => panic!("xtask manifest dir has no parent"),
    }
}

#[test]
fn bounded_chio_script_is_retired() {
    let path = root().join("scripts/qualify-bounded-chio.sh");
    assert!(
        !path.exists(),
        "legacy bounded-chio script must stay retired; it was replaced by \
         `cargo xtask qualify bounded-chio`"
    );
}

#[test]
fn bounded_matrix_entrypoint_points_at_the_xtask_leaf() {
    // The matrix entrypoint must name the live gate, not the retired script.
    // This is the same string the qualify leaf asserts; the test guards against
    // a future edit silently re-pointing the matrix at a dead script path.
    let matrix = root().join("docs/standards/CHIO_BOUNDED_QUALIFICATION_MATRIX.json");
    let raw = std::fs::read_to_string(&matrix)
        .unwrap_or_else(|err| panic!("bounded matrix must read: {err}"));
    let value: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|err| panic!("bounded matrix must parse: {err}"));
    let entrypoint = value
        .get("entrypoint")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("bounded matrix has no entrypoint"));
    assert_eq!(
        entrypoint, "cargo xtask qualify bounded-chio",
        "bounded matrix entrypoint must point at the live xtask gate"
    );
}
