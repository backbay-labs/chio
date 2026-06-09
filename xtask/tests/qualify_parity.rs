// Retirement guard for the bounded-chio qualification gate.
//
// `scripts/qualify-bounded-chio.sh` was a doc-grep tautology: it copied docs
// into target/, generated a checklist, and emitted a SHA256SUMS manifest whose
// only inputs were files it had just copied. It additionally had drifted red
// (its hard-coded README reference list named release docs the README no longer
// links). The single load-bearing contract it guarded - the structural shape of
// the bounded qualification matrix - was ported to `cargo xtask qualify
// bounded-chio` (see xtask/src/qualify.rs) and proved equivalent via a dual-run
// parity sweep before the script was deleted. This test enforces that the
// script stays retired: a re-added script would resurrect the tautology and
// would not be exercised by any workflow (the matrix entrypoint and the release
// docs now point at the xtask leaf).

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
