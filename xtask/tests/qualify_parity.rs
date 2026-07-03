use std::path::PathBuf;

fn root() -> PathBuf {
    match PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent() {
        Some(parent) => parent.to_path_buf(),
        None => panic!("xtask manifest dir has no parent"),
    }
}

#[test]
fn bounded_matrix_entrypoint_points_at_the_xtask_leaf() {
    // The matrix entrypoint must equal the xtask leaf.
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
