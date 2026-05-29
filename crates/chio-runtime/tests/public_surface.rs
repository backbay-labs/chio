#[test]
fn chio_runtime_schema_constants_are_owned_locally() {
    let lib = include_str!("../src/lib.rs");
    let schema_reexports = lib
        .lines()
        .filter(|line| {
            line.contains("pub const CHIO_RUNTIME_") && line.contains("chio_runtime_core::")
        })
        .collect::<Vec<_>>();

    assert!(
        schema_reexports.is_empty(),
        "chio-runtime public Chio schema constants must be owned locally, not reexported from the historical runtime crate: {schema_reexports:#?}"
    );
}
