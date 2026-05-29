#[test]
fn chio_pheromone_does_not_reexport_chio_schema_constants() {
    let lib = include_str!("../src/lib.rs");
    let reexported_schema_constants = lib
        .lines()
        .filter(|line| line.contains("pub const CHIO_") && line.contains("_SCHEMA"))
        .collect::<Vec<_>>();

    assert!(
        reexported_schema_constants.is_empty(),
        "chio-pheromone public API must not re-export CHIO_*_SCHEMA constants (they are owned by their defining crate): {reexported_schema_constants:#?}"
    );
}
