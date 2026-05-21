#[test]
fn chio_pheromone_does_not_export_legacy_chiodos_schema_constants() {
    let lib = include_str!("../src/lib.rs");
    let legacy_schema_exports = lib
        .lines()
        .filter(|line| line.contains("pub const CHIODOS_") && line.contains("_SCHEMA"))
        .collect::<Vec<_>>();

    assert!(
        legacy_schema_exports.is_empty(),
        "chio-pheromone public API must expose Chio schema constants only: {legacy_schema_exports:#?}"
    );
}
