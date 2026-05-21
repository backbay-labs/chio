#[test]
fn chio_attest_buyer_does_not_export_legacy_chiodos_schema_constants() {
    let lib = include_str!("../src/lib.rs");
    let legacy_exports = lib
        .lines()
        .filter(|line| line.contains("pub const CHIODOS_") && line.contains("_SCHEMA"))
        .collect::<Vec<_>>();

    assert!(
        legacy_exports.is_empty(),
        "chio-attest-buyer public API must expose Chio-native schema constants only: {legacy_exports:#?}"
    );
}

#[test]
fn chio_attest_buyer_schema_constants_are_owned_locally() {
    let lib = include_str!("../src/lib.rs");
    let historical_aliases = lib
        .lines()
        .filter(|line| line.contains("chio_chiodos_runtime::CHIO_") && line.contains("_SCHEMA"))
        .collect::<Vec<_>>();

    assert!(
        historical_aliases.is_empty(),
        "chio-attest-buyer public Chio schema constants must not be sourced from the historical runtime crate: {historical_aliases:#?}"
    );
}
