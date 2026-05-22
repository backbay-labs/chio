#[test]
fn chio_attest_buyer_does_not_export_retired_schema_ids() {
    let lib = include_str!("../src/lib.rs");
    let retired_schema_prefix = ["chio", "chio", ""].join(".");
    let retired_schema_path = ["spec", "schemas", "chio", "v1"].join("/");
    let retired_exports = lib
        .lines()
        .filter(|line| line.contains(&retired_schema_prefix) || line.contains(&retired_schema_path))
        .collect::<Vec<_>>();

    assert!(
        retired_exports.is_empty(),
        "chio-attest-buyer public API must expose Chio-native schema constants only: {retired_exports:#?}"
    );
}

#[test]
fn chio_attest_buyer_schema_constants_are_owned_locally() {
    let lib = include_str!("../src/lib.rs");
    let historical_aliases = lib
        .lines()
        .filter(|line| line.contains("chio_runtime_core::CHIO_") && line.contains("_SCHEMA"))
        .collect::<Vec<_>>();

    assert!(
        historical_aliases.is_empty(),
        "chio-attest-buyer public Chio schema constants must not be sourced from the historical runtime crate: {historical_aliases:#?}"
    );
}
