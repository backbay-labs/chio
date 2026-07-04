#[test]
fn chio_attest_buyer_schema_constants_are_owned_locally() {
    let lib = include_str!("../src/lib.rs");
    let runtime_core_aliases = lib
        .lines()
        .filter(|line| line.contains("chio_runtime_core::CHIO_") && line.contains("_SCHEMA"))
        .collect::<Vec<_>>();

    assert!(
        runtime_core_aliases.is_empty(),
        "chio-attest-buyer public Chio schema constants must not be sourced from the runtime-core crate: {runtime_core_aliases:#?}"
    );
}
