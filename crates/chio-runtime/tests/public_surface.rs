#[test]
fn chio_runtime_facade_does_not_export_legacy_chiodos_schema_constants() {
    let lib = include_str!("../src/lib.rs");
    let legacy_exports = lib
        .lines()
        .filter(|line| line.contains("CHIODOS_") && line.contains("_SCHEMA"))
        .collect::<Vec<_>>();

    assert!(
        legacy_exports.is_empty(),
        "chio-runtime public facade must not export legacy Chiodos schema constants: {legacy_exports:#?}"
    );
}

#[test]
fn chio_runtime_schema_constants_are_owned_locally() {
    let lib = include_str!("../src/lib.rs");
    let Some(reexport_start) = lib.find("pub use chio_chiodos_runtime::{") else {
        panic!("runtime facade must keep an explicit historical reexport block");
    };
    let reexport_tail = &lib[reexport_start..];
    let Some(reexport_end) = reexport_tail.find("};") else {
        panic!("runtime facade historical reexport block must terminate");
    };
    let reexport_block = &reexport_tail[..reexport_end];
    let schema_reexports = reexport_block
        .lines()
        .filter(|line| line.contains("CHIO_RUNTIME_") && line.contains("_SCHEMA"))
        .collect::<Vec<_>>();

    assert!(
        schema_reexports.is_empty(),
        "chio-runtime public Chio schema constants must be owned locally, not reexported from the historical runtime crate: {schema_reexports:#?}"
    );
}
