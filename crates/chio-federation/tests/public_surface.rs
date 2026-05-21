#[test]
fn chio_federation_root_does_not_export_legacy_chiodos_treaty_schema_constants() {
    let lib = include_str!("../src/lib.rs");
    let legacy_schema_exports = [
        "CHIODOS_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA",
        "CHIODOS_GOVERNANCE_LADDER_MANIFEST_SCHEMA",
        "CHIODOS_LADDER_INTERSECTION_SCHEMA",
        "CHIODOS_TREATY_SCOPE_SCHEMA",
    ]
    .into_iter()
    .filter(|name| lib.contains(name))
    .collect::<Vec<_>>();

    assert!(
        legacy_schema_exports.is_empty(),
        "chio-federation root public API must not reexport legacy Chiodos treaty schema constants: {legacy_schema_exports:#?}"
    );
}

#[test]
fn chio_federation_root_exports_chio_named_bilateral_dsse_api() {
    let lib = include_str!("../src/lib.rs");
    let legacy_root_exports = [
        "build_chiodos_predicate",
        "build_chiodos_statement",
        "sign_chiodos_dsse_envelope",
        "sign_chiodos_dsse_envelope_with_cosigner",
        "verify_chiodos_dsse_envelope",
        "verify_chiodos_bilateral_invocation",
        "verify_treaty_bound_chiodos_bilateral_invocation",
        "StrictChiodosVerifierConfig",
        "PREDICATE_TYPE_CHIODOS_BILATERAL",
    ]
    .into_iter()
    .filter(|name| lib.contains(name))
    .collect::<Vec<_>>();

    assert!(
        legacy_root_exports.is_empty(),
        "chio-federation root public API must not reexport legacy Chiodos bilateral DSSE names: {legacy_root_exports:#?}"
    );

    let chio_root_exports = [
        "build_chio_bilateral_invocation_predicate",
        "build_chio_bilateral_invocation_statement",
        "sign_chio_bilateral_dsse_envelope",
        "sign_chio_bilateral_dsse_envelope_with_cosigner",
        "verify_chio_bilateral_dsse_envelope",
        "verify_chio_bilateral_invocation",
        "verify_treaty_bound_chio_bilateral_invocation",
        "ChioBilateralVerifierConfig",
        "PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION",
    ]
    .into_iter()
    .filter(|name| !lib.contains(name))
    .collect::<Vec<_>>();

    assert!(
        chio_root_exports.is_empty(),
        "chio-federation root public API must reexport Chio-named bilateral DSSE names: {chio_root_exports:#?}"
    );
}

#[test]
fn chio_federation_bilateral_modules_do_not_expose_public_chiodos_aliases() {
    let bilateral_dsse = include_str!("../src/bilateral_dsse.rs");
    let bilateral_verifier = include_str!("../src/bilateral_verifier.rs");

    let legacy_dsse_exports = [
        "pub const PREDICATE_TYPE_CHIODOS_BILATERAL",
        "pub fn build_chiodos_predicate",
        "pub fn build_chiodos_statement",
        "pub fn sign_chiodos_dsse_envelope",
        "pub fn sign_chiodos_dsse_envelope_with_cosigner",
        "pub fn verify_chiodos_dsse_envelope",
    ]
    .into_iter()
    .filter(|name| bilateral_dsse.contains(name))
    .collect::<Vec<_>>();

    assert!(
        legacy_dsse_exports.is_empty(),
        "chio-federation bilateral_dsse module must not expose public Chiodos aliases: {legacy_dsse_exports:#?}"
    );

    let legacy_verifier_exports = [
        "pub type StrictChiodosVerifierConfig",
        "pub fn verify_chiodos_bilateral_invocation",
        "pub fn verify_treaty_bound_chiodos_bilateral_invocation",
    ]
    .into_iter()
    .filter(|name| bilateral_verifier.contains(name))
    .collect::<Vec<_>>();

    assert!(
        legacy_verifier_exports.is_empty(),
        "chio-federation bilateral_verifier module must not expose public Chiodos aliases: {legacy_verifier_exports:#?}"
    );
}

#[test]
fn chio_federation_treaty_module_does_not_expose_public_chiodos_schema_constants() {
    let treaty = include_str!("../src/treaty.rs");
    let legacy_schema_exports = [
        "pub const CHIODOS_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA",
        "pub const CHIODOS_GOVERNANCE_LADDER_MANIFEST_SCHEMA",
        "pub const CHIODOS_LADDER_INTERSECTION_SCHEMA",
        "pub const CHIODOS_TREATY_SCOPE_SCHEMA",
    ]
    .into_iter()
    .filter(|name| treaty.contains(name))
    .collect::<Vec<_>>();

    assert!(
        legacy_schema_exports.is_empty(),
        "chio-federation treaty module must not expose public Chiodos schema constants: {legacy_schema_exports:#?}"
    );
}

#[test]
fn chio_federation_production_text_is_chio_named() {
    let sources = [
        ("lib.rs", production_source(include_str!("../src/lib.rs"))),
        (
            "bilateral.rs",
            production_source(include_str!("../src/bilateral.rs")),
        ),
        (
            "bilateral_dsse.rs",
            production_source(include_str!("../src/bilateral_dsse.rs")),
        ),
        (
            "bilateral_verifier.rs",
            production_source(include_str!("../src/bilateral_verifier.rs")),
        ),
        (
            "pheromone_gossip.rs",
            production_source(include_str!("../src/pheromone_gossip.rs")),
        ),
    ];

    let leaks = sources
        .into_iter()
        .flat_map(|(path, source)| {
            source.lines().enumerate().filter_map(move |(index, line)| {
                if line.contains("Chiodos") || line.contains("CHIODOS") || line.contains("chiodos")
                {
                    Some(format!("{path}:{}:{line}", index + 1))
                } else {
                    None
                }
            })
        })
        .collect::<Vec<_>>();

    assert!(
        leaks.is_empty(),
        "production Chio federation text must not expose Chiodos wording: {leaks:#?}"
    );
}

fn production_source(source: &str) -> &str {
    source.split("#[cfg(test)]").next().unwrap_or(source)
}
