#[test]
fn chio_federation_root_does_not_export_legacy_chio_treaty_schema_constants() {
    let lib = include_str!("../src/lib.rs");
    let legacy_schema_exports = [
        "CHIO_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA",
        "CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA",
        "CHIO_LADDER_INTERSECTION_SCHEMA",
        "CHIO_TREATY_SCOPE_SCHEMA",
    ]
    .into_iter()
    .filter(|name| lib.contains(name))
    .collect::<Vec<_>>();

    assert!(
        legacy_schema_exports.is_empty(),
        "chio-federation root public API must not reexport legacy Chio treaty schema constants: {legacy_schema_exports:#?}"
    );
}

#[test]
fn chio_federation_root_does_not_export_bilateral_dsse_api() {
    let lib = include_str!("../src/lib.rs");
    let legacy_root_exports = [
        "build_chio_predicate",
        "build_chio_statement",
        "sign_chio_dsse_envelope",
        "sign_chio_dsse_envelope_with_cosigner",
        "verify_chio_dsse_envelope",
        "StrictChioVerifierConfig",
        "PREDICATE_TYPE_CHIO_BILATERAL,",
    ]
    .into_iter()
    .filter(|name| lib.contains(name))
    .collect::<Vec<_>>();

    assert!(
        legacy_root_exports.is_empty(),
        "chio-federation root public API must not reexport legacy Chio bilateral DSSE names: {legacy_root_exports:#?}"
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
    .filter(|name| lib.contains(name))
    .collect::<Vec<_>>();

    assert!(
        chio_root_exports.is_empty(),
        "chio-federation root public API must not reexport Chio-named bilateral DSSE names: {chio_root_exports:#?}"
    );

    let bilateral_dsse = include_str!("../src/bilateral_dsse.rs");
    let bilateral_verifier = concat!(
        include_str!("../src/bilateral_verifier.rs"),
        include_str!("../src/bilateral_verifier/config.rs"),
        include_str!("../src/bilateral_verifier/cosign.rs"),
        include_str!("../src/bilateral_verifier/treaty.rs"),
    );
    let missing_module_exports = [
        (
            "bilateral_dsse",
            "build_chio_bilateral_invocation_predicate",
        ),
        (
            "bilateral_dsse",
            "build_chio_bilateral_invocation_statement",
        ),
        ("bilateral_dsse", "sign_chio_bilateral_dsse_envelope"),
        (
            "bilateral_dsse",
            "sign_chio_bilateral_dsse_envelope_with_cosigner",
        ),
        ("bilateral_dsse", "verify_chio_bilateral_dsse_envelope"),
        ("bilateral_dsse", "PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION"),
        ("bilateral_verifier", "verify_chio_bilateral_invocation"),
        (
            "bilateral_verifier",
            "verify_treaty_bound_chio_bilateral_invocation",
        ),
        ("bilateral_verifier", "ChioBilateralVerifierConfig"),
    ]
    .into_iter()
    .filter_map(|(module, name)| {
        let source = match module {
            "bilateral_dsse" => bilateral_dsse,
            "bilateral_verifier" => bilateral_verifier,
            _ => "",
        };
        (!source.contains(name)).then_some((module, name))
    })
    .collect::<Vec<_>>();

    assert!(
        missing_module_exports.is_empty(),
        "chio-federation bilateral modules must expose Chio-named DSSE API: {missing_module_exports:#?}"
    );
}

#[test]
fn chio_federation_bilateral_modules_do_not_expose_public_chio_aliases() {
    let bilateral_dsse = include_str!("../src/bilateral_dsse.rs");
    let bilateral_verifier = concat!(
        include_str!("../src/bilateral_verifier.rs"),
        include_str!("../src/bilateral_verifier/config.rs"),
        include_str!("../src/bilateral_verifier/cosign.rs"),
        include_str!("../src/bilateral_verifier/treaty.rs"),
    );

    let legacy_dsse_exports = [
        "pub const PREDICATE_TYPE_CHIO_BILATERAL:",
        "pub fn build_chio_predicate",
        "pub fn build_chio_statement",
        "pub fn sign_chio_dsse_envelope",
        "pub fn sign_chio_dsse_envelope_with_cosigner",
        "pub fn verify_chio_dsse_envelope",
    ]
    .into_iter()
    .filter(|name| bilateral_dsse.contains(name))
    .collect::<Vec<_>>();

    assert!(
        legacy_dsse_exports.is_empty(),
        "chio-federation bilateral_dsse module must not expose public Chio aliases: {legacy_dsse_exports:#?}"
    );

    let legacy_verifier_exports = ["pub type StrictChioVerifierConfig"]
        .into_iter()
        .filter(|name| bilateral_verifier.contains(name))
        .collect::<Vec<_>>();

    assert!(
        legacy_verifier_exports.is_empty(),
        "chio-federation bilateral_verifier module must not expose public Chio aliases: {legacy_verifier_exports:#?}"
    );
}

#[test]
fn chio_federation_treaty_module_does_not_expose_public_chio_schema_constants() {
    let treaty = include_str!("../src/treaty.rs");
    let legacy_schema_exports = [
        "pub const CHIO_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA",
        "pub const CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA",
        "pub const CHIO_LADDER_INTERSECTION_SCHEMA",
        "pub const CHIO_TREATY_SCOPE_SCHEMA",
    ]
    .into_iter()
    .filter(|name| treaty.contains(name))
    .collect::<Vec<_>>();

    assert!(
        legacy_schema_exports.is_empty(),
        "chio-federation treaty module must not expose public Chio schema constants: {legacy_schema_exports:#?}"
    );
}

#[test]
fn chio_federation_production_text_is_chio_named() {
    let retired_schema_prefix_text = ["chio", "chio", ""].join(".");
    let retired_schema_path_text = ["spec", "schemas", "chio", "v1"].join("/");
    let retired_schema_prefix = retired_schema_prefix_text.as_str();
    let retired_schema_path = retired_schema_path_text.as_str();
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
                if line.contains(retired_schema_prefix)
                    || line.contains(retired_schema_path)
                    || line.contains("build_chio_predicate")
                    || line.contains("build_chio_statement")
                    || line.contains("sign_chio_dsse_envelope")
                    || line.contains("verify_chio_dsse_envelope")
                    || line.contains("StrictChioVerifierConfig")
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
        "production Chio federation text must not expose retired schema or alias wording: {leaks:#?}"
    );
}

fn production_source(source: &str) -> &str {
    source.split("#[cfg(test)]").next().unwrap_or(source)
}
