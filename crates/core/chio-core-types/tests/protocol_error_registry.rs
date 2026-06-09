#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{collections::BTreeSet, fs, path::PathBuf};

use serde::Deserialize;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ErrorRegistry {
    schema: String,
    categories: Vec<String>,
    codes: Vec<ErrorEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ErrorEntry {
    code: u64,
    name: String,
    category: String,
    transient: bool,
    retry: RetryGuidance,
}

#[derive(Debug, Deserialize)]
struct RetryGuidance {
    strategy: String,
    guidance: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NegotiationArtifact {
    schema: String,
    surfaces: NegotiationSurfaces,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NegotiationSurfaces {
    native_chio: NativeNegotiationSurface,
    hosted_mcp: HostedNegotiationSurface,
    trust_control: TrustControlNegotiationSurface,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeNegotiationSurface {
    wire_version: String,
    exchange_format: String,
    compatibility: String,
    downgrade_behavior: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostedNegotiationSurface {
    initialize_request_field: String,
    initialize_response_field: String,
    session_header: String,
    supported_protocol_versions: Vec<String>,
    selection_policy: String,
    downgrade_behavior: String,
    connection_rejection: ConnectionRejection,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustControlNegotiationSurface {
    versioning: String,
    base_path_prefix: String,
    compatibility: String,
    downgrade_behavior: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionRejection {
    chio_error_code: u64,
}

fn load_json<T: for<'de> Deserialize<'de>>(relative_path: &str) -> T {
    let contents =
        fs::read_to_string(repo_root().join(relative_path)).expect("artifact file exists");
    serde_json::from_str(&contents).expect("artifact parses")
}

#[test]
fn protocol_error_registry_has_unique_codes_and_complete_categories() {
    let registry: ErrorRegistry = load_json("spec/errors/chio-error-registry.v1.json");

    assert_eq!(registry.schema, "chio.error-registry.v1");
    let expected_categories = BTreeSet::from([
        "auth".to_string(),
        "budget".to_string(),
        "capability".to_string(),
        "guard".to_string(),
        "internal".to_string(),
        "protocol".to_string(),
        "tool".to_string(),
    ]);
    let listed_categories = registry.categories.into_iter().collect::<BTreeSet<_>>();
    assert_eq!(listed_categories, expected_categories);

    let mut seen_codes = BTreeSet::new();
    let mut seen_entry_categories = BTreeSet::new();
    for entry in registry.codes {
        assert!(
            seen_codes.insert(entry.code),
            "duplicate code {}",
            entry.code
        );
        assert!(
            expected_categories.contains(&entry.category),
            "unknown category {}",
            entry.category
        );
        assert!(!entry.name.trim().is_empty(), "empty error name");
        assert!(
            !entry.retry.strategy.trim().is_empty(),
            "missing retry strategy for {}",
            entry.name
        );
        assert!(
            !entry.retry.guidance.trim().is_empty(),
            "missing retry guidance for {}",
            entry.name
        );
        if entry.transient {
            assert_ne!(
                entry.retry.strategy, "do_not_retry",
                "transient error {} must not use do_not_retry",
                entry.name
            );
        }
        seen_entry_categories.insert(entry.category);
    }

    assert_eq!(seen_entry_categories, expected_categories);
}

#[test]
fn protocol_error_registry_version_negotiation_artifact_is_consistent() {
    let registry: ErrorRegistry = load_json("spec/errors/chio-error-registry.v1.json");
    let negotiation: NegotiationArtifact =
        load_json("spec/versions/chio-protocol-negotiation.v1.json");

    assert_eq!(negotiation.schema, "chio.protocol-negotiation.v1");
    assert_eq!(
        negotiation.surfaces.native_chio.wire_version,
        "chio-wire-v1"
    );
    assert_eq!(
        negotiation.surfaces.native_chio.exchange_format,
        "out_of_band"
    );
    assert_eq!(
        negotiation.surfaces.native_chio.compatibility,
        "exact_match"
    );
    assert_eq!(
        negotiation.surfaces.native_chio.downgrade_behavior,
        "not_supported"
    );
    assert_eq!(
        negotiation.surfaces.hosted_mcp.initialize_request_field,
        "params.protocolVersion"
    );
    assert_eq!(
        negotiation.surfaces.hosted_mcp.initialize_response_field,
        "result.protocolVersion"
    );
    assert_eq!(
        negotiation.surfaces.hosted_mcp.session_header,
        "MCP-Protocol-Version"
    );
    assert_eq!(
        negotiation.surfaces.hosted_mcp.selection_policy,
        "exact_match_from_supported_set"
    );
    assert_eq!(
        negotiation.surfaces.hosted_mcp.downgrade_behavior,
        "current implementation publishes one supported version and rejects mismatches"
    );
    assert!(!negotiation
        .surfaces
        .hosted_mcp
        .supported_protocol_versions
        .is_empty());
    assert!(negotiation
        .surfaces
        .hosted_mcp
        .supported_protocol_versions
        .contains(&"2025-11-25".to_string()));
    assert_eq!(negotiation.surfaces.trust_control.versioning, "path_prefix");
    assert_eq!(negotiation.surfaces.trust_control.base_path_prefix, "/v1");
    assert_eq!(
        negotiation.surfaces.trust_control.compatibility,
        "exact_prefix_match"
    );
    assert_eq!(
        negotiation.surfaces.trust_control.downgrade_behavior,
        "not_applicable"
    );

    let registry_codes = registry
        .codes
        .into_iter()
        .map(|entry| entry.code)
        .collect::<BTreeSet<_>>();
    assert!(registry_codes.contains(
        &negotiation
            .surfaces
            .hosted_mcp
            .connection_rejection
            .chio_error_code
    ));
}
