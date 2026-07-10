use std::collections::HashSet;

use super::validation::validate_evidence_runtime_guardrails;
use super::*;

fn sample_inventory() -> ChioExtensionInventory {
    ChioExtensionInventory {
        schema: CHIO_EXTENSION_INVENTORY_SCHEMA.to_string(),
        chio_contract_version: "2.0".to_string(),
        canonical_truth: vec![CanonicalTruthSurface {
            id: "chio.canonical.receipt".to_string(),
            name: "Signed receipts and checkpoints".to_string(),
            crate_path: "crates/core/chio-core/src/receipt.rs".to_string(),
            contract_kind: CanonicalContractKind::Receipt,
            artifact_schemas: vec!["chio.receipt.v1".to_string(), "chio.checkpoint.v1".to_string()],
            notes: "Extensions may project evidence around receipts, but they must not mutate signed receipt or checkpoint truth."
                .to_string(),
            extensions_may_write: false,
        }],
        extension_points: vec![
            ChioExtensionPoint {
                id: "chio.kernel.receipt_store".to_string(),
                name: "Receipt store backend".to_string(),
                point_kind: ExtensionPointKind::Store,
                owner: "kernel".to_string(),
                contract_path: "crates/kernel/chio-kernel/src/receipt_store.rs::ReceiptStore".to_string(),
                stability: ExtensionStability::Supported,
                allowed_isolations: vec![
                    ExtensionIsolation::InProcess,
                    ExtensionIsolation::RemoteService,
                ],
                allowed_evidence_modes: vec![ExtensionEvidenceMode::None],
                allowed_privileges: vec![
                    ExtensionPrivilege::FilesystemRead,
                    ExtensionPrivilege::FilesystemWrite,
                    ExtensionPrivilege::NetworkEgress,
                ],
                custom_implementations_allowed: true,
                policy_activation_required: false,
                official_component_ids: vec![
                    "chio.sqlite-receipt-store".to_string(),
                    "chio.remote-receipt-store".to_string(),
                ],
            },
            ChioExtensionPoint {
                id: "chio.kernel.tool_server_connection".to_string(),
                name: "Tool server connection".to_string(),
                point_kind: ExtensionPointKind::ToolServerConnection,
                owner: "kernel".to_string(),
                contract_path: "crates/kernel/chio-kernel/src/runtime.rs::ToolServerConnection".to_string(),
                stability: ExtensionStability::Supported,
                allowed_isolations: vec![
                    ExtensionIsolation::InProcess,
                    ExtensionIsolation::Subprocess,
                    ExtensionIsolation::RemoteService,
                ],
                allowed_evidence_modes: vec![
                    ExtensionEvidenceMode::None,
                    ExtensionEvidenceMode::ImportOnly,
                    ExtensionEvidenceMode::DispatchOnly,
                    ExtensionEvidenceMode::ImportAndDispatch,
                ],
                allowed_privileges: vec![
                    ExtensionPrivilege::FilesystemRead,
                    ExtensionPrivilege::NetworkEgress,
                    ExtensionPrivilege::ProcessExecution,
                    ExtensionPrivilege::OperatorSecrets,
                ],
                custom_implementations_allowed: true,
                policy_activation_required: true,
                official_component_ids: vec!["chio.native-chio-service".to_string()],
            },
        ],
    }
}

fn sample_official_stack() -> OfficialStackPackage {
    OfficialStackPackage {
        schema: CHIO_OFFICIAL_STACK_SCHEMA.to_string(),
        package_id: "chio.official-stack".to_string(),
        version: "0.1.0".to_string(),
        chio_contract_version: "2.0".to_string(),
        components: vec![
            OfficialStackComponent {
                id: "chio.sqlite-receipt-store".to_string(),
                name: "SQLite receipt store".to_string(),
                extension_point_ids: vec!["chio.kernel.receipt_store".to_string()],
                crate_path:
                    "crates/platform/chio-store-sqlite/src/receipt_store.rs::SqliteReceiptStore"
                        .to_string(),
                implementation_source: OfficialImplementationSource::FirstParty,
            },
            OfficialStackComponent {
                id: "chio.remote-receipt-store".to_string(),
                name: "Remote receipt store".to_string(),
                extension_point_ids: vec!["chio.kernel.receipt_store".to_string()],
                crate_path:
                    "crates/platform/chio-control-plane/src/trust_control.rs::RemoteReceiptStore"
                        .to_string(),
                implementation_source: OfficialImplementationSource::FirstParty,
            },
            OfficialStackComponent {
                id: "chio.native-chio-service".to_string(),
                name: "Native Chio service".to_string(),
                extension_point_ids: vec!["chio.kernel.tool_server_connection".to_string()],
                crate_path: "crates/protocol/chio-mcp-adapter/src/native.rs::NativeChioService"
                    .to_string(),
                implementation_source: OfficialImplementationSource::FirstParty,
            },
        ],
        profiles: vec![
            OfficialStackProfile {
                id: "local_default".to_string(),
                name: "Local default".to_string(),
                description: "Local stores with native Chio service".to_string(),
                component_ids: vec![
                    "chio.sqlite-receipt-store".to_string(),
                    "chio.native-chio-service".to_string(),
                ],
            },
            OfficialStackProfile {
                id: "shared_control_plane".to_string(),
                name: "Shared control plane".to_string(),
                description: "Remote store components with first-party service adapters"
                    .to_string(),
                component_ids: vec![
                    "chio.remote-receipt-store".to_string(),
                    "chio.native-chio-service".to_string(),
                ],
            },
        ],
    }
}

fn sample_manifest() -> ChioExtensionManifest {
    ChioExtensionManifest {
        schema: CHIO_EXTENSION_MANIFEST_SCHEMA.to_string(),
        extension_id: "sample.pg-receipt-store".to_string(),
        display_name: "Sample Postgres Receipt Store".to_string(),
        version: "1.0.0".to_string(),
        distribution: ExtensionDistribution::ThirdPartyCustom,
        extension_point_id: "chio.kernel.receipt_store".to_string(),
        capabilities: vec![
            "receipt_append".to_string(),
            "receipt_query".to_string(),
            "checkpoint_replay_safe".to_string(),
        ],
        supported_profiles: vec!["shared_control_plane".to_string()],
        compatibility: ExtensionCompatibility {
            chio_contract_version: "2.0".to_string(),
            official_stack_package_id: "chio.official-stack".to_string(),
            supported_component_ids: vec!["chio.remote-receipt-store".to_string()],
            supported_contract_schemas: vec![
                CHIO_EXTENSION_MANIFEST_SCHEMA.to_string(),
                "chio.receipt.v1".to_string(),
                "chio.checkpoint.v1".to_string(),
            ],
        },
        runtime: ExtensionRuntimeEnvelope {
            isolation: ExtensionIsolation::RemoteService,
            allowed_privileges: vec![
                ExtensionPrivilege::NetworkEgress,
                ExtensionPrivilege::FilesystemRead,
            ],
            evidence_mode: ExtensionEvidenceMode::None,
            requires_subject_binding: false,
            requires_signer_verification: false,
            requires_freshness_check: false,
            requires_local_policy_activation: false,
            allows_truth_mutation: false,
            allows_trust_widening: false,
        },
    }
}

fn sample_qualification_matrix() -> ExtensionQualificationMatrix {
    ExtensionQualificationMatrix {
        schema: CHIO_EXTENSION_QUALIFICATION_MATRIX_SCHEMA.to_string(),
        official_stack_package_id: "chio.official-stack".to_string(),
        chio_contract_version: "2.0".to_string(),
        cases: vec![ExtensionQualificationCase {
            id: "tool-server-pass".to_string(),
            name: "Supported tool-server extension remains bounded".to_string(),
            extension_point_id: "chio.kernel.tool_server_connection".to_string(),
            supported_component_id: "chio.native-chio-service".to_string(),
            candidate_extension_id: "sample.tool-server".to_string(),
            mode: QualificationMode::OfficialToCustom,
            expected_outcome: QualificationOutcome::Pass,
            observed_outcome: QualificationOutcome::Pass,
            rejection_codes: vec![],
            invariants: vec![
                QualificationInvariant::PreservesCanonicalTruth,
                QualificationInvariant::RequiresLocalPolicyActivation,
            ],
        }],
    }
}

fn rejection_codes(
    report: &ExtensionNegotiationReport,
) -> HashSet<ExtensionNegotiationRejectionCode> {
    report.reasons.iter().map(|reason| reason.code).collect()
}

#[test]
fn rejects_duplicate_inventory_ids() {
    let mut inventory = sample_inventory();
    inventory
        .extension_points
        .push(inventory.extension_points[0].clone());
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::DuplicateValue(_))
    ));
}

#[test]
fn inventory_rejects_evidence_capable_points_without_policy_activation() {
    let mut inventory = sample_inventory();
    inventory.extension_points[1].policy_activation_required = false;

    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::InvalidGuardrail(_))
    ));
}

#[test]
fn inventory_validation_rejects_remaining_shape_and_guardrail_errors() {
    let mut inventory = sample_inventory();
    inventory.schema = "chio.extension-inventory.v9".to_string();
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::UnsupportedSchema(_))
    ));

    let mut inventory = sample_inventory();
    inventory.chio_contract_version.clear();
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::MissingField(
            "chio_contract_version"
        ))
    ));

    let mut inventory = sample_inventory();
    inventory.canonical_truth.clear();
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::MissingField("canonical_truth"))
    ));

    let mut inventory = sample_inventory();
    inventory.extension_points.clear();
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::MissingField("extension_points"))
    ));

    let mut inventory = sample_inventory();
    inventory.canonical_truth[0].artifact_schemas.clear();
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::MissingField(
            "canonical_truth.artifact_schemas"
        ))
    ));

    let mut inventory = sample_inventory();
    inventory.canonical_truth[0].extensions_may_write = true;
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::InvalidGuardrail(_))
    ));

    let mut inventory = sample_inventory();
    inventory.canonical_truth[0]
        .artifact_schemas
        .push("chio.receipt.v1".to_string());
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut inventory = sample_inventory();
    inventory.extension_points[0].allowed_isolations.clear();
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::MissingField(
            "extension_points.allowed_isolations"
        ))
    ));

    let mut inventory = sample_inventory();
    inventory.extension_points[0].allowed_evidence_modes.clear();
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::MissingField(
            "extension_points.allowed_evidence_modes"
        ))
    ));

    let mut inventory = sample_inventory();
    inventory.extension_points[0].allowed_privileges.clear();
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::MissingField(
            "extension_points.allowed_privileges"
        ))
    ));

    let mut inventory = sample_inventory();
    inventory.extension_points[0].official_component_ids.clear();
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::MissingField(
            "extension_points.official_component_ids"
        ))
    ));

    let mut inventory = sample_inventory();
    inventory.extension_points[0]
        .allowed_isolations
        .push(ExtensionIsolation::InProcess);
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut inventory = sample_inventory();
    inventory.extension_points[0]
        .allowed_evidence_modes
        .push(ExtensionEvidenceMode::None);
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut inventory = sample_inventory();
    inventory.extension_points[0]
        .allowed_privileges
        .push(ExtensionPrivilege::FilesystemRead);
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut inventory = sample_inventory();
    inventory.extension_points[0]
        .official_component_ids
        .push("chio.sqlite-receipt-store".to_string());
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut inventory = sample_inventory();
    inventory.extension_points[1].allowed_evidence_modes = vec![ExtensionEvidenceMode::None];
    assert!(matches!(
        validate_extension_inventory(&inventory),
        Err(ExtensionContractError::InvalidGuardrail(_))
    ));
}

#[test]
fn accepts_supported_custom_store_extension() {
    let report = negotiate_extension(
        &sample_inventory(),
        &sample_official_stack(),
        &sample_manifest(),
    );
    assert_eq!(report.outcome, ExtensionNegotiationOutcome::Accepted);
    assert!(report.reasons.is_empty());
}

#[test]
fn official_stack_validation_rejects_inventory_components_that_do_not_implement_the_point() {
    let mut inventory = sample_inventory();
    inventory.extension_points[0].official_component_ids =
        vec!["chio.native-chio-service".to_string()];

    assert!(matches!(
        validate_official_stack_package(&inventory, &sample_official_stack()),
        Err(ExtensionContractError::UnknownReference(_))
    ));
}

#[test]
fn official_stack_validation_rejects_components_not_advertised_by_inventory() {
    let mut package = sample_official_stack();
    package.components[0].extension_point_ids =
        vec!["chio.kernel.tool_server_connection".to_string()];

    assert!(matches!(
        validate_official_stack_package(&sample_inventory(), &package),
        Err(ExtensionContractError::UnknownReference(_))
    ));
}

#[test]
fn negotiation_rejects_unreciprocated_official_component_edges() {
    let mut package = sample_official_stack();
    package.components[0].extension_point_ids =
        vec!["chio.kernel.tool_server_connection".to_string()];

    let report = negotiate_extension(&sample_inventory(), &package, &sample_manifest());
    assert_eq!(report.outcome, ExtensionNegotiationOutcome::Rejected);
    assert!(rejection_codes(&report)
        .contains(&ExtensionNegotiationRejectionCode::MalformedOfficialStack));
}

#[test]
fn official_stack_validation_rejects_remaining_reference_and_profile_errors() {
    let inventory = sample_inventory();

    let mut package = sample_official_stack();
    package.schema = "chio.official-stack.v9".to_string();
    assert!(matches!(
        validate_official_stack_package(&inventory, &package),
        Err(ExtensionContractError::UnsupportedSchema(_))
    ));

    let mut package = sample_official_stack();
    package.package_id.clear();
    assert!(matches!(
        validate_official_stack_package(&inventory, &package),
        Err(ExtensionContractError::MissingField(
            "official_stack.package_id"
        ))
    ));

    let mut package = sample_official_stack();
    package.components.clear();
    assert!(matches!(
        validate_official_stack_package(&inventory, &package),
        Err(ExtensionContractError::MissingField(
            "official_stack.components"
        ))
    ));

    let mut package = sample_official_stack();
    package.profiles.clear();
    assert!(matches!(
        validate_official_stack_package(&inventory, &package),
        Err(ExtensionContractError::MissingField(
            "official_stack.profiles"
        ))
    ));

    let mut package = sample_official_stack();
    package.components[0].extension_point_ids.clear();
    assert!(matches!(
        validate_official_stack_package(&inventory, &package),
        Err(ExtensionContractError::MissingField(
            "official_stack.components.extension_point_ids"
        ))
    ));

    let mut package = sample_official_stack();
    package.components[0]
        .extension_point_ids
        .push("chio.kernel.receipt_store".to_string());
    assert!(matches!(
        validate_official_stack_package(&inventory, &package),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut package = sample_official_stack();
    package.components[0].extension_point_ids = vec!["chio.kernel.unknown".to_string()];
    assert!(matches!(
        validate_official_stack_package(&inventory, &package),
        Err(ExtensionContractError::UnknownReference(_))
    ));

    let mut package = sample_official_stack();
    package.components[1].id = package.components[0].id.clone();
    assert!(matches!(
        validate_official_stack_package(&inventory, &package),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut package = sample_official_stack();
    package.profiles[0].component_ids.clear();
    assert!(matches!(
        validate_official_stack_package(&inventory, &package),
        Err(ExtensionContractError::MissingField(
            "official_stack.profiles.component_ids"
        ))
    ));

    let mut package = sample_official_stack();
    package.profiles[1].id = package.profiles[0].id.clone();
    assert!(matches!(
        validate_official_stack_package(&inventory, &package),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut package = sample_official_stack();
    package.profiles[0]
        .component_ids
        .push("chio.sqlite-receipt-store".to_string());
    assert!(matches!(
        validate_official_stack_package(&inventory, &package),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut package = sample_official_stack();
    package.profiles[0].component_ids = vec!["chio.unknown-component".to_string()];
    assert!(matches!(
        validate_official_stack_package(&inventory, &package),
        Err(ExtensionContractError::UnknownReference(_))
    ));

    let mut package = sample_official_stack();
    package.profiles[0]
        .component_ids
        .push("chio.remote-receipt-store".to_string());
    assert!(matches!(
        validate_official_stack_package(&inventory, &package),
        Err(ExtensionContractError::InvalidProfile(_))
    ));

    let mut inventory = sample_inventory();
    inventory.extension_points[0]
        .official_component_ids
        .push("chio.unknown-component".to_string());
    assert!(matches!(
        validate_official_stack_package(&inventory, &sample_official_stack()),
        Err(ExtensionContractError::UnknownReference(_))
    ));
}

#[test]
fn manifest_validation_rejects_remaining_shape_and_runtime_guardrails() {
    let mut manifest = sample_manifest();
    manifest.schema = "chio.extension-manifest.v9".to_string();
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::UnsupportedSchema(_))
    ));

    let mut manifest = sample_manifest();
    manifest.extension_id.clear();
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::MissingField(
            "extension_manifest.extension_id"
        ))
    ));

    let mut manifest = sample_manifest();
    manifest.capabilities.clear();
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::MissingField(
            "extension_manifest.capabilities"
        ))
    ));

    let mut manifest = sample_manifest();
    manifest.supported_profiles.clear();
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::MissingField(
            "extension_manifest.supported_profiles"
        ))
    ));

    let mut manifest = sample_manifest();
    manifest.capabilities.push("receipt_append".to_string());
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut manifest = sample_manifest();
    manifest
        .supported_profiles
        .push("shared_control_plane".to_string());
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut manifest = sample_manifest();
    manifest.compatibility.supported_component_ids.clear();
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::MissingField(
            "extension_manifest.compatibility.supported_component_ids"
        ))
    ));

    let mut manifest = sample_manifest();
    manifest.compatibility.supported_contract_schemas.clear();
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::MissingField(
            "extension_manifest.compatibility.supported_contract_schemas"
        ))
    ));

    let mut manifest = sample_manifest();
    manifest
        .compatibility
        .supported_component_ids
        .push("chio.remote-receipt-store".to_string());
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut manifest = sample_manifest();
    manifest
        .compatibility
        .supported_contract_schemas
        .push("chio.receipt.v1".to_string());
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut manifest = sample_manifest();
    manifest.compatibility.supported_contract_schemas = vec![
        "chio.receipt.v1".to_string(),
        "chio.checkpoint.v1".to_string(),
    ];
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::InvalidGuardrail(_))
    ));

    let mut manifest = sample_manifest();
    manifest
        .runtime
        .allowed_privileges
        .push(ExtensionPrivilege::FilesystemRead);
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut manifest = sample_manifest();
    manifest.runtime.allows_truth_mutation = true;
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::InvalidGuardrail(_))
    ));

    let mut manifest = sample_manifest();
    manifest.runtime.allows_trust_widening = true;
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::InvalidGuardrail(_))
    ));

    let mut manifest = sample_manifest();
    manifest.runtime.evidence_mode = ExtensionEvidenceMode::ImportOnly;
    manifest.runtime.requires_signer_verification = true;
    manifest.runtime.requires_freshness_check = true;
    manifest.runtime.requires_local_policy_activation = true;
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::InvalidGuardrail(_))
    ));

    let mut manifest = sample_manifest();
    manifest.runtime.evidence_mode = ExtensionEvidenceMode::ImportOnly;
    manifest.runtime.requires_subject_binding = true;
    manifest.runtime.requires_freshness_check = true;
    manifest.runtime.requires_local_policy_activation = true;
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::InvalidGuardrail(_))
    ));

    let mut manifest = sample_manifest();
    manifest.runtime.evidence_mode = ExtensionEvidenceMode::ImportOnly;
    manifest.runtime.requires_subject_binding = true;
    manifest.runtime.requires_signer_verification = true;
    manifest.runtime.requires_local_policy_activation = true;
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::InvalidGuardrail(_))
    ));

    let mut manifest = sample_manifest();
    manifest.runtime.evidence_mode = ExtensionEvidenceMode::ImportOnly;
    manifest.runtime.requires_subject_binding = true;
    manifest.runtime.requires_signer_verification = true;
    manifest.runtime.requires_freshness_check = true;
    assert!(matches!(
        validate_extension_manifest(&manifest),
        Err(ExtensionContractError::InvalidGuardrail(_))
    ));
}

#[test]
fn evidence_runtime_guardrail_helper_preserves_fail_closed_requirements() {
    let mut runtime = sample_manifest().runtime;
    runtime.evidence_mode = ExtensionEvidenceMode::None;
    assert!(validate_evidence_runtime_guardrails(&runtime).is_ok());

    runtime.evidence_mode = ExtensionEvidenceMode::ImportOnly;
    runtime.requires_subject_binding = true;
    runtime.requires_signer_verification = true;
    runtime.requires_freshness_check = true;
    runtime.requires_local_policy_activation = true;
    assert!(validate_evidence_runtime_guardrails(&runtime).is_ok());

    type RuntimeGuardrailMutation = fn(&mut ExtensionRuntimeEnvelope);
    let cases: [(&str, RuntimeGuardrailMutation); 4] = [
        ("subject binding", |runtime| {
            runtime.requires_subject_binding = false;
        }),
        ("signer verification", |runtime| {
            runtime.requires_signer_verification = false;
        }),
        ("freshness checks", |runtime| {
            runtime.requires_freshness_check = false;
        }),
        ("local policy activation", |runtime| {
            runtime.requires_local_policy_activation = false;
        }),
    ];
    for (expected_detail, remove_guardrail) in cases {
        let mut runtime = runtime.clone();
        remove_guardrail(&mut runtime);
        let Err(ExtensionContractError::InvalidGuardrail(message)) =
            validate_evidence_runtime_guardrails(&runtime)
        else {
            panic!("missing guardrail should fail closed: {expected_detail}");
        };
        assert!(message.contains(expected_detail));
    }
}

#[test]
fn rejects_policy_bypass_for_evidence_capable_extension() {
    let mut manifest = sample_manifest();
    manifest.extension_id = "sample.web3-oracle".to_string();
    manifest.extension_point_id = "chio.kernel.tool_server_connection".to_string();
    manifest.compatibility.supported_component_ids = vec!["chio.native-chio-service".to_string()];
    manifest.runtime.evidence_mode = ExtensionEvidenceMode::ImportAndDispatch;
    manifest.runtime.requires_subject_binding = true;
    manifest.runtime.requires_signer_verification = false;
    manifest.runtime.requires_freshness_check = true;
    manifest.runtime.requires_local_policy_activation = false;
    manifest.runtime.allowed_privileges = vec![
        ExtensionPrivilege::NetworkEgress,
        ExtensionPrivilege::OperatorSecrets,
    ];

    let report = negotiate_extension(&sample_inventory(), &sample_official_stack(), &manifest);
    assert_eq!(report.outcome, ExtensionNegotiationOutcome::Rejected);
    assert!(report.reasons.iter().any(|reason| {
        reason.code == ExtensionNegotiationRejectionCode::MalformedManifest
            || reason.code == ExtensionNegotiationRejectionCode::LocalPolicyActivationRequired
    }));
}

#[test]
fn negotiation_rejects_malformed_and_mismatched_inputs() {
    let mut inventory = sample_inventory();
    inventory.canonical_truth.clear();
    let mut package = sample_official_stack();
    package.components.clear();
    let mut manifest = sample_manifest();
    manifest.capabilities.clear();

    let report = negotiate_extension(&inventory, &package, &manifest);
    let codes = rejection_codes(&report);
    assert_eq!(report.outcome, ExtensionNegotiationOutcome::Rejected);
    assert!(codes.contains(&ExtensionNegotiationRejectionCode::MalformedInventory));
    assert!(codes.contains(&ExtensionNegotiationRejectionCode::MalformedOfficialStack));
    assert!(codes.contains(&ExtensionNegotiationRejectionCode::MalformedManifest));

    let mut manifest = sample_manifest();
    manifest.compatibility.official_stack_package_id = "chio.other-stack".to_string();
    manifest.compatibility.chio_contract_version = "9.9".to_string();
    let report = negotiate_extension(&sample_inventory(), &sample_official_stack(), &manifest);
    let codes = rejection_codes(&report);
    assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnsupportedOfficialStack));
    assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnsupportedChioContract));

    let mut manifest = sample_manifest();
    manifest.extension_point_id = "chio.kernel.unknown".to_string();
    let report = negotiate_extension(&sample_inventory(), &sample_official_stack(), &manifest);
    let codes = rejection_codes(&report);
    assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnknownExtensionPoint));
}

#[test]
fn negotiation_rejects_reserved_and_incompatible_extension_claims() {
    let mut inventory = sample_inventory();
    inventory.extension_points[0].custom_implementations_allowed = false;
    inventory.extension_points[0].stability = ExtensionStability::Internal;
    let report = negotiate_extension(&inventory, &sample_official_stack(), &sample_manifest());
    let codes = rejection_codes(&report);
    assert!(codes.contains(&ExtensionNegotiationRejectionCode::OfficialOnlyPoint));
    assert!(codes.contains(&ExtensionNegotiationRejectionCode::InternalOnlyPoint));

    let mut manifest = sample_manifest();
    manifest.supported_profiles = vec!["missing-profile".to_string()];
    manifest.compatibility.supported_component_ids = vec![
        "chio.native-chio-service".to_string(),
        "chio.unknown-component".to_string(),
    ];
    manifest.runtime.isolation = ExtensionIsolation::Subprocess;
    manifest.runtime.evidence_mode = ExtensionEvidenceMode::ImportOnly;
    manifest
        .runtime
        .allowed_privileges
        .push(ExtensionPrivilege::OperatorSecrets);
    manifest.runtime.requires_subject_binding = true;
    manifest.runtime.requires_signer_verification = true;
    manifest.runtime.requires_freshness_check = true;
    manifest.runtime.requires_local_policy_activation = true;

    let report = negotiate_extension(&sample_inventory(), &sample_official_stack(), &manifest);
    let codes = rejection_codes(&report);
    assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnsupportedProfile));
    assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnsupportedComponent));
    assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnsupportedIsolation));
    assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnsupportedEvidenceMode));
    assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnsupportedPrivilege));
}

#[test]
fn qualification_matrix_requires_rejection_codes_for_fail_closed_cases() {
    let matrix = ExtensionQualificationMatrix {
        schema: CHIO_EXTENSION_QUALIFICATION_MATRIX_SCHEMA.to_string(),
        official_stack_package_id: "chio.official-stack".to_string(),
        chio_contract_version: "2.0".to_string(),
        cases: vec![ExtensionQualificationCase {
            id: "missing-reasons".to_string(),
            name: "Broken case".to_string(),
            extension_point_id: "chio.kernel.receipt_store".to_string(),
            supported_component_id: "chio.sqlite-receipt-store".to_string(),
            candidate_extension_id: "sample.bad".to_string(),
            mode: QualificationMode::OfficialToCustom,
            expected_outcome: QualificationOutcome::FailClosed,
            observed_outcome: QualificationOutcome::FailClosed,
            rejection_codes: vec![],
            invariants: vec![QualificationInvariant::RejectsVersionMismatch],
        }],
    };
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::InvalidQualificationCase(_))
    ));
}

#[test]
fn qualification_matrix_rejects_remaining_shape_and_outcome_errors() {
    let mut matrix = sample_qualification_matrix();
    matrix.schema = "chio.extension-qualification-matrix.v9".to_string();
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::UnsupportedSchema(_))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.official_stack_package_id.clear();
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::MissingField(
            "qualification_matrix.official_stack_package_id"
        ))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.chio_contract_version.clear();
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::MissingField(
            "qualification_matrix.chio_contract_version"
        ))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases.clear();
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::MissingField(
            "qualification_matrix.cases"
        ))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases[0].id.clear();
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::MissingField(
            "qualification_matrix.case.id"
        ))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases[0].name.clear();
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::MissingField(
            "qualification_matrix.case.name"
        ))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases[0].extension_point_id.clear();
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::MissingField(
            "qualification_matrix.case.extension_point_id"
        ))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases[0].supported_component_id.clear();
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::MissingField(
            "qualification_matrix.case.supported_component_id"
        ))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases[0].candidate_extension_id.clear();
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::MissingField(
            "qualification_matrix.case.candidate_extension_id"
        ))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases.push(matrix.cases[0].clone());
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases[0].invariants.clear();
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::InvalidQualificationCase(_))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases[0]
        .invariants
        .push(QualificationInvariant::PreservesCanonicalTruth);
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases[0].expected_outcome = QualificationOutcome::FailClosed;
    matrix.cases[0].observed_outcome = QualificationOutcome::FailClosed;
    matrix.cases[0].rejection_codes = vec![
        ExtensionNegotiationRejectionCode::UnsupportedProfile,
        ExtensionNegotiationRejectionCode::UnsupportedProfile,
    ];
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::DuplicateValue(_))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases[0].rejection_codes = vec![ExtensionNegotiationRejectionCode::UnsupportedProfile];
    assert!(matches!(
        validate_qualification_matrix(&matrix),
        Err(ExtensionContractError::InvalidQualificationCase(_))
    ));
}

#[test]
fn reference_artifacts_parse_and_validate() {
    let inventory: ChioExtensionInventory = serde_json::from_str(include_str!(
        "../../../../../docs/standards/CHIO_EXTENSION_INVENTORY.json"
    ))
    .unwrap();
    let official_stack: OfficialStackPackage = serde_json::from_str(include_str!(
        "../../../../../docs/standards/CHIO_OFFICIAL_STACK.json"
    ))
    .unwrap();
    let manifest: ChioExtensionManifest = serde_json::from_str(include_str!(
        "../../../../../docs/standards/CHIO_EXTENSION_MANIFEST_EXAMPLE.json"
    ))
    .unwrap();
    let matrix: ExtensionQualificationMatrix = serde_json::from_str(include_str!(
        "../../../../../docs/standards/CHIO_EXTENSION_QUALIFICATION_MATRIX.json"
    ))
    .unwrap();

    validate_extension_inventory(&inventory).unwrap();
    validate_official_stack_package(&inventory, &official_stack).unwrap();
    validate_extension_manifest(&manifest).unwrap();
    validate_qualification_matrix(&matrix).unwrap();

    let report = negotiate_extension(&inventory, &official_stack, &manifest);
    assert_eq!(report.outcome, ExtensionNegotiationOutcome::Accepted);
}
