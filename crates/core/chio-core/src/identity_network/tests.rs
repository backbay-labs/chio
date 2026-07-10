use super::validators::{
    contains_non_chio_method, ensure_refs_present, ensure_required_transports, validate_hex_digest,
    validate_https_url, validate_identity_artifact_reference,
};
use super::*;

fn expect_contract_err<T>(
    result: Result<T, IdentityNetworkContractError>,
    context: &str,
) -> IdentityNetworkContractError {
    match result {
        Ok(_) => panic!("{context}: unexpected success"),
        Err(error) => error,
    }
}

fn hex(seed: char) -> String {
    std::iter::repeat_n(seed, 64).collect()
}

fn sample_reference(
    kind: IdentityArtifactKind,
    schema: &str,
    artifact_id: &str,
    operator_id: &str,
    seed: char,
) -> IdentityArtifactReference {
    IdentityArtifactReference {
        kind,
        schema: schema.to_string(),
        artifact_id: artifact_id.to_string(),
        operator_id: operator_id.to_string(),
        sha256: hex(seed),
        uri: Some(format!("https://example.com/{artifact_id}")),
    }
}

fn sample_profile() -> PublicIdentityProfileArtifact {
    PublicIdentityProfileArtifact {
        schema: CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA.to_string(),
        profile_id: "pip-1".to_string(),
        issued_at: 1_710_000_000,
        supported_subject_methods: vec![
            IdentityDidMethod::DidChio,
            IdentityDidMethod::DidWeb,
            IdentityDidMethod::DidKey,
        ],
        supported_issuer_methods: vec![
            IdentityDidMethod::DidChio,
            IdentityDidMethod::DidWeb,
            IdentityDidMethod::DidJwk,
        ],
        supported_credential_families: vec![
            IdentityCredentialFamily::ChioAgentPassportJson,
            IdentityCredentialFamily::DcSdJwt,
            IdentityCredentialFamily::JwtVcJson,
        ],
        supported_proof_families: vec![
            IdentityProofFamily::Ed25519Signature2020,
            IdentityProofFamily::DcSdJwt,
            IdentityProofFamily::JwtVcJson,
        ],
        supported_transports: vec![
            WalletTransportMode::Oid4vpSameDevice,
            WalletTransportMode::Oid4vpCrossDevice,
            WalletTransportMode::Oid4vpRelay,
        ],
        basis_refs: vec![
            sample_reference(
                IdentityArtifactKind::PortableTrustProfile,
                "chio.portable-trust-profile.v1",
                "ptp-1",
                "chio",
                'a',
            ),
            sample_reference(
                IdentityArtifactKind::Oid4vciIssuerMetadata,
                "openid-credential-issuer-metadata",
                "oid4vci-1",
                "issuer-operator-1",
                'b',
            ),
            sample_reference(
                IdentityArtifactKind::Oid4vpVerifierMetadata,
                "chio.oid4vp-verifier-metadata.v1",
                "oid4vp-1",
                "verifier-operator-1",
                'c',
            ),
        ],
        binding_policy: IdentityBindingPolicy::default(),
        note: Some("bounded broader identity support".to_string()),
    }
}

fn sample_directory_entry() -> PublicWalletDirectoryEntryArtifact {
    PublicWalletDirectoryEntryArtifact {
        schema: CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_SCHEMA.to_string(),
        entry_id: "wde-1".to_string(),
        issued_at: 1_710_000_010,
        directory_operator_id: "wallet-operator-1".to_string(),
        wallet_id: "wallet.example".to_string(),
        supported_subject_methods: vec![
            IdentityDidMethod::DidChio,
            IdentityDidMethod::DidWeb,
            IdentityDidMethod::DidKey,
        ],
        supported_issuer_methods: vec![
            IdentityDidMethod::DidChio,
            IdentityDidMethod::DidWeb,
            IdentityDidMethod::DidJwk,
        ],
        supported_credential_families: vec![
            IdentityCredentialFamily::DcSdJwt,
            IdentityCredentialFamily::JwtVcJson,
        ],
        supported_proof_families: vec![
            IdentityProofFamily::DcSdJwt,
            IdentityProofFamily::JwtVcJson,
        ],
        discovery_ref: sample_reference(
            IdentityArtifactKind::PublicVerifierDiscovery,
            "chio.public-verifier-discovery.v1",
            "pvd-1",
            "verifier-operator-1",
            'd',
        ),
        profile_ref: sample_reference(
            IdentityArtifactKind::PublicIdentityProfile,
            CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA,
            "pip-1",
            "chio",
            'e',
        ),
        metadata_url: "https://wallet.example/.well-known/openid-credential-wallet".to_string(),
        request_uri_prefix: "https://wallet.example/wallet-exchanges/".to_string(),
        lookup_guardrails: WalletDirectoryLookupGuardrails::default(),
        note: Some("verifier-scoped public wallet routing".to_string()),
    }
}

fn sample_routing_manifest() -> PublicWalletRoutingManifestArtifact {
    PublicWalletRoutingManifestArtifact {
        schema: CHIO_PUBLIC_WALLET_ROUTING_MANIFEST_SCHEMA.to_string(),
        route_id: "wrm-1".to_string(),
        issued_at: 1_710_000_020,
        directory_entry_ref: sample_reference(
            IdentityArtifactKind::PublicWalletDirectoryEntry,
            CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_SCHEMA,
            "wde-1",
            "wallet-operator-1",
            'f',
        ),
        verifier_id: "https://verifier.example.com".to_string(),
        response_uri_prefix: "https://verifier.example.com/v1/public/passport/wallet-exchanges/"
            .to_string(),
        relay_url: "https://wallet.example/relay".to_string(),
        transport_modes: vec![
            WalletTransportMode::Oid4vpSameDevice,
            WalletTransportMode::Oid4vpCrossDevice,
            WalletTransportMode::Oid4vpRelay,
        ],
        requires_signed_request_object: true,
        requires_replay_anchors: true,
        routing_guardrails: WalletRoutingGuardrails::default(),
        note: Some("bounded public wallet routing".to_string()),
    }
}

fn sample_matrix() -> IdentityInteropQualificationMatrix {
    IdentityInteropQualificationMatrix {
        schema: CHIO_IDENTITY_INTEROP_QUALIFICATION_MATRIX_SCHEMA.to_string(),
        profile_ref: sample_reference(
            IdentityArtifactKind::PublicIdentityProfile,
            CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA,
            "pip-1",
            "chio",
            'a',
        ),
        directory_entry_ref: sample_reference(
            IdentityArtifactKind::PublicWalletDirectoryEntry,
            CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_SCHEMA,
            "wde-1",
            "wallet-operator-1",
            'b',
        ),
        routing_manifest_ref: sample_reference(
            IdentityArtifactKind::PublicWalletRoutingManifest,
            CHIO_PUBLIC_WALLET_ROUTING_MANIFEST_SCHEMA,
            "wrm-1",
            "wallet-operator-1",
            'c',
        ),
        cases: vec![
            IdentityInteropQualificationCase {
                id: "method-support".to_string(),
                name: "Unsupported DID methods fail closed".to_string(),
                requirement_ids: vec!["IDMAX-01".to_string()],
                scenario: IdentityInteropScenarioKind::UnsupportedDidMethod,
                expected_outcome: IdentityQualificationOutcome::FailClosed,
                observed_outcome: IdentityQualificationOutcome::FailClosed,
                notes: vec!["Unsupported method families are rejected explicitly".to_string()],
            },
            IdentityInteropQualificationCase {
                id: "directory-poisoning".to_string(),
                name: "Directory poisoning fails closed".to_string(),
                requirement_ids: vec!["IDMAX-02".to_string()],
                scenario: IdentityInteropScenarioKind::DirectoryPoisoning,
                expected_outcome: IdentityQualificationOutcome::FailClosed,
                observed_outcome: IdentityQualificationOutcome::FailClosed,
                notes: vec!["Directory entries stay verifier-bound and non-ambient".to_string()],
            },
            IdentityInteropQualificationCase {
                id: "multi-wallet".to_string(),
                name: "Multi-wallet selection remains replay safe".to_string(),
                requirement_ids: vec!["IDMAX-03".to_string()],
                scenario: IdentityInteropScenarioKind::MultiWalletSelection,
                expected_outcome: IdentityQualificationOutcome::Pass,
                observed_outcome: IdentityQualificationOutcome::Pass,
                notes: vec![
                    "Supported multi-wallet routing completes inside explicit guardrails"
                        .to_string(),
                ],
            },
            IdentityInteropQualificationCase {
                id: "cross-operator-boundary".to_string(),
                name: "Cross-operator issuer mismatch fails closed".to_string(),
                requirement_ids: vec!["IDMAX-04".to_string()],
                scenario: IdentityInteropScenarioKind::CrossOperatorIssuerMismatch,
                expected_outcome: IdentityQualificationOutcome::FailClosed,
                observed_outcome: IdentityQualificationOutcome::FailClosed,
                notes: vec!["Issuer and admission boundaries remain explicit".to_string()],
            },
            IdentityInteropQualificationCase {
                id: "release-closure".to_string(),
                name: "Release boundary stays honest".to_string(),
                requirement_ids: vec!["IDMAX-05".to_string()],
                scenario: IdentityInteropScenarioKind::ReleaseBoundaryClosure,
                expected_outcome: IdentityQualificationOutcome::Pass,
                observed_outcome: IdentityQualificationOutcome::Pass,
                notes: vec!["Final public claim remains bounded and specific".to_string()],
            },
        ],
    }
}

#[test]
fn profile_validation_rejects_remaining_schema_reference_and_policy_errors() {
    let mut profile = sample_profile();
    profile.schema = "chio.public-identity-profile.v9".to_string();
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::UnsupportedSchema(_))
    ));

    let mut profile = sample_profile();
    profile.profile_id.clear();
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::MissingField("profile_id"))
    ));

    let mut profile = sample_profile();
    profile
        .supported_subject_methods
        .push(IdentityDidMethod::DidChio);
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::DuplicateValue(_))
    ));

    let mut profile = sample_profile();
    profile
        .supported_credential_families
        .push(IdentityCredentialFamily::DcSdJwt);
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::DuplicateValue(_))
    ));

    let mut profile = sample_profile();
    profile
        .supported_proof_families
        .push(IdentityProofFamily::DcSdJwt);
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::DuplicateValue(_))
    ));

    let mut profile = sample_profile();
    profile
        .supported_transports
        .push(WalletTransportMode::Oid4vpRelay);
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::DuplicateValue(_))
    ));

    let mut profile = sample_profile();
    profile.basis_refs.clear();
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::MissingField("basis_refs"))
    ));

    let mut profile = sample_profile();
    profile.binding_policy.requires_chio_issuer_provenance = false;
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::InvalidProfile(_))
    ));

    let mut profile = sample_profile();
    profile
        .binding_policy
        .requires_same_subject_across_credentials = false;
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::InvalidProfile(_))
    ));

    let mut profile = sample_profile();
    profile.binding_policy.manual_subject_rebinding_required = false;
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::InvalidProfile(_))
    ));

    let mut profile = sample_profile();
    profile.binding_policy.unsupported_mappings_fail_closed = false;
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::InvalidProfile(_))
    ));

    let mut profile = sample_profile();
    profile.supported_subject_methods = vec![IdentityDidMethod::DidWeb];
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::InvalidProfile(_))
    ));

    let mut profile = sample_profile();
    profile.supported_credential_families = vec![IdentityCredentialFamily::DcSdJwt];
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::InvalidProfile(_))
    ));

    let mut profile = sample_profile();
    profile.supported_credential_families = vec![IdentityCredentialFamily::ChioAgentPassportJson];
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::InvalidProfile(_))
    ));

    let mut profile = sample_profile();
    profile.basis_refs.remove(0);
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::InvalidProfile(_))
    ));

    let mut profile = sample_profile();
    profile.basis_refs[0].sha256 = "abcd".to_string();
    assert!(matches!(
        validate_public_identity_profile(&profile),
        Err(IdentityNetworkContractError::InvalidReference(_))
    ));
}

#[test]
fn profile_requires_chio_anchor_and_broader_support() {
    let mut profile = sample_profile();
    profile.binding_policy.requires_chio_subject_provenance = false;
    let error = expect_contract_err(
        validate_public_identity_profile(&profile),
        "missing chio subject provenance",
    );
    assert!(matches!(
        error,
        IdentityNetworkContractError::InvalidProfile(_)
    ));

    let mut profile = sample_profile();
    profile.supported_subject_methods = vec![IdentityDidMethod::DidChio];
    profile.supported_issuer_methods = vec![IdentityDidMethod::DidChio];
    let error = expect_contract_err(
        validate_public_identity_profile(&profile),
        "missing broader method",
    );
    assert!(matches!(
        error,
        IdentityNetworkContractError::InvalidProfile(_)
    ));
}

#[test]
fn wallet_directory_requires_verifier_guardrails() {
    let mut entry = sample_directory_entry();
    entry.lookup_guardrails.requires_explicit_verifier_binding = false;
    let error = expect_contract_err(
        validate_public_wallet_directory_entry(&entry),
        "missing verifier binding guardrail",
    );
    assert!(matches!(
        error,
        IdentityNetworkContractError::InvalidDirectoryEntry(_)
    ));
}

#[test]
fn wallet_directory_validation_rejects_remaining_reference_url_and_guardrail_errors() {
    let mut entry = sample_directory_entry();
    entry.schema = "chio.public-wallet-directory-entry.v9".to_string();
    assert!(matches!(
        validate_public_wallet_directory_entry(&entry),
        Err(IdentityNetworkContractError::UnsupportedSchema(_))
    ));

    let mut entry = sample_directory_entry();
    entry.entry_id.clear();
    assert!(matches!(
        validate_public_wallet_directory_entry(&entry),
        Err(IdentityNetworkContractError::MissingField("entry_id"))
    ));

    let mut entry = sample_directory_entry();
    entry
        .supported_subject_methods
        .push(IdentityDidMethod::DidChio);
    assert!(matches!(
        validate_public_wallet_directory_entry(&entry),
        Err(IdentityNetworkContractError::DuplicateValue(_))
    ));

    let mut entry = sample_directory_entry();
    entry.discovery_ref.kind = IdentityArtifactKind::PublicIdentityProfile;
    assert!(matches!(
        validate_public_wallet_directory_entry(&entry),
        Err(IdentityNetworkContractError::InvalidDirectoryEntry(_))
    ));

    let mut entry = sample_directory_entry();
    entry.profile_ref.kind = IdentityArtifactKind::PortableTrustProfile;
    assert!(matches!(
        validate_public_wallet_directory_entry(&entry),
        Err(IdentityNetworkContractError::InvalidDirectoryEntry(_))
    ));

    let mut entry = sample_directory_entry();
    entry.metadata_url = "http://wallet.example/metadata".to_string();
    assert!(matches!(
        validate_public_wallet_directory_entry(&entry),
        Err(IdentityNetworkContractError::InvalidReference(_))
    ));

    let mut entry = sample_directory_entry();
    entry.request_uri_prefix = "https://".to_string();
    assert!(matches!(
        validate_public_wallet_directory_entry(&entry),
        Err(IdentityNetworkContractError::InvalidReference(_))
    ));

    let mut entry = sample_directory_entry();
    entry
        .lookup_guardrails
        .requires_manual_subject_binding_review = false;
    assert!(matches!(
        validate_public_wallet_directory_entry(&entry),
        Err(IdentityNetworkContractError::InvalidDirectoryEntry(_))
    ));

    let mut entry = sample_directory_entry();
    entry.lookup_guardrails.reject_ambient_directory_trust = false;
    assert!(matches!(
        validate_public_wallet_directory_entry(&entry),
        Err(IdentityNetworkContractError::InvalidDirectoryEntry(_))
    ));

    let mut entry = sample_directory_entry();
    entry.lookup_guardrails.fail_closed_on_unknown_wallet_family = false;
    assert!(matches!(
        validate_public_wallet_directory_entry(&entry),
        Err(IdentityNetworkContractError::InvalidDirectoryEntry(_))
    ));

    let mut entry = sample_directory_entry();
    entry.supported_subject_methods = vec![IdentityDidMethod::DidChio];
    assert!(matches!(
        validate_public_wallet_directory_entry(&entry),
        Err(IdentityNetworkContractError::InvalidDirectoryEntry(_))
    ));

    let mut entry = sample_directory_entry();
    entry.supported_credential_families = vec![IdentityCredentialFamily::ChioAgentPassportJson];
    assert!(matches!(
        validate_public_wallet_directory_entry(&entry),
        Err(IdentityNetworkContractError::InvalidDirectoryEntry(_))
    ));
}

#[test]
fn routing_manifest_requires_all_transports() {
    let mut manifest = sample_routing_manifest();
    manifest.transport_modes = vec![
        WalletTransportMode::Oid4vpSameDevice,
        WalletTransportMode::Oid4vpCrossDevice,
    ];
    let error = expect_contract_err(
        validate_public_wallet_routing_manifest(&manifest),
        "missing relay transport",
    );
    assert!(matches!(
        error,
        IdentityNetworkContractError::DuplicateValue(_)
    ));
}

#[test]
fn routing_manifest_validation_rejects_remaining_guardrails_and_reference_errors() {
    let mut manifest = sample_routing_manifest();
    manifest.schema = "chio.public-wallet-routing-manifest.v9".to_string();
    assert!(matches!(
        validate_public_wallet_routing_manifest(&manifest),
        Err(IdentityNetworkContractError::UnsupportedSchema(_))
    ));

    let mut manifest = sample_routing_manifest();
    manifest.route_id.clear();
    assert!(matches!(
        validate_public_wallet_routing_manifest(&manifest),
        Err(IdentityNetworkContractError::MissingField("route_id"))
    ));

    let mut manifest = sample_routing_manifest();
    manifest.directory_entry_ref.kind = IdentityArtifactKind::PublicIdentityProfile;
    assert!(matches!(
        validate_public_wallet_routing_manifest(&manifest),
        Err(IdentityNetworkContractError::InvalidRouting(_))
    ));

    let mut manifest = sample_routing_manifest();
    manifest.verifier_id = "not-a-url".to_string();
    assert!(matches!(
        validate_public_wallet_routing_manifest(&manifest),
        Err(IdentityNetworkContractError::InvalidReference(_))
    ));

    let mut manifest = sample_routing_manifest();
    manifest.response_uri_prefix = "http://verifier.example.com/response".to_string();
    assert!(matches!(
        validate_public_wallet_routing_manifest(&manifest),
        Err(IdentityNetworkContractError::InvalidReference(_))
    ));

    let mut manifest = sample_routing_manifest();
    manifest.relay_url = "https://".to_string();
    assert!(matches!(
        validate_public_wallet_routing_manifest(&manifest),
        Err(IdentityNetworkContractError::InvalidReference(_))
    ));

    let mut manifest = sample_routing_manifest();
    manifest.routing_guardrails.requires_replay_safe_exchange = false;
    assert!(matches!(
        validate_public_wallet_routing_manifest(&manifest),
        Err(IdentityNetworkContractError::InvalidRouting(_))
    ));

    let mut manifest = sample_routing_manifest();
    manifest.routing_guardrails.fail_closed_on_subject_mismatch = false;
    assert!(matches!(
        validate_public_wallet_routing_manifest(&manifest),
        Err(IdentityNetworkContractError::InvalidRouting(_))
    ));

    let mut manifest = sample_routing_manifest();
    manifest
        .routing_guardrails
        .fail_closed_on_cross_operator_issuer_mismatch = false;
    assert!(matches!(
        validate_public_wallet_routing_manifest(&manifest),
        Err(IdentityNetworkContractError::InvalidRouting(_))
    ));

    let mut manifest = sample_routing_manifest();
    manifest.requires_signed_request_object = false;
    assert!(matches!(
        validate_public_wallet_routing_manifest(&manifest),
        Err(IdentityNetworkContractError::InvalidRouting(_))
    ));

    let mut manifest = sample_routing_manifest();
    manifest.requires_replay_anchors = false;
    assert!(matches!(
        validate_public_wallet_routing_manifest(&manifest),
        Err(IdentityNetworkContractError::InvalidRouting(_))
    ));
}

#[test]
fn qualification_matrix_requires_requirement_coverage() {
    let mut matrix = sample_matrix();
    matrix.cases.pop();
    let _ = expect_contract_err(
        validate_identity_interop_qualification_matrix(&matrix),
        "missing requirement coverage",
    );
}

#[test]
fn qualification_matrix_rejects_remaining_reference_and_case_errors() {
    let mut matrix = sample_matrix();
    matrix.schema = "chio.identity-interop-qualification-matrix.v9".to_string();
    assert!(matches!(
        validate_identity_interop_qualification_matrix(&matrix),
        Err(IdentityNetworkContractError::UnsupportedSchema(_))
    ));

    let mut matrix = sample_matrix();
    matrix.profile_ref.kind = IdentityArtifactKind::PublicWalletDirectoryEntry;
    assert!(matches!(
        validate_identity_interop_qualification_matrix(&matrix),
        Err(IdentityNetworkContractError::InvalidQualificationCase(_))
    ));

    let mut matrix = sample_matrix();
    matrix.directory_entry_ref.kind = IdentityArtifactKind::PortableTrustProfile;
    assert!(matches!(
        validate_identity_interop_qualification_matrix(&matrix),
        Err(IdentityNetworkContractError::InvalidQualificationCase(_))
    ));

    let mut matrix = sample_matrix();
    matrix.routing_manifest_ref.kind = IdentityArtifactKind::PublicIdentityProfile;
    assert!(matches!(
        validate_identity_interop_qualification_matrix(&matrix),
        Err(IdentityNetworkContractError::InvalidQualificationCase(_))
    ));

    let mut matrix = sample_matrix();
    matrix.cases.clear();
    assert!(matches!(
        validate_identity_interop_qualification_matrix(&matrix),
        Err(IdentityNetworkContractError::MissingField("cases"))
    ));

    let mut matrix = sample_matrix();
    matrix.cases[0].id.clear();
    assert!(matches!(
        validate_identity_interop_qualification_matrix(&matrix),
        Err(IdentityNetworkContractError::MissingField("case.id"))
    ));

    let mut matrix = sample_matrix();
    matrix.cases[0].name.clear();
    assert!(matches!(
        validate_identity_interop_qualification_matrix(&matrix),
        Err(IdentityNetworkContractError::MissingField("case.name"))
    ));

    let mut matrix = sample_matrix();
    matrix.cases[0].observed_outcome = IdentityQualificationOutcome::Pass;
    assert!(matches!(
        validate_identity_interop_qualification_matrix(&matrix),
        Err(IdentityNetworkContractError::InvalidQualificationCase(_))
    ));

    let mut matrix = sample_matrix();
    matrix.cases[0].requirement_ids.push("IDMAX-01".to_string());
    assert!(matches!(
        validate_identity_interop_qualification_matrix(&matrix),
        Err(IdentityNetworkContractError::DuplicateValue(_))
    ));

    let mut matrix = sample_matrix();
    matrix.cases[0].notes.push(" ".to_string());
    assert!(matches!(
        validate_identity_interop_qualification_matrix(&matrix),
        Err(IdentityNetworkContractError::MissingField("case.notes"))
    ));

    let mut matrix = sample_matrix();
    matrix.cases.push(matrix.cases[0].clone());
    assert!(matches!(
        validate_identity_interop_qualification_matrix(&matrix),
        Err(IdentityNetworkContractError::DuplicateValue(_))
    ));
}

#[test]
fn identity_helper_validators_cover_remaining_reference_edges() {
    let mut reference = sample_reference(
        IdentityArtifactKind::PublicIdentityProfile,
        CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA,
        "pip-1",
        "chio",
        'j',
    );
    reference.schema.clear();
    assert!(matches!(
        validate_identity_artifact_reference(&reference),
        Err(IdentityNetworkContractError::MissingField(
            "reference.schema"
        ))
    ));

    let mut reference = sample_reference(
        IdentityArtifactKind::PublicIdentityProfile,
        CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA,
        "pip-1",
        "chio",
        'k',
    );
    reference.artifact_id.clear();
    assert!(matches!(
        validate_identity_artifact_reference(&reference),
        Err(IdentityNetworkContractError::MissingField(
            "reference.artifact_id"
        ))
    ));

    let mut reference = sample_reference(
        IdentityArtifactKind::PublicIdentityProfile,
        CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA,
        "pip-1",
        "chio",
        'l',
    );
    reference.operator_id.clear();
    assert!(matches!(
        validate_identity_artifact_reference(&reference),
        Err(IdentityNetworkContractError::MissingField(
            "reference.operator_id"
        ))
    ));

    assert!(matches!(
        validate_https_url("mailto:test@example.com", "reference.uri"),
        Err(IdentityNetworkContractError::InvalidReference(_))
    ));
    assert!(matches!(
        validate_https_url("https://", "reference.uri"),
        Err(IdentityNetworkContractError::InvalidReference(_))
    ));
    assert!(matches!(
        validate_hex_digest("zzzz", "reference.sha256"),
        Err(IdentityNetworkContractError::InvalidReference(_))
    ));
    assert!(!contains_non_chio_method(&[IdentityDidMethod::DidChio]));
    assert!(contains_non_chio_method(&[
        IdentityDidMethod::DidChio,
        IdentityDidMethod::DidWeb,
    ]));

    assert!(matches!(
        ensure_required_transports(
            &[
                WalletTransportMode::Oid4vpSameDevice,
                WalletTransportMode::Oid4vpSameDevice,
                WalletTransportMode::Oid4vpRelay,
            ],
            "transport_modes",
        ),
        Err(IdentityNetworkContractError::DuplicateValue(_))
    ));
    assert!(matches!(
        ensure_refs_present(&[], "basis_refs"),
        Err(IdentityNetworkContractError::MissingField("basis_refs"))
    ));

    let duplicate_refs = vec![
        sample_reference(
            IdentityArtifactKind::PublicIdentityProfile,
            CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA,
            "pip-1",
            "chio",
            'm',
        ),
        sample_reference(
            IdentityArtifactKind::PublicWalletDirectoryEntry,
            CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_SCHEMA,
            "pip-1",
            "chio",
            'n',
        ),
    ];
    assert!(matches!(
        ensure_refs_present(&duplicate_refs, "basis_refs"),
        Err(IdentityNetworkContractError::DuplicateValue(_))
    ));
}

#[test]
fn reference_artifacts_parse_and_validate() {
    let profile: PublicIdentityProfileArtifact = serde_json::from_str(include_str!(
        "../../../../../docs/standards/CHIO_PUBLIC_IDENTITY_PROFILE.json"
    ))
    .unwrap_or_else(|error| panic!("parse public identity profile fixture: {error}"));
    validate_public_identity_profile(&profile)
        .unwrap_or_else(|error| panic!("validate public identity profile fixture: {error:?}"));

    let entry: PublicWalletDirectoryEntryArtifact = serde_json::from_str(include_str!(
        "../../../../../docs/standards/CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_EXAMPLE.json"
    ))
    .unwrap_or_else(|error| panic!("parse wallet directory entry fixture: {error}"));
    validate_public_wallet_directory_entry(&entry)
        .unwrap_or_else(|error| panic!("validate wallet directory entry fixture: {error:?}"));

    let routing: PublicWalletRoutingManifestArtifact = serde_json::from_str(include_str!(
        "../../../../../docs/standards/CHIO_PUBLIC_WALLET_ROUTING_EXAMPLE.json"
    ))
    .unwrap_or_else(|error| panic!("parse wallet routing manifest fixture: {error}"));
    validate_public_wallet_routing_manifest(&routing)
        .unwrap_or_else(|error| panic!("validate wallet routing manifest fixture: {error:?}"));

    let matrix: IdentityInteropQualificationMatrix = serde_json::from_str(include_str!(
        "../../../../../docs/standards/CHIO_PUBLIC_IDENTITY_QUALIFICATION_MATRIX.json"
    ))
    .unwrap_or_else(|error| panic!("parse identity qualification matrix fixture: {error}"));
    validate_identity_interop_qualification_matrix(&matrix).unwrap_or_else(|error| {
        panic!("validate identity qualification matrix fixture: {error:?}")
    });
}
