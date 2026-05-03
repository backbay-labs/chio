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
struct ThreatModel {
    schema: String,
    threats: Vec<ThreatEntry>,
    transport_requirements: TransportRequirements,
}

#[derive(Debug, Deserialize)]
struct ThreatEntry {
    id: String,
    mitigations: Vec<MitigationEntry>,
    #[serde(rename = "residualRisk")]
    residual_risk: String,
}

#[derive(Debug, Deserialize)]
struct MitigationEntry {
    status: String,
    control: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransportRequirements {
    profiles: Vec<TransportProfile>,
    attestation_rule: String,
    failure_behavior: String,
}

#[derive(Debug, Deserialize)]
struct TransportProfile {
    surface: String,
    tls: String,
    mtls: String,
    dpop: String,
    #[serde(rename = "withoutTransportSecurity")]
    without_transport_security: String,
}

fn load_json<T: for<'de> Deserialize<'de>>(relative_path: &str) -> T {
    let contents =
        fs::read_to_string(repo_root().join(relative_path)).expect("artifact file exists");
    serde_json::from_str(&contents).expect("artifact parses")
}

#[test]
fn threat_model_register_lists_required_threats_with_mitigations() {
    let threat_model: ThreatModel = load_json("spec/security/chio-threat-model.v1.json");

    assert_eq!(threat_model.schema, "chio.threat-model.v1");

    let expected_threats = BTreeSet::from([
        "audience_confusion".to_string(),
        "capability_token_theft".to_string(),
        "agent_velocity_abuse".to_string(),
        "behavioral_sequence_attack".to_string(),
        "cumulative_data_exfiltration".to_string(),
        "delegation_chain_abuse".to_string(),
        "device_key_extraction".to_string(),
        "kernel_impersonation".to_string(),
        "mobile_attestation_replay".to_string(),
        "native_channel_replay".to_string(),
        "passkey_credential_theft".to_string(),
        "pii_phi_exposure".to_string(),
        "play_integrity_token_replay".to_string(),
        "pq_signature_downgrade".to_string(),
        "resource_exhaustion_dos".to_string(),
        "ssrf_via_http_substrate".to_string(),
        "tee_quote_forgery".to_string(),
        "tool_server_escape".to_string(),
        "wasm_guard_resource_exhaustion".to_string(),
        "weights_hash_spoof".to_string(),
    ]);

    let mut seen = BTreeSet::new();
    for threat in threat_model.threats {
        assert!(
            seen.insert(threat.id.clone()),
            "duplicate threat {}",
            threat.id
        );
        assert!(
            !threat.mitigations.is_empty(),
            "threat {} is missing mitigations",
            threat.id
        );
        assert!(
            !threat.residual_risk.trim().is_empty(),
            "threat {} is missing residual risk",
            threat.id
        );
        for mitigation in threat.mitigations {
            assert!(
                matches!(
                    mitigation.status.as_str(),
                    "existing" | "planned" | "implemented"
                ),
                "unexpected mitigation status {}",
                mitigation.status
            );
            assert!(
                !mitigation.control.trim().is_empty(),
                "empty mitigation control for threat {}",
                threat.id
            );
        }
    }

    assert_eq!(seen, expected_threats);
}

#[test]
fn threat_model_transport_requirements_cover_required_surfaces() {
    let threat_model: ThreatModel = load_json("spec/security/chio-threat-model.v1.json");

    let profiles = threat_model
        .transport_requirements
        .profiles
        .into_iter()
        .map(|profile| (profile.surface.clone(), profile))
        .collect::<std::collections::BTreeMap<_, _>>();

    let expected_surfaces = BTreeSet::from([
        "hosted_mcp_http".to_string(),
        "kernel_to_tool_transport".to_string(),
        "native_chio_direct".to_string(),
        "trust_control_http".to_string(),
    ]);
    let seen_surfaces = profiles.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(seen_surfaces, expected_surfaces);

    let native = profiles.get("native_chio_direct").expect("native profile");
    assert_eq!(native.tls, "required_on_cross_host_or_untrusted_networks");
    assert_eq!(
        native.dpop,
        "required_when_matched_grant_sets_dpop_required"
    );
    assert!(
        native
            .without_transport_security
            .contains("same_host_uds_or_loopback_dev"),
        "native profile must constrain plaintext transport to local-only posture"
    );

    let hosted = profiles.get("hosted_mcp_http").expect("hosted profile");
    assert_eq!(
        hosted.tls,
        "required_for_any_remote_or_non_loopback_deployment"
    );
    assert!(
        hosted
            .mtls
            .contains("active_sender_constrained_profile_binds_to_an_mtls_thumbprint"),
        "hosted profile must record when mTLS becomes mandatory"
    );
    assert!(
        hosted
            .dpop
            .contains("sender_constrained_profile_or_downstream_grant_requires_it"),
        "hosted profile must record when DPoP becomes mandatory"
    );

    let tool = profiles
        .get("kernel_to_tool_transport")
        .expect("kernel-to-tool profile");
    assert_eq!(
        tool.mtls,
        "required_for_cross_host_or_cross_process_tcp_transport"
    );

    assert_eq!(
        threat_model.transport_requirements.attestation_rule,
        "attestation_binding_never_authorizes_alone_it_must_pair_with_dpop_or_mtls_continuity"
    );
    assert_eq!(
        threat_model.transport_requirements.failure_behavior,
        "missing_required_transport_security_must_deny_or_downgrade_to_explicit_local_dev_only_posture"
    );
}
