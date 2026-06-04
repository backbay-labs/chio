use chio_core::web3::{
    verify_web3_identity_binding, SignedWeb3IdentityBinding, Web3KeyBindingPurpose,
};
use serde::{Deserialize, Serialize};

use crate::{
    bundle::{verify_proof_bundle, AnchorLaneKind, AnchorProofBundle, AnchorVerificationReport},
    evm::parse_validated_evm_anchor_target,
    ops::{AnchorEmergencyMode, AnchorLaneHealthStatus, AnchorRuntimeReport},
    AnchorError, AnchorServiceConfig,
};

pub const CHIO_ANCHOR_DISCOVERY_SCHEMA: &str = "chio.anchor-discovery.v1";
pub const CHIO_ANCHOR_SERVICE_TYPE: &str = "ChioAnchorService";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorDiscoveryChain {
    pub chain_id: String,
    pub contract_address: String,
    pub operator_address: String,
    pub publisher_address: String,
    pub requires_delegate_authorization: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorDiscoveryServiceEndpoint {
    pub chains: Vec<AnchorDiscoveryChain>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitcoin_anchor_method: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ots_calendars: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solana_cluster: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_policy: Option<AnchorDiscoveryPublicationPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain_runtime: Vec<AnchorDiscoveryChainRuntimeState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_freshness: Option<AnchorDiscoveryFreshnessState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorDiscoveryService {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub service_endpoint: AnchorDiscoveryServiceEndpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootPublicationOwnership {
    pub chain_id: String,
    pub root_owner_address: String,
    pub publisher_address: String,
    pub delegate_publication_allowed: bool,
    pub ownership_rule: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnchorDiscoveryFreshnessStatus {
    Current,
    Lagging,
    Stale,
    Paused,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorDiscoveryPublicationPolicy {
    pub primary_lane: AnchorLaneKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secondary_lanes: Vec<AnchorLaneKind>,
    pub requires_trust_anchor_binding: bool,
    pub requires_witness_or_immutable_anchor_reference: bool,
    pub delegate_publication_allowed: bool,
    pub emergency_mode: AnchorEmergencyMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorDiscoveryFreshnessState {
    pub status: AnchorDiscoveryFreshnessStatus,
    pub checked_at: u64,
    pub freshness_window_secs: u64,
    pub latest_checkpoint_seq: u64,
    pub indexed_checkpoint_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_published_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_age_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorDiscoveryChainRuntimeState {
    pub chain_id: String,
    pub lane: AnchorLaneKind,
    pub status: AnchorDiscoveryFreshnessStatus,
    pub checked_at: u64,
    pub freshness_window_secs: u64,
    pub latest_checkpoint_seq: u64,
    pub indexed_checkpoint_seq: u64,
    pub reorg_depth: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_published_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_age_secs: Option<u64>,
    pub has_active_conflict: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incident_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorDiscoveryArtifact {
    pub schema: String,
    pub chio_identity: String,
    pub operator_binding: SignedWeb3IdentityBinding,
    pub service: AnchorDiscoveryService,
    pub root_publication_ownership: Vec<RootPublicationOwnership>,
}

pub fn build_anchor_discovery_artifact(
    config: &AnchorServiceConfig,
    binding: &SignedWeb3IdentityBinding,
) -> Result<AnchorDiscoveryArtifact, AnchorError> {
    verify_web3_identity_binding(binding)
        .map_err(|error| AnchorError::InvalidBinding(error.to_string()))?;
    if !binding
        .certificate
        .purpose
        .contains(&Web3KeyBindingPurpose::Anchor)
    {
        return Err(AnchorError::InvalidBinding(
            "binding certificate does not include anchor purpose".to_string(),
        ));
    }
    let validated_targets = config
        .evm_targets
        .iter()
        .map(parse_validated_evm_anchor_target)
        .collect::<Result<Vec<_>, _>>()?;
    validate_binding_covers_targets(config, binding)?;

    let chains: Vec<AnchorDiscoveryChain> = config
        .evm_targets
        .iter()
        .zip(validated_targets.iter())
        .map(|(target, validated)| AnchorDiscoveryChain {
            chain_id: target.chain_id.clone(),
            contract_address: target.contract_address.clone(),
            operator_address: target.operator_address.clone(),
            publisher_address: target.publisher_address.clone(),
            requires_delegate_authorization: validated.publisher != validated.operator,
        })
        .collect();
    let root_publication_ownership = config
        .evm_targets
        .iter()
        .zip(validated_targets.iter())
        .map(|(target, validated)| {
            let delegate_publication_allowed = validated.publisher != validated.operator;
            RootPublicationOwnership {
                chain_id: target.chain_id.clone(),
                root_owner_address: target.operator_address.clone(),
                publisher_address: target.publisher_address.clone(),
                delegate_publication_allowed,
                ownership_rule: if delegate_publication_allowed {
                    "operator-owned-root delegate-published-via-root-registry-authorization"
                        .to_string()
                } else {
                    "operator-published".to_string()
                },
            }
        })
        .collect();

    Ok(AnchorDiscoveryArtifact {
        schema: CHIO_ANCHOR_DISCOVERY_SCHEMA.to_string(),
        chio_identity: binding.certificate.chio_identity.clone(),
        operator_binding: binding.clone(),
        service: AnchorDiscoveryService {
            id: format!("{}#anchor", binding.certificate.chio_identity),
            service_type: CHIO_ANCHOR_SERVICE_TYPE.to_string(),
            service_endpoint: AnchorDiscoveryServiceEndpoint {
                chains,
                bitcoin_anchor_method: (!config.ots_calendars.is_empty())
                    .then(|| "opentimestamps".to_string()),
                ots_calendars: config.ots_calendars.clone(),
                solana_cluster: config.solana_cluster.clone(),
                publication_policy: None,
                chain_runtime: Vec::new(),
                current_freshness: None,
            },
        },
        root_publication_ownership,
    })
}

pub fn verify_proof_bundle_with_discovery(
    bundle: &AnchorProofBundle,
    discovery: &AnchorDiscoveryArtifact,
) -> Result<AnchorVerificationReport, AnchorError> {
    let report = verify_proof_bundle(bundle)?;
    let bundle_binding = &bundle.primary_proof.key_binding_certificate.certificate;
    let discovery_binding = &discovery.operator_binding.certificate;
    if bundle_binding.chio_identity != discovery_binding.chio_identity
        || bundle_binding.chio_public_key != discovery_binding.chio_public_key
        || bundle_binding.settlement_address != discovery_binding.settlement_address
    {
        return Err(AnchorError::Verification(
            "proof bundle binding does not match the discovery operator binding".to_string(),
        ));
    }

    let policy = discovery
        .service
        .service_endpoint
        .publication_policy
        .as_ref()
        .ok_or_else(|| {
            AnchorError::Verification(
                "discovery artifact is missing publication policy".to_string(),
            )
        })?;
    let freshness = discovery
        .service
        .service_endpoint
        .current_freshness
        .as_ref()
        .ok_or_else(|| {
            AnchorError::Verification(
                "discovery artifact is missing current freshness state".to_string(),
            )
        })?;

    if matches!(
        freshness.status,
        AnchorDiscoveryFreshnessStatus::Paused | AnchorDiscoveryFreshnessStatus::Stale
    ) {
        return Err(AnchorError::Verification(format!(
            "discovery freshness state {} does not permit bundle verification",
            freshness_status_label(freshness.status)
        )));
    }

    if policy.requires_witness_or_immutable_anchor_reference && policy.secondary_lanes.is_empty() {
        return Err(AnchorError::Verification(
            "discovery policy requires witness or immutable anchor support but declares no secondary lanes".to_string(),
        ));
    }

    let actual_lanes = normalized_lane_labels(&bundle.secondary_lanes);
    let expected_lanes = normalized_lane_labels(&policy.secondary_lanes);
    if actual_lanes != expected_lanes {
        return Err(AnchorError::Verification(format!(
            "proof bundle secondary lanes {:?} do not match discovery policy {:?}",
            actual_lanes, expected_lanes
        )));
    }

    Ok(report)
}

fn validate_binding_covers_targets(
    config: &AnchorServiceConfig,
    binding: &SignedWeb3IdentityBinding,
) -> Result<(), AnchorError> {
    for target in &config.evm_targets {
        if !binding
            .certificate
            .chain_scope
            .iter()
            .any(|chain| chain == &target.chain_id)
        {
            return Err(AnchorError::InvalidBinding(format!(
                "binding certificate does not cover {}",
                target.chain_id
            )));
        }
        if binding.certificate.settlement_address != target.operator_address {
            return Err(AnchorError::InvalidBinding(format!(
                "binding settlement address {} does not match operator address {} for {}",
                binding.certificate.settlement_address, target.operator_address, target.chain_id
            )));
        }
    }
    Ok(())
}

pub fn build_anchor_discovery_artifact_with_runtime(
    config: &AnchorServiceConfig,
    binding: &SignedWeb3IdentityBinding,
    runtime_report: &AnchorRuntimeReport,
    freshness_window_secs: u64,
) -> Result<AnchorDiscoveryArtifact, AnchorError> {
    if freshness_window_secs == 0 {
        return Err(AnchorError::InvalidInput(
            "anchor discovery freshness window must be non-zero".to_string(),
        ));
    }

    let mut artifact = build_anchor_discovery_artifact(config, binding)?;
    let chain_runtime = build_chain_runtime_states(config, runtime_report, freshness_window_secs);
    let delegate_publication_allowed = artifact
        .root_publication_ownership
        .iter()
        .any(|ownership| ownership.delegate_publication_allowed);
    artifact.service.service_endpoint.publication_policy = Some(build_publication_policy(
        config,
        runtime_report,
        delegate_publication_allowed,
    ));
    artifact.service.service_endpoint.chain_runtime = chain_runtime.clone();
    artifact.service.service_endpoint.current_freshness = Some(aggregate_current_freshness(
        runtime_report,
        freshness_window_secs,
        &chain_runtime,
    ));
    Ok(artifact)
}

fn build_publication_policy(
    config: &AnchorServiceConfig,
    runtime_report: &AnchorRuntimeReport,
    delegate_publication_allowed: bool,
) -> AnchorDiscoveryPublicationPolicy {
    let mut secondary_lanes = Vec::new();
    if !config.ots_calendars.is_empty() {
        secondary_lanes.push(AnchorLaneKind::BitcoinOts);
    }
    if config.solana_cluster.is_some() {
        secondary_lanes.push(AnchorLaneKind::SolanaMemo);
    }
    AnchorDiscoveryPublicationPolicy {
        primary_lane: AnchorLaneKind::EvmPrimary,
        secondary_lanes,
        requires_trust_anchor_binding: true,
        requires_witness_or_immutable_anchor_reference: true,
        delegate_publication_allowed,
        emergency_mode: runtime_report.controls.mode,
    }
}

fn build_chain_runtime_states(
    config: &AnchorServiceConfig,
    runtime_report: &AnchorRuntimeReport,
    freshness_window_secs: u64,
) -> Vec<AnchorDiscoveryChainRuntimeState> {
    config
        .evm_targets
        .iter()
        .map(|target| {
            let lane = select_primary_lane_for_chain(config, runtime_report, &target.chain_id);
            build_chain_runtime_state(
                runtime_report,
                freshness_window_secs,
                &target.chain_id,
                AnchorLaneKind::EvmPrimary,
                lane,
            )
        })
        .collect()
}

fn select_primary_lane_for_chain<'a>(
    config: &AnchorServiceConfig,
    runtime_report: &'a AnchorRuntimeReport,
    chain_id: &str,
) -> Option<&'a crate::AnchorLaneRuntimeStatus> {
    runtime_report
        .lanes
        .iter()
        .find(|lane| {
            lane.lane == AnchorLaneKind::EvmPrimary && lane.chain_id.as_deref() == Some(chain_id)
        })
        .or_else(|| {
            (config.evm_targets.len() == 1)
                .then(|| {
                    runtime_report
                        .lanes
                        .iter()
                        .find(|lane| lane.lane == AnchorLaneKind::EvmPrimary)
                })
                .flatten()
        })
}

fn build_chain_runtime_state(
    runtime_report: &AnchorRuntimeReport,
    freshness_window_secs: u64,
    chain_id: &str,
    lane_kind: AnchorLaneKind,
    lane: Option<&crate::AnchorLaneRuntimeStatus>,
) -> AnchorDiscoveryChainRuntimeState {
    let status = classify_discovery_status(
        runtime_report,
        freshness_window_secs,
        lane_kind,
        Some(chain_id),
        lane,
    );
    let incidents = runtime_report.lane_incidents(lane_kind, Some(chain_id));
    let incident_codes = incidents
        .iter()
        .map(|incident| incident.code.clone())
        .collect::<Vec<_>>();
    let note = lane
        .and_then(|lane| lane.note.clone())
        .or_else(|| incidents.first().map(|incident| incident.message.clone()));

    AnchorDiscoveryChainRuntimeState {
        chain_id: chain_id.to_string(),
        lane: lane_kind,
        status,
        checked_at: runtime_report.generated_at,
        freshness_window_secs,
        latest_checkpoint_seq: lane.map(|lane| lane.latest_checkpoint_seq).unwrap_or(0),
        indexed_checkpoint_seq: lane.map(|lane| lane.indexed_checkpoint_seq).unwrap_or(0),
        reorg_depth: lane.map(|lane| lane.reorg_depth).unwrap_or(0),
        last_published_at: lane.and_then(|lane| lane.last_published_at),
        publication_age_secs: lane
            .and_then(|lane| lane.last_published_at)
            .and_then(|published_at| runtime_report.generated_at.checked_sub(published_at)),
        has_active_conflict: runtime_report.lane_has_active_conflict(lane_kind, Some(chain_id)),
        incident_codes,
        note,
    }
}

fn aggregate_current_freshness(
    runtime_report: &AnchorRuntimeReport,
    freshness_window_secs: u64,
    chain_runtime: &[AnchorDiscoveryChainRuntimeState],
) -> AnchorDiscoveryFreshnessState {
    if let Some(worst) = chain_runtime
        .iter()
        .max_by_key(|state| freshness_status_rank(state.status))
    {
        return AnchorDiscoveryFreshnessState {
            status: worst.status,
            checked_at: worst.checked_at,
            freshness_window_secs: worst.freshness_window_secs,
            latest_checkpoint_seq: worst.latest_checkpoint_seq,
            indexed_checkpoint_seq: worst.indexed_checkpoint_seq,
            last_published_at: worst.last_published_at,
            publication_age_secs: worst.publication_age_secs,
            note: worst.note.clone(),
        };
    }
    build_current_freshness_state(runtime_report, freshness_window_secs)
}

fn build_current_freshness_state(
    runtime_report: &AnchorRuntimeReport,
    freshness_window_secs: u64,
) -> AnchorDiscoveryFreshnessState {
    let lane = runtime_report
        .lanes
        .iter()
        .find(|lane| lane.lane == AnchorLaneKind::EvmPrimary);

    let status = classify_discovery_status(
        runtime_report,
        freshness_window_secs,
        AnchorLaneKind::EvmPrimary,
        lane.and_then(|lane| lane.chain_id.as_deref()),
        lane,
    );

    AnchorDiscoveryFreshnessState {
        status,
        checked_at: runtime_report.generated_at,
        freshness_window_secs,
        latest_checkpoint_seq: lane.map(|lane| lane.latest_checkpoint_seq).unwrap_or(0),
        indexed_checkpoint_seq: lane.map(|lane| lane.indexed_checkpoint_seq).unwrap_or(0),
        last_published_at: lane.and_then(|lane| lane.last_published_at),
        publication_age_secs: lane
            .and_then(|lane| lane.last_published_at)
            .and_then(|published_at| runtime_report.generated_at.checked_sub(published_at)),
        note: lane.and_then(|lane| lane.note.clone()),
    }
}

fn classify_discovery_status(
    runtime_report: &AnchorRuntimeReport,
    freshness_window_secs: u64,
    lane_kind: AnchorLaneKind,
    chain_id: Option<&str>,
    lane: Option<&crate::AnchorLaneRuntimeStatus>,
) -> AnchorDiscoveryFreshnessStatus {
    let last_published_at = lane.and_then(|lane| lane.last_published_at);
    let publication_age_secs = last_published_at
        .and_then(|published_at| runtime_report.generated_at.checked_sub(published_at));
    let publication_timestamp_in_future = last_published_at
        .map(|published_at| published_at > runtime_report.generated_at)
        .unwrap_or(false);
    let latest_checkpoint_seq = lane.map(|lane| lane.latest_checkpoint_seq).unwrap_or(0);
    let indexed_checkpoint_seq = lane.map(|lane| lane.indexed_checkpoint_seq).unwrap_or(0);
    let lane_status = lane.map(|lane| lane.status);
    let has_active_conflict = runtime_report.lane_has_active_conflict(lane_kind, chain_id);
    let lane_is_stale = has_active_conflict
        || matches!(
            lane_status,
            Some(AnchorLaneHealthStatus::Failed | AnchorLaneHealthStatus::Drifted)
        )
        || publication_timestamp_in_future
        || publication_age_secs
            .map(|age| age > freshness_window_secs)
            .unwrap_or_else(|| lane.is_some() && last_published_at.is_none());
    let lane_is_paused = matches!(lane_status, Some(AnchorLaneHealthStatus::Paused));
    let lane_is_lagging = matches!(
        lane_status,
        Some(AnchorLaneHealthStatus::Lagging | AnchorLaneHealthStatus::Recovering)
    ) || indexed_checkpoint_seq < latest_checkpoint_seq;

    match runtime_report.controls.mode {
        AnchorEmergencyMode::Normal => match lane {
            None => AnchorDiscoveryFreshnessStatus::Unknown,
            Some(_) if lane_is_stale => AnchorDiscoveryFreshnessStatus::Stale,
            Some(_) if lane_is_paused => AnchorDiscoveryFreshnessStatus::Paused,
            Some(_) if lane_is_lagging => AnchorDiscoveryFreshnessStatus::Lagging,
            Some(_) => AnchorDiscoveryFreshnessStatus::Current,
        },
        AnchorEmergencyMode::PublishPaused
        | AnchorEmergencyMode::ProofImportOnly
        | AnchorEmergencyMode::RecoveryOnly
        | AnchorEmergencyMode::Halted => match lane {
            Some(_) if lane_is_stale => AnchorDiscoveryFreshnessStatus::Stale,
            _ => AnchorDiscoveryFreshnessStatus::Paused,
        },
    }
}

fn freshness_status_rank(status: AnchorDiscoveryFreshnessStatus) -> u8 {
    match status {
        AnchorDiscoveryFreshnessStatus::Current => 0,
        AnchorDiscoveryFreshnessStatus::Unknown => 1,
        AnchorDiscoveryFreshnessStatus::Lagging => 2,
        AnchorDiscoveryFreshnessStatus::Paused => 3,
        AnchorDiscoveryFreshnessStatus::Stale => 4,
    }
}

fn normalized_lane_labels(lanes: &[AnchorLaneKind]) -> Vec<&'static str> {
    let mut labels: Vec<_> = lanes.iter().map(|lane| lane_label(*lane)).collect();
    labels.sort_unstable();
    labels.dedup();
    labels
}

fn lane_label(lane: AnchorLaneKind) -> &'static str {
    match lane {
        AnchorLaneKind::EvmPrimary => "evm_primary",
        AnchorLaneKind::BitcoinOts => "bitcoin_ots",
        AnchorLaneKind::SolanaMemo => "solana_memo",
    }
}

fn freshness_status_label(status: AnchorDiscoveryFreshnessStatus) -> &'static str {
    match status {
        AnchorDiscoveryFreshnessStatus::Current => "current",
        AnchorDiscoveryFreshnessStatus::Lagging => "lagging",
        AnchorDiscoveryFreshnessStatus::Stale => "stale",
        AnchorDiscoveryFreshnessStatus::Paused => "paused",
        AnchorDiscoveryFreshnessStatus::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use chio_core::crypto::Keypair;
    use chio_core::web3::{
        verify_web3_identity_binding, SignedWeb3IdentityBinding, Web3IdentityBindingCertificate,
        Web3KeyBindingPurpose, CHIO_KEY_BINDING_CERTIFICATE_SCHEMA,
    };

    use super::{build_anchor_discovery_artifact, build_anchor_discovery_artifact_with_runtime};
    use crate::{
        AnchorAlertSeverity, AnchorDiscoveryFreshnessStatus, AnchorEmergencyControls,
        AnchorEmergencyMode, AnchorIncidentAlert, AnchorLaneHealthStatus, AnchorLaneKind,
        AnchorLaneRuntimeStatus, AnchorRuntimeReport, AnchorServiceConfig, EvmAnchorTarget,
        CHIO_ANCHOR_RUNTIME_REPORT_SCHEMA,
    };

    use chio_test_support::prelude::*;

    fn sample_binding_with_keypair() -> (Keypair, SignedWeb3IdentityBinding) {
        let keypair = Keypair::generate();
        let certificate = Web3IdentityBindingCertificate {
            schema: CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
            chio_identity: "did:chio:anchor-test".to_string(),
            chio_public_key: keypair.public_key(),
            chain_scope: vec!["eip155:8453".to_string()],
            purpose: vec![Web3KeyBindingPurpose::Anchor],
            settlement_address: "0x1111111111111111111111111111111111111111".to_string(),
            issued_at: 1_775_100_000,
            expires_at: 1_775_200_000,
            nonce: "anchor-discovery-1".to_string(),
        };
        let binding = SignedWeb3IdentityBinding {
            signature: keypair.sign_canonical(&certificate).test_unwrap().0,
            certificate,
        };
        (keypair, binding)
    }

    fn sample_binding() -> SignedWeb3IdentityBinding {
        sample_binding_with_keypair().1
    }

    fn sample_config() -> AnchorServiceConfig {
        AnchorServiceConfig {
            evm_targets: vec![EvmAnchorTarget {
                chain_id: "eip155:8453".to_string(),
                rpc_url: "https://rpc.example".to_string(),
                contract_address: "0x1000000000000000000000000000000000000001".to_string(),
                operator_address: "0x1111111111111111111111111111111111111111".to_string(),
                publisher_address: "0x2000000000000000000000000000000000000002".to_string(),
            }],
            ots_calendars: Vec::new(),
            solana_cluster: None,
        }
    }

    fn sample_runtime_report(
        mode: AnchorEmergencyMode,
        status: AnchorLaneHealthStatus,
        last_published_at: Option<u64>,
    ) -> AnchorRuntimeReport {
        AnchorRuntimeReport {
            schema: CHIO_ANCHOR_RUNTIME_REPORT_SCHEMA.to_string(),
            generated_at: 1_775_137_800,
            controls: AnchorEmergencyControls {
                mode,
                changed_at: 1_775_137_700,
                reason: None,
            },
            lanes: vec![AnchorLaneRuntimeStatus {
                lane: AnchorLaneKind::EvmPrimary,
                chain_id: Some("eip155:8453".to_string()),
                status,
                latest_checkpoint_seq: 42,
                indexed_checkpoint_seq: 42,
                reorg_depth: 0,
                last_published_at,
                next_action: None,
                note: None,
            }],
            indexers: Vec::new(),
            incidents: Vec::new(),
        }
    }

    #[test]
    fn discovery_artifact_rejects_invalid_binding_signature() {
        let mut binding = sample_binding();
        binding.certificate.chio_identity = "did:chio:tampered".to_string();
        let verification_error = verify_web3_identity_binding(&binding).test_unwrap_err();
        assert!(verification_error
            .to_string()
            .contains("identity binding signature verification failed"));

        let error = build_anchor_discovery_artifact(&sample_config(), &binding).test_unwrap_err();

        assert!(error
            .to_string()
            .contains("identity binding signature verification failed"));
    }

    #[test]
    fn discovery_artifact_rejects_binding_without_target_chain_scope() {
        let (keypair, mut binding) = sample_binding_with_keypair();
        binding.certificate.chain_scope = vec!["eip155:42161".to_string()];
        binding.signature = keypair.sign_canonical(&binding.certificate).test_unwrap().0;

        let error = build_anchor_discovery_artifact(&sample_config(), &binding).test_unwrap_err();

        assert!(error.to_string().contains("does not cover eip155:8453"));
    }

    #[test]
    fn discovery_artifact_rejects_binding_with_operator_address_mismatch() {
        let (keypair, mut binding) = sample_binding_with_keypair();
        binding.certificate.settlement_address =
            "0x2222222222222222222222222222222222222222".to_string();
        binding.signature = keypair.sign_canonical(&binding.certificate).test_unwrap().0;

        let error = build_anchor_discovery_artifact(&sample_config(), &binding).test_unwrap_err();

        assert!(error
            .to_string()
            .contains("does not match operator address"));
    }

    #[test]
    fn discovery_artifact_rejects_malformed_evm_target_metadata() {
        let binding = sample_binding();
        let mut config = sample_config();
        config.evm_targets[0].contract_address = "0xabc".to_string();

        let error = build_anchor_discovery_artifact(&config, &binding)
            .test_expect_err("malformed discovery target should fail closed");

        assert!(matches!(error, crate::AnchorError::InvalidInput(_)));
        assert!(error.to_string().contains("contract address"));
    }

    #[test]
    fn discovery_runtime_reports_paused_when_primary_lane_is_paused() {
        let binding = sample_binding();
        let artifact = build_anchor_discovery_artifact_with_runtime(
            &AnchorServiceConfig {
                ots_calendars: vec!["https://calendar.example".to_string()],
                ..sample_config()
            },
            &binding,
            &sample_runtime_report(
                AnchorEmergencyMode::Normal,
                AnchorLaneHealthStatus::Paused,
                Some(1_775_137_760),
            ),
            120,
        )
        .test_unwrap();

        assert_eq!(
            artifact
                .service
                .service_endpoint
                .current_freshness
                .test_expect("freshness state")
                .status,
            AnchorDiscoveryFreshnessStatus::Paused
        );
        assert_eq!(artifact.service.service_endpoint.chain_runtime.len(), 1);
        assert_eq!(
            artifact.service.service_endpoint.chain_runtime[0].status,
            AnchorDiscoveryFreshnessStatus::Paused
        );
    }

    #[test]
    fn discovery_runtime_reports_stale_when_publication_timestamp_is_in_future() {
        let binding = sample_binding();
        let artifact = build_anchor_discovery_artifact_with_runtime(
            &AnchorServiceConfig {
                ots_calendars: vec!["https://calendar.example".to_string()],
                ..sample_config()
            },
            &binding,
            &sample_runtime_report(
                AnchorEmergencyMode::Normal,
                AnchorLaneHealthStatus::Healthy,
                Some(1_775_137_900),
            ),
            120,
        )
        .test_unwrap();

        let freshness = artifact
            .service
            .service_endpoint
            .current_freshness
            .test_expect("freshness state");
        assert_eq!(freshness.status, AnchorDiscoveryFreshnessStatus::Stale);
        assert_eq!(freshness.publication_age_secs, None);
    }

    #[test]
    fn discovery_runtime_projects_conflict_incident_into_chain_runtime() {
        let binding = sample_binding();
        let mut report = sample_runtime_report(
            AnchorEmergencyMode::Normal,
            AnchorLaneHealthStatus::Healthy,
            Some(1_775_137_760),
        );
        report.incidents.push(AnchorIncidentAlert {
            code: "checkpoint_equivocation_detected".to_string(),
            severity: AnchorAlertSeverity::Critical,
            lane: AnchorLaneKind::EvmPrimary,
            chain_id: Some("eip155:8453".to_string()),
            checkpoint_seq: Some(42),
            observed_at: 1_775_137_790,
            message: "conflicting checkpoint publication observed".to_string(),
        });

        let artifact = build_anchor_discovery_artifact_with_runtime(
            &AnchorServiceConfig {
                ots_calendars: vec!["https://calendar.example".to_string()],
                ..sample_config()
            },
            &binding,
            &report,
            120,
        )
        .test_unwrap();

        let chain_runtime = artifact
            .service
            .service_endpoint
            .chain_runtime
            .first()
            .test_expect("chain runtime");
        assert_eq!(chain_runtime.chain_id, "eip155:8453");
        assert_eq!(chain_runtime.status, AnchorDiscoveryFreshnessStatus::Stale);
        assert!(chain_runtime.has_active_conflict);
        assert_eq!(
            chain_runtime.incident_codes,
            vec!["checkpoint_equivocation_detected".to_string()]
        );
        assert_eq!(
            artifact
                .service
                .service_endpoint
                .current_freshness
                .test_expect("freshness state")
                .status,
            AnchorDiscoveryFreshnessStatus::Stale
        );
    }
}
