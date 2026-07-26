use super::{read_utf8_json_file, unix_now_ms, write_json_string, RelayTrustedIssuersDocument};
use crate::CliError;
use std::path::Path;

pub(crate) fn cmd_chio_pheromone_relay_directory_inspect(
    state: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let json = read_utf8_json_file(state, "Chio peer-directory state")?;
    let state = chio_pheromone_relay::peer_directory_state_from_json(&json).map_err(|error| {
        CliError::cli_other_error(format!("Chio peer-directory state: {error}"))
    })?;
    let inspection = chio_pheromone_relay::PeerDirectoryRotationReport {
        schema: chio_pheromone_relay::PHEROMONE_PEER_DIRECTORY_ROTATION_REPORT_SCHEMA.to_string(),
        accepted: state.active.is_some(),
        code: if state.active.is_some() {
            "accepted".to_string()
        } else {
            "peer_directory_state_invalid".to_string()
        },
        detail: if state.active.is_some() {
            "peer-directory state has an active directory".to_string()
        } else {
            "peer-directory state has no active directory".to_string()
        },
        local_kernel_id: state.local_kernel_id.clone(),
        generated_at_unix_ms: unix_now_ms(),
        previous_version: state.active.as_ref().map(|entry| entry.version),
        promoted_version: None,
        active_bundle_sha256: state
            .active
            .as_ref()
            .map(|entry| entry.bundle_sha256.clone()),
        candidate_bundle_sha256: state
            .candidate
            .as_ref()
            .map(|entry| entry.bundle_sha256.clone()),
        removed_peer_ids: state
            .active
            .as_ref()
            .map(|entry| entry.removed_peer_ids.clone())
            .unwrap_or_default(),
    };
    write_pretty_json(report, &inspection, "Chio peer-directory inspection")
}

pub(crate) fn cmd_chio_pheromone_relay_directory_promote(
    state: &Path,
    candidate: &Path,
    trusted_issuers: &Path,
    profile: chio_pheromone_relay::RelayProfile,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let now = now_unix_ms.unwrap_or_else(unix_now_ms);
    let candidate = load_relay_peer_directory_bundle(candidate)?;
    let mut state_document = load_or_create_peer_directory_state(state, &candidate, now)?;
    let trust = build_peer_directory_bundle_trust(trusted_issuers, now, profile)?;
    let result = chio_pheromone_relay::promote_peer_directory_candidate(
        &mut state_document,
        candidate,
        &trust,
        now,
    );
    let report_document = match result {
        Ok(report_document) => report_document,
        Err(error) => {
            let report_document =
                peer_directory_rotation_error_report(&state_document, now, &error);
            write_peer_directory_state(state, &state_document)?;
            write_pretty_json(report, &report_document, "Chio peer-directory rotation")?;
            return Err(CliError::cli_other_error(format!(
                "Chio peer-directory candidate promote: {error}"
            )));
        }
    };
    write_peer_directory_state(state, &state_document)?;
    write_pretty_json(report, &report_document, "Chio peer-directory rotation")
}

pub(crate) fn cmd_chio_pheromone_relay_directory_reject(
    state: &Path,
    candidate: &Path,
    reason: &str,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let now = now_unix_ms.unwrap_or_else(unix_now_ms);
    let candidate = load_relay_peer_directory_bundle(candidate)?;
    let mut state_document = load_or_create_peer_directory_state(state, &candidate, now)?;
    let report_document = chio_pheromone_relay::reject_peer_directory_candidate(
        &mut state_document,
        candidate,
        reason,
        now,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio peer-directory candidate reject: {error}"))
    })?;
    write_peer_directory_state(state, &state_document)?;
    write_pretty_json(report, &report_document, "Chio peer-directory rejection")
}

pub(crate) fn cmd_chio_pheromone_relay_supervisor_lint(
    profile: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let profile_json = read_utf8_json_file(profile, "Chio relay supervisor profile")?;
    let lint_report = match chio_pheromone_relay::relay_supervisor_profile_from_json(&profile_json)
    {
        Ok(profile_document) => {
            chio_pheromone_relay::lint_relay_supervisor_profile(&profile_document, unix_now_ms())
        }
        Err(error) => chio_pheromone_relay::RelayDrillReport {
            schema: chio_pheromone_relay::PHEROMONE_RELAY_DRILL_REPORT_SCHEMA.to_string(),
            accepted: false,
            code: error.code().to_string(),
            detail: error.to_string(),
            generated_at_unix_ms: unix_now_ms(),
            checks: vec![chio_pheromone_relay::RelayDrillCheck {
                code: error.code().to_string(),
                accepted: false,
                detail: "relay supervisor profile could not be parsed".to_string(),
            }],
        },
    };
    write_pretty_json(report, &lint_report, "Chio relay supervisor lint")
}

pub(crate) fn load_relay_peer_directory_from_paths(
    peer_directory: Option<&Path>,
    peer_directory_state: Option<&Path>,
    now_unix_ms: u64,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<&Path>,
    label: &str,
) -> Result<chio_pheromone_relay::PeerDirectory, CliError> {
    if let Some(state_path) = peer_directory_state {
        let state_json = read_utf8_json_file(state_path, "Chio peer-directory state")?;
        let state = chio_pheromone_relay::peer_directory_state_from_json(&state_json)
            .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")))?;
        let trusted_issuers = trusted_issuers.ok_or_else(|| {
            CliError::cli_other_error(format!(
                "{label}: signed peer-directory state requires trusted issuers"
            ))
        })?;
        let trust = build_peer_directory_bundle_trust(trusted_issuers, now_unix_ms, profile)?;
        return state
            .active_directory(&trust)
            .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")));
    }
    let peer_directory = peer_directory.ok_or_else(|| {
        CliError::cli_other_error(format!("{label}: peer directory or state is required"))
    })?;
    if profile == chio_pheromone_relay::RelayProfile::Production {
        return Err(CliError::cli_other_error(format!(
            "{label}: production profile requires peer-directory state"
        )));
    }
    let json = read_utf8_json_file(peer_directory, label)?;
    let trusted = load_optional_relay_trusted_issuers(trusted_issuers)?;
    parse_relay_peer_directory_json(&json, now_unix_ms, profile, trusted)
        .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")))
}

pub(crate) fn parse_relay_peer_directory_json(
    json: &str,
    now_unix_ms: u64,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<(Vec<chio_pheromone_relay::TrustedPeerDirectoryIssuer>, u64)>,
) -> Result<chio_pheromone_relay::PeerDirectory, chio_pheromone_relay::PheromoneRelayError> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|error| chio_pheromone_relay::PheromoneRelayError::Json(error.to_string()))?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if schema == chio_pheromone_relay::PHEROMONE_PEER_DIRECTORY_BUNDLE_SCHEMA {
        let bundle: chio_pheromone_relay::PeerDirectoryBundleDocument =
            serde_json::from_value(value)
                .map_err(chio_pheromone_relay::PheromoneRelayError::from)?;
        let (issuers, min_version) = trusted_issuers.ok_or_else(|| {
            chio_pheromone_relay::PheromoneRelayError::UnknownPeerDirectoryIssuer(
                "signed peer-directory bundle requires trusted issuers".to_string(),
            )
        })?;
        let trust = chio_pheromone_relay::PeerDirectoryBundleTrust {
            issuers,
            min_version,
            now_unix_ms,
            profile,
            limits: chio_pheromone_relay::RelayProfileLimits::production_defaults(),
        };
        return bundle.verify(&trust);
    }
    if profile == chio_pheromone_relay::RelayProfile::Production {
        return Err(
            chio_pheromone_relay::PheromoneRelayError::PeerDirectoryUnsigned(
                "production profile requires a signed peer-directory bundle".to_string(),
            ),
        );
    }
    chio_pheromone_relay::peer_directory_from_json_with_profile(
        json,
        now_unix_ms,
        profile,
        &chio_pheromone_relay::RelayProfileLimits::production_defaults(),
    )
}

pub(crate) fn load_optional_relay_trusted_issuers(
    path: Option<&Path>,
) -> Result<Option<(Vec<chio_pheromone_relay::TrustedPeerDirectoryIssuer>, u64)>, CliError> {
    path.map(load_relay_trusted_issuers).transpose()
}

pub(crate) fn load_relay_trusted_issuers(
    path: &Path,
) -> Result<(Vec<chio_pheromone_relay::TrustedPeerDirectoryIssuer>, u64), CliError> {
    let json = read_utf8_json_file(path, "Chio relay trusted issuers")?;
    let document: RelayTrustedIssuersDocument = serde_json::from_str(&json).map_err(|error| {
        CliError::cli_other_error(format!("Chio relay trusted issuers: {error}"))
    })?;
    let issuers = document
        .issuers
        .into_iter()
        .map(|issuer| chio_pheromone_relay::TrustedPeerDirectoryIssuer {
            issuer: issuer.issuer,
            key_id: issuer.key_id,
            public_key: issuer.public_key,
        })
        .collect();
    Ok((issuers, document.min_version.unwrap_or(0)))
}

pub(crate) fn build_peer_directory_bundle_trust(
    trusted_issuers: &Path,
    now_unix_ms: u64,
    profile: chio_pheromone_relay::RelayProfile,
) -> Result<chio_pheromone_relay::PeerDirectoryBundleTrust, CliError> {
    let (issuers, min_version) = load_relay_trusted_issuers(trusted_issuers)?;
    Ok(chio_pheromone_relay::PeerDirectoryBundleTrust {
        issuers,
        min_version,
        now_unix_ms,
        profile,
        limits: chio_pheromone_relay::RelayProfileLimits::production_defaults(),
    })
}

pub(crate) fn load_relay_peer_directory_bundle(
    path: &Path,
) -> Result<chio_pheromone_relay::PeerDirectoryBundleDocument, CliError> {
    let json = read_utf8_json_file(path, "Chio peer-directory bundle")?;
    serde_json::from_str(&json)
        .map_err(|error| CliError::cli_other_error(format!("Chio peer-directory bundle: {error}")))
}

pub(crate) fn load_or_create_peer_directory_state(
    path: &Path,
    candidate: &chio_pheromone_relay::PeerDirectoryBundleDocument,
    now_unix_ms: u64,
) -> Result<chio_pheromone_relay::PeerDirectoryStateDocument, CliError> {
    if path.exists() {
        let json = read_utf8_json_file(path, "Chio peer-directory state")?;
        chio_pheromone_relay::peer_directory_state_from_json(&json).map_err(|error| {
            CliError::cli_other_error(format!("Chio peer-directory state: {error}"))
        })
    } else {
        Ok(chio_pheromone_relay::PeerDirectoryStateDocument::new(
            &candidate.directory.local_kernel_id,
            now_unix_ms,
        ))
    }
}

pub(crate) fn write_peer_directory_state(
    path: &Path,
    state: &chio_pheromone_relay::PeerDirectoryStateDocument,
) -> Result<(), CliError> {
    write_pretty_json(path, state, "Chio peer-directory state")
}

pub(crate) fn peer_directory_rotation_error_report(
    state: &chio_pheromone_relay::PeerDirectoryStateDocument,
    now_unix_ms: u64,
    error: &chio_pheromone_relay::PheromoneRelayError,
) -> chio_pheromone_relay::PeerDirectoryRotationReport {
    let rejected = state.rejected.last();
    chio_pheromone_relay::PeerDirectoryRotationReport {
        schema: chio_pheromone_relay::PHEROMONE_PEER_DIRECTORY_ROTATION_REPORT_SCHEMA.to_string(),
        accepted: false,
        code: error.code().to_string(),
        detail: error.to_string(),
        local_kernel_id: state.local_kernel_id.clone(),
        generated_at_unix_ms: now_unix_ms,
        previous_version: state.active.as_ref().map(|entry| entry.version),
        promoted_version: None,
        active_bundle_sha256: state
            .active
            .as_ref()
            .map(|entry| entry.bundle_sha256.clone()),
        candidate_bundle_sha256: rejected.and_then(|entry| entry.bundle_sha256.clone()),
        removed_peer_ids: Vec::new(),
    }
}

pub(crate) fn write_pretty_json<T: serde::Serialize>(
    path: &Path,
    value: &T,
    label: &str,
) -> Result<(), CliError> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")))?;
    write_json_string(path, &format!("{json}\n"))
}
