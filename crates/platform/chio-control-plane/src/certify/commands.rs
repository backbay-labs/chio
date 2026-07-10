use std::fs;
use std::io::Write;
use std::path::Path;

use chio_conformance::{load_results_from_dir, load_scenarios_from_dir};

use crate::enterprise_federation::CertificationDiscoveryNetwork;
use crate::{load_or_create_authority_keypair, CliError};

use super::artifact::{build_certification_body, sign_artifact};
use super::helpers::{
    ensure_parent_dir, load_signed_certification_check, require_certification_discovery_path,
    require_existing_dir,
};
use super::network;
use super::types::{
    CertificationConsumptionRequest, CertificationDisputeRequest, CertificationDisputeState,
    CertificationMarketplaceSearchQuery, CertificationMarketplaceTransparencyQuery,
    CertificationPublicSearchQuery, CertificationRegistry, CertificationRegistryEntry,
    CertificationRegistryListResponse, CertificationRegistryState, CertificationResolutionState,
    CertificationTransparencyQuery,
};
use super::verify::certification_artifact_id;

pub fn cmd_certify_verify(input: &Path, json_output: bool) -> Result<(), CliError> {
    let artifact = load_signed_certification_check(input)?;
    let artifact_id = certification_artifact_id(&artifact)?;
    if json_output {
        let message = serde_json::json!({
            "input": input.display().to_string(),
            "artifactId": artifact_id,
            "toolServerId": artifact.body.target.tool_server_id,
            "toolServerName": artifact.body.target.tool_server_name,
            "verdict": artifact.body.verdict.label(),
            "checkedAt": artifact.body.checked_at,
            "signerPublicKey": artifact.signer_public_key,
            "verified": true,
        });
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{message}")?;
    } else {
        println!("certification verified");
        println!("artifact_id:      {artifact_id}");
        println!("tool_server_id:   {}", artifact.body.target.tool_server_id);
        println!("verdict:          {}", artifact.body.verdict.label());
        println!("checked_at:       {}", artifact.body.checked_at);
    }
    Ok(())
}

pub fn cmd_certify_check(
    scenarios_dir: &Path,
    results_dir: &Path,
    output: &Path,
    tool_server_id: &str,
    tool_server_name: Option<&str>,
    report_output: Option<&Path>,
    criteria_profile: &str,
    signing_seed_file: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    require_existing_dir(scenarios_dir, "scenarios")?;
    require_existing_dir(results_dir, "results")?;

    let scenarios = load_scenarios_from_dir(scenarios_dir)?;
    let results = load_results_from_dir(results_dir)?;
    let (body, report_bytes) = build_certification_body(
        criteria_profile,
        tool_server_id,
        tool_server_name,
        scenarios_dir,
        results_dir,
        report_output,
        scenarios,
        results,
    )?;

    if let Some(report_output) = report_output {
        ensure_parent_dir(report_output)?;
        fs::write(report_output, &report_bytes)?;
    }

    let signing_key = load_or_create_authority_keypair(signing_seed_file)?;
    let artifact = sign_artifact(body, &signing_key)?;
    ensure_parent_dir(output)?;
    fs::write(output, serde_json::to_vec_pretty(&artifact)?)?;

    if json_output {
        let message = serde_json::json!({
            "output": output.display().to_string(),
            "verdict": artifact.body.verdict.label(),
            "criteriaProfile": artifact.body.criteria_profile,
            "summary": artifact.body.summary,
            "signerPublicKey": artifact.signer_public_key,
        });
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{message}")?;
    } else {
        println!(
            "wrote certification artifact to {} ({}, {} result(s))",
            output.display(),
            artifact.body.verdict.label(),
            artifact.body.summary.result_count
        );
        if let Some(report_output) = report_output {
            println!("wrote certification report to {}", report_output.display());
        }
    }

    Ok(())
}

pub fn cmd_certify_registry_publish_local(
    input: &Path,
    registry_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let artifact = load_signed_certification_check(input)?;
    let mut registry = CertificationRegistry::load(registry_path)?;
    let entry = registry.publish(artifact)?;
    registry.save(registry_path)?;
    emit_registry_entry("published certification artifact", &entry, json_output)
}

pub fn cmd_certify_registry_list_local(
    registry_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let registry = CertificationRegistry::load(registry_path)?;
    let response = CertificationRegistryListResponse {
        configured: true,
        count: registry.artifacts.len(),
        artifacts: registry.artifacts.into_values().collect(),
    };
    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("certifications: {}", response.count);
        for artifact in response.artifacts {
            println!(
                "- {} server={} verdict={} status={}",
                artifact.artifact_id,
                artifact.tool_server_id,
                artifact.verdict.label(),
                artifact.status.label()
            );
        }
    }
    Ok(())
}

pub fn cmd_certify_registry_get_local(
    artifact_id: &str,
    registry_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let registry = CertificationRegistry::load(registry_path)?;
    let entry = registry.get(artifact_id).cloned().ok_or_else(|| {
        CliError::attest_error(format!(
            "certification artifact `{artifact_id}` was not found"
        ))
    })?;
    emit_registry_entry("certification artifact", &entry, json_output)
}

pub fn cmd_certify_registry_resolve_local(
    tool_server_id: &str,
    registry_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let registry = CertificationRegistry::load(registry_path)?;
    let response = registry.resolve(tool_server_id);
    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("tool_server_id: {}", response.tool_server_id);
        println!(
            "state:          {}",
            match response.state {
                CertificationResolutionState::Active => "active",
                CertificationResolutionState::Superseded => "superseded",
                CertificationResolutionState::Revoked => "revoked",
                CertificationResolutionState::NotFound => "not-found",
            }
        );
        println!("total_entries:  {}", response.total_entries);
        if let Some(current) = response.current {
            println!("artifact_id:    {}", current.artifact_id);
            println!("verdict:        {}", current.verdict.label());
            println!("status:         {}", current.status.label());
        }
    }
    Ok(())
}

pub fn cmd_certify_registry_revoke_local(
    artifact_id: &str,
    registry_path: &Path,
    reason: Option<&str>,
    revoked_at: Option<u64>,
    json_output: bool,
) -> Result<(), CliError> {
    let mut registry = CertificationRegistry::load(registry_path)?;
    let entry = registry.revoke(artifact_id, reason, revoked_at)?;
    registry.save(registry_path)?;
    emit_registry_entry("revoked certification artifact", &entry, json_output)
}

fn parse_registry_state_filter(
    status: Option<&str>,
) -> Result<Option<CertificationRegistryState>, CliError> {
    match status {
        None => Ok(None),
        Some("active") => Ok(Some(CertificationRegistryState::Active)),
        Some("superseded") => Ok(Some(CertificationRegistryState::Superseded)),
        Some("revoked") => Ok(Some(CertificationRegistryState::Revoked)),
        Some(other) => Err(CliError::attest_error(format!(
            "unsupported certification status filter `{other}`"
        ))),
    }
}

fn parse_dispute_state(state: &str) -> Result<CertificationDisputeState, CliError> {
    match state {
        "open" => Ok(CertificationDisputeState::Open),
        "under-review" => Ok(CertificationDisputeState::UnderReview),
        "resolved-no-change" => Ok(CertificationDisputeState::ResolvedNoChange),
        "resolved-revoked" => Ok(CertificationDisputeState::ResolvedRevoked),
        other => Err(CliError::attest_error(format!(
            "unsupported certification dispute state `{other}`"
        ))),
    }
}

pub fn cmd_certify_registry_search(
    discovery_path: Option<&Path>,
    tool_server_id: Option<&str>,
    criteria_profile: Option<&str>,
    evidence_profile: Option<&str>,
    status: Option<&str>,
    operator_ids: &[String],
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = CertificationMarketplaceSearchQuery {
        filters: CertificationPublicSearchQuery {
            tool_server_id: tool_server_id.map(str::to_string),
            criteria_profile: criteria_profile.map(str::to_string),
            evidence_profile: evidence_profile.map(str::to_string),
            status: parse_registry_state_filter(status)?,
        },
        operator_ids: (!operator_ids.is_empty()).then(|| operator_ids.join(",")),
    };
    let response = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .search_certification_marketplace(&query)?
    } else {
        let path = require_certification_discovery_path(discovery_path)?;
        let network = CertificationDiscoveryNetwork::load(path)?;
        network::search_public_certifications_across_network(&network, &query)
    };
    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("search_results: {}", response.count);
        println!("reachable:      {}", response.reachable_count);
        for result in response.results {
            println!(
                "- publisher={} server={} status={} verdict={} artifact={}",
                result.publisher.publisher_id,
                result.entry.tool_server_id,
                result.entry.status.label(),
                result.entry.verdict.label(),
                result.entry.artifact_id
            );
        }
        for error in response.errors {
            println!(
                "- operator={} error={} registry={}",
                error.operator_id, error.error, error.registry_url
            );
        }
    }
    Ok(())
}

pub fn cmd_certify_registry_transparency(
    discovery_path: Option<&Path>,
    tool_server_id: Option<&str>,
    operator_ids: &[String],
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = CertificationMarketplaceTransparencyQuery {
        filters: CertificationTransparencyQuery {
            tool_server_id: tool_server_id.map(str::to_string),
        },
        operator_ids: (!operator_ids.is_empty()).then(|| operator_ids.join(",")),
    };
    let response = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .certification_marketplace_transparency(&query)?
    } else {
        let path = require_certification_discovery_path(discovery_path)?;
        let network = CertificationDiscoveryNetwork::load(path)?;
        network::transparency_public_certifications_across_network(&network, &query)
    };
    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("events:    {}", response.count);
        println!("reachable: {}", response.reachable_count);
        for event in response.events {
            println!(
                "- publisher={} kind={:?} server={} artifact={} at={}",
                event.publisher.publisher_id,
                event.kind,
                event.tool_server_id,
                event.artifact_id,
                event.observed_at
            );
        }
    }
    Ok(())
}

pub fn cmd_certify_registry_consume(
    discovery_path: Option<&Path>,
    tool_server_id: &str,
    operator_ids: &[String],
    allowed_criteria_profiles: &[String],
    allowed_evidence_profiles: &[String],
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = CertificationConsumptionRequest {
        tool_server_id: tool_server_id.to_string(),
        operator_ids: operator_ids.to_vec(),
        allowed_criteria_profiles: allowed_criteria_profiles.to_vec(),
        allowed_evidence_profiles: allowed_evidence_profiles.to_vec(),
    };
    let response = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .consume_certification_marketplace(&request)?
    } else {
        let path = require_certification_discovery_path(discovery_path)?;
        let network = CertificationDiscoveryNetwork::load(path)?;
        network::consume_public_certification_across_network(&network, &request)
    };
    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("admitted: {}", response.admitted_count);
        println!("rejected: {}", response.rejected_count);
        for decision in response.decisions {
            println!(
                "- operator={} accepted={} reasons={}",
                decision.operator_id,
                decision.accepted,
                decision.reasons.join("; ")
            );
        }
    }
    Ok(())
}

pub fn cmd_certify_registry_dispute(
    artifact_id: &str,
    state: &str,
    note: Option<&str>,
    updated_at: Option<u64>,
    certification_registry_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = CertificationDisputeRequest {
        state: parse_dispute_state(state)?,
        note: note.map(str::to_string),
        updated_at,
    };
    let entry = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .dispute_certification(artifact_id, &request)?
    } else {
        let path = certification_registry_file.ok_or_else(|| {
            CliError::attest_error(
                "certification dispute requires --certification-registry-file when not using --control-url"
                    .to_string(),
            )
        })?;
        let mut registry = CertificationRegistry::load(path)?;
        let entry = registry.dispute(artifact_id, &request)?;
        registry.save(path)?;
        entry
    };
    emit_registry_entry("updated certification dispute state", &entry, json_output)
}

fn emit_registry_entry(
    headline: &str,
    entry: &CertificationRegistryEntry,
    json_output: bool,
) -> Result<(), CliError> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(entry)?);
    } else {
        println!("{headline}");
        println!("artifact_id:     {}", entry.artifact_id);
        println!("tool_server_id:  {}", entry.tool_server_id);
        println!("verdict:         {}", entry.verdict.label());
        println!("status:          {}", entry.status.label());
        println!("published_at:    {}", entry.published_at);
        if let Some(revoked_at) = entry.revoked_at {
            println!("revoked_at:      {revoked_at}");
        }
        if let Some(reason) = entry.revoked_reason.as_deref() {
            println!("revoked_reason:  {reason}");
        }
        if let Some(dispute) = entry.dispute.as_ref() {
            println!("dispute_state:   {}", dispute.state.label());
            println!("dispute_at:      {}", dispute.updated_at);
            if let Some(note) = dispute.note.as_deref() {
                println!("dispute_note:    {note}");
            }
        }
        if let Some(superseded_by) = entry.superseded_by.as_deref() {
            println!("superseded_by:   {superseded_by}");
        }
    }
    Ok(())
}

pub(crate) fn certification_resolution_label(state: CertificationResolutionState) -> &'static str {
    match state {
        CertificationResolutionState::Active => "active",
        CertificationResolutionState::Superseded => "superseded",
        CertificationResolutionState::Revoked => "revoked",
        CertificationResolutionState::NotFound => "not-found",
    }
}
