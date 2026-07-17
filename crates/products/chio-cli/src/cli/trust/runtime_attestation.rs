use super::*;

pub(crate) fn parse_governed_autonomy_tier(value: &str) -> Result<GovernedAutonomyTier, CliError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|_| {
        CliError::policy_constraint_error(format!("invalid governed autonomy tier `{value}`"))
    })
}

pub(crate) fn parse_runtime_assurance_tier(value: &str) -> Result<RuntimeAssuranceTier, CliError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|_| {
        CliError::policy_constraint_error(format!("invalid runtime assurance tier `{value}`"))
    })
}

pub(crate) fn load_runtime_attestation_evidence(
    path: &Path,
) -> Result<RuntimeAttestationEvidence, CliError> {
    let contents = fs::read_to_string(path)?;
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "yaml" | "yml"))
    {
        Ok(serde_yml::from_str(&contents)?)
    } else if let Ok(evidence) = serde_json::from_str(&contents) {
        Ok(evidence)
    } else {
        Ok(serde_yml::from_str(&contents)?)
    }
}

pub(crate) fn load_signed_runtime_attestation_appraisal_result(
    path: &Path,
) -> Result<SignedRuntimeAttestationAppraisalResult, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_runtime_attestation_import_policy(
    path: &Path,
) -> Result<RuntimeAttestationImportedAppraisalPolicy, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn cmd_trust_runtime_attestation_appraisal_export(
    input_path: &Path,
    policy_file: Option<&Path>,
    json_output: bool,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let evidence = load_runtime_attestation_evidence(input_path)?;
    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .runtime_attestation_appraisal(&RuntimeAttestationAppraisalRequest {
                runtime_attestation: evidence,
            })?
    } else {
        let runtime_assurance_policy = policy_file
            .map(load_policy)
            .transpose()?
            .and_then(|loaded| loaded.runtime_assurance_policy);
        trust_control::reports::build_signed_runtime_attestation_appraisal_report(
            authority_seed_path,
            authority_db_path,
            runtime_assurance_policy.as_ref(),
            &evidence,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.body.schema);
        println!("generated_at:           {}", report.body.generated_at);
        println!("signer_key:             {}", report.signer_key.to_hex());
        println!(
            "evidence_schema:        {}",
            report.body.appraisal.evidence.schema
        );
        println!(
            "verifier:               {}",
            report.body.appraisal.evidence.verifier
        );
        println!(
            "verifier_family:        {:?}",
            report.body.appraisal.verifier_family
        );
        println!(
            "verdict:                {:?}",
            report.body.appraisal.verdict
        );
        println!(
            "policy_configured:      {}",
            report.body.policy_outcome.trust_policy_configured
        );
        println!(
            "policy_accepted:        {}",
            report.body.policy_outcome.accepted
        );
        println!(
            "effective_tier:         {:?}",
            report.body.policy_outcome.effective_tier
        );
        if let Some(reason) = report.body.policy_outcome.reason.as_deref() {
            println!("policy_reason:          {reason}");
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_runtime_attestation_appraisal_result_export(
    issuer: &str,
    input_path: &Path,
    policy_file: Option<&Path>,
    json_output: bool,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let evidence = load_runtime_attestation_evidence(input_path)?;
    let result = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .runtime_attestation_appraisal_result(
                &RuntimeAttestationAppraisalResultExportRequest {
                    issuer: issuer.to_string(),
                    runtime_attestation: evidence,
                },
            )?
    } else {
        let runtime_assurance_policy = policy_file
            .map(load_policy)
            .transpose()?
            .and_then(|loaded| loaded.runtime_assurance_policy);
        trust_control::reports::build_signed_runtime_attestation_appraisal_result(
            authority_seed_path,
            authority_db_path,
            runtime_assurance_policy.as_ref(),
            &RuntimeAttestationAppraisalResultExportRequest {
                issuer: issuer.to_string(),
                runtime_attestation: evidence,
            },
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("schema:                 {}", result.body.schema);
        println!("result_id:              {}", result.body.result_id);
        println!("exported_at:            {}", result.body.exported_at);
        println!("issuer:                 {}", result.body.issuer);
        println!("signer_key:             {}", result.signer_key.to_hex());
        println!(
            "verifier_family:        {:?}",
            result.body.appraisal.verifier.verifier_family
        );
        println!(
            "exporter_accepted:      {}",
            result.body.exporter_policy_outcome.accepted
        );
        println!(
            "effective_tier:         {:?}",
            result.body.exporter_policy_outcome.effective_tier
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_runtime_attestation_appraisal_import(
    input_path: &Path,
    policy_path: &Path,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = RuntimeAttestationAppraisalImportRequest {
        signed_result: load_signed_runtime_attestation_appraisal_result(input_path)?,
        local_policy: load_runtime_attestation_import_policy(policy_path)?,
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .import_runtime_attestation_appraisal(&request)?
    } else {
        trust_control::reports::build_runtime_attestation_appraisal_import_report(
            &request,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
                .as_secs(),
        )
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("evaluated_at:           {}", report.evaluated_at);
        println!("result_id:              {}", report.result.result_id);
        println!("issuer:                 {}", report.result.issuer);
        println!("signer_key:             {}", report.signer_key_hex);
        println!(
            "disposition:            {:?}",
            report.local_policy_outcome.disposition
        );
        println!(
            "effective_tier:         {:?}",
            report.local_policy_outcome.effective_tier
        );
        for reason in &report.local_policy_outcome.reasons {
            println!("- {:?}: {}", reason.code, reason.description);
        }
    }

    Ok(())
}
