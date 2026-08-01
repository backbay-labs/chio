use super::super::*;
use super::exports::{
    export_downstream_review, export_governance_workbench, export_pilot_scenario,
    export_supervised_live_capture, export_supervised_live_qualification,
};

pub fn cmd_mercury_proof_export(
    input: &Path,
    output: &Path,
    bundle_manifest_paths: &[PathBuf],
    json_output: bool,
) -> Result<(), CliError> {
    let package = build_proof_package(input, bundle_manifest_paths)?;
    package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    write_json_file(output, &package)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&package)?);
    } else {
        println!("mercury proof package exported");
        println!("output:              {}", output.display());
        println!("package_id:          {}", package.package_id);
        println!("workflow_id:         {}", package.workflow_id);
        println!("receipt_count:       {}", package.receipt_records.len());
        println!("bundle_manifests:    {}", package.bundle_manifests.len());
    }

    Ok(())
}

pub fn cmd_mercury_inquiry_export(
    input: &Path,
    output: &Path,
    audience: &str,
    redaction_profile: Option<&str>,
    verifier_equivalent: bool,
    json_output: bool,
) -> Result<(), CliError> {
    let proof_package: MercuryProofPackage = read_json_file(input)?;
    proof_package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package = build_inquiry_package(
        proof_package,
        audience,
        redaction_profile,
        verifier_equivalent,
    )?;
    let report = package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    write_json_file(output, &package)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&package)?);
    } else {
        println!("mercury inquiry package exported");
        println!("output:              {}", output.display());
        println!("inquiry_id:          {}", package.inquiry_id);
        println!("workflow_id:         {}", package.proof_package.workflow_id);
        println!("audience:            {}", package.audience);
        println!("verifier_equivalent: {}", report.verifier_equivalent);
    }

    Ok(())
}

pub fn cmd_mercury_verify(input: &Path, json_output: bool, explain: bool) -> Result<(), CliError> {
    let value: serde_json::Value = read_json_file(input)?;
    let schema = value
        .get("schema")
        .and_then(|schema| schema.as_str())
        .ok_or_else(|| CliError::Other("mercury package is missing schema".to_string()))?;
    let report = match schema {
        MERCURY_PROOF_PACKAGE_SCHEMA => {
            let package: MercuryProofPackage = serde_json::from_value(value)?;
            package
                .verify(unix_now())
                .map_err(|error| CliError::Other(error.to_string()))?
        }
        MERCURY_INQUIRY_PACKAGE_SCHEMA => {
            let package: MercuryInquiryPackage = serde_json::from_value(value)?;
            package
                .verify(unix_now())
                .map_err(|error| CliError::Other(error.to_string()))?
        }
        _ => {
            return Err(CliError::Other(format!(
                "unsupported mercury package schema: {schema}"
            )))
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let package_kind = match report.package_kind {
            MercuryPackageKind::Proof => "proof",
            MercuryPackageKind::Inquiry => "inquiry",
        };
        println!("mercury {package_kind} package verified");
        println!("package_id:          {}", report.package_id);
        println!("workflow_id:         {}", report.workflow_id);
        println!("receipt_count:       {}", report.receipt_count);
        println!("verifier_equivalent: {}", report.verifier_equivalent);
        if explain {
            println!("steps:");
            for step in &report.steps {
                println!("  - {}: {}", step.name, step.detail);
            }
        }
    }

    Ok(())
}

pub fn cmd_mercury_pilot_export(output: &Path, json_output: bool) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let summary = export_pilot_scenario(output, MercuryPilotScenario::gold_release_control())?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury pilot corpus exported");
        println!("output:              {}", output.display());
        println!("scenario_id:         {}", summary.scenario_id);
        println!("workflow_id:         {}", summary.workflow_id);
        println!("primary_receipts:    {}", summary.primary_receipt_count);
        println!("rollback_receipts:   {}", summary.rollback_receipt_count);
        println!(
            "primary_proof:       {}",
            summary.primary.proof_package_file
        );
        if let Some(inquiry_package_file) = summary.primary.inquiry_package_file.as_deref() {
            println!("primary_inquiry:     {}", inquiry_package_file);
        }
        println!(
            "rollback_proof:      {}",
            summary.rollback.proof_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_supervised_live_export(
    input: &Path,
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let capture: MercurySupervisedLiveCapture = read_json_file(input)?;
    let summary = export_supervised_live_capture(output, capture)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury supervised-live capture exported");
        println!("output:              {}", output.display());
        println!("capture_id:          {}", summary.capture_id);
        println!("workflow_id:         {}", summary.workflow_id);
        println!("mode:                {}", summary.mode);
        println!("receipt_count:       {}", summary.receipt_count);
        println!(
            "coverage_state:      {}",
            summary.control_state.coverage_state.as_str()
        );
        println!(
            "release_gate:        {}",
            summary.control_state.release_gate.state.as_str()
        );
        println!(
            "rollback_gate:       {}",
            summary.control_state.rollback_gate.state.as_str()
        );
        println!("proof_package:       {}", summary.export.proof_package_file);
        if let Some(inquiry_package_file) = summary.export.inquiry_package_file.as_deref() {
            println!("inquiry_package:     {}", inquiry_package_file);
        }
    }

    Ok(())
}

pub fn cmd_mercury_supervised_live_qualify(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let (_, reviewer_package) = export_supervised_live_qualification(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&reviewer_package)?);
    } else {
        println!("mercury supervised-live qualification package exported");
        println!("output:                     {}", output.display());
        println!(
            "workflow_id:                {}",
            reviewer_package.workflow_id
        );
        println!("decision:                   {}", reviewer_package.decision);
        println!(
            "qualification_report:       {}",
            reviewer_package.qualification_report_file
        );
        println!(
            "reviewer_package:           {}",
            output.join("reviewer-package.json").display()
        );
        println!(
            "supervised_live_proof:      {}",
            reviewer_package.supervised_live_proof_package_file
        );
        println!(
            "rollback_proof:             {}",
            reviewer_package.rollback_proof_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_downstream_review_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_downstream_review(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury downstream-review package exported");
        println!("output:                     {}", output.display());
        println!("workflow_id:                {}", summary.workflow_id);
        println!("consumer_profile:           {}", summary.consumer_profile);
        println!("transport:                  {}", summary.transport);
        println!(
            "internal_assurance:         {}",
            summary.internal_assurance_package_file
        );
        println!(
            "external_assurance:         {}",
            summary.external_assurance_package_file
        );
        println!(
            "downstream_review_package:  {}",
            summary.downstream_review_package_file
        );
        println!(
            "consumer_manifest:          {}",
            summary.consumer_manifest_file
        );
        println!(
            "acknowledgement:            {}",
            summary.acknowledgement_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_downstream_review_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let downstream_review_dir = output.join("downstream-review");
    let summary = export_downstream_review(&downstream_review_dir)?;
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryDownstreamReviewDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_DOWNSTREAM_DECISION.to_string(),
        selected_consumer_profile: summary.consumer_profile.clone(),
        approved_scope:
            "Proceed with the bounded case-management review consumer path only."
                .to_string(),
        deferred_scope: vec![
            "additional archive connectors".to_string(),
            "surveillance connectors".to_string(),
            "governance workbench breadth".to_string(),
            "OMS/EMS or FIX coupling".to_string(),
            "OEM packaging and trust-network work".to_string(),
        ],
        rationale: "The downstream review package now strengthens buyer review flows without widening MERCURY into multi-consumer sprawl or deep runtime coupling."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryDownstreamReviewValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_DOWNSTREAM_DECISION.to_string(),
        consumer_profile: summary.consumer_profile.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        downstream_review: summary,
        decision_record_file: decision_record_file.display().to_string(),
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury downstream-review validation package exported");
        println!("output:                     {}", output.display());
        println!("workflow_id:                {}", report.workflow_id);
        println!("decision:                   {}", report.decision);
        println!("consumer_profile:           {}", report.consumer_profile);
        println!(
            "validation_report:          {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:            {}",
            decision_record_file.display()
        );
        println!(
            "downstream_review_package:  {}",
            report.downstream_review.downstream_review_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_governance_workbench_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_governance_workbench(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury governance-workbench package exported");
        println!("output:                     {}", output.display());
        println!("workflow_id:                {}", summary.workflow_id);
        println!("workflow_path:              {}", summary.workflow_path);
        println!("workflow_owner:             {}", summary.workflow_owner);
        println!("control_team_owner:         {}", summary.control_team_owner);
        println!(
            "governance_decision:        {}",
            summary.governance_decision_package_file
        );
        println!(
            "workflow_owner_review:      {}",
            summary.workflow_owner_review_package_file
        );
        println!(
            "control_team_review:        {}",
            summary.control_team_review_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_governance_workbench_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let governance_dir = output.join("governance-workbench");
    let summary = export_governance_workbench(&governance_dir)?;
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryGovernanceWorkbenchDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_GOVERNANCE_DECISION.to_string(),
        selected_workflow_path: summary.workflow_path.clone(),
        approved_scope:
            "Proceed with the bounded governance workbench change-review path only."
                .to_string(),
        deferred_scope: vec![
            "additional governance workflow breadth".to_string(),
            "additional downstream consumer connectors".to_string(),
            "OMS/EMS or FIX coupling".to_string(),
            "OEM packaging and trust-network work".to_string(),
            "generic workflow orchestration".to_string(),
        ],
        rationale: "The governance workbench package now deepens buyer review and control workflows without widening MERCURY into generic orchestration, connector sprawl, or deep runtime coupling."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryGovernanceWorkbenchValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_GOVERNANCE_DECISION.to_string(),
        workflow_path: summary.workflow_path.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        governance_workbench: summary,
        decision_record_file: decision_record_file.display().to_string(),
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury governance-workbench validation package exported");
        println!("output:                     {}", output.display());
        println!("workflow_id:                {}", report.workflow_id);
        println!("decision:                   {}", report.decision);
        println!("workflow_path:              {}", report.workflow_path);
        println!(
            "validation_report:          {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:            {}",
            decision_record_file.display()
        );
        println!(
            "governance_decision:        {}",
            report.governance_workbench.governance_decision_package_file
        );
    }

    Ok(())
}
