use super::*;

pub fn cmd_mercury_selective_account_activation_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_selective_account_activation(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury selective-account-activation package exported");
        println!("output:                             {}", output.display());
        println!(
            "workflow_id:                        {}",
            summary.workflow_id
        );
        println!(
            "activation_motion:                  {}",
            summary.activation_motion
        );
        println!(
            "delivery_surface:                   {}",
            summary.delivery_surface
        );
        println!(
            "activation_owner:                   {}",
            summary.activation_owner
        );
        println!(
            "approval_owner:                     {}",
            summary.approval_owner
        );
        println!(
            "delivery_owner:                     {}",
            summary.delivery_owner
        );
        println!(
            "selective_account_activation_package: {}",
            summary.selective_account_activation_package_file
        );
        println!(
            "activation_approval_refresh:        {}",
            summary.activation_approval_refresh_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_selective_account_activation_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let selective_account_activation_dir = output.join("selective-account-activation");
    let summary = export_selective_account_activation(&selective_account_activation_dir)?;
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercurySelectiveAccountActivationDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_DECISION.to_string(),
        selected_activation_motion: summary.activation_motion.clone(),
        selected_delivery_surface: summary.delivery_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury selective-account activation lane only."
                .to_string(),
        deferred_scope: vec![
            "additional selective-account activation motions or surfaces".to_string(),
            "generic onboarding tooling, CRM workflows, or commercial consoles".to_string(),
            "channel marketplaces or multi-segment activation programs".to_string(),
            "merged Mercury and Chio-Wall commercial packaging".to_string(),
            "Chio-side commercial control surfaces".to_string(),
        ],
        rationale: "The selective-account activation lane now packages one controlled delivery motion over the validated broader-distribution stack without widening Mercury into a generic onboarding platform or polluting Chio's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("selective-account-activation-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercurySelectiveAccountActivationValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_DECISION.to_string(),
        activation_motion: summary.activation_motion.clone(),
        delivery_surface: summary.delivery_surface.clone(),
        activation_owner: summary.activation_owner.clone(),
        approval_owner: summary.approval_owner.clone(),
        delivery_owner: summary.delivery_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        selective_account_activation: summary,
        decision_record_file: decision_record_file.display().to_string(),
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury selective-account-activation validation package exported");
        println!("output:                             {}", output.display());
        println!("workflow_id:                        {}", report.workflow_id);
        println!("decision:                           {}", report.decision);
        println!(
            "activation_motion:                  {}",
            report.activation_motion
        );
        println!(
            "delivery_surface:                   {}",
            report.delivery_surface
        );
        println!(
            "activation_owner:                   {}",
            report.activation_owner
        );
        println!(
            "approval_owner:                     {}",
            report.approval_owner
        );
        println!(
            "delivery_owner:                     {}",
            report.delivery_owner
        );
        println!(
            "validation_report:                  {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:                    {}",
            decision_record_file.display()
        );
        println!(
            "selective_account_activation_package: {}",
            report
                .selective_account_activation
                .selective_account_activation_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_delivery_continuity_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_delivery_continuity(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury delivery-continuity package exported");
        println!("output:                             {}", output.display());
        println!(
            "workflow_id:                        {}",
            summary.workflow_id
        );
        println!(
            "continuity_motion:                  {}",
            summary.continuity_motion
        );
        println!(
            "continuity_surface:                 {}",
            summary.continuity_surface
        );
        println!(
            "continuity_owner:                   {}",
            summary.continuity_owner
        );
        println!(
            "renewal_owner:                      {}",
            summary.renewal_owner
        );
        println!(
            "evidence_owner:                     {}",
            summary.evidence_owner
        );
        println!(
            "delivery_continuity_package:        {}",
            summary.delivery_continuity_package_file
        );
        println!(
            "renewal_gate:                       {}",
            summary.renewal_gate_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_delivery_continuity_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let delivery_continuity_dir = output.join("delivery-continuity");
    let summary = export_delivery_continuity(&delivery_continuity_dir)?;
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryDeliveryContinuityDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_DELIVERY_CONTINUITY_DECISION.to_string(),
        selected_continuity_motion: summary.continuity_motion.clone(),
        selected_continuity_surface: summary.continuity_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury controlled-delivery continuity lane only."
                .to_string(),
        deferred_scope: vec![
            "additional continuity motions or delivery surfaces".to_string(),
            "generic onboarding tooling, CRM workflows, or support desks".to_string(),
            "channel marketplaces, multi-account continuity programs, or merged shells"
                .to_string(),
            "Chio-side commercial control surfaces".to_string(),
        ],
        rationale: "The controlled-delivery continuity lane now packages one outcome-evidence bundle and one renewal gate over the validated selective-account-activation chain without widening Mercury into a generic customer platform or polluting Chio's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("delivery-continuity-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryDeliveryContinuityValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_DELIVERY_CONTINUITY_DECISION.to_string(),
        continuity_motion: summary.continuity_motion.clone(),
        continuity_surface: summary.continuity_surface.clone(),
        continuity_owner: summary.continuity_owner.clone(),
        renewal_owner: summary.renewal_owner.clone(),
        evidence_owner: summary.evidence_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        delivery_continuity: summary,
        decision_record_file: decision_record_file.display().to_string(),
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury delivery-continuity validation package exported");
        println!("output:                             {}", output.display());
        println!("workflow_id:                        {}", report.workflow_id);
        println!("decision:                           {}", report.decision);
        println!(
            "continuity_motion:                  {}",
            report.continuity_motion
        );
        println!(
            "continuity_surface:                 {}",
            report.continuity_surface
        );
        println!(
            "continuity_owner:                   {}",
            report.continuity_owner
        );
        println!(
            "renewal_owner:                      {}",
            report.renewal_owner
        );
        println!(
            "evidence_owner:                     {}",
            report.evidence_owner
        );
        println!(
            "validation_report:                  {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:                    {}",
            decision_record_file.display()
        );
        println!(
            "delivery_continuity_package:        {}",
            report.delivery_continuity.delivery_continuity_package_file
        );
    }

    Ok(())
}
