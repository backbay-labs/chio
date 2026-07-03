use super::super::*;

pub fn cmd_mercury_assurance_suite_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_assurance_suite(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury assurance-suite package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!("reviewer_owner:                {}", summary.reviewer_owner);
        println!("support_owner:                 {}", summary.support_owner);
        println!(
            "assurance_suite_package:       {}",
            summary.assurance_suite_package_file
        );
        println!(
            "internal_review_package:       {}",
            summary.internal_review_package_file
        );
        println!(
            "auditor_review_package:        {}",
            summary.auditor_review_package_file
        );
        println!(
            "counterparty_review_package:   {}",
            summary.counterparty_review_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_assurance_suite_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let assurance_dir = output.join("assurance-suite");
    let summary = export_assurance_suite(&assurance_dir)?;
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryAssuranceSuiteDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_ASSURANCE_DECISION.to_string(),
        selected_reviewer_populations: summary.reviewer_populations.clone(),
        approved_scope:
            "Proceed with the bounded assurance-suite reviewer populations only."
                .to_string(),
        deferred_scope: vec![
            "additional reviewer populations".to_string(),
            "generic review portal or case-management product breadth".to_string(),
            "additional downstream or governance workflow lanes".to_string(),
            "OMS/EMS or FIX coupling".to_string(),
            "OEM packaging and trust-network work".to_string(),
        ],
        rationale: "The assurance suite now packages internal, auditor, and counterparty review over the same Mercury proof chain without widening Mercury into a generic portal, connector sprawl, or embedded platform."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryAssuranceSuiteValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_ASSURANCE_DECISION.to_string(),
        reviewer_owner: summary.reviewer_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        assurance_suite: summary,
        decision_record_file: decision_record_file.display().to_string(),
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury assurance-suite validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("reviewer_owner:                {}", report.reviewer_owner);
        println!("support_owner:                 {}", report.support_owner);
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "assurance_suite_package:       {}",
            report.assurance_suite.assurance_suite_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_embedded_oem_export(output: &Path, json_output: bool) -> Result<(), CliError> {
    let summary = export_embedded_oem(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury embedded-oem package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!("partner_surface:               {}", summary.partner_surface);
        println!("sdk_surface:                   {}", summary.sdk_surface);
        println!(
            "reviewer_population:           {}",
            summary.reviewer_population
        );
        println!("partner_owner:                 {}", summary.partner_owner);
        println!("support_owner:                 {}", summary.support_owner);
        println!(
            "embedded_oem_package:          {}",
            summary.embedded_oem_package_file
        );
        println!(
            "partner_sdk_manifest:          {}",
            summary.partner_sdk_manifest_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_embedded_oem_validate(output: &Path, json_output: bool) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let embedded_oem_dir = output.join("embedded-oem");
    let summary = export_embedded_oem(&embedded_oem_dir)?;
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryEmbeddedOemDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_EMBEDDED_OEM_DECISION.to_string(),
        selected_partner_surface: summary.partner_surface.clone(),
        selected_sdk_surface: summary.sdk_surface.clone(),
        selected_reviewer_population: summary.reviewer_population.clone(),
        approved_scope:
            "Proceed with the bounded reviewer-workbench embedded OEM path only."
                .to_string(),
        deferred_scope: vec![
            "additional partner surfaces".to_string(),
            "multi-partner OEM breadth".to_string(),
            "generic SDK platform or multi-language client breadth".to_string(),
            "trust-network services".to_string(),
            "Chio-Wall and companion-product work".to_string(),
        ],
        rationale: "The embedded OEM bundle now packages one counterparty-review Mercury surface for one partner workbench without widening Mercury into a generic SDK platform, multi-partner OEM program, or separate trust service."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryEmbeddedOemValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_EMBEDDED_OEM_DECISION.to_string(),
        partner_surface: summary.partner_surface.clone(),
        sdk_surface: summary.sdk_surface.clone(),
        reviewer_population: summary.reviewer_population.clone(),
        partner_owner: summary.partner_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        embedded_oem: summary,
        decision_record_file: decision_record_file.display().to_string(),
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury embedded-oem validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("partner_surface:               {}", report.partner_surface);
        println!("sdk_surface:                   {}", report.sdk_surface);
        println!(
            "reviewer_population:           {}",
            report.reviewer_population
        );
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "embedded_oem_package:          {}",
            report.embedded_oem.embedded_oem_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_trust_network_export(output: &Path, json_output: bool) -> Result<(), CliError> {
    let summary = export_trust_network(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury trust-network package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!(
            "sponsor_boundary:              {}",
            summary.sponsor_boundary
        );
        println!("trust_anchor:                  {}", summary.trust_anchor);
        println!("interop_surface:               {}", summary.interop_surface);
        println!(
            "reviewer_population:           {}",
            summary.reviewer_population
        );
        println!(
            "trust_network_package:         {}",
            summary.trust_network_package_file
        );
        println!(
            "interop_manifest:              {}",
            summary.interop_manifest_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_trust_network_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let trust_network_dir = output.join("trust-network");
    let summary = export_trust_network(&trust_network_dir)?;
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryTrustNetworkDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_TRUST_NETWORK_DECISION.to_string(),
        selected_sponsor_boundary: summary.sponsor_boundary.clone(),
        selected_trust_anchor: summary.trust_anchor.clone(),
        selected_interop_surface: summary.interop_surface.clone(),
        selected_reviewer_population: summary.reviewer_population.clone(),
        approved_scope:
            "Proceed with the bounded counterparty-review trust-network path only."
                .to_string(),
        deferred_scope: vec![
            "additional trust-network sponsor boundaries".to_string(),
            "multi-network witness or trust-broker services".to_string(),
            "generic ecosystem interoperability infrastructure".to_string(),
            "Chio-Wall companion-product work".to_string(),
            "multi-product platform hardening".to_string(),
        ],
        rationale: "The trust-network lane now shares one bounded counterparty-review proof and inquiry bundle over one checkpoint-backed witness chain without widening Mercury into a generic trust broker, ecosystem network, or companion-product platform."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryTrustNetworkValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_TRUST_NETWORK_DECISION.to_string(),
        sponsor_boundary: summary.sponsor_boundary.clone(),
        trust_anchor: summary.trust_anchor.clone(),
        interop_surface: summary.interop_surface.clone(),
        reviewer_population: summary.reviewer_population.clone(),
        sponsor_owner: summary.sponsor_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        trust_network: summary,
        decision_record_file: decision_record_file.display().to_string(),
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury trust-network validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("sponsor_boundary:              {}", report.sponsor_boundary);
        println!("trust_anchor:                  {}", report.trust_anchor);
        println!("interop_surface:               {}", report.interop_surface);
        println!(
            "reviewer_population:           {}",
            report.reviewer_population
        );
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "trust_network_package:         {}",
            report.trust_network.trust_network_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_release_readiness_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_release_readiness(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury release-readiness package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!(
            "delivery_surface:              {}",
            summary.delivery_surface
        );
        println!(
            "audiences:                     {}",
            summary.audiences.join(", ")
        );
        println!("release_owner:                 {}", summary.release_owner);
        println!("partner_owner:                 {}", summary.partner_owner);
        println!("support_owner:                 {}", summary.support_owner);
        println!(
            "release_readiness_package:     {}",
            summary.release_readiness_package_file
        );
        println!(
            "partner_delivery_manifest:     {}",
            summary.partner_delivery_manifest_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_release_readiness_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let release_readiness_dir = output.join("release-readiness");
    let summary = export_release_readiness(&release_readiness_dir)?;
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryReleaseReadinessDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_RELEASE_READINESS_DECISION.to_string(),
        selected_delivery_surface: summary.delivery_surface.clone(),
        selected_audiences: summary.audiences.clone(),
        approved_scope: "Launch one bounded Mercury release-readiness lane only.".to_string(),
        deferred_scope: vec![
            "additional partner-delivery surfaces".to_string(),
            "generic Chio release console or merged shell".to_string(),
            "new Mercury product-line claims".to_string(),
            "additional trust-network sponsor breadth".to_string(),
            "Chio-Wall or cross-product packaging unification".to_string(),
        ],
        rationale: "The release-readiness lane now packages one Mercury reviewer, partner, and operator path over the validated proof, inquiry, assurance, and trust-network stack without widening Chio or creating a new product line."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryReleaseReadinessValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_RELEASE_READINESS_DECISION.to_string(),
        audiences: summary.audiences.clone(),
        delivery_surface: summary.delivery_surface.clone(),
        release_owner: summary.release_owner.clone(),
        partner_owner: summary.partner_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        release_readiness: summary,
        decision_record_file: decision_record_file.display().to_string(),
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury release-readiness validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("delivery_surface:              {}", report.delivery_surface);
        println!(
            "audiences:                     {}",
            report.audiences.join(", ")
        );
        println!("release_owner:                 {}", report.release_owner);
        println!("partner_owner:                 {}", report.partner_owner);
        println!("support_owner:                 {}", report.support_owner);
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "release_readiness_package:     {}",
            report.release_readiness.release_readiness_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_controlled_adoption_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_controlled_adoption(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury controlled-adoption package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!("cohort:                        {}", summary.cohort);
        println!(
            "adoption_surface:              {}",
            summary.adoption_surface
        );
        println!(
            "customer_success_owner:        {}",
            summary.customer_success_owner
        );
        println!("reference_owner:               {}", summary.reference_owner);
        println!("support_owner:                 {}", summary.support_owner);
        println!(
            "controlled_adoption_package:   {}",
            summary.controlled_adoption_package_file
        );
        println!(
            "renewal_evidence_manifest:     {}",
            summary.renewal_evidence_manifest_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_controlled_adoption_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let controlled_adoption_dir = output.join("controlled-adoption");
    let summary = export_controlled_adoption(&controlled_adoption_dir)?;
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryControlledAdoptionDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_CONTROLLED_ADOPTION_DECISION.to_string(),
        selected_cohort: summary.cohort.clone(),
        selected_adoption_surface: summary.adoption_surface.clone(),
        approved_scope: "Scale one bounded Mercury controlled-adoption lane only.".to_string(),
        deferred_scope: vec![
            "additional adoption cohorts".to_string(),
            "broader Mercury product lines or delivery surfaces".to_string(),
            "generic Chio renewal tooling or release consoles".to_string(),
            "merged Mercury and Chio-Wall packaging".to_string(),
            "new cross-product runtime coupling".to_string(),
        ],
        rationale: "The controlled-adoption lane now packages one design-partner renewal and reference path over the validated Mercury release-readiness stack without widening Mercury into a new product surface or polluting Chio generic crates."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryControlledAdoptionValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_CONTROLLED_ADOPTION_DECISION.to_string(),
        cohort: summary.cohort.clone(),
        adoption_surface: summary.adoption_surface.clone(),
        customer_success_owner: summary.customer_success_owner.clone(),
        reference_owner: summary.reference_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        controlled_adoption: summary,
        decision_record_file: decision_record_file.display().to_string(),
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury controlled-adoption validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("cohort:                        {}", report.cohort);
        println!("adoption_surface:              {}", report.adoption_surface);
        println!(
            "customer_success_owner:        {}",
            report.customer_success_owner
        );
        println!("reference_owner:               {}", report.reference_owner);
        println!("support_owner:                 {}", report.support_owner);
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "controlled_adoption_package:   {}",
            report.controlled_adoption.controlled_adoption_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_reference_distribution_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_reference_distribution(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury reference-distribution package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!(
            "expansion_motion:              {}",
            summary.expansion_motion
        );
        println!(
            "distribution_surface:          {}",
            summary.distribution_surface
        );
        println!("reference_owner:               {}", summary.reference_owner);
        println!(
            "buyer_approval_owner:          {}",
            summary.buyer_approval_owner
        );
        println!("sales_owner:                   {}", summary.sales_owner);
        println!(
            "reference_distribution_package: {}",
            summary.reference_distribution_package_file
        );
        println!(
            "buyer_reference_approval:      {}",
            summary.buyer_reference_approval_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_reference_distribution_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let reference_distribution_dir = output.join("reference-distribution");
    let summary = export_reference_distribution(&reference_distribution_dir)?;
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryReferenceDistributionDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_REFERENCE_DISTRIBUTION_DECISION.to_string(),
        selected_expansion_motion: summary.expansion_motion.clone(),
        selected_distribution_surface: summary.distribution_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury reference-distribution lane only.".to_string(),
        deferred_scope: vec![
            "additional landed-account motions".to_string(),
            "generic sales tooling, CRM workflows, or commercial consoles".to_string(),
            "merged Mercury and Chio-Wall commercial packaging".to_string(),
            "Chio-side commercial control surfaces".to_string(),
            "broader product-family or universal rollout claims".to_string(),
        ],
        rationale: "The reference-distribution lane now packages one approved landed-account expansion motion over the validated controlled-adoption stack without widening Mercury into a generic sales platform or polluting Chio's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryReferenceDistributionValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_REFERENCE_DISTRIBUTION_DECISION.to_string(),
        expansion_motion: summary.expansion_motion.clone(),
        distribution_surface: summary.distribution_surface.clone(),
        reference_owner: summary.reference_owner.clone(),
        buyer_approval_owner: summary.buyer_approval_owner.clone(),
        sales_owner: summary.sales_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        reference_distribution: summary,
        decision_record_file: decision_record_file.display().to_string(),
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury reference-distribution validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("expansion_motion:              {}", report.expansion_motion);
        println!(
            "distribution_surface:          {}",
            report.distribution_surface
        );
        println!("reference_owner:               {}", report.reference_owner);
        println!(
            "buyer_approval_owner:          {}",
            report.buyer_approval_owner
        );
        println!("sales_owner:                   {}", report.sales_owner);
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "reference_distribution_package: {}",
            report
                .reference_distribution
                .reference_distribution_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_broader_distribution_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_broader_distribution(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury broader-distribution package exported");
        println!("output:                         {}", output.display());
        println!("workflow_id:                    {}", summary.workflow_id);
        println!(
            "distribution_motion:            {}",
            summary.distribution_motion
        );
        println!(
            "distribution_surface:           {}",
            summary.distribution_surface
        );
        println!(
            "qualification_owner:            {}",
            summary.qualification_owner
        );
        println!("approval_owner:                 {}", summary.approval_owner);
        println!(
            "distribution_owner:             {}",
            summary.distribution_owner
        );
        println!(
            "broader_distribution_package:   {}",
            summary.broader_distribution_package_file
        );
        println!(
            "selective_account_approval:     {}",
            summary.selective_account_approval_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_broader_distribution_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let broader_distribution_dir = output.join("broader-distribution");
    let summary = export_broader_distribution(&broader_distribution_dir)?;
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryBroaderDistributionDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_BROADER_DISTRIBUTION_DECISION.to_string(),
        selected_distribution_motion: summary.distribution_motion.clone(),
        selected_distribution_surface: summary.distribution_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury broader-distribution lane only.".to_string(),
        deferred_scope: vec![
            "additional broader-distribution motions or surfaces".to_string(),
            "generic sales tooling, CRM workflows, or commercial consoles".to_string(),
            "multi-segment channel programs or partner marketplaces".to_string(),
            "merged Mercury and Chio-Wall commercial packaging".to_string(),
            "Chio-side commercial control surfaces".to_string(),
        ],
        rationale: "The broader-distribution lane now packages one governed selective-account qualification motion over the validated reference-distribution stack without widening Mercury into a generic commercial platform or polluting Chio's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("broader-distribution-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryBroaderDistributionValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_BROADER_DISTRIBUTION_DECISION.to_string(),
        distribution_motion: summary.distribution_motion.clone(),
        distribution_surface: summary.distribution_surface.clone(),
        qualification_owner: summary.qualification_owner.clone(),
        approval_owner: summary.approval_owner.clone(),
        distribution_owner: summary.distribution_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        broader_distribution: summary,
        decision_record_file: decision_record_file.display().to_string(),
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury broader-distribution validation package exported");
        println!("output:                         {}", output.display());
        println!("workflow_id:                    {}", report.workflow_id);
        println!("decision:                       {}", report.decision);
        println!(
            "distribution_motion:            {}",
            report.distribution_motion
        );
        println!(
            "distribution_surface:           {}",
            report.distribution_surface
        );
        println!(
            "qualification_owner:            {}",
            report.qualification_owner
        );
        println!("approval_owner:                 {}", report.approval_owner);
        println!(
            "distribution_owner:             {}",
            report.distribution_owner
        );
        println!(
            "validation_report:              {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:                {}",
            decision_record_file.display()
        );
        println!(
            "broader_distribution_package:   {}",
            report
                .broader_distribution
                .broader_distribution_package_file
        );
    }

    Ok(())
}
