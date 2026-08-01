use super::*;

pub(crate) struct UnderwritingPolicyInputArgs<'a> {
    pub(crate) capability_id: Option<&'a str>,
    pub(crate) agent_subject: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) since: Option<u64>,
    pub(crate) until: Option<u64>,
    pub(crate) receipt_limit: usize,
}

pub(crate) struct UnderwritingDecisionSimulateArgs<'a> {
    pub(crate) input: UnderwritingPolicyInputArgs<'a>,
    pub(crate) policy_file: &'a Path,
}

pub(crate) struct UnderwritingDecisionIssueArgs<'a> {
    pub(crate) input: UnderwritingPolicyInputArgs<'a>,
    pub(crate) supersedes_decision_id: Option<&'a str>,
}

pub(crate) struct UnderwritingDecisionListArgs<'a> {
    pub(crate) decision_id: Option<&'a str>,
    pub(crate) capability_id: Option<&'a str>,
    pub(crate) agent_subject: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) outcome: Option<&'a str>,
    pub(crate) lifecycle_state: Option<&'a str>,
    pub(crate) appeal_status: Option<&'a str>,
    pub(crate) limit: usize,
}

pub(crate) struct UnderwritingAppealResolveArgs<'a> {
    pub(crate) appeal_id: &'a str,
    pub(crate) resolution: &'a str,
    pub(crate) resolved_by: &'a str,
    pub(crate) note: Option<&'a str>,
    pub(crate) replacement_decision_id: Option<&'a str>,
}

pub(crate) fn build_underwriting_policy_input_query(
    args: &UnderwritingPolicyInputArgs<'_>,
) -> chio_kernel::UnderwritingPolicyInputQuery {
    chio_kernel::UnderwritingPolicyInputQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        receipt_limit: Some(args.receipt_limit),
    }
}

pub(crate) fn cmd_trust_underwriting_input_export(
    args: UnderwritingPolicyInputArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = build_underwriting_policy_input_query(&args);

    let input = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .underwriting_policy_input(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "underwriting input export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_signed_underwriting_policy_input(
            receipt_db_path,
            backend.budget_db_path,
            backend.authority_seed_path,
            backend.authority_db_path,
            backend.certification_registry_file,
            &query,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&input)?);
    } else {
        println!("schema:                 {}", input.body.schema);
        println!("generated_at:           {}", input.body.generated_at);
        println!("signer_key:             {}", input.signer_key.to_hex());
        println!(
            "matching_receipts:      {}",
            input.body.receipts.matching_receipts
        );
        println!(
            "returned_receipts:      {}",
            input.body.receipts.returned_receipts
        );
        println!(
            "governed_receipts:      {}",
            input.body.receipts.governed_receipts
        );
        println!(
            "runtime_assurance:      {}",
            input.body.receipts.runtime_assurance_receipts
        );
        println!("signals:                {}", input.body.signals.len());
        if let Some(reputation) = input.body.reputation.as_ref() {
            println!("subject_key:            {}", reputation.subject_key);
            println!("effective_score:        {:.4}", reputation.effective_score);
            println!("probationary:           {}", reputation.probationary);
        }
        if let Some(certification) = input.body.certification.as_ref() {
            println!("certification_state:    {:?}", certification.state);
        }
        for signal in &input.body.signals {
            println!(
                "- {:?} {:?}: {}",
                signal.class, signal.reason, signal.description
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_underwriting_decision_evaluate(
    args: UnderwritingPolicyInputArgs<'_>,
    backend: BudgetQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = build_underwriting_policy_input_query(&args);

    let report = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .underwriting_decision(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "underwriting decision evaluation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        let trusted_kernel_keys = trusted_kernel_keys_from_authority(backend.authority_seed_path)?;
        trust_control::build_underwriting_decision_report(
            receipt_db_path,
            backend.budget_db_path,
            backend.certification_registry_file,
            &query,
            &trusted_kernel_keys,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("generated_at:           {}", report.generated_at);
        println!("outcome:                {:?}", report.outcome);
        println!("risk_class:             {:?}", report.risk_class);
        println!("policy_version:         {}", report.policy.version);
        if let Some(factor) = report.suggested_ceiling_factor {
            println!("ceiling_factor:         {:.2}", factor);
        }
        println!(
            "matching_receipts:      {}",
            report.input.receipts.matching_receipts
        );
        println!("findings:               {}", report.findings.len());
        for finding in &report.findings {
            println!(
                "- {:?} {:?}: {}",
                finding.outcome, finding.reason, finding.description
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_underwriting_decision_simulate(
    args: UnderwritingDecisionSimulateArgs<'_>,
    backend: BudgetQueryBackend<'_>,
) -> Result<(), CliError> {
    let request = chio_kernel::UnderwritingSimulationRequest {
        query: build_underwriting_policy_input_query(&args.input),
        policy: load_underwriting_decision_policy(args.policy_file)?,
    };

    let report = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .simulate_underwriting_decision(&request)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "underwriting simulation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        let trusted_kernel_keys = trusted_kernel_keys_from_authority(backend.authority_seed_path)?;
        trust_control::build_underwriting_simulation_report(
            receipt_db_path,
            backend.budget_db_path,
            backend.certification_registry_file,
            &request,
            &trusted_kernel_keys,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("generated_at:           {}", report.generated_at);
        println!(
            "baseline_outcome:       {:?}",
            report.default_evaluation.outcome
        );
        println!(
            "simulated_outcome:      {:?}",
            report.simulated_evaluation.outcome
        );
        println!("outcome_changed:        {}", report.delta.outcome_changed);
        println!(
            "risk_class_changed:     {}",
            report.delta.risk_class_changed
        );
        println!(
            "matching_receipts:      {}",
            report.input.receipts.matching_receipts
        );
        println!(
            "added_reasons:          {}",
            report.delta.added_reasons.len()
        );
        println!(
            "removed_reasons:        {}",
            report.delta.removed_reasons.len()
        );
    }

    Ok(())
}

pub(crate) fn parse_underwriting_decision_outcome(
    value: &str,
) -> Result<chio_kernel::UnderwritingDecisionOutcome, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::cli_other_error(format!("invalid underwriting outcome `{value}`")))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::items_after_test_module,
    clippy::unwrap_used
)]
mod trust_command_error_classification_tests {
    use super::*;

    #[test]
    fn invalid_underwriting_outcome_literal_is_cli_error() {
        let err = parse_underwriting_decision_outcome("not-a-valid-outcome").unwrap_err();
        match err {
            CliError::Chio(chio) => {
                assert_eq!(chio.code().as_str(), "urn:chio:error:cli:other");
                assert_eq!(chio.domain().as_str(), "cli");
            }
            other => panic!("expected registry-backed CliError::Chio, got: {other:?}"),
        }
    }
}

pub(crate) fn parse_underwriting_lifecycle_state(
    value: &str,
) -> Result<chio_kernel::UnderwritingDecisionLifecycleState, CliError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|_| {
        CliError::policy_constraint_error(format!("invalid underwriting lifecycle state `{value}`"))
    })
}

pub(crate) fn parse_underwriting_appeal_status(
    value: &str,
) -> Result<chio_kernel::UnderwritingAppealStatus, CliError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|_| {
        CliError::policy_constraint_error(format!("invalid underwriting appeal status `{value}`"))
    })
}

pub(crate) fn parse_underwriting_appeal_resolution(
    value: &str,
) -> Result<chio_kernel::UnderwritingAppealResolution, CliError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|_| {
        CliError::policy_constraint_error(format!(
            "invalid underwriting appeal resolution `{value}`"
        ))
    })
}

pub(crate) fn load_underwriting_decision_policy(
    path: &Path,
) -> Result<chio_kernel::UnderwritingDecisionPolicy, CliError> {
    let contents = fs::read_to_string(path)?;
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "yaml" | "yml"))
    {
        Ok(serde_yml::from_str(&contents)?)
    } else if let Ok(policy) = serde_json::from_str(&contents) {
        Ok(policy)
    } else {
        Ok(serde_yml::from_str(&contents)?)
    }
}

pub(crate) fn cmd_trust_underwriting_decision_issue(
    args: UnderwritingDecisionIssueArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let request = trust_control::UnderwritingDecisionIssueRequest {
        query: build_underwriting_policy_input_query(&args.input),
        supersedes_decision_id: args.supersedes_decision_id.map(ToOwned::to_owned),
    };

    let decision = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .issue_underwriting_decision(&request)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "underwriting decision issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_underwriting_decision(
            receipt_db_path,
            backend.budget_db_path,
            backend.authority_seed_path,
            backend.authority_db_path,
            backend.certification_registry_file,
            &request.query,
            request.supersedes_decision_id.as_deref(),
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&decision)?);
    } else {
        println!("schema:                 {}", decision.body.schema);
        println!("decision_id:            {}", decision.body.decision_id);
        println!("issued_at:              {}", decision.body.issued_at);
        println!("signer_key:             {}", decision.signer_key.to_hex());
        println!(
            "outcome:                {:?}",
            decision.body.evaluation.outcome
        );
        println!("review_state:           {:?}", decision.body.review_state);
        println!("budget_action:          {:?}", decision.body.budget.action);
        println!("premium_state:          {:?}", decision.body.premium.state);
    }

    Ok(())
}

pub(crate) fn cmd_trust_underwriting_decision_list(
    args: UnderwritingDecisionListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::UnderwritingDecisionQuery {
        decision_id: args.decision_id.map(ToOwned::to_owned),
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        outcome: args
            .outcome
            .map(parse_underwriting_decision_outcome)
            .transpose()?,
        lifecycle_state: args
            .lifecycle_state
            .map(parse_underwriting_lifecycle_state)
            .transpose()?,
        appeal_status: args
            .appeal_status
            .map(parse_underwriting_appeal_status)
            .transpose()?,
        limit: Some(args.limit),
    };

    let report = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .list_underwriting_decisions(&query)?
    } else {
        let receipt_db_path = backend.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "underwriting decision list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_underwriting_decisions(receipt_db_path, &query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "matching_decisions:     {}",
            report.summary.matching_decisions
        );
        println!(
            "returned_decisions:     {}",
            report.summary.returned_decisions
        );
        println!("open_appeals:           {}", report.summary.open_appeals);
        for row in report.decisions {
            println!(
                "- {} outcome={:?} lifecycle={:?} open_appeals={}",
                row.decision.body.decision_id,
                row.decision.body.evaluation.outcome,
                row.lifecycle_state,
                row.open_appeal_count
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_underwriting_appeal_create(
    decision_id: &str,
    requested_by: &str,
    reason: &str,
    note: Option<&str>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = chio_kernel::UnderwritingAppealCreateRequest {
        decision_id: decision_id.to_string(),
        requested_by: requested_by.to_string(),
        reason: reason.to_string(),
        note: note.map(ToOwned::to_owned),
    };
    let record = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .create_underwriting_appeal(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "underwriting appeal create requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::create_underwriting_appeal(receipt_db_path, &request)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!("appeal_id:              {}", record.appeal_id);
        println!("decision_id:            {}", record.decision_id);
        println!("status:                 {:?}", record.status);
    }

    Ok(())
}

pub(crate) fn cmd_trust_underwriting_appeal_resolve(
    args: UnderwritingAppealResolveArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let request = chio_kernel::UnderwritingAppealResolveRequest {
        appeal_id: args.appeal_id.to_string(),
        resolution: parse_underwriting_appeal_resolution(args.resolution)?,
        resolved_by: args.resolved_by.to_string(),
        note: args.note.map(ToOwned::to_owned),
        replacement_decision_id: args.replacement_decision_id.map(ToOwned::to_owned),
    };
    let record = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .resolve_underwriting_appeal(&request)?
    } else {
        let receipt_db_path = backend.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "underwriting appeal resolve requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::resolve_underwriting_appeal(receipt_db_path, &request)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!("appeal_id:              {}", record.appeal_id);
        println!("status:                 {:?}", record.status);
        if let Some(replacement_decision_id) = record.replacement_decision_id.as_deref() {
            println!("replacement_decision:   {}", replacement_decision_id);
        }
    }

    Ok(())
}
