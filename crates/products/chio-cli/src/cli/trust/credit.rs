use super::*;
use crate::runtime_trust_reports::build_credit_loss_lifecycle_query;

pub(crate) struct CreditLossLifecycleListArgs<'a> {
    pub(crate) event_id: Option<&'a str>,
    pub(crate) bond_id: Option<&'a str>,
    pub(crate) facility_id: Option<&'a str>,
    pub(crate) capability_id: Option<&'a str>,
    pub(crate) agent_subject: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) event_kind: Option<&'a str>,
    pub(crate) limit: usize,
}

pub(crate) struct CreditBacktestExportArgs<'a> {
    pub(crate) agent_subject: &'a str,
    pub(crate) capability_id: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) since: Option<u64>,
    pub(crate) until: Option<u64>,
    pub(crate) receipt_limit: usize,
    pub(crate) decision_limit: usize,
    pub(crate) window_seconds: u64,
    pub(crate) window_count: usize,
    pub(crate) stale_after_seconds: u64,
}

pub(crate) struct ProviderRiskPackageExportArgs<'a> {
    pub(crate) agent_subject: &'a str,
    pub(crate) capability_id: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) since: Option<u64>,
    pub(crate) until: Option<u64>,
    pub(crate) receipt_limit: usize,
    pub(crate) decision_limit: usize,
    pub(crate) recent_loss_limit: usize,
}

pub(crate) fn cmd_trust_credit_loss_lifecycle_evaluate(
    bond_id: &str,
    event_kind: &str,
    amount_units: Option<u64>,
    amount_currency: Option<&str>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query =
        build_credit_loss_lifecycle_query(bond_id, event_kind, amount_units, amount_currency)?;

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .credit_loss_lifecycle_report(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "credit loss lifecycle evaluation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_credit_loss_lifecycle_report(receipt_db_path, &query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                       {}", report.schema);
        println!("generated_at:                 {}", report.generated_at);
        println!("bond_id:                      {}", report.summary.bond_id);
        println!(
            "event_kind:                   {:?}",
            report.query.event_kind
        );
        println!(
            "current_bond_lifecycle:       {:?}",
            report.summary.current_bond_lifecycle_state
        );
        println!(
            "projected_bond_lifecycle:     {:?}",
            report.summary.projected_bond_lifecycle_state
        );
        println!(
            "outstanding_delinquent_units: {}",
            report
                .summary
                .outstanding_delinquent_amount
                .as_ref()
                .map(|amount| amount.units)
                .unwrap_or(0)
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_credit_loss_lifecycle_issue(
    bond_id: &str,
    event_kind: &str,
    amount_units: Option<u64>,
    amount_currency: Option<&str>,
    authority_chain_file: Option<&Path>,
    execution_window_file: Option<&Path>,
    rail_file: Option<&Path>,
    observed_execution_file: Option<&Path>,
    appeal_window_ends_at: Option<u64>,
    description: Option<&str>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = trust_control::CreditLossLifecycleIssueRequest {
        query: build_credit_loss_lifecycle_query(
            bond_id,
            event_kind,
            amount_units,
            amount_currency,
        )?,
        authority_chain: authority_chain_file
            .map(load_json_or_yaml::<Vec<chio_kernel::CapitalExecutionAuthorityStep>>)
            .transpose()?
            .unwrap_or_default(),
        execution_window: execution_window_file
            .map(load_json_or_yaml::<chio_kernel::CapitalExecutionWindow>)
            .transpose()?,
        rail: rail_file
            .map(load_json_or_yaml::<chio_kernel::CapitalExecutionRail>)
            .transpose()?,
        observed_execution: observed_execution_file
            .map(load_json_or_yaml::<chio_kernel::CapitalExecutionObservation>)
            .transpose()?,
        appeal_window_ends_at,
        description: description.map(ToOwned::to_owned),
    };

    let event = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .issue_credit_loss_lifecycle(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "credit loss lifecycle issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_credit_loss_lifecycle(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&event)?);
    } else {
        println!("schema:                       {}", event.body.schema);
        println!("event_id:                     {}", event.body.event_id);
        println!("bond_id:                      {}", event.body.bond_id);
        println!("issued_at:                    {}", event.body.issued_at);
        println!("event_kind:                   {:?}", event.body.event_kind);
        println!(
            "projected_bond_lifecycle:     {:?}",
            event.body.projected_bond_lifecycle_state
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_credit_loss_lifecycle_list(
    args: CreditLossLifecycleListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::CreditLossLifecycleListQuery {
        event_id: args.event_id.map(ToOwned::to_owned),
        bond_id: args.bond_id.map(ToOwned::to_owned),
        facility_id: args.facility_id.map(ToOwned::to_owned),
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        event_kind: args
            .event_kind
            .map(parse_credit_loss_lifecycle_event_kind)
            .transpose()?,
        limit: Some(args.limit),
    };

    let report = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .list_credit_loss_lifecycle(&query)?
    } else {
        let receipt_db_path = backend.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "credit loss lifecycle list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_credit_loss_lifecycle(receipt_db_path, &query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "matching_events:              {}",
            report.summary.matching_events
        );
        println!(
            "returned_events:              {}",
            report.summary.returned_events
        );
        println!(
            "delinquency_events:           {}",
            report.summary.delinquency_events
        );
        println!(
            "recovery_events:              {}",
            report.summary.recovery_events
        );
        println!(
            "reserve_release_events:       {}",
            report.summary.reserve_release_events
        );
        println!(
            "reserve_slash_events:         {}",
            report.summary.reserve_slash_events
        );
        println!(
            "write_off_events:             {}",
            report.summary.write_off_events
        );
        for row in report.events {
            println!(
                "- {} kind={:?} bond={} projected={:?}",
                row.event.body.event_id,
                row.event.body.event_kind,
                row.event.body.bond_id,
                row.event.body.projected_bond_lifecycle_state
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_credit_backtest_export(
    args: CreditBacktestExportArgs<'_>,
    backend: BudgetQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::CreditBacktestQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: Some(args.agent_subject.to_string()),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        receipt_limit: Some(args.receipt_limit),
        decision_limit: Some(args.decision_limit),
        window_seconds: Some(args.window_seconds),
        window_count: Some(args.window_count),
        stale_after_seconds: Some(args.stale_after_seconds),
    };

    let report = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.credit_backtest(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "credit backtest export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        let trusted_kernel_keys = trusted_kernel_keys_from_authority(backend.authority_seed_path)?;
        trust_control::build_credit_backtest_report(
            receipt_db_path,
            backend.budget_db_path,
            backend.certification_registry_file,
            None,
            &query,
            &trusted_kernel_keys,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("generated_at:           {}", report.generated_at);
        println!("subject_key:            {}", args.agent_subject);
        println!(
            "windows_evaluated:      {}",
            report.summary.windows_evaluated
        );
        println!("drift_windows:          {}", report.summary.drift_windows);
        println!(
            "manual_review_windows:  {}",
            report.summary.manual_review_windows
        );
        println!("denied_windows:         {}", report.summary.denied_windows);
        println!(
            "over_utilized_windows:  {}",
            report.summary.over_utilized_windows
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_provider_risk_package_export(
    args: ProviderRiskPackageExportArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::CreditProviderRiskPackageQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: Some(args.agent_subject.to_string()),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        receipt_limit: Some(args.receipt_limit),
        decision_limit: Some(args.decision_limit),
        recent_loss_limit: Some(args.recent_loss_limit),
    };

    let report = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .credit_provider_risk_package(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "provider risk package export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_signed_credit_provider_risk_package(
            receipt_db_path,
            backend.budget_db_path,
            backend.authority_seed_path,
            backend.authority_db_path,
            backend.certification_registry_file,
            None,
            &query,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.body.schema);
        println!("generated_at:           {}", report.body.generated_at);
        println!("subject_key:            {}", report.body.subject_key);
        println!("signer_key:             {}", report.signer_key.to_hex());
        println!(
            "facility_disposition:   {:?}",
            report.body.facility_report.disposition
        );
        println!(
            "score_band:             {:?}",
            report.body.scorecard.body.summary.band
        );
        println!(
            "recent_loss_events:     {}",
            report.body.recent_loss_history.summary.matching_loss_events
        );
    }

    Ok(())
}

pub(crate) fn parse_credit_facility_disposition(
    value: &str,
) -> Result<chio_kernel::CreditFacilityDisposition, CliError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|_| {
        CliError::policy_constraint_error(format!("invalid credit facility disposition `{value}`"))
    })
}

pub(crate) fn parse_credit_facility_lifecycle_state(
    value: &str,
) -> Result<chio_kernel::CreditFacilityLifecycleState, CliError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|_| {
        CliError::policy_constraint_error(format!(
            "invalid credit facility lifecycle state `{value}`"
        ))
    })
}

pub(crate) fn parse_credit_bond_disposition(
    value: &str,
) -> Result<chio_kernel::CreditBondDisposition, CliError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|_| {
        CliError::policy_constraint_error(format!("invalid credit bond disposition `{value}`"))
    })
}

pub(crate) fn parse_credit_bond_lifecycle_state(
    value: &str,
) -> Result<chio_kernel::CreditBondLifecycleState, CliError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|_| {
        CliError::policy_constraint_error(format!("invalid credit bond lifecycle state `{value}`"))
    })
}

pub(crate) fn parse_credit_loss_lifecycle_event_kind(
    value: &str,
) -> Result<chio_kernel::CreditLossLifecycleEventKind, CliError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|_| {
        CliError::policy_constraint_error(format!(
            "invalid credit loss lifecycle event kind `{value}`"
        ))
    })
}

pub(crate) fn load_credit_bonded_execution_control_policy(
    path: &Path,
) -> Result<chio_kernel::CreditBondedExecutionControlPolicy, CliError> {
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
