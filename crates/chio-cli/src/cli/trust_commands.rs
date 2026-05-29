use super::*;

pub(crate) struct QueryBackend<'a> {
    pub(crate) json_output: bool,
    pub(crate) receipt_db_path: Option<&'a Path>,
    pub(crate) control_url: Option<&'a str>,
    pub(crate) control_token: Option<&'a str>,
}

/// Derive a trusted-kernel-key list from an authority seed file. Returns the
/// loaded public key (so locally signed receipts can pass reputation integrity
/// validation) or an empty vec when no seed file is configured. See
/// `chio-reputation::receipt_integrity_valid`.
pub(crate) fn trusted_kernel_keys_from_authority(
    authority_seed_path: Option<&Path>,
) -> Result<Vec<String>, CliError> {
    let Some(path) = authority_seed_path else {
        return Ok(Vec::new());
    };
    let keypair = load_or_create_authority_keypair(path)?;
    Ok(vec![keypair.public_key().to_hex()])
}

pub(crate) struct BudgetQueryBackend<'a> {
    pub(crate) query: QueryBackend<'a>,
    pub(crate) budget_db_path: Option<&'a Path>,
    pub(crate) certification_registry_file: Option<&'a Path>,
    /// Optional authority seed file used to derive the trusted kernel key
    /// for local reputation scoring. Plumbing this through means receipts
    /// signed by the local kernel are not silently filtered out as unsigned.
    /// See `chio-reputation::receipt_integrity_valid`.
    pub(crate) authority_seed_path: Option<&'a Path>,
}

pub(crate) struct SignedQueryBackend<'a> {
    pub(crate) query: QueryBackend<'a>,
    pub(crate) budget_db_path: Option<&'a Path>,
    pub(crate) authority_seed_path: Option<&'a Path>,
    pub(crate) authority_db_path: Option<&'a Path>,
    pub(crate) certification_registry_file: Option<&'a Path>,
}

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

pub(crate) struct LiabilityMarketListArgs<'a> {
    pub(crate) quote_request_id: Option<&'a str>,
    pub(crate) provider_id: Option<&'a str>,
    pub(crate) agent_subject: Option<&'a str>,
    pub(crate) jurisdiction: Option<&'a str>,
    pub(crate) coverage_class: Option<&'a str>,
    pub(crate) currency: Option<&'a str>,
    pub(crate) limit: usize,
}

pub(crate) struct LiabilityClaimsListArgs<'a> {
    pub(crate) claim_id: Option<&'a str>,
    pub(crate) provider_id: Option<&'a str>,
    pub(crate) agent_subject: Option<&'a str>,
    pub(crate) jurisdiction: Option<&'a str>,
    pub(crate) policy_number: Option<&'a str>,
    pub(crate) limit: usize,
}

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

pub(crate) struct ReceiptListArgs<'a> {
    pub(crate) capability: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) outcome: Option<&'a str>,
    pub(crate) since: Option<u64>,
    pub(crate) until: Option<u64>,
    pub(crate) min_cost: Option<u64>,
    pub(crate) max_cost: Option<u64>,
    pub(crate) limit: usize,
    pub(crate) cursor: Option<u64>,
    pub(crate) tenant: Option<&'a str>,
    pub(crate) admin_all: bool,
}

pub(crate) struct ReceiptExplainArgs<'a> {
    pub(crate) receipt_id: &'a str,
    pub(crate) input_file: Option<&'a Path>,
    pub(crate) depth: usize,
    pub(crate) fanout_limit: usize,
    /// Inspect-only: the CLI does not carry the org A / org B passport
    /// public keys and cannot perform real Ed25519 verification, so the
    /// trace reports structural / schema checks only. The legacy CLI flag
    /// spelling is preserved as a `clap` alias on the parent enum.
    pub(crate) inspect_bilateral: bool,
    pub(crate) tenant: Option<&'a str>,
    pub(crate) admin_all: bool,
}

pub(crate) const CHIO_CLI_RECEIPT_HEALTH_SCHEMA: &str = "chio.cli.receipt.health.v1";
pub(crate) const CHIO_CLI_RECEIPT_FLUSH_SCHEMA: &str = "chio.cli.receipt.flush.v1";
pub(crate) const CHIO_CLI_RECEIPT_CHECKPOINT_STATUS_SCHEMA: &str =
    "chio.cli.receipt.checkpoint_status.v1";
pub(crate) const CHIO_CLI_RECEIPT_CHECKPOINT_CREATE_SCHEMA: &str =
    "chio.cli.receipt.checkpoint_create.v1";
pub(crate) const CHIO_CLI_RECEIPT_CHECKPOINT_VERIFY_SCHEMA: &str =
    "chio.cli.receipt.checkpoint_verify.v1";

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReceiptOperatorJsonEnvelope<'a, T>
where
    T: serde::Serialize + ?Sized,
{
    schema: &'static str,
    report: &'a T,
}

pub(crate) fn receipt_operator_json_value<T>(
    schema: &'static str,
    report: &T,
) -> Result<serde_json::Value, CliError>
where
    T: serde::Serialize + ?Sized,
{
    Ok(serde_json::to_value(ReceiptOperatorJsonEnvelope {
        schema,
        report,
    })?)
}

pub(crate) fn print_receipt_operator_json<T>(
    schema: &'static str,
    report: &T,
) -> Result<(), CliError>
where
    T: serde::Serialize + ?Sized,
{
    println!(
        "{}",
        serde_json::to_string_pretty(&receipt_operator_json_value(schema, report)?)?
    );
    Ok(())
}

pub(crate) fn optional_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

pub(crate) fn push_writer_counters_human(
    lines: &mut Vec<String>,
    writer: &chio_kernel::ReceiptWriterCounters,
) {
    lines.push(format!("writer_accepted_total: {}", writer.accepted_total));
    lines.push(format!("writer_committed_total: {}", writer.committed_total));
    lines.push(format!("writer_failed_total: {}", writer.failed_total));
    lines.push(format!("writer_saturated_total: {}", writer.saturated_total));
    lines.push(format!("writer_inflight: {}", writer.inflight));
    lines.push(format!(
        "writer_last_commit_unix_ms: {}",
        optional_u64(writer.last_commit_unix_ms)
    ));
    lines.push(format!(
        "writer_last_error: {}",
        writer.last_error.as_deref().unwrap_or("none")
    ));
}

pub(crate) fn render_receipt_health_human(report: &chio_kernel::ReceiptStoreHealthReport) -> String {
    let mut lines = vec![
        format!(
            "status: {}",
            if report.healthy {
                "healthy"
            } else {
                "unhealthy"
            }
        ),
        format!("committed_entry_seq: {}", report.latest_committed_entry_seq),
        format!("checkpoint_seq: {}", optional_u64(report.latest_checkpoint_seq)),
        format!(
            "checkpointed_entry_seq: {}",
            report.latest_checkpointed_entry_seq
        ),
    ];
    if let (Some(start), Some(end)) = (
        report.uncheckpointed_start_seq,
        report.uncheckpointed_end_seq,
    ) {
        lines.push(format!("uncheckpointed_range: {start}..={end}"));
    }
    push_writer_counters_human(&mut lines, &report.writer);
    lines.push(format!(
        "db_size_bytes: {}",
        optional_u64(report.db_size_bytes)
    ));
    if let Some(error) = report.checkpoint_error.as_deref() {
        lines.push(format!("checkpoint_error: {error}"));
    }
    lines.join("\n") + "\n"
}

pub(crate) fn render_receipt_flush_human(report: &chio_kernel::ReceiptFlushReport) -> String {
    let mut lines = vec![
        "flushed: true".to_string(),
        format!("committed_entry_seq: {}", report.latest_committed_entry_seq),
        format!("checkpoint_seq: {}", optional_u64(report.latest_checkpoint_seq)),
        format!(
            "checkpointed_entry_seq: {}",
            report.latest_checkpointed_entry_seq
        ),
    ];
    if let (Some(start), Some(end)) = (
        report.uncheckpointed_start_seq,
        report.uncheckpointed_end_seq,
    ) {
        lines.push(format!("uncheckpointed_range: {start}..={end}"));
    }
    push_writer_counters_human(&mut lines, &report.writer);
    lines.push(format!(
        "db_size_bytes: {}",
        optional_u64(report.db_size_bytes)
    ));
    if let Some(wal) = &report.wal_checkpoint {
        lines.push(format!("wal_checkpoint_busy: {}", wal.busy));
        lines.push(format!("wal_checkpoint_log_frames: {}", wal.log_frames));
        lines.push(format!(
            "wal_checkpoint_checkpointed_frames: {}",
            wal.checkpointed_frames
        ));
    } else {
        lines.push("wal_checkpoint_busy: none".to_string());
        lines.push("wal_checkpoint_log_frames: none".to_string());
        lines.push("wal_checkpoint_checkpointed_frames: none".to_string());
    }
    lines.join("\n") + "\n"
}

pub(crate) fn render_receipt_checkpoint_status_human(
    report: &chio_kernel::ReceiptCheckpointStatusReport,
) -> String {
    let mut lines = vec![
        format!(
            "status: {}",
            if report.healthy {
                "healthy"
            } else {
                "unhealthy"
            }
        ),
        format!("committed_entry_seq: {}", report.latest_committed_entry_seq),
        format!("checkpoint_seq: {}", optional_u64(report.latest_checkpoint_seq)),
        format!(
            "checkpointed_entry_seq: {}",
            report.latest_checkpointed_entry_seq
        ),
    ];
    if let Some(range) = &report.next_range {
        lines.push(format!("next_range: {}..={}", range.start_seq, range.end_seq));
    } else {
        lines.push("next_range: none".to_string());
    }
    if let Some(error) = report.checkpoint_error.as_deref() {
        lines.push(format!("checkpoint_error: {error}"));
    }
    lines.join("\n") + "\n"
}

pub(crate) fn render_receipt_checkpoint_create_human(
    report: &chio_kernel::ReceiptCheckpointCreateReport,
) -> String {
    let mut lines = vec![
        format!("created: {}", report.created),
        format!("checkpoint_seq: {}", optional_u64(report.checkpoint_seq)),
    ];
    if let (Some(start), Some(end)) = (report.batch_start_seq, report.batch_end_seq) {
        lines.push(format!("checkpoint_range: {start}..={end}"));
    } else {
        lines.push("checkpoint_range: none".to_string());
    }
    lines.push(format!(
        "committed_entry_seq: {}",
        report.latest_committed_entry_seq
    ));
    lines.push(format!(
        "checkpointed_entry_seq: {}",
        report.latest_checkpointed_entry_seq
    ));
    lines.join("\n") + "\n"
}

pub(crate) fn receipt_checkpoint_report_error(
    report: &chio_kernel::ReceiptCheckpointStatusReport,
) -> CliError {
    CliError::cli_other_error(
        report
            .checkpoint_error
            .as_deref()
            .unwrap_or("receipt checkpoint verification failed")
            .to_string(),
    )
}

pub(crate) fn receipt_health_report_error(report: &chio_kernel::ReceiptStoreHealthReport) -> CliError {
    CliError::cli_other_error(
        report
            .checkpoint_error
            .as_deref()
            .unwrap_or("receipt store health check failed")
            .to_string(),
    )
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
        trust_control::build_client(url, token)?.credit_loss_lifecycle_report(&query)?
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
        trust_control::build_client(url, token)?.issue_credit_loss_lifecycle(&request)?
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
        trust_control::build_client(url, token)?.list_credit_loss_lifecycle(&query)?
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
        trust_control::build_client(url, token)?.credit_backtest(&query)?
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
        trust_control::build_client(url, token)?.credit_provider_risk_package(&query)?
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

pub(crate) fn cmd_trust_liability_provider_issue(
    input_file: &Path,
    supersedes_provider_record_id: Option<&str>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let report = load_liability_provider_report(input_file)?;
    let provider = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let request = trust_control::LiabilityProviderIssueRequest {
            report,
            supersedes_provider_record_id: supersedes_provider_record_id.map(ToOwned::to_owned),
        };
        trust_control::build_client(url, token)?.issue_liability_provider(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability provider issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_provider(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &report,
            supersedes_provider_record_id,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&provider)?);
    } else {
        println!("provider_record_id: {}", provider.body.provider_record_id);
        println!("provider_id:        {}", provider.body.report.provider_id);
        println!("display_name:       {}", provider.body.report.display_name);
        println!("lifecycle_state:    {:?}", provider.body.lifecycle_state);
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_provider_list(
    provider_id: Option<&str>,
    jurisdiction: Option<&str>,
    coverage_class: Option<&str>,
    currency: Option<&str>,
    lifecycle_state: Option<&str>,
    limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = chio_kernel::LiabilityProviderListQuery {
        provider_id: provider_id.map(ToOwned::to_owned),
        jurisdiction: jurisdiction.map(ToOwned::to_owned),
        coverage_class: coverage_class
            .map(parse_liability_coverage_class)
            .transpose()?,
        currency: currency.map(ToOwned::to_owned),
        lifecycle_state: lifecycle_state
            .map(parse_liability_provider_lifecycle_state)
            .transpose()?,
        limit: Some(limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.list_liability_providers(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability provider list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_liability_providers(receipt_db_path, &query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("providers: {}", report.summary.returned_providers);
        for row in report.providers {
            println!(
                "- {} [{}] lifecycle={:?}",
                row.provider.body.report.provider_id,
                row.provider.body.report.display_name,
                row.lifecycle_state
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_provider_resolve(
    provider_id: &str,
    jurisdiction: &str,
    coverage_class: &str,
    currency: &str,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = chio_kernel::LiabilityProviderResolutionQuery {
        provider_id: provider_id.to_string(),
        jurisdiction: jurisdiction.to_string(),
        coverage_class: parse_liability_coverage_class(coverage_class)?,
        currency: currency.to_string(),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.resolve_liability_provider(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability provider resolution requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::resolve_liability_provider(receipt_db_path, &query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "provider_id:        {}",
            report.provider.body.report.provider_id
        );
        println!(
            "display_name:       {}",
            report.provider.body.report.display_name
        );
        println!("jurisdiction:       {}", report.matched_policy.jurisdiction);
        println!(
            "coverage_classes:   {}",
            serde_json::to_string(&report.matched_policy.coverage_classes)?
        );
        println!(
            "currencies:         {}",
            serde_json::to_string(&report.matched_policy.supported_currencies)?
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_quote_request_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_quote_request_issue_request(input_file)?;
    let quote_request = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_quote_request(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability quote request issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_quote_request(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&quote_request)?);
    } else {
        println!(
            "quote_request_id:      {}",
            quote_request.body.quote_request_id
        );
        println!(
            "provider_id:           {}",
            quote_request.body.provider_policy.provider_id
        );
        println!(
            "jurisdiction:          {}",
            quote_request.body.provider_policy.jurisdiction
        );
        println!(
            "coverage_class:        {:?}",
            quote_request.body.provider_policy.coverage_class
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_quote_response_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_quote_response_issue_request(input_file)?;
    let quote_response = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_quote_response(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability quote response issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_quote_response(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&quote_response)?);
    } else {
        println!(
            "quote_response_id:     {}",
            quote_response.body.quote_response_id
        );
        println!(
            "quote_request_id:      {}",
            quote_response.body.quote_request.body.quote_request_id
        );
        println!(
            "disposition:           {:?}",
            quote_response.body.disposition
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_pricing_authority_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_pricing_authority_issue_request(input_file)?;
    let authority = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_pricing_authority(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability pricing authority issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_pricing_authority(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&authority)?);
    } else {
        println!("authority_id:          {}", authority.body.authority_id);
        println!(
            "quote_request_id:      {}",
            authority.body.quote_request.body.quote_request_id
        );
        println!("expires_at:            {}", authority.body.expires_at);
        println!(
            "auto_bind_enabled:     {}",
            authority.body.auto_bind_enabled
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_placement_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_placement_issue_request(input_file)?;
    let placement = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_placement(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability placement issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_placement(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&placement)?);
    } else {
        println!("placement_id:          {}", placement.body.placement_id);
        println!(
            "quote_response_id:     {}",
            placement.body.quote_response.body.quote_response_id
        );
        println!("effective_from:        {}", placement.body.effective_from);
        println!("effective_until:       {}", placement.body.effective_until);
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_bound_coverage_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_bound_coverage_issue_request(input_file)?;
    let bound = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_bound_coverage(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability bound coverage issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_bound_coverage(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&bound)?);
    } else {
        println!("bound_coverage_id:     {}", bound.body.bound_coverage_id);
        println!(
            "placement_id:          {}",
            bound.body.placement.body.placement_id
        );
        println!("policy_number:         {}", bound.body.policy_number);
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_auto_bind_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_auto_bind_issue_request(input_file)?;
    let decision = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_auto_bind(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability auto-bind issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_auto_bind(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&decision)?);
    } else {
        println!("decision_id:           {}", decision.body.decision_id);
        println!("disposition:           {:?}", decision.body.disposition);
        println!(
            "authority_id:          {}",
            decision.body.authority.body.authority_id
        );
        println!(
            "placement_id:          {}",
            decision
                .body
                .placement
                .as_ref()
                .map(|placement| placement.body.placement_id.as_str())
                .unwrap_or("-"),
        );
        println!(
            "bound_coverage_id:     {}",
            decision
                .body
                .bound_coverage
                .as_ref()
                .map(|bound| bound.body.bound_coverage_id.as_str())
                .unwrap_or("-"),
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_issue_request(input_file)?;
    let claim = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_claim_package(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_package(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&claim)?);
    } else {
        println!("claim_id:              {}", claim.body.claim_id);
        println!(
            "bound_coverage_id:     {}",
            claim.body.bound_coverage.body.bound_coverage_id
        );
        println!("claimant:              {}", claim.body.claimant);
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_response_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_response_issue_request(input_file)?;
    let response = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_claim_response(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim response issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_response(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("claim_response_id:     {}", response.body.claim_response_id);
        println!(
            "claim_id:              {}",
            response.body.claim.body.claim_id
        );
        println!("disposition:           {:?}", response.body.disposition);
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_dispute_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_dispute_issue_request(input_file)?;
    let dispute = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_claim_dispute(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim dispute issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_dispute(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&dispute)?);
    } else {
        println!("dispute_id:            {}", dispute.body.dispute_id);
        println!(
            "claim_response_id:     {}",
            dispute.body.provider_response.body.claim_response_id
        );
        println!("opened_by:             {}", dispute.body.opened_by);
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_adjudication_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_adjudication_issue_request(input_file)?;
    let adjudication = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_claim_adjudication(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim adjudication issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_adjudication(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&adjudication)?);
    } else {
        println!(
            "adjudication_id:       {}",
            adjudication.body.adjudication_id
        );
        println!(
            "dispute_id:            {}",
            adjudication.body.dispute.body.dispute_id
        );
        println!("outcome:               {:?}", adjudication.body.outcome);
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_payout_instruction_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_payout_instruction_issue_request(input_file)?;
    let payout_instruction = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?
            .issue_liability_claim_payout_instruction(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim payout instruction issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_payout_instruction(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&payout_instruction)?);
    } else {
        println!(
            "payout_instruction_id: {}",
            payout_instruction.body.payout_instruction_id
        );
        println!(
            "adjudication_id:       {}",
            payout_instruction.body.adjudication.body.adjudication_id
        );
        println!(
            "capital_instruction_id:{}",
            payout_instruction
                .body
                .capital_instruction
                .body
                .instruction_id
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_payout_receipt_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_payout_receipt_issue_request(input_file)?;
    let payout_receipt = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_claim_payout_receipt(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim payout receipt issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_payout_receipt(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&payout_receipt)?);
    } else {
        println!(
            "payout_receipt_id:     {}",
            payout_receipt.body.payout_receipt_id
        );
        println!(
            "payout_instruction_id: {}",
            payout_receipt
                .body
                .payout_instruction
                .body
                .payout_instruction_id
        );
        println!(
            "reconciliation_state:  {:?}",
            payout_receipt.body.reconciliation_state
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_settlement_instruction_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_settlement_instruction_issue_request(input_file)?;
    let settlement_instruction = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?
            .issue_liability_claim_settlement_instruction(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim settlement instruction issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_settlement_instruction(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&settlement_instruction)?);
    } else {
        println!(
            "settlement_instruction_id: {}",
            settlement_instruction.body.settlement_instruction_id
        );
        println!(
            "payout_receipt_id:        {}",
            settlement_instruction
                .body
                .payout_receipt
                .body
                .payout_receipt_id
        );
        println!(
            "settlement_kind:          {:?}",
            settlement_instruction.body.settlement_kind
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_settlement_receipt_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_settlement_receipt_issue_request(input_file)?;
    let settlement_receipt = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?
            .issue_liability_claim_settlement_receipt(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim settlement receipt issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_settlement_receipt(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&settlement_receipt)?);
    } else {
        println!(
            "settlement_receipt_id:    {}",
            settlement_receipt.body.settlement_receipt_id
        );
        println!(
            "settlement_instruction_id:{}",
            settlement_receipt
                .body
                .settlement_instruction
                .body
                .settlement_instruction_id
        );
        println!(
            "reconciliation_state:     {:?}",
            settlement_receipt.body.reconciliation_state
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_market_list(
    args: LiabilityMarketListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::LiabilityMarketWorkflowQuery {
        quote_request_id: args.quote_request_id.map(ToOwned::to_owned),
        provider_id: args.provider_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        jurisdiction: args.jurisdiction.map(ToOwned::to_owned),
        coverage_class: args
            .coverage_class
            .map(parse_liability_coverage_class)
            .transpose()?,
        currency: args.currency.map(ToOwned::to_owned),
        limit: Some(args.limit),
    };

    let report = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::build_client(url, token)?.liability_market_workflows(&query)?
    } else {
        let receipt_db_path = backend.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability market list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_liability_market_workflows(receipt_db_path, &query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "matching_requests:     {}",
            report.summary.matching_requests
        );
        println!(
            "returned_requests:     {}",
            report.summary.returned_requests
        );
        println!("quote_responses:       {}", report.summary.quote_responses);
        println!(
            "pricing_authorities:   {}",
            report.summary.pricing_authorities
        );
        println!(
            "auto_bind_decisions:   {}",
            report.summary.auto_bind_decisions
        );
        println!(
            "auto_bound_decisions:  {}",
            report.summary.auto_bound_decisions
        );
        println!("placements:            {}", report.summary.placements);
        println!("bound_coverages:       {}", report.summary.bound_coverages);
        for workflow in report.workflows {
            println!(
                "- {} provider={} response={} authority={} auto_bind={} placement={} bound={}",
                workflow.quote_request.body.quote_request_id,
                workflow.quote_request.body.provider_policy.provider_id,
                workflow
                    .latest_quote_response
                    .as_ref()
                    .map(|response| response.body.quote_response_id.as_str())
                    .unwrap_or("-"),
                workflow
                    .pricing_authority
                    .as_ref()
                    .map(|authority| authority.body.authority_id.as_str())
                    .unwrap_or("-"),
                workflow
                    .latest_auto_bind_decision
                    .as_ref()
                    .map(|decision| decision.body.decision_id.as_str())
                    .unwrap_or("-"),
                workflow
                    .placement
                    .as_ref()
                    .map(|placement| placement.body.placement_id.as_str())
                    .unwrap_or("-"),
                workflow
                    .bound_coverage
                    .as_ref()
                    .map(|bound| bound.body.bound_coverage_id.as_str())
                    .unwrap_or("-"),
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claims_list(
    args: LiabilityClaimsListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::LiabilityClaimWorkflowQuery {
        claim_id: args.claim_id.map(ToOwned::to_owned),
        provider_id: args.provider_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        jurisdiction: args.jurisdiction.map(ToOwned::to_owned),
        policy_number: args.policy_number.map(ToOwned::to_owned),
        limit: Some(args.limit),
    };

    let report = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::build_client(url, token)?.liability_claim_workflows(&query)?
    } else {
        let receipt_db_path = backend.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claims list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_liability_claim_workflows(receipt_db_path, &query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("matching_claims:       {}", report.summary.matching_claims);
        println!("returned_claims:       {}", report.summary.returned_claims);
        println!(
            "provider_responses:    {}",
            report.summary.provider_responses
        );
        println!(
            "accepted_responses:    {}",
            report.summary.accepted_responses
        );
        println!("denied_responses:      {}", report.summary.denied_responses);
        println!("disputes:              {}", report.summary.disputes);
        println!("adjudications:         {}", report.summary.adjudications);
        println!(
            "payout_instructions:   {}",
            report.summary.payout_instructions
        );
        println!("payout_receipts:       {}", report.summary.payout_receipts);
        println!(
            "matched_payouts:       {}",
            report.summary.matched_payout_receipts
        );
        println!(
            "mismatched_payouts:    {}",
            report.summary.mismatched_payout_receipts
        );
        println!(
            "settlement_instructions:{}",
            report.summary.settlement_instructions
        );
        println!(
            "settlement_receipts:   {}",
            report.summary.settlement_receipts
        );
        println!(
            "matched_settlements:   {}",
            report.summary.matched_settlement_receipts
        );
        println!(
            "mismatched_settlements:{}",
            report.summary.mismatched_settlement_receipts
        );
        println!(
            "counterparty_mismatch_settlements:{}",
            report.summary.counterparty_mismatch_settlement_receipts
        );
        for claim in report.claims {
            println!(
                "- {} policy={} response={} dispute={} adjudication={} payout_instruction={} payout_receipt={} settlement_instruction={} settlement_receipt={}",
                claim.claim.body.claim_id,
                claim.claim.body.bound_coverage.body.policy_number,
                claim.provider_response
                    .as_ref()
                    .map(|response| response.body.claim_response_id.as_str())
                    .unwrap_or("-"),
                claim.dispute
                    .as_ref()
                    .map(|dispute| dispute.body.dispute_id.as_str())
                    .unwrap_or("-"),
                claim.adjudication
                    .as_ref()
                    .map(|adjudication| adjudication.body.adjudication_id.as_str())
                    .unwrap_or("-"),
                claim.payout_instruction
                    .as_ref()
                    .map(|instruction| instruction.body.payout_instruction_id.as_str())
                    .unwrap_or("-"),
                claim.payout_receipt
                    .as_ref()
                    .map(|receipt| receipt.body.payout_receipt_id.as_str())
                    .unwrap_or("-"),
                claim.settlement_instruction
                    .as_ref()
                    .map(|instruction| instruction.body.settlement_instruction_id.as_str())
                    .unwrap_or("-"),
                claim.settlement_receipt
                    .as_ref()
                    .map(|receipt| receipt.body.settlement_receipt_id.as_str())
                    .unwrap_or("-"),
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_underwriting_input_export(
    args: UnderwritingPolicyInputArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = build_underwriting_policy_input_query(&args);

    let input = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::build_client(url, token)?.underwriting_policy_input(&query)?
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
        trust_control::build_client(url, token)?.underwriting_decision(&query)?
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
        trust_control::build_client(url, token)?.simulate_underwriting_decision(&request)?
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

pub(crate) fn parse_credit_facility_disposition(
    value: &str,
) -> Result<chio_kernel::CreditFacilityDisposition, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::policy_constraint_error(format!("invalid credit facility disposition `{value}`")))
}

pub(crate) fn parse_credit_facility_lifecycle_state(
    value: &str,
) -> Result<chio_kernel::CreditFacilityLifecycleState, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::policy_constraint_error(format!("invalid credit facility lifecycle state `{value}`")))
}

pub(crate) fn parse_credit_bond_disposition(
    value: &str,
) -> Result<chio_kernel::CreditBondDisposition, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::policy_constraint_error(format!("invalid credit bond disposition `{value}`")))
}

pub(crate) fn parse_credit_bond_lifecycle_state(
    value: &str,
) -> Result<chio_kernel::CreditBondLifecycleState, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::policy_constraint_error(format!("invalid credit bond lifecycle state `{value}`")))
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

pub(crate) fn parse_underwriting_lifecycle_state(
    value: &str,
) -> Result<chio_kernel::UnderwritingDecisionLifecycleState, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::policy_constraint_error(format!("invalid underwriting lifecycle state `{value}`")))
}

pub(crate) fn parse_underwriting_appeal_status(
    value: &str,
) -> Result<chio_kernel::UnderwritingAppealStatus, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::policy_constraint_error(format!("invalid underwriting appeal status `{value}`")))
}

pub(crate) fn parse_underwriting_appeal_resolution(
    value: &str,
) -> Result<chio_kernel::UnderwritingAppealResolution, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::policy_constraint_error(format!("invalid underwriting appeal resolution `{value}`")))
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

pub(crate) fn load_json_or_yaml<T: DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    let contents = fs::read_to_string(path)?;
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "yaml" | "yml"))
    {
        Ok(serde_yml::from_str(&contents)?)
    } else if let Ok(value) = serde_json::from_str(&contents) {
        Ok(value)
    } else {
        Ok(serde_yml::from_str(&contents)?)
    }
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

pub(crate) fn load_liability_provider_report(
    path: &Path,
) -> Result<chio_kernel::LiabilityProviderReport, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_quote_request_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityQuoteRequestIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_quote_response_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityQuoteResponseIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_pricing_authority_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityPricingAuthorityIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_placement_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityPlacementIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_bound_coverage_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityBoundCoverageIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_auto_bind_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityAutoBindIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimPackageIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_response_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimResponseIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_dispute_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimDisputeIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_adjudication_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimAdjudicationIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_payout_instruction_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimPayoutInstructionIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_payout_receipt_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimPayoutReceiptIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_settlement_instruction_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimSettlementInstructionIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_settlement_receipt_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimSettlementReceiptIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn parse_liability_coverage_class(
    value: &str,
) -> Result<chio_kernel::LiabilityCoverageClass, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::policy_constraint_error(format!("invalid liability coverage class `{value}`")))
}

pub(crate) fn parse_liability_provider_lifecycle_state(
    value: &str,
) -> Result<chio_kernel::LiabilityProviderLifecycleState, CliError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|_| {
        CliError::policy_constraint_error(format!(
            "invalid liability provider lifecycle state `{value}`"
        ))
    })
}

pub(crate) fn parse_governed_autonomy_tier(value: &str) -> Result<GovernedAutonomyTier, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::policy_constraint_error(format!("invalid governed autonomy tier `{value}`")))
}

pub(crate) fn parse_runtime_assurance_tier(value: &str) -> Result<RuntimeAssuranceTier, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::policy_constraint_error(format!("invalid runtime assurance tier `{value}`")))
}

pub(crate) fn load_runtime_attestation_evidence(path: &Path) -> Result<RuntimeAttestationEvidence, CliError> {
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
        trust_control::build_client(url, token)?.runtime_attestation_appraisal(
            &RuntimeAttestationAppraisalRequest {
                runtime_attestation: evidence,
            },
        )?
    } else {
        let runtime_assurance_policy = policy_file
            .map(load_policy)
            .transpose()?
            .and_then(|loaded| loaded.runtime_assurance_policy);
        trust_control::build_signed_runtime_attestation_appraisal_report(
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
        trust_control::build_client(url, token)?.runtime_attestation_appraisal_result(
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
        trust_control::build_signed_runtime_attestation_appraisal_result(
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
        trust_control::build_client(url, token)?.import_runtime_attestation_appraisal(&request)?
    } else {
        trust_control::build_runtime_attestation_appraisal_import_report(
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
        trust_control::build_client(url, token)?.issue_underwriting_decision(&request)?
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
        trust_control::build_client(url, token)?.list_underwriting_decisions(&query)?
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
        trust_control::build_client(url, token)?.create_underwriting_appeal(&request)?
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
        trust_control::build_client(url, token)?.resolve_underwriting_appeal(&request)?
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

pub(crate) fn cmd_receipt_list(
    args: ReceiptListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    if let Some(url) = backend.control_url {
        if args.tenant.is_some() || args.admin_all {
            return Err(CliError::cli_other_error(
                "receipt list read-boundary flags apply to local --receipt-db; remote reads derive scope from the control token"
                    .to_string(),
            ));
        }
        let token = require_control_token(backend.control_token)?;
        let client = trust_control::build_client(url, token)?;
        let query = trust_control::ReceiptQueryHttpQuery {
            capability_id: args.capability.map(ToOwned::to_owned),
            tool_server: args.tool_server.map(ToOwned::to_owned),
            tool_name: args.tool_name.map(ToOwned::to_owned),
            outcome: args.outcome.map(ToOwned::to_owned),
            since: args.since,
            until: args.until,
            min_cost: args.min_cost,
            max_cost: args.max_cost,
            cursor: args.cursor,
            limit: Some(args.limit),
            agent_subject: None,
        };
        let response = client.query_receipts(&query)?;
        for receipt in &response.receipts {
            println!("{}", serde_json::to_string(receipt)?);
        }
        if let Some(next_cursor) = response.next_cursor {
            eprintln!(
                "next_cursor={next_cursor} total_count={}",
                response.total_count
            );
        }
    } else {
        let path = backend.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "receipt commands require --receipt-db <path> or --control-url".to_string(),
            )
        })?;
        if !path.is_file() {
            return Err(CliError::cli_other_error(format!(
                "receipt list requires an existing --receipt-db <path>: {}",
                path.display()
            )));
        }
        let read_context = local_receipt_read_context(args.tenant, args.admin_all)?;
        let store = chio_store_sqlite::SqliteReceiptStore::open_existing(path)?;
        let kernel_query = chio_kernel::ReceiptQuery {
            capability_id: args.capability.map(ToOwned::to_owned),
            tool_server: args.tool_server.map(ToOwned::to_owned),
            tool_name: args.tool_name.map(ToOwned::to_owned),
            outcome: args.outcome.map(ToOwned::to_owned),
            since: args.since,
            until: args.until,
            min_cost: args.min_cost,
            max_cost: args.max_cost,
            cursor: args.cursor,
            limit: args.limit,
            agent_subject: None,
            tenant_filter: args.tenant.map(ToOwned::to_owned),
            read_context: Some(read_context),
        };
        let result = store.query_receipts(&kernel_query)?;
        for stored in &result.receipts {
            println!("{}", serde_json::to_string(&stored.receipt)?);
        }
        if let Some(next_cursor) = result.next_cursor {
            eprintln!(
                "next_cursor={next_cursor} total_count={}",
                result.total_count
            );
        }
    }
    Ok(())
}

/// Resolve the local-CLI receipt read context from explicit operator
/// flags. The local CLI does NOT silently default to admin-all reads
/// across all tenants. Exactly one of `--tenant <id>` or `--admin-all`
/// must be specified by the operator for any local --receipt-db
/// listing or lookup; otherwise this function fails closed.
///
/// Note: clap is configured with `conflicts_with = "admin_all"` on the
/// `--tenant` flag, so the both-set case is rejected at parse time.
/// This function still defends against the both-set state in case any
/// caller bypasses the clap surface.
pub(crate) fn local_receipt_read_context(
    tenant: Option<&str>,
    admin_all: bool,
) -> Result<chio_kernel::ReceiptReadContext, CliError> {
    match (tenant, admin_all) {
        (Some(_), true) => Err(CliError::cli_other_error(
            "--tenant <id> and --admin-all are mutually exclusive".to_string(),
        )),
        (Some(tenant), false) => Ok(chio_kernel::ReceiptReadContext::authenticated_tenant(
            tenant.to_string(),
        )),
        (None, true) => Ok(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
        (None, false) => Err(CliError::cli_other_error(
            "--tenant <id> or --admin-all is required for local receipt reads".to_string(),
        )),
    }
}

pub(crate) fn local_receipt_store(
    backend: &QueryBackend<'_>,
    command_name: &str,
) -> Result<chio_store_sqlite::SqliteReceiptStore, CliError> {
    if backend.control_url.is_some() {
        return Err(CliError::cli_other_error(format!(
            "{command_name} requires local --receipt-db; remote receipt operator operations are not supported in this release"
        )));
    }
    let path = backend.receipt_db_path.ok_or_else(|| {
        CliError::cli_other_error(format!("{command_name} requires --receipt-db <path>"))
    })?;
    if !path.is_file() {
        return Err(CliError::cli_other_error(format!(
            "{command_name} requires an existing --receipt-db <path>: {}",
            path.display()
        )));
    }
    chio_store_sqlite::SqliteReceiptStore::open_existing(path).map_err(CliError::from)
}

pub(crate) fn load_existing_kernel_checkpoint_keypair(path: &Path) -> Result<chio_core::Keypair, CliError> {
    let seed_hex = std::fs::read_to_string(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CliError::cli_other_error(format!(
                "receipt checkpoint create requires an existing kernel seed file: {}",
                path.display()
            ))
        } else {
            CliError::Io(error)
        }
    })?;
    chio_core::Keypair::from_seed_hex(seed_hex.trim()).map_err(CliError::from)
}

pub(crate) fn cmd_receipt_health(backend: QueryBackend<'_>) -> Result<(), CliError> {
    let store = local_receipt_store(&backend, "receipt health")?;
    let report = store.receipt_store_health()?;
    if backend.json_output {
        print_receipt_operator_json(CHIO_CLI_RECEIPT_HEALTH_SCHEMA, &report)?;
    } else {
        print!("{}", render_receipt_health_human(&report));
    }
    if report.healthy {
        Ok(())
    } else {
        Err(receipt_health_report_error(&report))
    }
}

pub(crate) fn cmd_receipt_flush(
    timeout_ms: u64,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let store = local_receipt_store(&backend, "receipt flush")?;
    let report =
        store.flush_receipt_writes_with_timeout(std::time::Duration::from_millis(timeout_ms))?;
    if backend.json_output {
        print_receipt_operator_json(CHIO_CLI_RECEIPT_FLUSH_SCHEMA, &report)?;
    } else {
        print!("{}", render_receipt_flush_human(&report));
    }
    Ok(())
}

pub(crate) fn cmd_receipt_checkpoint_status(
    max_batch: u64,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let store = local_receipt_store(&backend, "receipt checkpoint status")?;
    let report = store.receipt_checkpoint_status(Some(max_batch))?;
    if backend.json_output {
        print_receipt_operator_json(CHIO_CLI_RECEIPT_CHECKPOINT_STATUS_SCHEMA, &report)?;
    } else {
        print!("{}", render_receipt_checkpoint_status_human(&report));
    }
    if report.healthy {
        Ok(())
    } else {
        Err(receipt_checkpoint_report_error(&report))
    }
}

pub(crate) fn cmd_receipt_checkpoint_create(
    kernel_seed_file: &Path,
    max_batch: u64,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let store = local_receipt_store(&backend, "receipt checkpoint create")?;
    let keypair = load_existing_kernel_checkpoint_keypair(kernel_seed_file)?;
    let report = store.create_next_receipt_checkpoint(max_batch, &keypair)?;
    if backend.json_output {
        print_receipt_operator_json(CHIO_CLI_RECEIPT_CHECKPOINT_CREATE_SCHEMA, &report)?;
    } else {
        print!("{}", render_receipt_checkpoint_create_human(&report));
    }
    Ok(())
}

pub(crate) fn cmd_receipt_checkpoint_verify(backend: QueryBackend<'_>) -> Result<(), CliError> {
    let store = local_receipt_store(&backend, "receipt checkpoint verify")?;
    let report = store.receipt_checkpoint_status(Some(1))?;
    if backend.json_output {
        print_receipt_operator_json(CHIO_CLI_RECEIPT_CHECKPOINT_VERIFY_SCHEMA, &report)?;
    } else {
        print!("{}", render_receipt_checkpoint_status_human(&report));
    }
    if report.healthy {
        Ok(())
    } else {
        Err(receipt_checkpoint_report_error(&report))
    }
}

pub(crate) fn cmd_receipt_explain(
    args: ReceiptExplainArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let value = if let Some(input_file) = args.input_file {
        serde_json::from_slice::<serde_json::Value>(&fs::read(input_file)?)?
    } else {
        load_receipt_for_explain(args.receipt_id, args.tenant, args.admin_all, &backend)?
    };
    if is_bilateral_artifacts_value(&value) {
        return render_bilateral_explain(&value, &args, &backend);
    }
    let report = explain_receipt_value(args.receipt_id, value, args.depth, args.fanout_limit)?;
    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("receipt: {}", report["receipt_id"].as_str().unwrap_or(args.receipt_id));
        println!("schema: {}", report["schema"].as_str().unwrap_or("unknown"));
        println!("identity: {}", report["identity"].as_str().unwrap_or("unknown"));
        println!("decision: {}", report["decision"].as_str().unwrap_or("unknown"));
        if let Some(reason) = report.get("reason").and_then(|value| value.as_str()) {
            println!("reason: {reason}");
        }
        if let Some(guard) = report.get("guard").and_then(|value| value.as_str()) {
            println!("guard: {guard}");
        }
        if let Some(policy_hash) = report.get("policy_hash").and_then(|value| value.as_str()) {
            println!("policy_hash: {policy_hash}");
        }
        if let Some(scope) = report.get("scope_diff").and_then(|value| value.as_str()) {
            println!("scope_diff: {scope}");
        }
        if let Some(parents) = report.get("parents").and_then(|value| value.as_array()) {
            println!("parents: {}", parents.len());
            for parent in parents.iter().take(args.fanout_limit) {
                if let Some(parent) = parent.as_str() {
                    println!("  {parent}");
                }
            }
        }
        if let Some(witness) = report.get("batch_witness").and_then(|value| value.as_str()) {
            println!("batch_witness: {witness}");
        }
        if let Some(hint) = report.get("repair_hint").and_then(|value| value.as_str()) {
            println!("repair_hint: {hint}");
        }
    }
    Ok(())
}


pub(crate) fn is_bilateral_artifacts_value(value: &serde_json::Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    let has_dual = obj.contains_key("dual_signed_receipt") || obj.contains_key("dualSignedReceipt");
    let has_dsse = obj.contains_key("dsse_envelope") || obj.contains_key("dsseEnvelope");
    has_dual && has_dsse
}

pub(crate) fn bilateral_field<'a>(
    value: &'a serde_json::Value,
    snake: &str,
    camel: &str,
) -> Option<&'a serde_json::Value> {
    value.get(snake).or_else(|| value.get(camel))
}

pub(crate) fn render_bilateral_explain(
    value: &serde_json::Value,
    args: &ReceiptExplainArgs<'_>,
    backend: &QueryBackend<'_>,
) -> Result<(), CliError> {
    let dual = bilateral_field(value, "dual_signed_receipt", "dualSignedReceipt").ok_or_else(
        || {
            CliError::cli_other_error(
                "bilateral artifact missing dual_signed_receipt section".to_string(),
            )
        },
    )?;
    let dsse = bilateral_field(value, "dsse_envelope", "dsseEnvelope").ok_or_else(|| {
        CliError::cli_other_error(
            "bilateral artifact missing dsse_envelope section".to_string(),
        )
    })?;

    let dual_section = explain_dual_signed_receipt(dual)?;
    let dsse_section = explain_dsse_envelope(dsse)?;
    // Emit a structural inspection trace, not a "verifier trace".
    // The CLI does not have org A / org B passport public keys in
    // scope and cannot perform real Ed25519 verification.
    let trace_section = if args.inspect_bilateral {
        Some(inspect_bilateral_envelope_trace(dual, dsse)?)
    } else {
        None
    };

    let report = serde_json::json!({
        "schema": "chio.cli.receipt-explain.bilateral.v1",
        "shape": "BilateralCoSignArtifacts",
        "dual_signed_receipt": dual_section,
        "dsse_envelope": dsse_section,
        "bilateral_inspection_trace": trace_section,
    });

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Pretty-print: boxed sections.
    print_bilateral_human(&report, args.inspect_bilateral);
    Ok(())
}

pub(crate) fn explain_dual_signed_receipt(
    dual: &serde_json::Value,
) -> Result<serde_json::Value, CliError> {
    let body = dual.get("body").cloned().unwrap_or(serde_json::Value::Null);
    let receipt_id = body
        .get("id")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let org_a = dual
        .get("org_a_kernel_id")
        .or_else(|| dual.get("orgAKernelId"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let org_b = dual
        .get("org_b_kernel_id")
        .or_else(|| dual.get("orgBKernelId"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let org_a_sig = dual
        .get("org_a_signature")
        .or_else(|| dual.get("orgASignature"))
        .cloned();
    let org_b_sig = dual
        .get("org_b_signature")
        .or_else(|| dual.get("orgBSignature"))
        .cloned();
    let schema = dual
        .get("schema")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    Ok(serde_json::json!({
        "schema": schema,
        "receipt_id": receipt_id,
        "org_a_kernel_id": org_a,
        "org_b_kernel_id": org_b,
        "org_a_signature": org_a_sig,
        "org_b_signature": org_b_sig,
        "non_section6_disclaimer": "DualSignedReceipt signs canonical JSON of CoSigningBody, not the DSSE PAE preimage required by section 6. This section is NOT section-6 conformant. For section-6 conformance use the dsse_envelope section.",
    }))
}

pub(crate) fn explain_dsse_envelope(dsse: &serde_json::Value) -> Result<serde_json::Value, CliError> {
    // DsseEnvelope is `serde(rename_all = "camelCase")` so wire keys are
    // camelCase: `payloadType`, `payload`, `signatures`, optional `schema`.
    let payload_type = dsse
        .get("payloadType")
        .or_else(|| dsse.get("payload_type"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let payload_b64 = dsse
        .get("payload")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let payload_hex = payload_b64
        .as_deref()
        .and_then(|p| {
            use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
            use base64::Engine;
            BASE64_STANDARD.decode(p.as_bytes()).ok()
        })
        .map(hex::encode);
    let signatures = dsse
        .get("signatures")
        .and_then(|v| v.as_array())
        .map(|sigs| {
            sigs.iter()
                .map(|s| {
                    serde_json::json!({
                        "keyid": s.get("keyid").and_then(|v| v.as_str()),
                        "sig": s.get("sig").and_then(|v| v.as_str()),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let schema = dsse
        .get("schema")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    Ok(serde_json::json!({
        "schema": schema,
        "payload_type": payload_type,
        "payload_b64": payload_b64,
        "payload_hex": payload_hex,
        "signatures": signatures,
        "section6_conformance_note": "This is the DSSE signature-slice API artifact. The signatures cover Ed25519(pae(payloadType, base64_decode(payload))), but the predicate is not the strict treaty-bound bilateral invocation schema.",
    }))
}

/// Produces an INSPECTION trace (structural / schema /
/// fingerprint-presence checks only); the CLI does not have the org A /
/// org B passport public keys in scope and cannot perform real Ed25519
/// verification, and the emitted JSON labels itself accordingly. Real
/// verification belongs in
/// `chio_federation::bilateral_dsse::verify_dsse_envelope` against
/// pinned passport keys.
pub(crate) fn inspect_bilateral_envelope_trace(
    dual: &serde_json::Value,
    dsse: &serde_json::Value,
) -> Result<serde_json::Value, CliError> {
    use chio_federation::bilateral_dsse;

    let mut steps: Vec<serde_json::Value> = Vec::with_capacity(17);
    let mut step = |idx: u8, name: &str, status: &str, note: &str| {
        steps.push(serde_json::json!({
            "step": idx,
            "name": name,
            "status": status,
            "note": note,
        }));
    };

    // Step 1: receipt body present in dual artifact (subject anchor).
    let body = dual.get("body");
    if body.is_none() {
        step(
            1,
            "receipt_body_present",
            "fail",
            "dual_signed_receipt.body missing",
        );
    } else {
        step(
            1,
            "receipt_body_present",
            "ok",
            "dual_signed_receipt.body parsed",
        );
    }

    // Step 2: payloadType binding.
    let payload_type = dsse
        .get("payloadType")
        .or_else(|| dsse.get("payload_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if payload_type == bilateral_dsse::PAYLOAD_TYPE_IN_TOTO {
        step(
            2,
            "payload_type_binding",
            "ok",
            "payloadType == application/vnd.in-toto+json",
        );
    } else {
        step(
            2,
            "payload_type_binding",
            "fail",
            "payloadType does not bind to in-toto",
        );
    }

    // Step 3: payload base64 decodes.
    let payload_b64 = dsse
        .get("payload")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let payload_bytes = {
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use base64::Engine;
        BASE64_STANDARD.decode(payload_b64.as_bytes()).ok()
    };
    if payload_bytes.is_some() {
        step(
            3,
            "payload_base64_decodable",
            "ok",
            "payload bytes recovered",
        );
    } else {
        step(
            3,
            "payload_base64_decodable",
            "fail",
            "payload base64 decode failed",
        );
    }

    // Step 4: predicateType is the chio bilateral or its in-toto.io alias.
    let stmt_value: Option<serde_json::Value> = payload_bytes
        .as_ref()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok());
    let predicate_type = stmt_value
        .as_ref()
        .and_then(|s| s.get("predicateType"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if predicate_type == bilateral_dsse::PREDICATE_TYPE_BILATERAL
        || predicate_type == "https://in-toto.io/attestation/bilateral-cosign-invocation/v1"
    {
        step(
            4,
            "predicate_type_recognised",
            "ok",
            predicate_type,
        );
    } else {
        step(
            4,
            "predicate_type_recognised",
            "fail",
            "predicateType not recognised",
        );
    }

    // Step 5: statement _type is in-toto v1.
    let stmt_type = stmt_value
        .as_ref()
        .and_then(|s| s.get("_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if stmt_type == bilateral_dsse::STATEMENT_TYPE_V1 {
        step(5, "statement_type_v1", "ok", stmt_type);
    } else {
        step(
            5,
            "statement_type_v1",
            "fail",
            "_type does not bind to in-toto Statement v1",
        );
    }

    // Step 6: subject array length == 1.
    let subjects_len = stmt_value
        .as_ref()
        .and_then(|s| s.get("subject"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    if subjects_len == 1 {
        step(6, "subject_arity_one", "ok", "exactly one subject");
    } else {
        step(
            6,
            "subject_arity_one",
            "fail",
            "envelopes carry exactly one subject",
        );
    }

    // Step 7: subject digest == sha256(canonical_json(receipt)). We bound
    // this: with only the deserialised `body` JSON value we cannot
    // reliably re-canonicalise without a `ChioReceipt` round-trip; we
    // perform a best-effort canonical re-encoding via canonical_json on
    // the body subtree.
    let claimed_digest = stmt_value
        .as_ref()
        .and_then(|s| s.get("subject"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|s0| s0.get("digest"))
        .and_then(|d| d.get("sha256"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    if claimed_digest.is_some() {
        step(
            7,
            "subject_digest_present",
            "bounded",
            "receipt-explain renders the claimed digest; full re-canonicalisation against the underlying ChioReceipt is deferred to the in-process verifier",
        );
    } else {
        step(
            7,
            "subject_digest_present",
            "fail",
            "subject[0].digest.sha256 missing",
        );
    }

    // Step 8: signature count == 2.
    let sigs = dsse
        .get("signatures")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if sigs.len() == 2 {
        step(8, "signature_count_two", "ok", "exactly two signatures");
    } else {
        step(
            8,
            "signature_count_two",
            "fail",
            "envelopes MUST carry exactly two signatures",
        );
    }

    // Step 9: each signature has keyid + sig.
    let well_formed = sigs.iter().all(|s| {
        s.get("keyid").and_then(|v| v.as_str()).is_some()
            && s.get("sig").and_then(|v| v.as_str()).is_some()
    });
    if well_formed {
        step(
            9,
            "signature_fields_present",
            "ok",
            "every signature has keyid + sig",
        );
    } else {
        step(
            9,
            "signature_fields_present",
            "fail",
            "at least one signature lacks keyid or sig",
        );
    }

    // Step 10: keyids match the predicate's tool_server fingerprints.
    let predicate = stmt_value
        .as_ref()
        .and_then(|s| s.get("predicate"));
    let fp_a = predicate
        .and_then(|p| p.get("tool_server_a"))
        .and_then(|s| s.get("passport_key_fingerprint"))
        .and_then(|v| v.as_str());
    let fp_b = predicate
        .and_then(|p| p.get("tool_server_b"))
        .and_then(|s| s.get("passport_key_fingerprint"))
        .and_then(|v| v.as_str());
    let sig_keyids: std::collections::HashSet<&str> = sigs
        .iter()
        .filter_map(|s| s.get("keyid").and_then(|v| v.as_str()))
        .collect();
    let keyid_a_present = fp_a.map(|f| sig_keyids.contains(f)).unwrap_or(false);
    let keyid_b_present = fp_b.map(|f| sig_keyids.contains(f)).unwrap_or(false);
    if keyid_a_present && keyid_b_present {
        step(
            10,
            "keyids_match_predicate_fingerprints",
            "ok",
            "both tool_server fingerprints present in signatures",
        );
    } else {
        step(
            10,
            "keyids_match_predicate_fingerprints",
            "fail",
            "at least one keyid is unbound to a predicate.tool_server_*",
        );
    }

    // Step 11: cryptographic verification of org A signature.
    // Step 12: cryptographic verification of org B signature.
    // The CLI does not have the passport public keys in scope. The
    // signatures are NOT verified here. The honest label is
    // `not-verified`; operators that need real verification must route
    // the envelope through
    // `chio_federation::bilateral_dsse::verify_dsse_envelope` with
    // pinned passport keys.
    step(
        11,
        "ed25519_verify_org_a_pae",
        "not-verified",
        "CLI does not carry Org A passport public key; signature is NOT cryptographically verified by this inspect output",
    );
    step(
        12,
        "ed25519_verify_org_b_pae",
        "not-verified",
        "CLI does not carry Org B passport public key; signature is NOT cryptographically verified by this inspect output",
    );

    // Step 13: predicate body schema discriminator. The
    // BilateralPredicate struct serialises `schema: String` as the
    // body's discriminator (distinct from the parent Statement's
    // `predicateType`); the upstream is `serde(rename_all =
    // "snake_case")` so on the wire this is `schema`.
    let pred_schema = predicate
        .and_then(|p| p.get("schema").or_else(|| p.get("_type")))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if pred_schema == bilateral_dsse::PREDICATE_BODY_SCHEMA {
        step(
            13,
            "predicate_body_schema",
            "ok",
            "predicate.schema matches chio.bilateral-cosign.signature-slice.v1",
        );
    } else {
        step(
            13,
            "predicate_body_schema",
            "fail",
            "predicate.schema does not match the chio bilateral schema",
        );
    }

    step(
        14,
        "capability_lease_resolution",
        "bounded",
        "deferred (out of scope here; CLI verifier does not resolve this step)",
    );

    step(
        15,
        "governance_receipt_resolution",
        "bounded",
        "deferred (out of scope here; CLI verifier does not resolve this step)",
    );

    step(
        16,
        "consistency_anchor_reconciliation",
        "bounded",
        "deferred (out of scope here; CLI verifier does not resolve this step)",
    );

    step(
        17,
        "peer_pin_revocation_freshness",
        "bounded",
        "this CLI does not carry a revocation oracle handle; route to the kernel-resident verifier for steps 7-9",
    );

    Ok(serde_json::json!({
        "spec": "treaty-bound bilateral invocation profile section 7",
        "trace_kind": "inspection",
        "verification_performed": false,
        "scope_note": "ok = locally verifiable structural check, not-verified = no cryptographic verification (use bilateral_dsse::verify_dsse_envelope), bounded = step deferred to kernel-resident verifier, fail = local structural check failed",
        "honesty_note": "This is an INSPECTION trace, not a verifier trace. Ed25519 signatures are NOT verified here; this trace is informational only. For cryptographic verification, pin org A / org B passport keys and call bilateral_dsse::verify_dsse_envelope or the kernel-resident bilateral verifier.",
        "steps": steps,
    }))
}

pub(crate) fn print_bilateral_human(report: &serde_json::Value, with_trace: bool) {
    println!("=== bilateral co-sign artifacts ===");
    println!("schema: {}", report["schema"].as_str().unwrap_or("?"));
    println!("shape:  {}", report["shape"].as_str().unwrap_or("?"));
    println!();

    println!("--- DualSignedReceipt (NON-SECTION-6-CONFORMANT) ---");
    let dual = &report["dual_signed_receipt"];
    println!(
        "  receipt_id:       {}",
        dual["receipt_id"].as_str().unwrap_or("?")
    );
    println!(
        "  schema:           {}",
        dual["schema"].as_str().unwrap_or("?")
    );
    println!(
        "  org_a_kernel_id:  {}",
        dual["org_a_kernel_id"].as_str().unwrap_or("?")
    );
    println!(
        "  org_b_kernel_id:  {}",
        dual["org_b_kernel_id"].as_str().unwrap_or("?")
    );
    println!(
        "  disclaimer:       {}",
        dual["non_section6_disclaimer"].as_str().unwrap_or("?")
    );
    println!();

    println!("--- DSSE envelope (signature-slice API artifact) ---");
    let dsse = &report["dsse_envelope"];
    println!(
        "  schema:        {}",
        dsse["schema"].as_str().unwrap_or("?")
    );
    println!(
        "  payload_type:  {}",
        dsse["payload_type"].as_str().unwrap_or("?")
    );
    let payload_hex = dsse["payload_hex"].as_str().unwrap_or("");
    if payload_hex.len() > 96 {
        println!("  payload_hex:   {}... ({} bytes)", &payload_hex[..96], payload_hex.len() / 2);
    } else {
        println!("  payload_hex:   {}", payload_hex);
    }
    if let Some(sigs) = dsse["signatures"].as_array() {
        println!("  signatures:");
        for sig in sigs {
            println!(
                "    - keyid: {}",
                sig["keyid"].as_str().unwrap_or("?")
            );
            let s = sig["sig"].as_str().unwrap_or("");
            if s.len() > 32 {
                println!("      sig:   {}... ({} chars)", &s[..32], s.len());
            } else {
                println!("      sig:   {}", s);
            }
        }
    }
    println!(
        "  conformance:   {}",
        dsse["section6_conformance_note"].as_str().unwrap_or("?")
    );
    println!();

    if with_trace {
        if let Some(trace) = report.get("bilateral_inspection_trace") {
            println!("--- bilateral envelope inspection trace ---");
            println!(
                "  WARNING: this is an inspection trace, not a verifier trace."
            );
            println!(
                "  Ed25519 signatures are NOT cryptographically verified here."
            );
            println!(
                "  spec: {}",
                trace["spec"].as_str().unwrap_or("?")
            );
            println!(
                "  scope: {}",
                trace["scope_note"].as_str().unwrap_or("?")
            );
            if let Some(steps) = trace["steps"].as_array() {
                for entry in steps {
                    let idx = entry["step"].as_u64().unwrap_or(0);
                    let name = entry["name"].as_str().unwrap_or("?");
                    let status = entry["status"].as_str().unwrap_or("?");
                    let note = entry["note"].as_str().unwrap_or("");
                    println!("  [{:>2}] {:<38} {:<8} {}", idx, name, status, note);
                }
            }
        }
    }
}

pub(crate) fn load_receipt_for_explain(
    receipt_id: &str,
    tenant: Option<&str>,
    admin_all: bool,
    backend: &QueryBackend<'_>,
) -> Result<serde_json::Value, CliError> {
    const RECEIPT_EXPLAIN_PAGE_LIMIT: usize = 1000;

    if let Some(url) = backend.control_url {
        if tenant.is_some() || admin_all {
            return Err(CliError::cli_other_error(
                "receipt explain read-boundary flags apply to local --receipt-db; remote reads derive scope from the control token"
                    .to_string(),
            ));
        }
        let token = require_control_token(backend.control_token)?;
        let client = trust_control::build_client(url, token)?;
        let mut cursor = None;
        let mut matches = Vec::new();
        loop {
            let query = trust_control::ReceiptQueryHttpQuery {
                capability_id: None,
                tool_server: None,
                tool_name: None,
                outcome: None,
                since: None,
                until: None,
                min_cost: None,
                max_cost: None,
                cursor,
                limit: Some(RECEIPT_EXPLAIN_PAGE_LIMIT),
                agent_subject: None,
            };
            let response = client.query_receipts(&query)?;
            push_receipt_explain_matches(receipt_id, response.receipts, &mut matches)?;
            match response.next_cursor {
                Some(next_cursor) => {
                    if cursor == Some(next_cursor) {
                        return Err(CliError::cli_other_error(
                            "control plane receipt query returned a non-advancing cursor"
                                .to_string(),
                        ));
                    }
                    cursor = Some(next_cursor);
                }
                None => break,
            }
        }
        return finish_receipt_for_explain(
            receipt_id,
            matches,
            "control plane receipt query",
        );
    }
    let path = backend.receipt_db_path.ok_or_else(|| {
        CliError::cli_other_error(
            "receipt explain requires --input-file, --receipt-db, or --control-url".to_string(),
        )
    })?;
    if !path.is_file() {
        return Err(CliError::cli_other_error(format!(
            "receipt explain requires an existing --receipt-db <path>: {}",
            path.display()
        )));
    }
    let read_context = local_receipt_read_context(tenant, admin_all)?;
    let store = chio_store_sqlite::SqliteReceiptStore::open_existing(path)?;
    let mut cursor = None;
    let mut matches = Vec::new();
    loop {
        let result = store.query_receipts(&chio_kernel::ReceiptQuery {
            capability_id: None,
            tool_server: None,
            tool_name: None,
            outcome: None,
            since: None,
            until: None,
            min_cost: None,
            max_cost: None,
            cursor,
            limit: RECEIPT_EXPLAIN_PAGE_LIMIT,
            agent_subject: None,
            tenant_filter: tenant.map(ToOwned::to_owned),
            read_context: Some(read_context.clone()),
        })?;
        let receipts = result
            .receipts
            .into_iter()
            .map(|stored| serde_json::to_value(stored.receipt))
            .collect::<Result<Vec<_>, _>>()?;
        push_receipt_explain_matches(receipt_id, receipts, &mut matches)?;
        match result.next_cursor {
            Some(next_cursor) => {
                if cursor == Some(next_cursor) {
                    return Err(CliError::cli_other_error(
                        "local receipt store returned a non-advancing cursor".to_string(),
                    ));
                }
                cursor = Some(next_cursor);
            }
            None => break,
        }
    }
    finish_receipt_for_explain(receipt_id, matches, "local receipt store")
}

#[cfg(test)]
pub(crate) fn select_receipt_for_explain(
    receipt_id: &str,
    receipts: Vec<serde_json::Value>,
    source: &str,
) -> Result<serde_json::Value, CliError> {
    let mut matches = Vec::new();
    push_receipt_explain_matches(receipt_id, receipts, &mut matches)?;
    finish_receipt_for_explain(receipt_id, matches, source)
}

pub(crate) fn push_receipt_explain_matches(
    receipt_id: &str,
    receipts: Vec<serde_json::Value>,
    matches: &mut Vec<serde_json::Value>,
) -> Result<(), CliError> {
    for receipt in receipts {
        if receipt_value_matches_id(&receipt, receipt_id) {
            matches.push(receipt);
            if matches.len() > 1 {
                return Err(CliError::cli_other_error(format!(
                    "receipt ID prefix `{receipt_id}` is ambiguous"
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn finish_receipt_for_explain(
    receipt_id: &str,
    mut matches: Vec<serde_json::Value>,
    source: &str,
) -> Result<serde_json::Value, CliError> {
    if matches.len() == 1 {
        return Ok(matches.remove(0));
    }
    Err(CliError::cli_other_error(format!(
        "receipt `{receipt_id}` not found in paginated receipt rows from {source}"
    )))
}

pub(crate) fn receipt_value_matches_id(value: &serde_json::Value, receipt_id: &str) -> bool {
    let candidate_paths = [
        ["id"].as_slice(),
        ["receipt_id"].as_slice(),
        ["receiptId"].as_slice(),
        ["receipt", "id"].as_slice(),
        ["receipt", "receipt_id"].as_slice(),
        ["receipt", "receiptId"].as_slice(),
    ];
    candidate_paths
        .iter()
        .filter_map(|path| json_path_str(value, path))
        .any(|candidate| candidate == receipt_id)
}

pub(crate) fn json_path_str<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_str()
}

pub(crate) fn explain_receipt_value(
    requested_id: &str,
    value: serde_json::Value,
    depth: usize,
    fanout_limit: usize,
) -> Result<serde_json::Value, CliError> {
    let receipt: chio_core::receipt::ChioReceipt = serde_json::from_value(value)?;
    let signature_ok = receipt.verify_signature()?;
    let receipt_id_ok = chio_core::receipt::chio_receipt_id(&receipt.body())? == receipt.id;
    let parameter_hash_ok = receipt.action.verify_hash()?;
    let decision = explain_decision_label(receipt.decision.as_ref());
    let semantics = receipt.semantic_fields();
    let semantic_authorized = semantics.is_authorized(receipt.decision.as_ref());
    let verified = signature_ok && receipt_id_ok && parameter_hash_ok;
    let result = if verified || !semantic_authorized {
        semantics.result_label(receipt.decision.as_ref())
    } else {
        "Unverified"
    };
    let authorized = verified && semantic_authorized;
    let receipt_kind = semantics.receipt_kind.as_str();
    let boundary_class = semantics.boundary_class.as_str();
    let observation_outcome = semantics
        .observation_outcome
        .map(|outcome| outcome.as_str());
    let tool_origin = semantics.tool_origin.as_str();
    let redaction_mode = semantics.redaction_mode.as_str();
    let (reason, guard) = decision_details(receipt.decision.as_ref());
    let parents = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("parent_receipt_ids"))
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                .take(fanout_limit)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let batch_witness = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("batch_witness"))
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    Ok(serde_json::json!({
        "schema": "chio.receipt.v1",
        "receipt_id": receipt.id,
        "identity": receipt.id,
        "requested_id": requested_id,
        "signature_ok": signature_ok,
        "receipt_id_ok": receipt_id_ok,
        "parameter_hash_ok": parameter_hash_ok,
        "decision": decision,
        "receipt_kind": receipt_kind,
        "boundary_class": boundary_class,
        "observation_outcome": observation_outcome,
        "tool_origin": tool_origin,
        "redaction_mode": redaction_mode,
        "result": result,
        "authorized": authorized,
        "reason": reason,
        "guard": guard,
        "policy_hash": receipt.policy_hash,
        "guards": receipt.evidence,
        "scope_diff": "requested scope vs granted scope is not embedded in this receipt",
        "parents": parents,
        "depth_limit": depth,
        "fanout_limit": fanout_limit,
        "batch_witness": batch_witness,
        "repair_hint": repair_hint(receipt.decision.as_ref()),
    }))
}

pub(crate) fn explain_decision_label(decision: Option<&chio_core::receipt::Decision>) -> &'static str {
    match decision {
        Some(chio_core::receipt::Decision::Allow) => "allow",
        Some(chio_core::receipt::Decision::Deny { .. }) => "deny",
        Some(chio_core::receipt::Decision::Cancelled { .. }) => "cancelled",
        Some(chio_core::receipt::Decision::Incomplete { .. }) => "incomplete",
        None => "none",
    }
}

pub(crate) fn decision_details(
    decision: Option<&chio_core::receipt::Decision>,
) -> (Option<&str>, Option<&str>) {
    match decision {
        Some(chio_core::receipt::Decision::Deny { reason, guard }) => {
            (Some(reason.as_str()), Some(guard.as_str()))
        }
        Some(chio_core::receipt::Decision::Cancelled { reason })
        | Some(chio_core::receipt::Decision::Incomplete { reason }) => {
            (Some(reason.as_str()), None)
        }
        Some(chio_core::receipt::Decision::Allow) | None => (None, None),
    }
}

pub(crate) fn repair_hint(decision: Option<&chio_core::receipt::Decision>) -> Option<&'static str> {
    match decision {
        Some(chio_core::receipt::Decision::Deny { .. }) => {
            Some("inspect the guard and policy_hash, then mint or narrow a matching capability")
        }
        Some(chio_core::receipt::Decision::Incomplete { .. }) => {
            Some("retry after checking the parent receipt and terminal operation state")
        }
        Some(chio_core::receipt::Decision::Cancelled { .. }) => {
            Some("resume only if the caller still owns the request and session")
        }
        Some(chio_core::receipt::Decision::Allow) | None => None,
    }
}

#[cfg(test)]
mod receipt_explain_tests {
    use super::*;

    fn signed_explain_receipt(
        decision: chio_core::receipt::Decision,
        semantics: Option<chio_core::receipt::ReceiptSemanticFields>,
    ) -> chio_core::receipt::ChioReceipt {
        let keypair = Keypair::generate();
        let semantics = semantics
            .unwrap_or_else(chio_core::receipt::ReceiptSemanticFields::mediated_prevent);
        let decision =
            if semantics.receipt_kind == chio_core::receipt::ReceiptKind::MediatedDecision {
                Some(decision)
            } else {
                None
            };
        let trust_level =
            if semantics.receipt_kind == chio_core::receipt::ReceiptKind::MediatedDecision {
                chio_core::TrustLevel::Mediated
            } else {
                chio_core::TrustLevel::Verified
            };
        chio_core::receipt::ChioReceipt::sign(
            chio_core::receipt::ChioReceiptBody {
                id: "ignored-before-content-id".to_string(),
                timestamp: 1,
                capability_id: "cap-explain".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: chio_core::receipt::ToolCallAction::from_parameters(
                    serde_json::json!({}),
                )
                .unwrap_or_else(|error| panic!("valid tool action: {error}")),
                decision,
                receipt_kind: semantics.receipt_kind,
                boundary_class: semantics.boundary_class,
                observation_outcome: semantics.observation_outcome,
                tool_origin: semantics.tool_origin,
                redaction_mode: semantics.redaction_mode,
                actor_chain: semantics.actor_chain,
                content_hash: "content-explain".to_string(),
                policy_hash: "policy-explain".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level,
                tenant_id: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .unwrap_or_else(|error| panic!("valid receipt: {error}"))
    }

    #[test]
    fn receipt_value_matches_flat_and_nested_ids() {
        let flat = serde_json::json!({
            "id": "receipt-legacy",
            "decision": {"type": "allow"}
        });
        let nested = serde_json::json!({
            "receipt": {
                "id": "nested-receipt"
            }
        });

        assert!(receipt_value_matches_id(&flat, "receipt-legacy"));
        assert!(receipt_value_matches_id(&nested, "nested-receipt"));
        assert!(!receipt_value_matches_id(&flat, "missing"));
    }

    #[test]
    fn select_receipt_for_explain_requires_one_match() -> Result<(), CliError> {
        let receipt = serde_json::json!({"id": "receipt-a"});
        let selected =
            select_receipt_for_explain("receipt-a", vec![receipt.clone()], "test source")?;
        assert_eq!(selected, receipt);

        let duplicate = select_receipt_for_explain(
            "receipt-a",
            vec![
                serde_json::json!({"id": "receipt-a"}),
                serde_json::json!({"receiptId": "receipt-a"}),
            ],
            "test source",
        );
        assert!(duplicate.is_err());

        let missing = select_receipt_for_explain(
            "missing",
            vec![serde_json::json!({"id": "receipt-a"})],
            "test source",
        );
        assert!(missing.is_err());

        Ok(())
    }

    #[test]
    fn receipt_explain_match_collection_spans_pages() -> Result<(), CliError> {
        let mut matches = Vec::new();
        push_receipt_explain_matches(
            "receipt-b",
            vec![serde_json::json!({"id": "receipt-a"})],
            &mut matches,
        )?;
        push_receipt_explain_matches(
            "receipt-b",
            vec![serde_json::json!({"id": "receipt-b"})],
            &mut matches,
        )?;

        let selected = finish_receipt_for_explain("receipt-b", matches, "test source")?;
        assert_eq!(selected["id"].as_str(), Some("receipt-b"));

        Ok(())
    }

    #[test]
    fn receipt_explain_reports_semantic_authorization_fields() -> Result<(), CliError> {
        let mediated =
            signed_explain_receipt(chio_core::receipt::Decision::Allow, None);
        let mediated_explain = explain_receipt_value(
            &mediated.id,
            serde_json::to_value(&mediated)?,
            1,
            1,
        )?;
        assert_eq!(mediated_explain["receipt_kind"].as_str(), Some("mediated_decision"));
        assert_eq!(mediated_explain["boundary_class"].as_str(), Some("prevent"));
        assert_eq!(mediated_explain["result"].as_str(), Some("Authorized"));
        assert_eq!(mediated_explain["authorized"].as_bool(), Some(true));

        let trace = signed_explain_receipt(
            chio_core::receipt::Decision::Incomplete {
                reason: "trace only".to_string(),
            },
            Some(chio_core::receipt::ReceiptSemanticFields::trace_detect_only()),
        );
        let trace_explain = explain_receipt_value(
            &trace.id,
            serde_json::to_value(&trace)?,
            1,
            1,
        )?;
        assert_eq!(trace_explain["receipt_kind"].as_str(), Some("trace_observation"));
        assert_eq!(trace_explain["boundary_class"].as_str(), Some("detect_only"));
        assert_eq!(trace_explain["result"].as_str(), Some("Observed"));
        assert_eq!(trace_explain["authorized"].as_bool(), Some(false));

        Ok(())
    }
}

#[cfg(test)]
mod receipt_operator_tests {
    use super::*;
    use chio_kernel::ReceiptStore;

    fn unique_temp_path(name: &str, suffix: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("chio-{name}-{}-{stamp}.{suffix}", std::process::id()))
    }

    fn operator_sample_receipt() -> Result<chio_core::receipt::ChioReceipt, chio_core::Error> {
        let keypair = chio_core::crypto::Keypair::generate();
        operator_sample_receipt_with_keypair(&keypair)
    }

    fn operator_sample_receipt_with_keypair(
        keypair: &chio_core::crypto::Keypair,
    ) -> Result<chio_core::receipt::ChioReceipt, chio_core::Error> {
        chio_core::receipt::ChioReceipt::sign(
            chio_core::receipt::ChioReceiptBody {
                id: "receipt-operator-1".to_string(),
                timestamp: 1_775_137_626,
                capability_id: "cap-operator-1".to_string(),
                tool_server: "operator".to_string(),
                tool_name: "flush".to_string(),
                action: chio_core::receipt::ToolCallAction::from_parameters(
                    serde_json::json!({"operation":"flush"}),
                )?,
                decision: Some(chio_core::receipt::Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: "content-operator-1".to_string(),
                policy_hash: "policy-operator-1".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
            },
            keypair,
        )
    }

    fn backend<'a>(
        receipt_db_path: Option<&'a Path>,
        control_url: Option<&'a str>,
    ) -> QueryBackend<'a> {
        QueryBackend {
            json_output: true,
            receipt_db_path,
            control_url,
            control_token: None,
        }
    }

    #[test]
    fn receipt_operator_json_envelope_includes_schema_and_null_fields() -> Result<(), CliError> {
        let health = chio_kernel::ReceiptStoreHealthReport {
            healthy: true,
            ..chio_kernel::ReceiptStoreHealthReport::default()
        };
        let flush = chio_kernel::ReceiptFlushReport::default();
        let status = chio_kernel::ReceiptCheckpointStatusReport {
            healthy: true,
            ..chio_kernel::ReceiptCheckpointStatusReport::default()
        };
        let create = chio_kernel::ReceiptCheckpointCreateReport::default();

        for (schema, report) in [
            (
                CHIO_CLI_RECEIPT_HEALTH_SCHEMA,
                receipt_operator_json_value(CHIO_CLI_RECEIPT_HEALTH_SCHEMA, &health)?,
            ),
            (
                CHIO_CLI_RECEIPT_FLUSH_SCHEMA,
                receipt_operator_json_value(CHIO_CLI_RECEIPT_FLUSH_SCHEMA, &flush)?,
            ),
            (
                CHIO_CLI_RECEIPT_CHECKPOINT_STATUS_SCHEMA,
                receipt_operator_json_value(CHIO_CLI_RECEIPT_CHECKPOINT_STATUS_SCHEMA, &status)?,
            ),
            (
                CHIO_CLI_RECEIPT_CHECKPOINT_CREATE_SCHEMA,
                receipt_operator_json_value(CHIO_CLI_RECEIPT_CHECKPOINT_CREATE_SCHEMA, &create)?,
            ),
            (
                CHIO_CLI_RECEIPT_CHECKPOINT_VERIFY_SCHEMA,
                receipt_operator_json_value(CHIO_CLI_RECEIPT_CHECKPOINT_VERIFY_SCHEMA, &status)?,
            ),
        ] {
            assert_eq!(report["schema"].as_str(), Some(schema));
        }

        let value = receipt_operator_json_value(CHIO_CLI_RECEIPT_HEALTH_SCHEMA, &health)?;
        assert!(value["report"]["latestCheckpointSeq"].is_null());
        assert!(value["report"]["uncheckpointedStartSeq"].is_null());
        assert!(value["report"]["writer"]["lastError"].is_null());

        let create_value =
            receipt_operator_json_value(CHIO_CLI_RECEIPT_CHECKPOINT_CREATE_SCHEMA, &create)?;
        assert!(create_value["report"]["checkpointSeq"].is_null());
        assert!(create_value["report"]["batchStartSeq"].is_null());
        Ok(())
    }

    #[test]
    fn receipt_operator_human_output_includes_operational_fields() {
        let counters = chio_kernel::ReceiptWriterCounters {
            accepted_total: 10,
            committed_total: 9,
            failed_total: 1,
            saturated_total: 2,
            inflight: 3,
            last_commit_unix_ms: Some(1234),
            last_error: Some("writer lag".to_string()),
        };
        let health = chio_kernel::ReceiptStoreHealthReport {
            healthy: false,
            writer: counters.clone(),
            latest_committed_entry_seq: 12,
            latest_checkpoint_seq: Some(2),
            latest_checkpointed_entry_seq: 8,
            uncheckpointed_start_seq: Some(9),
            uncheckpointed_end_seq: Some(12),
            checkpoint_error: Some("projection drift".to_string()),
            db_size_bytes: Some(4096),
        };
        let health_output = render_receipt_health_human(&health);
        assert!(health_output.contains("checkpoint_seq: 2"));
        assert!(health_output.contains("uncheckpointed_range: 9..=12"));
        assert!(health_output.contains("writer_accepted_total: 10"));
        assert!(health_output.contains("writer_saturated_total: 2"));
        assert!(health_output.contains("db_size_bytes: 4096"));
        assert!(health_output.contains("checkpoint_error: projection drift"));
        assert!(health_output.contains("writer_last_error: writer lag"));

        let flush = chio_kernel::ReceiptFlushReport {
            writer: counters,
            latest_committed_entry_seq: 12,
            latest_checkpoint_seq: Some(2),
            latest_checkpointed_entry_seq: 8,
            uncheckpointed_start_seq: Some(9),
            uncheckpointed_end_seq: Some(12),
            wal_checkpoint: Some(chio_kernel::ReceiptWalCheckpointReport {
                busy: 0,
                log_frames: 7,
                checkpointed_frames: 6,
            }),
            db_size_bytes: Some(4096),
        };
        let flush_output = render_receipt_flush_human(&flush);
        assert!(flush_output.contains("wal_checkpoint_log_frames: 7"));
        assert!(flush_output.contains("wal_checkpoint_checkpointed_frames: 6"));

        let create = chio_kernel::ReceiptCheckpointCreateReport {
            created: true,
            checkpoint_seq: Some(3),
            batch_start_seq: Some(9),
            batch_end_seq: Some(12),
            latest_committed_entry_seq: 12,
            latest_checkpointed_entry_seq: 12,
        };
        let create_output = render_receipt_checkpoint_create_human(&create);
        assert!(create_output.contains("checkpoint_seq: 3"));
        assert!(create_output.contains("checkpoint_range: 9..=12"));
    }

    fn assert_remote_unsupported(result: Result<(), CliError>) {
        let error = match result {
            Ok(()) => panic!("remote receipt operator command should be deferred"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("requires local --receipt-db; remote receipt operator operations are not supported in this release"));
        assert!(!error.to_string().contains("requires --receipt-db"));
    }

    #[test]
    fn receipt_operator_commands_reject_remote_control_backend_first() {
        let error = match local_receipt_store(
            &backend(None, Some("http://127.0.0.1:9977")),
            "receipt flush",
        ) {
            Ok(_) => panic!("remote receipt flush should be deferred"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("requires local --receipt-db; remote receipt operator operations are not supported in this release"));
        assert!(!error.to_string().contains("requires --receipt-db"));
    }

    #[test]
    fn receipt_operator_entrypoints_reject_remote_control_backend_first() {
        let control_url = Some("http://127.0.0.1:9977");

        assert_remote_unsupported(cmd_receipt_health(backend(None, control_url)));
        assert_remote_unsupported(cmd_receipt_flush(5000, backend(None, control_url)));
        assert_remote_unsupported(cmd_receipt_checkpoint_status(
            1000,
            backend(None, control_url),
        ));
        assert_remote_unsupported(cmd_receipt_checkpoint_create(
            Path::new("kernel.seed"),
            1000,
            backend(None, control_url),
        ));
        assert_remote_unsupported(cmd_receipt_checkpoint_verify(backend(None, control_url)));
    }

    #[test]
    fn receipt_operator_entrypoints_work_against_local_temp_db(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let db_path = unique_temp_path("receipt-operator", "sqlite3");
        let seed_path = unique_temp_path("receipt-operator-kernel", "seed");
        let keypair = chio_core::crypto::Keypair::generate();
        let store = chio_store_sqlite::SqliteReceiptStore::open(&db_path)?;
        store.append_chio_receipt(&operator_sample_receipt_with_keypair(&keypair)?)?;
        drop(store);
        std::fs::write(&seed_path, keypair.seed_hex())?;

        cmd_receipt_health(backend(Some(&db_path), None))?;
        cmd_receipt_flush(5000, backend(Some(&db_path), None))?;
        cmd_receipt_checkpoint_status(10, backend(Some(&db_path), None))?;
        cmd_receipt_checkpoint_create(&seed_path, 10, backend(Some(&db_path), None))?;
        cmd_receipt_checkpoint_verify(backend(Some(&db_path), None))?;

        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(seed_path);
        Ok(())
    }

    #[test]
    fn receipt_operator_commands_require_local_receipt_db() {
        let error = match local_receipt_store(&backend(None, None), "receipt health") {
            Ok(_) => panic!("local receipt health should require a database"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("receipt health requires --receipt-db <path>"));
    }

    #[test]
    fn receipt_operator_commands_reject_missing_receipt_db_path() {
        let db_path = unique_temp_path("receipt-missing", "sqlite3");
        let error = match local_receipt_store(&backend(Some(&db_path), None), "receipt health") {
            Ok(_) => panic!("missing receipt database must not be created"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("receipt health requires an existing --receipt-db"));
        assert!(
            !db_path.exists(),
            "receipt operator command must not create a missing database"
        );
    }

    #[test]
    fn receipt_operator_commands_reject_touched_empty_receipt_db_file() -> Result<(), CliError> {
        let db_path = unique_temp_path("receipt-empty", "sqlite3");
        std::fs::write(&db_path, "")?;

        let error = match local_receipt_store(&backend(Some(&db_path), None), "receipt health") {
            Ok(_) => panic!("empty receipt database file must not be initialized"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("not an initialized Chio receipt store"),
            "unexpected error: {error}"
        );
        assert!(
            db_path.is_file(),
            "receipt operator command should refuse, not remove, an empty database file"
        );

        let _ = std::fs::remove_file(db_path);
        Ok(())
    }

    #[test]
    fn receipt_checkpoint_create_requires_existing_kernel_seed() -> Result<(), CliError> {
        let db_path = unique_temp_path("receipt-checkpoint-seed", "sqlite3");
        let seed_path = unique_temp_path("receipt-checkpoint-missing-seed", "seed");
        let store = chio_store_sqlite::SqliteReceiptStore::open(&db_path)?;
        store.append_chio_receipt(&operator_sample_receipt()?)?;
        drop(store);

        let error = match cmd_receipt_checkpoint_create(&seed_path, 10, backend(Some(&db_path), None))
        {
            Ok(_) => panic!("checkpoint create must not generate a missing seed"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("receipt checkpoint create requires an existing kernel seed file"),
            "unexpected error: {error}"
        );
        assert!(
            !seed_path.exists(),
            "checkpoint create must not create a new kernel seed"
        );

        let _ = std::fs::remove_file(db_path);
        Ok(())
    }
}
