//! Trust evidence, authorization-context, exposure, capital, and credit command handlers.

use super::*;

pub(crate) struct SharedEvidenceListArgs<'a> {
    pub(crate) capability_id: Option<&'a str>,
    pub(crate) agent_subject: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) since: Option<u64>,
    pub(crate) until: Option<u64>,
    pub(crate) issuer: Option<&'a str>,
    pub(crate) partner: Option<&'a str>,
    pub(crate) limit: usize,
}

pub(crate) struct AuthorizationContextListArgs<'a> {
    pub(crate) capability_id: Option<&'a str>,
    pub(crate) agent_subject: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) since: Option<u64>,
    pub(crate) until: Option<u64>,
    pub(crate) limit: usize,
}

pub(crate) struct BehavioralFeedExportArgs<'a> {
    pub(crate) capability_id: Option<&'a str>,
    pub(crate) agent_subject: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) since: Option<u64>,
    pub(crate) until: Option<u64>,
    pub(crate) receipt_limit: usize,
}

pub(crate) struct ExposureLedgerQueryArgs<'a> {
    pub(crate) capability_id: Option<&'a str>,
    pub(crate) agent_subject: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) since: Option<u64>,
    pub(crate) until: Option<u64>,
    pub(crate) receipt_limit: usize,
    pub(crate) decision_limit: usize,
}

pub(crate) struct AgentExposureLedgerQueryArgs<'a> {
    pub(crate) agent_subject: &'a str,
    pub(crate) capability_id: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) since: Option<u64>,
    pub(crate) until: Option<u64>,
    pub(crate) receipt_limit: usize,
    pub(crate) decision_limit: usize,
}

pub(crate) struct CapitalBookExportArgs<'a> {
    pub(crate) agent_subject: &'a str,
    pub(crate) capability_id: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) since: Option<u64>,
    pub(crate) until: Option<u64>,
    pub(crate) receipt_limit: usize,
    pub(crate) facility_limit: usize,
    pub(crate) bond_limit: usize,
    pub(crate) loss_event_limit: usize,
}

pub(crate) struct CreditFacilityIssueArgs<'a> {
    pub(crate) query: AgentExposureLedgerQueryArgs<'a>,
    pub(crate) supersedes_facility_id: Option<&'a str>,
}

pub(crate) struct CreditFacilityListArgs<'a> {
    pub(crate) facility_id: Option<&'a str>,
    pub(crate) capability_id: Option<&'a str>,
    pub(crate) agent_subject: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) disposition: Option<&'a str>,
    pub(crate) lifecycle_state: Option<&'a str>,
    pub(crate) limit: usize,
}

pub(crate) struct CreditBondIssueArgs<'a> {
    pub(crate) query: AgentExposureLedgerQueryArgs<'a>,
    pub(crate) supersedes_bond_id: Option<&'a str>,
}

pub(crate) struct CreditBondListArgs<'a> {
    pub(crate) bond_id: Option<&'a str>,
    pub(crate) facility_id: Option<&'a str>,
    pub(crate) capability_id: Option<&'a str>,
    pub(crate) agent_subject: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) disposition: Option<&'a str>,
    pub(crate) lifecycle_state: Option<&'a str>,
    pub(crate) limit: usize,
}

pub(crate) fn build_exposure_ledger_query(
    args: &ExposureLedgerQueryArgs<'_>,
) -> chio_kernel::ExposureLedgerQuery {
    chio_kernel::ExposureLedgerQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        receipt_limit: Some(args.receipt_limit),
        decision_limit: Some(args.decision_limit),
    }
}

pub(crate) fn build_agent_exposure_ledger_query(
    args: &AgentExposureLedgerQueryArgs<'_>,
) -> chio_kernel::ExposureLedgerQuery {
    chio_kernel::ExposureLedgerQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: Some(args.agent_subject.to_string()),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        receipt_limit: Some(args.receipt_limit),
        decision_limit: Some(args.decision_limit),
    }
}

pub(crate) fn cmd_trust_evidence_share_list(
    args: SharedEvidenceListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::SharedEvidenceQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        issuer: args.issuer.map(ToOwned::to_owned),
        partner: args.partner.map(ToOwned::to_owned),
        limit: Some(args.limit),
        read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
    };

    let report = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .shared_evidence_report(&query)?
    } else {
        let path = require_receipt_db_path(backend.receipt_db_path)?;
        let store = chio_store_sqlite::SqliteReceiptStore::open(path)?;
        store.query_shared_evidence_report(&query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "matching_shares:         {}",
            report.summary.matching_shares
        );
        println!(
            "matching_references:     {}",
            report.summary.matching_references
        );
        println!(
            "matching_local_receipts: {}",
            report.summary.matching_local_receipts
        );
        println!(
            "remote_tool_receipts:    {}",
            report.summary.remote_tool_receipts
        );
        println!(
            "remote_lineage_records:  {}",
            report.summary.remote_lineage_records
        );
        for reference in report.references {
            println!(
                "- {} partner={} remote_capability={} local_anchor={} receipts={}",
                reference.share.share_id,
                reference.share.partner,
                reference.capability_id,
                reference
                    .local_anchor_capability_id
                    .as_deref()
                    .unwrap_or("n/a"),
                reference.matched_local_receipts
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_authorization_context_metadata(
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .authorization_profile_metadata()?
    } else {
        let path = require_receipt_db_path(receipt_db_path)?;
        let store = chio_store_sqlite::SqliteReceiptStore::open(path)?;
        store.authorization_profile_metadata_report()
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                     {}", report.schema);
        println!("generated_at:               {}", report.generated_at);
        println!("profile_id:                 {}", report.profile.id);
        println!("profile_schema:             {}", report.profile.schema);
        println!("report_schema:              {}", report.report_schema);
        println!(
            "discovery_informational:    {}",
            report.discovery.discovery_informational_only
        );
        println!(
            "auth_server_metadata_path:  {}",
            report.discovery.authorization_server_metadata_path_template
        );
        for path in report.discovery.protected_resource_metadata_paths {
            println!("protected_resource_path:    {path}");
        }
        println!(
            "sender_constrained:         {}",
            report.support_boundary.sender_constrained_projection
        );
        println!(
            "runtime_assurance:          {}",
            report.support_boundary.runtime_assurance_projection
        );
        println!(
            "delegated_call_chain:       {}",
            report.support_boundary.delegated_call_chain_projection
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_authorization_context_list(
    args: AuthorizationContextListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::OperatorReportQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        authorization_limit: Some(args.limit),
        read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
        ..chio_kernel::OperatorReportQuery::default()
    };

    let report = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .authorization_context_report(&query)?
    } else {
        let path = require_receipt_db_path(backend.receipt_db_path)?;
        let store = chio_store_sqlite::SqliteReceiptStore::open(path)?;
        store.query_authorization_context_report(&query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                     {}", report.schema);
        println!("profile_id:                 {}", report.profile.id);
        println!(
            "profile_source:             {}",
            report.profile.authoritative_source
        );
        println!(
            "matching_receipts:          {}",
            report.summary.matching_receipts
        );
        println!(
            "returned_receipts:          {}",
            report.summary.returned_receipts
        );
        println!(
            "approval_receipts:          {}",
            report.summary.approval_receipts
        );
        println!(
            "approved_receipts:          {}",
            report.summary.approved_receipts
        );
        println!(
            "call_chain_receipts:        {}",
            report.summary.call_chain_receipts
        );
        println!(
            "metered_billing_receipts:   {}",
            report.summary.metered_billing_receipts
        );
        println!(
            "runtime_assurance_receipts: {}",
            report.summary.runtime_assurance_receipts
        );
        println!(
            "sender_bound_receipts:      {}",
            report.summary.sender_bound_receipts
        );
        println!(
            "dpop_bound_receipts:        {}",
            report.summary.dpop_bound_receipts
        );
        for row in report.receipts {
            println!(
                "- {} intent={} tool={}/{} details={} sender={} proof={} call_chain={}",
                row.receipt_id,
                row.transaction_context.intent_id,
                row.tool_server,
                row.tool_name,
                row.authorization_details.len(),
                row.sender_constraint.subject_key,
                row.sender_constraint
                    .proof_type
                    .as_deref()
                    .unwrap_or("none"),
                row.transaction_context
                    .call_chain
                    .as_ref()
                    .map(|value| value.chain_id.as_str())
                    .unwrap_or("n/a")
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_authorization_context_review_pack(
    args: AuthorizationContextListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::OperatorReportQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        authorization_limit: Some(args.limit),
        read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
        ..chio_kernel::OperatorReportQuery::default()
    };

    let pack = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .authorization_review_pack(&query)?
    } else {
        let path = require_receipt_db_path(backend.receipt_db_path)?;
        let store = chio_store_sqlite::SqliteReceiptStore::open(path)?;
        store.query_authorization_review_pack(&query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&pack)?);
    } else {
        println!("schema:                     {}", pack.schema);
        println!("generated_at:               {}", pack.generated_at);
        println!("profile_id:                 {}", pack.metadata.profile.id);
        println!(
            "matching_receipts:          {}",
            pack.summary.matching_receipts
        );
        println!(
            "returned_receipts:          {}",
            pack.summary.returned_receipts
        );
        println!(
            "dpop_required_receipts:     {}",
            pack.summary.dpop_required_receipts
        );
        println!(
            "runtime_assurance_receipts: {}",
            pack.summary.runtime_assurance_receipts
        );
        println!(
            "delegated_call_chain:       {}",
            pack.summary.delegated_call_chain_receipts
        );
        for record in pack.records {
            println!(
                "- {} intent={} tool={}/{} approval={} sender={}",
                record.receipt_id,
                record.governed_transaction.intent_id,
                record.authorization_context.tool_server,
                record.authorization_context.tool_name,
                record
                    .governed_transaction
                    .approval
                    .as_ref()
                    .map(|value| value.token_id.as_str())
                    .unwrap_or("none"),
                record.authorization_context.sender_constraint.subject_key
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_behavioral_feed_export(
    args: BehavioralFeedExportArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::BehavioralFeedQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        receipt_limit: Some(args.receipt_limit),
        read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
    };

    let feed = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.behavioral_feed(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "behavioral feed export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::reports::build_signed_behavioral_feed(
            receipt_db_path,
            backend.budget_db_path,
            backend.authority_seed_path,
            backend.authority_db_path,
            &query,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&feed)?);
    } else {
        println!("schema:                 {}", feed.body.schema);
        println!("generated_at:           {}", feed.body.generated_at);
        println!("signer_key:             {}", feed.signer_key.to_hex());
        println!(
            "matching_receipts:      {}",
            feed.body.privacy.matching_receipts
        );
        println!(
            "returned_receipts:      {}",
            feed.body.privacy.returned_receipts
        );
        println!(
            "allow_count:            {}",
            feed.body.decisions.allow_count
        );
        println!("deny_count:             {}", feed.body.decisions.deny_count);
        println!(
            "governed_receipts:      {}",
            feed.body.governed_actions.governed_receipts
        );
        if let Some(reputation) = feed.body.reputation.as_ref() {
            println!("subject_key:            {}", reputation.subject_key);
            println!("effective_score:        {:.4}", reputation.effective_score);
            println!(
                "imported_signals:       {}",
                reputation.imported_signal_count
            );
            println!(
                "accepted_imported:      {}",
                reputation.accepted_imported_signal_count
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_exposure_ledger_export(
    args: ExposureLedgerQueryArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = build_exposure_ledger_query(&args);

    let report = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.exposure_ledger(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "exposure ledger export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::reports::build_signed_exposure_ledger_report(
            receipt_db_path,
            backend.authority_seed_path,
            backend.authority_db_path,
            &query,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.body.schema);
        println!("generated_at:           {}", report.body.generated_at);
        println!("signer_key:             {}", report.signer_key.to_hex());
        println!(
            "matching_receipts:      {}",
            report.body.summary.matching_receipts
        );
        println!(
            "matching_decisions:     {}",
            report.body.summary.matching_decisions
        );
        println!(
            "currencies:             {}",
            if report.body.summary.currencies.is_empty() {
                "none".to_string()
            } else {
                report.body.summary.currencies.join(", ")
            }
        );
        println!(
            "mixed_currency_book:    {}",
            report.body.summary.mixed_currency_book
        );
        for position in &report.body.positions {
            println!(
                "- {} governed={} reserved={} settled={} pending={} failed={} loss={} quoted_premium={} active_premium={}",
                position.currency,
                position.governed_max_exposure_units,
                position.reserved_units,
                position.settled_units,
                position.pending_units,
                position.failed_units,
                position.provisional_loss_units,
                position.quoted_premium_units,
                position.active_quoted_premium_units
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_credit_scorecard_export(
    agent_subject: &str,
    args: ExposureLedgerQueryArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = build_exposure_ledger_query(&args);

    let report = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .credit_scorecard(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "credit scorecard export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::reports::build_signed_credit_scorecard_report(
            receipt_db_path,
            backend.budget_db_path,
            backend.authority_seed_path,
            backend.authority_db_path,
            &query,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.body.schema);
        println!("generated_at:           {}", report.body.generated_at);
        println!("signer_key:             {}", report.signer_key.to_hex());
        println!("subject_key:            {}", agent_subject);
        println!(
            "overall_score:          {:.4}",
            report.body.summary.overall_score
        );
        println!(
            "confidence:             {:?}",
            report.body.summary.confidence
        );
        println!("band:                   {:?}", report.body.summary.band);
        println!(
            "probationary:           {}",
            report.body.summary.probationary
        );
        println!(
            "matching_receipts:      {}",
            report.body.summary.matching_receipts
        );
        println!(
            "matching_decisions:     {}",
            report.body.summary.matching_decisions
        );
        println!(
            "anomaly_count:          {}",
            report.body.summary.anomaly_count
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_capital_book_export(
    args: CapitalBookExportArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::CapitalBookQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: Some(args.agent_subject.to_string()),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        receipt_limit: Some(args.receipt_limit),
        facility_limit: Some(args.facility_limit),
        bond_limit: Some(args.bond_limit),
        loss_event_limit: Some(args.loss_event_limit),
    };

    let report = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.capital_book(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "capital book export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::reports::build_signed_capital_book_report(
            receipt_db_path,
            backend.authority_seed_path,
            backend.authority_db_path,
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
            "funding_sources:        {}",
            report.body.summary.funding_sources
        );
        println!(
            "ledger_events:          {}",
            report.body.summary.ledger_events
        );
        println!(
            "currencies:             {}",
            if report.body.summary.currencies.is_empty() {
                "none".to_string()
            } else {
                report.body.summary.currencies.join(", ")
            }
        );
        for source in &report.body.sources {
            println!(
                "- {} kind={:?} owner={:?} committed={} held={} drawn={} disbursed={} released={} repaid={} impaired={}",
                source.source_id,
                source.kind,
                source.owner_role,
                source.committed_amount.as_ref().map_or(0, |amount| amount.units),
                source.held_amount.as_ref().map_or(0, |amount| amount.units),
                source.drawn_amount.as_ref().map_or(0, |amount| amount.units),
                source.disbursed_amount.as_ref().map_or(0, |amount| amount.units),
                source.released_amount.as_ref().map_or(0, |amount| amount.units),
                source.repaid_amount.as_ref().map_or(0, |amount| amount.units),
                source.impaired_amount.as_ref().map_or(0, |amount| amount.units),
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_capital_instruction_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request: trust_control::CapitalExecutionInstructionRequest = load_json_or_yaml(input_file)?;

    let instruction = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .issue_capital_execution_instruction(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "capital instruction issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::reports::issue_signed_capital_execution_instruction(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&instruction)?);
    } else {
        println!("schema:                 {}", instruction.body.schema);
        println!(
            "instruction_id:         {}",
            instruction.body.instruction_id
        );
        println!("issued_at:              {}", instruction.body.issued_at);
        println!("subject_key:            {}", instruction.body.subject_key);
        println!("source_id:              {}", instruction.body.source_id);
        println!("action:                 {:?}", instruction.body.action);
        println!(
            "reconciled_state:       {:?}",
            instruction.body.reconciled_state
        );
        println!(
            "signer_key:             {}",
            instruction.signer_key.to_hex()
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_capital_allocation_issue(
    input_file: &Path,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let request: trust_control::CapitalAllocationDecisionRequest = load_json_or_yaml(input_file)?;

    let allocation = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .issue_capital_allocation_decision(&request)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "capital allocation issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::reports::issue_signed_capital_allocation_decision(
            receipt_db_path,
            backend.budget_db_path,
            backend.authority_seed_path,
            backend.authority_db_path,
            backend.certification_registry_file,
            &request,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&allocation)?);
    } else {
        println!("schema:                 {}", allocation.body.schema);
        println!("allocation_id:          {}", allocation.body.allocation_id);
        println!("issued_at:              {}", allocation.body.issued_at);
        println!("subject_key:            {}", allocation.body.subject_key);
        println!(
            "governed_receipt_id:    {}",
            allocation.body.governed_receipt_id
        );
        println!("outcome:                {:?}", allocation.body.outcome);
        println!(
            "facility_id:            {}",
            allocation.body.facility_id.as_deref().unwrap_or("<none>")
        );
        println!(
            "source_id:              {}",
            allocation.body.source_id.as_deref().unwrap_or("<none>")
        );
        println!("signer_key:             {}", allocation.signer_key.to_hex());
    }

    Ok(())
}

pub(crate) fn cmd_trust_credit_facility_evaluate(
    args: AgentExposureLedgerQueryArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = build_agent_exposure_ledger_query(&args);

    let report = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .credit_facility_report(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "credit facility evaluation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        let trusted_kernel_keys = trusted_kernel_keys_from_authority(backend.authority_seed_path)?;
        trust_control::build_credit_facility_report(
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
        println!("disposition:            {:?}", report.disposition);
        println!("score_band:             {:?}", report.scorecard.band);
        println!(
            "overall_score:          {:.4}",
            report.scorecard.overall_score
        );
        println!(
            "runtime_prerequisite:   {:?}",
            report.prerequisites.minimum_runtime_assurance_tier
        );
        println!(
            "runtime_assurance_met:  {}",
            report.prerequisites.runtime_assurance_met
        );
        println!(
            "certification_met:      {}",
            report.prerequisites.certification_met
        );
        println!("findings:               {}", report.findings.len());
    }

    Ok(())
}

pub(crate) fn cmd_trust_credit_facility_issue(
    args: CreditFacilityIssueArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let request = trust_control::CreditFacilityIssueRequest {
        query: build_agent_exposure_ledger_query(&args.query),
        supersedes_facility_id: args.supersedes_facility_id.map(ToOwned::to_owned),
    };

    let facility = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .issue_credit_facility(&request)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "credit facility issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_credit_facility(trust_control::CreditIssuanceArgs {
            receipt_db_path,
            budget_db_path: backend.budget_db_path,
            authority_seed_path: backend.authority_seed_path,
            authority_db_path: backend.authority_db_path,
            certification_registry_file: backend.certification_registry_file,
            issuance_policy: None,
            query: &request.query,
            supersedes_artifact_id: request.supersedes_facility_id.as_deref(),
        })?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&facility)?);
    } else {
        println!("schema:                 {}", facility.body.schema);
        println!("facility_id:            {}", facility.body.facility_id);
        println!("issued_at:              {}", facility.body.issued_at);
        println!("expires_at:             {}", facility.body.expires_at);
        println!("signer_key:             {}", facility.signer_key.to_hex());
        println!(
            "disposition:            {:?}",
            facility.body.report.disposition
        );
        println!(
            "lifecycle_state:        {:?}",
            facility.body.lifecycle_state
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_credit_facility_list(
    args: CreditFacilityListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::CreditFacilityListQuery {
        facility_id: args.facility_id.map(ToOwned::to_owned),
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        disposition: args
            .disposition
            .map(parse_credit_facility_disposition)
            .transpose()?,
        lifecycle_state: args
            .lifecycle_state
            .map(parse_credit_facility_lifecycle_state)
            .transpose()?,
        limit: Some(args.limit),
    };

    let report = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .list_credit_facilities(&query)?
    } else {
        let receipt_db_path = backend.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "credit facility list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_credit_facilities(receipt_db_path, &query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "matching_facilities:    {}",
            report.summary.matching_facilities
        );
        println!(
            "returned_facilities:    {}",
            report.summary.returned_facilities
        );
        println!(
            "active_facilities:      {}",
            report.summary.active_facilities
        );
        println!(
            "manual_review_rows:     {}",
            report.summary.manual_review_facilities
        );
        for row in report.facilities {
            println!(
                "- {} disposition={:?} lifecycle={:?}",
                row.facility.body.facility_id,
                row.facility.body.report.disposition,
                row.lifecycle_state
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_credit_bond_evaluate(
    args: AgentExposureLedgerQueryArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = build_agent_exposure_ledger_query(&args);

    let report = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .credit_bond_report(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "credit bond evaluation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        let trusted_kernel_keys = trusted_kernel_keys_from_authority(backend.authority_seed_path)?;
        trust_control::build_credit_bond_report(
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
        println!("disposition:            {:?}", report.disposition);
        println!("score_band:             {:?}", report.scorecard.band);
        println!(
            "latest_facility_id:     {}",
            report.latest_facility_id.as_deref().unwrap_or("<none>")
        );
        println!(
            "active_facility_met:    {}",
            report.prerequisites.active_facility_met
        );
        println!(
            "runtime_assurance_met:  {}",
            report.prerequisites.runtime_assurance_met
        );
        println!(
            "certification_met:      {}",
            report.prerequisites.certification_met
        );
        println!("findings:               {}", report.findings.len());
    }

    Ok(())
}

pub(crate) fn cmd_trust_credit_bond_issue(
    args: CreditBondIssueArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let request = trust_control::CreditBondIssueRequest {
        query: build_agent_exposure_ledger_query(&args.query),
        supersedes_bond_id: args.supersedes_bond_id.map(ToOwned::to_owned),
    };

    let bond = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .issue_credit_bond(&request)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "credit bond issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_credit_bond(trust_control::CreditIssuanceArgs {
            receipt_db_path,
            budget_db_path: backend.budget_db_path,
            authority_seed_path: backend.authority_seed_path,
            authority_db_path: backend.authority_db_path,
            certification_registry_file: backend.certification_registry_file,
            issuance_policy: None,
            query: &request.query,
            supersedes_artifact_id: request.supersedes_bond_id.as_deref(),
        })?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&bond)?);
    } else {
        println!("schema:                 {}", bond.body.schema);
        println!("bond_id:                {}", bond.body.bond_id);
        println!("issued_at:              {}", bond.body.issued_at);
        println!("expires_at:             {}", bond.body.expires_at);
        println!("signer_key:             {}", bond.signer_key.to_hex());
        println!("disposition:            {:?}", bond.body.report.disposition);
        println!("lifecycle_state:        {:?}", bond.body.lifecycle_state);
    }

    Ok(())
}

pub(crate) fn cmd_trust_credit_bond_simulate(
    bond_id: &str,
    autonomy_tier: &str,
    runtime_assurance_tier: &str,
    call_chain_present: bool,
    policy_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = chio_kernel::CreditBondedExecutionSimulationRequest {
        query: chio_kernel::CreditBondedExecutionSimulationQuery {
            bond_id: bond_id.to_string(),
            autonomy_tier: parse_governed_autonomy_tier(autonomy_tier)?,
            runtime_assurance_tier: parse_runtime_assurance_tier(runtime_assurance_tier)?,
            call_chain_present,
        },
        policy: load_credit_bonded_execution_control_policy(policy_file)?,
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .simulate_credit_bonded_execution(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "credit bond simulation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_credit_bonded_execution_simulation_report(receipt_db_path, &request)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("generated_at:           {}", report.generated_at);
        println!("bond_id:                {}", report.bond.body.bond_id);
        println!(
            "baseline_decision:      {:?}",
            report.default_evaluation.decision
        );
        println!(
            "simulated_decision:     {:?}",
            report.simulated_evaluation.decision
        );
        println!("decision_changed:       {}", report.delta.decision_changed);
        println!(
            "sandbox_ready:          {}",
            report.simulated_evaluation.sandbox_integration_ready
        );
        println!(
            "findings:               {}",
            report.simulated_evaluation.findings.len()
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_credit_bond_list(
    args: CreditBondListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::CreditBondListQuery {
        bond_id: args.bond_id.map(ToOwned::to_owned),
        facility_id: args.facility_id.map(ToOwned::to_owned),
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        disposition: args
            .disposition
            .map(parse_credit_bond_disposition)
            .transpose()?,
        lifecycle_state: args
            .lifecycle_state
            .map(parse_credit_bond_lifecycle_state)
            .transpose()?,
        limit: Some(args.limit),
    };

    let report = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .list_credit_bonds(&query)?
    } else {
        let receipt_db_path = backend.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "credit bond list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_credit_bonds(receipt_db_path, &query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("matching_bonds:         {}", report.summary.matching_bonds);
        println!("returned_bonds:         {}", report.summary.returned_bonds);
        println!("active_bonds:           {}", report.summary.active_bonds);
        println!("locked_bonds:           {}", report.summary.locked_bonds);
        println!("held_bonds:             {}", report.summary.held_bonds);
        for row in report.bonds {
            println!(
                "- {} disposition={:?} lifecycle={:?}",
                row.bond.body.bond_id, row.bond.body.report.disposition, row.lifecycle_state
            );
        }
    }

    Ok(())
}

pub(crate) fn build_credit_loss_lifecycle_query(
    bond_id: &str,
    event_kind: &str,
    amount_units: Option<u64>,
    amount_currency: Option<&str>,
) -> Result<chio_kernel::CreditLossLifecycleQuery, CliError> {
    let amount =
        match (amount_units, amount_currency) {
            (Some(units), Some(currency)) => Some(MonetaryAmount {
                units,
                currency: currency.to_string(),
            }),
            (None, None) => None,
            _ => return Err(CliError::cli_other_error(
                "credit loss lifecycle amount requires both --amount-units and --amount-currency"
                    .to_string(),
            )),
        };

    Ok(chio_kernel::CreditLossLifecycleQuery {
        bond_id: bond_id.to_string(),
        event_kind: parse_credit_loss_lifecycle_event_kind(event_kind)?,
        amount,
    })
}
