// Dispatch handlers for the `chio receipt` and `chio evidence` command groups.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_receipt(
    command: ReceiptCommands,
    json_output: bool,
    receipt_db: Option<PathBuf>,
    control_url: Option<String>,
    control_token: Option<String>,
) -> Result<(), CliError> {
    match command {
            ReceiptCommands::List {
                capability,
                tool_server,
                tool_name,
                outcome,
                since,
                until,
                min_cost,
                max_cost,
                cost_currency,
                limit,
                cursor,
                tenant,
                admin_all,
            } => cmd_receipt_list(
                ReceiptListArgs {
                    capability: capability.as_deref(),
                    tool_server: tool_server.as_deref(),
                    tool_name: tool_name.as_deref(),
                    outcome: outcome.as_deref(),
                    since,
                    until,
                    min_cost,
                    max_cost,
                    cost_currency: cost_currency.as_deref(),
                    limit,
                    cursor,
                    tenant: tenant.as_deref(),
                    admin_all,
                },
                QueryBackend {
                    json_output,
                    receipt_db_path: receipt_db.as_deref(),
                    control_url: control_url.as_deref(),
                    control_token: control_token.as_deref(),
                },
            ),
            ReceiptCommands::Health => cmd_receipt_health(QueryBackend {
                json_output,
                receipt_db_path: receipt_db.as_deref(),
                control_url: control_url.as_deref(),
                control_token: control_token.as_deref(),
            }),
            ReceiptCommands::Audit { repair } => cmd_receipt_audit(
                repair,
                QueryBackend {
                    json_output,
                    receipt_db_path: receipt_db.as_deref(),
                    control_url: control_url.as_deref(),
                    control_token: control_token.as_deref(),
                },
            ),
            ReceiptCommands::Retention { command } => match command {
                ReceiptRetentionCommands::Repair { archive } => cmd_receipt_retention_repair(
                    &archive,
                    QueryBackend {
                        json_output,
                        receipt_db_path: receipt_db.as_deref(),
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
            },
            ReceiptCommands::Flush { timeout_ms } => cmd_receipt_flush(
                timeout_ms,
                QueryBackend {
                    json_output,
                    receipt_db_path: receipt_db.as_deref(),
                    control_url: control_url.as_deref(),
                    control_token: control_token.as_deref(),
                },
            ),
            ReceiptCommands::Checkpoint { command } => match command {
                ReceiptCheckpointCommands::Status { max_batch } => cmd_receipt_checkpoint_status(
                    max_batch,
                    QueryBackend {
                        json_output,
                        receipt_db_path: receipt_db.as_deref(),
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
                ReceiptCheckpointCommands::Create {
                    kernel_seed_file,
                    max_batch,
                } => cmd_receipt_checkpoint_create(
                    &kernel_seed_file,
                    max_batch,
                    QueryBackend {
                        json_output,
                        receipt_db_path: receipt_db.as_deref(),
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
                ReceiptCheckpointCommands::Verify => cmd_receipt_checkpoint_verify(QueryBackend {
                    json_output,
                    receipt_db_path: receipt_db.as_deref(),
                    control_url: control_url.as_deref(),
                    control_token: control_token.as_deref(),
                }),
            },
            ReceiptCommands::Explain {
                receipt_id,
                input_file,
                depth,
                fanout_limit,
                inspect_bilateral,
                tenant,
                admin_all,
            } => cmd_receipt_explain(
                ReceiptExplainArgs {
                    receipt_id: &receipt_id,
                    input_file: input_file.as_deref(),
                    depth,
                    fanout_limit,
                    inspect_bilateral,
                    tenant: tenant.as_deref(),
                    admin_all,
                },
                QueryBackend {
                    json_output,
                    receipt_db_path: receipt_db.as_deref(),
                    control_url: control_url.as_deref(),
                    control_token: control_token.as_deref(),
                },
            ),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_evidence(
    command: EvidenceCommands,
    json_output: bool,
    receipt_db: Option<PathBuf>,
    control_url: Option<String>,
    control_token: Option<String>,
) -> Result<(), CliError> {
    match command {
            EvidenceCommands::Export {
                output,
                capability,
                agent_subject,
                since,
                until,
                tenant,
                admin_all,
                policy_file,
                federation_policy,
                require_proofs,
            } => evidence_export::cmd_evidence_export(
                &output,
                capability.as_deref(),
                agent_subject.as_deref(),
                since,
                until,
                tenant.as_deref(),
                admin_all,
                policy_file.as_deref(),
                federation_policy.as_deref(),
                require_proofs,
                receipt_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            EvidenceCommands::Verify { input } => {
                evidence_export::cmd_evidence_verify(&input, json_output)
            }
            EvidenceCommands::Import { input } => evidence_export::cmd_evidence_import(
                &input,
                receipt_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
                json_output,
            ),
            EvidenceCommands::FederationPolicy { command } => match command {
                EvidenceFederationPolicyCommands::Create {
                    output,
                    signing_seed_file,
                    issuer,
                    partner,
                    capability,
                    agent_subject,
                    since,
                    until,
                    tenant,
                    admin_all,
                    expires_at,
                    require_proofs,
                    purpose,
                } => evidence_export::cmd_evidence_federation_policy_create(
                    evidence_export::EvidenceFederationPolicyCreateArgs {
                        output: &output,
                        signing_seed_file: &signing_seed_file,
                        issuer: &issuer,
                        partner: &partner,
                        capability_id: capability.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        since,
                        until,
                        tenant: tenant.as_deref(),
                        admin_all,
                        expires_at,
                        require_proofs,
                        purpose: purpose.as_deref(),
                        json_output,
                    },
                ),
            },
    }
}
