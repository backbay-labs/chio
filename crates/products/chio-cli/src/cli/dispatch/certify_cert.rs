// Dispatch handlers for the `chio certify` and `chio cert` command groups.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_certify(
    command: CertifyCommands,
    json_output: bool,
    control_url: Option<String>,
    control_token: Option<String>,
) -> Result<(), CliError> {
    match command {
        CertifyCommands::Check {
            scenarios_dir,
            results_dir,
            output,
            tool_server_id,
            tool_server_name,
            report_output,
            criteria_profile,
            signing_seed_file,
        } => certify::cmd_certify_check(
            &scenarios_dir,
            &results_dir,
            &output,
            &tool_server_id,
            tool_server_name.as_deref(),
            report_output.as_deref(),
            &criteria_profile,
            &signing_seed_file,
            json_output,
        ),
        CertifyCommands::Verify { input } => certify::cmd_certify_verify(&input, json_output),
        CertifyCommands::Registry { command } => match command {
            CertifyRegistryCommands::Publish {
                input,
                certification_registry_file,
            } => admin::cmd_certify_registry_publish(
                &input,
                certification_registry_file.as_deref(),
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            CertifyRegistryCommands::PublishNetwork {
                input,
                certification_discovery_file,
                operator_ids,
            } => certify::network::cmd_certify_registry_publish_network(
                &input,
                certification_discovery_file.as_deref(),
                &operator_ids,
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            CertifyRegistryCommands::List {
                certification_registry_file,
            } => admin::cmd_certify_registry_list(
                certification_registry_file.as_deref(),
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            CertifyRegistryCommands::Get {
                artifact_id,
                certification_registry_file,
            } => admin::cmd_certify_registry_get(
                &artifact_id,
                certification_registry_file.as_deref(),
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            CertifyRegistryCommands::Resolve {
                tool_server_id,
                certification_registry_file,
            } => admin::cmd_certify_registry_resolve(
                &tool_server_id,
                certification_registry_file.as_deref(),
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            CertifyRegistryCommands::Discover {
                tool_server_id,
                certification_discovery_file,
            } => certify::network::cmd_certify_registry_discover(
                &tool_server_id,
                certification_discovery_file.as_deref(),
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            CertifyRegistryCommands::Search {
                certification_discovery_file,
                tool_server_id,
                criteria_profile,
                evidence_profile,
                status,
                operator_ids,
            } => certify::cmd_certify_registry_search(
                certification_discovery_file.as_deref(),
                tool_server_id.as_deref(),
                criteria_profile.as_deref(),
                evidence_profile.as_deref(),
                status.as_deref(),
                &operator_ids,
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            CertifyRegistryCommands::Transparency {
                certification_discovery_file,
                tool_server_id,
                operator_ids,
            } => certify::cmd_certify_registry_transparency(
                certification_discovery_file.as_deref(),
                tool_server_id.as_deref(),
                &operator_ids,
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            CertifyRegistryCommands::Consume {
                tool_server_id,
                certification_discovery_file,
                operator_ids,
                allowed_criteria_profiles,
                allowed_evidence_profiles,
            } => certify::cmd_certify_registry_consume(
                certification_discovery_file.as_deref(),
                &tool_server_id,
                &operator_ids,
                &allowed_criteria_profiles,
                &allowed_evidence_profiles,
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            CertifyRegistryCommands::Revoke {
                artifact_id,
                reason,
                revoked_at,
                certification_registry_file,
            } => admin::cmd_certify_registry_revoke(
                &artifact_id,
                certification_registry_file.as_deref(),
                reason.as_deref(),
                revoked_at,
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            CertifyRegistryCommands::Dispute {
                artifact_id,
                state,
                note,
                updated_at,
                certification_registry_file,
            } => certify::cmd_certify_registry_dispute(
                &artifact_id,
                &state,
                note.as_deref(),
                updated_at,
                certification_registry_file.as_deref(),
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
        },
    }
}

pub(crate) fn dispatch_cert(
    command: CertCommands,
    json_output: bool,
    authority_seed_file: Option<PathBuf>,
) -> Result<(), CliError> {
    match command {
        CertCommands::Generate {
            session_id,
            receipt_db: cert_receipt_db,
            budget_limit,
            output,
        } => cert::cmd_cert_generate(
            &session_id,
            &cert_receipt_db,
            budget_limit,
            output.as_deref(),
            authority_seed_file.as_deref(),
            json_output,
        ),
        CertCommands::Verify {
            certificate,
            trusted_kernel_pubkey,
            full,
            receipt_db: cert_receipt_db,
        } => cert::cmd_cert_verify(
            &certificate,
            full,
            cert_receipt_db.as_deref(),
            &trusted_kernel_pubkey,
            json_output,
        ),
        CertCommands::Inspect { certificate } => cert::cmd_cert_inspect(&certificate, json_output),
    }
}
