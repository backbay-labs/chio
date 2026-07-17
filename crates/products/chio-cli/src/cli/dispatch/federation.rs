use super::*;

pub(crate) fn dispatch_chio_federation_command(
    command: ChioFederationCommands,
) -> Result<(), CliError> {
    match command {
        ChioFederationCommands::Authority { command } => dispatch_chio_authority_command(command),
        ChioFederationCommands::Treaty { command } => dispatch_chio_treaty_command(command),
    }
}

pub(crate) fn dispatch_chio_authority_command(
    command: ChioAuthorityCommands,
) -> Result<(), CliError> {
    match command {
        ChioAuthorityCommands::Issue {
            profile,
            request,
            signing_keys,
            out_dir,
        } => cmd_chio_federation_authority_issue(&profile, &request, &signing_keys, &out_dir),
        ChioAuthorityCommands::Checkpoint {
            profile,
            revocations,
            signing_keys,
            out,
        } => cmd_chio_federation_authority_checkpoint(&profile, &revocations, &signing_keys, &out),
        ChioAuthorityCommands::TrustBundle { command } => match command {
            ChioTrustBundleCommands::Assemble {
                profile,
                peer_pins,
                workflow_intersection,
                disclosure_policy,
                checkpoint,
                out,
            } => cmd_chio_federation_authority_trust_bundle_assemble(
                &profile,
                &peer_pins,
                &workflow_intersection,
                &disclosure_policy,
                &checkpoint,
                &out,
            ),
        },
    }
}

pub(crate) fn dispatch_chio_treaty_command(command: ChioTreatyCommands) -> Result<(), CliError> {
    match command {
        ChioTreatyCommands::Intersect {
            treaty_scope,
            manifest,
            now_unix_ms,
            report,
        } => cmd_chio_federation_treaty_intersect(&treaty_scope, &manifest, now_unix_ms, &report),
        ChioTreatyCommands::Admit {
            treaty_scope,
            ladder_intersection,
            expected_ladder_intersection_sha256,
            action_class_id,
            evidence,
            now_unix_ms,
            report,
        } => cmd_chio_federation_treaty_admit(
            &treaty_scope,
            &ladder_intersection,
            &expected_ladder_intersection_sha256,
            &action_class_id,
            &evidence,
            now_unix_ms,
            &report,
        ),
        ChioTreatyCommands::VerifyPacket {
            packet,
            lineage_statement,
            continuation,
            admission_report,
            bilateral_invocation,
            report,
        } => cmd_chio_federation_treaty_verify_packet(
            &packet,
            &lineage_statement,
            &continuation,
            &admission_report,
            &bilateral_invocation,
            &report,
        ),
    }
}
