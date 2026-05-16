use super::*;

pub(crate) fn cmd_chiodos_authority_issue(
    profile: &Path,
    request: &Path,
    signing_keys: &Path,
    out_dir: &Path,
) -> Result<(), CliError> {
    let profile = chio_chiodos_authority::authority_profile_from_json(&read_utf8_json_file(
        profile,
        "Chiodos authority profile",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chiodos authority profile: {error}")))?;
    let request = chio_chiodos_authority::issuance_request_from_json(&read_utf8_json_file(
        request,
        "Chiodos issuance request",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chiodos issuance request: {error}")))?;
    let signing_keys = chio_chiodos_authority::signing_keys_from_json(&read_utf8_json_file(
        signing_keys,
        "Chiodos local signing keys",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chiodos local signing keys: {error}")))?;
    let bundle = chio_chiodos_authority::issue_authority_bundle(
        &profile,
        &request,
        &signing_keys,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos authority issue: {error}")))?;
    fs::create_dir_all(out_dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create Chiodos authority output directory {}: {error}",
            out_dir.display()
        ))
    })?;
    write_json_string(
        &out_dir.join("issuance-bundle.json"),
        &chio_chiodos_authority::issuance_bundle_json(&bundle)
            .map_err(|error| CliError::cli_other_error(format!("Chiodos issuance bundle: {error}")))?,
    )?;
    write_json_string(
        &out_dir.join("capability-leases.json"),
        &serde_json::to_string_pretty(&bundle.capability_leases)
            .map_err(|error| CliError::cli_other_error(format!("Chiodos leases JSON: {error}")))?,
    )?;
    write_json_string(
        &out_dir.join("lease-scope-bindings.json"),
        &serde_json::to_string_pretty(&bundle.lease_scope_bindings).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos lease scope bindings JSON: {error}"))
        })?,
    )?;
    write_json_string(
        &out_dir.join("governance-receipts.json"),
        &serde_json::to_string_pretty(&bundle.governance_receipts).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos governance receipts JSON: {error}"))
        })?,
    )?;
    write_json_string(
        &out_dir.join("verification-context.json"),
        &chio_chiodos::verification_context_json(&bundle.verification_context)
            .map_err(|error| CliError::cli_other_error(format!("Chiodos context JSON: {error}")))?,
    )?;
    Ok(())
}

pub(crate) fn cmd_chiodos_authority_checkpoint(
    profile: &Path,
    revocations: &Path,
    signing_keys: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let profile = chio_chiodos_authority::authority_profile_from_json(&read_utf8_json_file(
        profile,
        "Chiodos authority profile",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chiodos authority profile: {error}")))?;
    let revocations =
        chio_chiodos_authority::revocation_publication_request_from_json(&read_utf8_json_file(
            revocations,
            "Chiodos revocation publication request",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos revocation publication request: {error}"))
        })?;
    let signing_keys = chio_chiodos_authority::signing_keys_from_json(&read_utf8_json_file(
        signing_keys,
        "Chiodos local signing keys",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chiodos local signing keys: {error}")))?;
    let checkpoint = chio_chiodos_authority::publish_revocation_checkpoint(
        &profile,
        &revocations,
        &signing_keys,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos checkpoint publish: {error}")))?;
    write_json_string(
        out,
        &chio_chiodos_authority::signed_revocation_checkpoint_json(&checkpoint)
            .map_err(|error| CliError::cli_other_error(format!("Chiodos checkpoint JSON: {error}")))?,
    )
}

pub(crate) fn cmd_chiodos_authority_trust_bundle_assemble(
    profile: &Path,
    peer_pins: &Path,
    workflow_intersection: &Path,
    disclosure_policy: &Path,
    checkpoint: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let profile = chio_chiodos_authority::authority_profile_from_json(&read_utf8_json_file(
        profile,
        "Chiodos authority profile",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chiodos authority profile: {error}")))?;
    let peer_pins = chio_chiodos_authority::peer_pins_from_json(&read_utf8_json_file(
        peer_pins,
        "Chiodos peer pins",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chiodos peer pins: {error}")))?;
    let workflow_intersection: chio_chiodos::WorkflowIntersectionArtifact =
        serde_json::from_str(&read_utf8_json_file(
            workflow_intersection,
            "Chiodos workflow intersection",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos workflow intersection JSON: {error}"))
        })?;
    let disclosure_policy: chio_chiodos::ChiodosDisclosurePolicy =
        serde_json::from_str(&read_utf8_json_file(
            disclosure_policy,
            "Chiodos disclosure policy",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos disclosure policy JSON: {error}"))
        })?;
    let checkpoint: chio_chiodos::SignedChiodosRevocationCheckpoint =
        serde_json::from_str(&read_utf8_json_file(
            checkpoint,
            "Chiodos revocation checkpoint",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos revocation checkpoint JSON: {error}"))
        })?;
    let document = chio_chiodos_authority::assemble_verifier_trust_bundle(
        &profile,
        &peer_pins,
        &workflow_intersection,
        disclosure_policy,
        checkpoint,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos trust bundle assemble: {error}")))?;
    write_json_string(
        out,
        &chio_chiodos::verifier_trust_bundle_json(&document).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos verifier trust bundle JSON: {error}"))
        })?,
    )
}

