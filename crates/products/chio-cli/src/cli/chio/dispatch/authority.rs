use super::{read_utf8_json_file, write_json_string};
use crate::CliError;
use std::fs;
use std::path::Path;

pub(crate) fn cmd_chio_federation_authority_issue(
    profile: &Path,
    request: &Path,
    signing_keys: &Path,
    out_dir: &Path,
) -> Result<(), CliError> {
    let profile = chio_federation_authority::authority_profile_from_json(&read_utf8_json_file(
        profile,
        "Chio federation authority profile",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chio authority profile: {error}")))?;
    let request = chio_federation_authority::issuance_request_from_json(&read_utf8_json_file(
        request,
        "Chio issuance request",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chio issuance request: {error}")))?;
    let signing_keys = chio_federation_authority::signing_keys_from_json(&read_utf8_json_file(
        signing_keys,
        "Chio local signing keys",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chio local signing keys: {error}")))?;
    let bundle =
        chio_federation_authority::issue_authority_bundle(&profile, &request, &signing_keys)
            .map_err(|error| CliError::cli_other_error(format!("Chio authority issue: {error}")))?;
    fs::create_dir_all(out_dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create Chio authority output directory {}: {error}",
            out_dir.display()
        ))
    })?;
    write_json_string(
        &out_dir.join("issuance-bundle.json"),
        &chio_federation_authority::issuance_bundle_json(&bundle)
            .map_err(|error| CliError::cli_other_error(format!("Chio issuance bundle: {error}")))?,
    )?;
    write_json_string(
        &out_dir.join("capability-leases.json"),
        &serde_json::to_string_pretty(&bundle.capability_leases)
            .map_err(|error| CliError::cli_other_error(format!("Chio leases JSON: {error}")))?,
    )?;
    write_json_string(
        &out_dir.join("lease-scope-bindings.json"),
        &serde_json::to_string_pretty(&bundle.lease_scope_bindings).map_err(|error| {
            CliError::cli_other_error(format!("Chio lease scope bindings JSON: {error}"))
        })?,
    )?;
    write_json_string(
        &out_dir.join("governance-receipts.json"),
        &serde_json::to_string_pretty(&bundle.governance_receipts).map_err(|error| {
            CliError::cli_other_error(format!("Chio governance receipts JSON: {error}"))
        })?,
    )?;
    write_json_string(
        &out_dir.join("verification-context.json"),
        &chio_attest_buyer_core::context::verification_context_json(&bundle.verification_context)
            .map_err(|error| CliError::cli_other_error(format!("Chio context JSON: {error}")))?,
    )?;
    Ok(())
}

pub(crate) fn cmd_chio_federation_authority_checkpoint(
    profile: &Path,
    revocations: &Path,
    signing_keys: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let profile = chio_federation_authority::authority_profile_from_json(&read_utf8_json_file(
        profile,
        "Chio federation authority profile",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chio authority profile: {error}")))?;
    let revocations = chio_federation_authority::revocation_publication_request_from_json(
        &read_utf8_json_file(revocations, "Chio revocation publication request")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio revocation publication request: {error}"))
    })?;
    let signing_keys = chio_federation_authority::signing_keys_from_json(&read_utf8_json_file(
        signing_keys,
        "Chio local signing keys",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chio local signing keys: {error}")))?;
    let checkpoint = chio_federation_authority::publish_revocation_checkpoint(
        &profile,
        &revocations,
        &signing_keys,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chio checkpoint publish: {error}")))?;
    write_json_string(
        out,
        &chio_federation_authority::signed_revocation_checkpoint_json(&checkpoint)
            .map_err(|error| CliError::cli_other_error(format!("Chio checkpoint JSON: {error}")))?,
    )
}

pub(crate) fn cmd_chio_federation_authority_trust_bundle_assemble(
    profile: &Path,
    peer_pins: &Path,
    workflow_intersection: &Path,
    disclosure_policy: &Path,
    checkpoint: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let profile = chio_federation_authority::authority_profile_from_json(&read_utf8_json_file(
        profile,
        "Chio federation authority profile",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chio authority profile: {error}")))?;
    let peer_pins = chio_federation_authority::peer_pins_from_json(&read_utf8_json_file(
        peer_pins,
        "Chio peer pins",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chio peer pins: {error}")))?;
    let workflow_intersection: chio_attest_buyer_core::claims::WorkflowIntersectionArtifact =
        serde_json::from_str(&read_utf8_json_file(
            workflow_intersection,
            "Chio workflow intersection",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio workflow intersection JSON: {error}"))
        })?;
    let disclosure_policy: chio_attest_buyer_core::disclosure::ChioDisclosurePolicy =
        serde_json::from_str(&read_utf8_json_file(
            disclosure_policy,
            "Chio disclosure policy",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio disclosure policy JSON: {error}"))
        })?;
    let checkpoint: chio_attest_buyer_core::revocation::SignedChioRevocationCheckpoint =
        serde_json::from_str(&read_utf8_json_file(
            checkpoint,
            "Chio revocation checkpoint",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio revocation checkpoint JSON: {error}"))
        })?;
    let document = chio_federation_authority::assemble_verifier_trust_bundle(
        &profile,
        &peer_pins,
        &workflow_intersection,
        disclosure_policy,
        checkpoint,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chio trust bundle assemble: {error}")))?;
    write_json_string(
        out,
        &chio_attest_buyer_core::trust_bundle::verifier_trust_bundle_json(&document).map_err(
            |error| CliError::cli_other_error(format!("Chio verifier trust bundle JSON: {error}")),
        )?,
    )
}
