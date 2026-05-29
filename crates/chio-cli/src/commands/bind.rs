//! `chio bind <provider> --card <path>` subcommand.
//!
//! Loads a model card from disk, optionally verifies the cosign bundle
//! through `chio_attest_verify::SigstoreVerifier::verify_bundle`, and
//! prints the resolved `(weights_hash, allowed_capability_set)` so an
//! operator can sanity check before promoting `policy.weights_card_required`
//! to `required` or `required_with_pin`.
//!
//! # CLI shape
//!
//! ```text
//! chio bind <provider> --card <path>
//!     [--bundle <path>] [--issuer-san-regex <regex>] [--issuer-oidc <url>]
//! ```
//!
//! - `--card` (required): path to the canonical-JSON encoded
//!   [`chio_weights::ModelCard`].
//! - `--bundle` (optional): path to the cosign bundle. When supplied,
//!   `--issuer-san-regex` and `--issuer-oidc` MUST also be supplied.
//! - `--issuer-san-regex` (required with `--bundle`): SAN regex pinned on
//!   the cosign certificate. Forwarded verbatim to
//!   `chio_attest_verify::ExpectedIdentity::certificate_identity_regexp`.
//! - `--issuer-oidc` (required with `--bundle`): OIDC issuer expected on
//!   the cosign certificate.
//!
//! # Output
//!
//! Human-readable summary to stdout when the card loads cleanly:
//!
//! ```text
//! provider: <provider>
//! card: <path>
//! card_version: 1
//! issuer: <issuer URI>
//! weights_hash: <64-char lowercase hex>
//! allowed_capability_set:
//!   - <scope>
//!   - <scope>
//! banned_tools:
//!   - <tool>
//! training_data_class: <class>
//! issued_at: <RFC 3339 UTC>
//! expires_at: <RFC 3339 UTC>
//! cosign: skipped|verified
//! ```
//!
//! All failure paths surface a stable `urn:chio:error:weights:*` URN via
//! [`chio_control_plane::CliError`].

use std::path::Path;

use chio_attest_verify::{ExpectedIdentity, SigstoreVerifier};
use chio_weights::bundle::verify_model_card_bundle;
use chio_weights::card::ModelCard;
use chrono::Utc;

use crate::CliError;

/// Entry point for `chio bind <provider> --card <path>`.
///
/// Returns `Ok(())` only when the card loads cleanly. When `bundle_path`
/// is supplied, also verifies the cosign bundle through `chio-attest-verify`
/// before printing the resolved binding summary.
pub(crate) fn cmd_bind(
    provider: &str,
    card_path: &Path,
    bundle_path: Option<&Path>,
    issuer_san_regex: Option<&str>,
    issuer_oidc: Option<&str>,
    json_output: bool,
) -> Result<(), CliError> {
    let card_bytes = std::fs::read(card_path).map_err(|e| {
        CliError::cli_other_error(format!(
            "failed to read model card from {:?}: {e}",
            card_path
        ))
    })?;
    let card = ModelCard::from_canonical_json(&card_bytes).map_err(|e| {
        CliError::cli_other_error(format!("model card validation failed [{}]: {e}", e.urn()))
    })?;

    let cosign_status = match bundle_path {
        Some(bp) => {
            let regex = issuer_san_regex.ok_or_else(|| {
                CliError::cli_other_error(
                    "--bundle requires --issuer-san-regex for the cosign cert SAN pin",
                )
            })?;
            let oidc = issuer_oidc.ok_or_else(|| {
                CliError::cli_other_error(
                    "--bundle requires --issuer-oidc for the cosign cert OIDC issuer pin",
                )
            })?;
            let bundle = std::fs::read(bp).map_err(|e| {
                CliError::cli_other_error(format!(
                    "failed to read cosign bundle from {:?}: {e}",
                    bp
                ))
            })?;
            let expected = ExpectedIdentity {
                certificate_identity_regexp: regex.to_string(),
                certificate_oidc_issuer: oidc.to_string(),
            };
            let verifier = SigstoreVerifier::with_embedded_root().map_err(|e| {
                CliError::cli_other_error(format!("sigstore trust root unavailable: {e}"))
            })?;
            verify_model_card_bundle(&verifier, &card_bytes, &bundle, &expected, Utc::now())
                .map_err(|e| {
                    CliError::cli_other_error(format!(
                        "cosign bundle verify failed [{}]: {e}",
                        e.urn()
                    ))
                })?;
            "verified"
        }
        None => "skipped",
    };

    if json_output {
        let payload = serde_json::json!({
            "provider": provider,
            "card_path": card_path.display().to_string(),
            "card_version": card.card_version,
            "issuer": card.issuer,
            "weights_hash": card.weights_hash,
            "allowed_capability_set": card
                .allowed_capability_set
                .iter()
                .collect::<Vec<_>>(),
            "banned_tools": card.banned_tools.iter().collect::<Vec<_>>(),
            "training_data_class": card.training_data_class,
            "issued_at": card.issued_at.to_rfc3339(),
            "expires_at": card.expires_at.to_rfc3339(),
            "cosign": cosign_status,
        });
        let s = serde_json::to_string_pretty(&payload).map_err(CliError::Json)?;
        println!("{s}");
        return Ok(());
    }

    println!("provider: {provider}");
    println!("card: {}", card_path.display());
    println!("card_version: {}", card.card_version);
    println!("issuer: {}", card.issuer);
    println!("weights_hash: {}", card.weights_hash);
    println!("allowed_capability_set:");
    for scope in card.allowed_capability_set.iter() {
        println!("  - {scope}");
    }
    println!("banned_tools:");
    for tool in card.banned_tools.iter() {
        println!("  - {tool}");
    }
    println!("training_data_class: {}", card.training_data_class);
    println!("issued_at: {}", card.issued_at.to_rfc3339());
    println!("expires_at: {}", card.expires_at.to_rfc3339());
    println!("cosign: {cosign_status}");

    Ok(())
}
