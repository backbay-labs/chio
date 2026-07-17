use std::str::FromStr;

use chio_core::PublicKey;
use chio_did::{DidChio, DidService, ResolveOptions};

use crate::CliError;

fn resolve_identifier(did: Option<&str>, public_key: Option<&str>) -> Result<DidChio, CliError> {
    match (did, public_key) {
        (Some(value), None) => {
            DidChio::from_str(value).map_err(|error| CliError::cli_other_error(error.to_string()))
        }
        (None, Some(value)) => {
            PublicKey::from_hex(value)
                .map_err(CliError::from)
                .and_then(|public_key| {
                    DidChio::from_public_key(public_key)
                        .map_err(|error| CliError::cli_other_error(error.to_string()))
                })
        }
        (Some(_), Some(_)) => Err(CliError::cli_other_error(
            "provide either --did or --public-key, not both".to_string(),
        )),
        (None, None) => Err(CliError::cli_other_error(
            "provide either --did or --public-key".to_string(),
        )),
    }
}

pub(crate) fn cmd_did_resolve(
    did: Option<&str>,
    public_key: Option<&str>,
    receipt_log_urls: &[String],
    passport_status_urls: &[String],
    _json_output: bool,
) -> Result<(), CliError> {
    let did = resolve_identifier(did, public_key)?;
    let mut options = ResolveOptions::default();
    for (index, url) in receipt_log_urls.iter().enumerate() {
        options = options.with_service(
            DidService::receipt_log(&did, index, url)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        );
    }
    for (index, url) in passport_status_urls.iter().enumerate() {
        options = options.with_service(
            DidService::passport_status(&did, index, url)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        );
    }
    let document = did.resolve_with_options(&options);
    println!("{}", serde_json::to_string_pretty(&document)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_identifier_requires_exactly_one_source() {
        assert!(resolve_identifier(None, None).is_err());
        assert!(resolve_identifier(
            Some("did:chio:d04ab232742bb4ab3a1368bd4615fa0ee602dfd08f52a2408e8dc3f92f2aee72"),
            Some("d04ab232742bb4ab3a1368bd4615fa0ee602dfd08f52a2408e8dc3f92f2aee72")
        )
        .is_err());
    }
}
