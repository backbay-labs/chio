use chio_transaction_passport::TransactionPassportError;

use super::super::claims::CLAIM_EXTERNAL_GRAPHQL_HTTP_SUBSCRIPTION_COVERAGE;
use super::super::evidence::validate_sha256_hex;
use super::{claim_failed, required_json_str, required_json_u64, ProjectionManifest};

pub(super) fn validate_subject(
    value: &serde_json::Value,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if !manifest
        .unsupported_claims
        .iter()
        .any(|claim| claim == CLAIM_EXTERNAL_GRAPHQL_HTTP_SUBSCRIPTION_COVERAGE)
    {
        return Err(claim_failed(
            "GraphQL subscription limitation was not declared",
        ));
    }

    let endpoint_url_digest = required_json_str(
        value,
        "endpoint_url_digest",
        "missing GraphQL endpoint digest",
    )?;
    let schema_digest = required_json_str(value, "schema_digest", "missing GraphQL schema digest")?;
    let document_digest =
        required_json_str(value, "document_digest", "missing GraphQL document digest")?;
    let variables_digest = required_json_str(
        value,
        "variables_digest",
        "missing GraphQL variables digest",
    )?;
    let response_digest =
        required_json_str(value, "response_digest", "missing GraphQL response digest")?;
    for digest_value in [
        endpoint_url_digest,
        schema_digest,
        document_digest,
        variables_digest,
        response_digest,
    ] {
        validate_sha256_hex(digest_value)
            .map_err(|_| claim_failed(format!("invalid GraphQL digest: {digest_value}")))?;
    }

    let method = required_json_str(value, "method", "missing GraphQL HTTP method")?;
    if !matches!(method, "GET" | "POST") {
        return Err(claim_failed("unsupported GraphQL HTTP method"));
    }
    let media_type = required_json_str(value, "media_type", "missing GraphQL media type")?;
    if media_type != "application/json" {
        return Err(claim_failed("unsupported GraphQL media type"));
    }
    let operation_type =
        required_json_str(value, "operation_type", "missing GraphQL operation type")?;
    match operation_type {
        "query" => {}
        "mutation" => {
            if method != "POST" {
                return Err(claim_failed("GraphQL mutation must use POST"));
            }
        }
        "subscription" => {
            return Err(claim_failed("GraphQL subscription projection unsupported"));
        }
        _ => return Err(claim_failed("unsupported GraphQL operation type")),
    }
    required_json_str(value, "operation_name", "missing GraphQL operation name")?;
    let status_code = required_json_u64(value, "status_code", "missing GraphQL status code")?;
    if !(100..=599).contains(&status_code) {
        return Err(claim_failed("unsupported GraphQL status code"));
    }
    if !(200..=299).contains(&status_code) {
        return Err(claim_failed("GraphQL HTTP status was not successful"));
    }
    if let Some(response_has_errors) = value.get("response_has_errors") {
        let Some(response_has_errors) = response_has_errors.as_bool() else {
            return Err(claim_failed("GraphQL response error flag must be boolean"));
        };
        if response_has_errors {
            let response_error_digest = required_json_str(
                value,
                "response_error_digest",
                "missing GraphQL response error digest",
            )?;
            validate_sha256_hex(response_error_digest).map_err(|_| {
                claim_failed(format!(
                    "invalid GraphQL response error digest: {response_error_digest}"
                ))
            })?;
            return Err(claim_failed("GraphQL response contains errors"));
        }
    }
    Ok(())
}
