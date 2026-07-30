use super::*;

use std::io::Read as _;

use chio_control_plane::trust_control::finding_purchase_routes::{
    FindingPurchaseRequest, FindingPurchaseResult, FindingPurchaseVerdict,
    FINDING_PURCHASE_MAX_RESULT_BYTES,
};
use chio_finding_verifier::MAX_RAW_FINDING_BYTES;

#[path = "finding/verify.rs"]
mod finding_verify;
use finding_verify::cmd_finding_verify;

#[path = "finding/challenge.rs"]
mod finding_challenge;
use finding_challenge::cmd_finding_challenge;

/// Authenticated canonical-artifact ingress.
const FINDING_PUBLISH_PATH: &str = "/v1/findings/publish";
/// Public bounded descriptor index.
const FINDING_SEARCH_PATH: &str = "/v1/findings/search";

/// Publish body cap. The venue enforces the same bound at its route
/// layer; checking it here turns a truncated upload into a local
/// diagnostic instead of a remote 413.
const FINDING_PUBLISH_MAX_BODY_BYTES: usize = 256 * 1024;

pub(crate) fn dispatch_finding(
    command: FindingCommands,
    json_output: bool,
    control_url: Option<String>,
    control_token: Option<String>,
) -> Result<(), CliError> {
    match command {
        FindingCommands::Publish { file } => cmd_finding_publish(
            &file,
            json_output,
            control_url.as_deref(),
            control_token.as_deref(),
        ),
        FindingCommands::Search {
            topic_prefix,
            context_sha256,
            after,
            limit,
        } => cmd_finding_search(
            &topic_prefix,
            context_sha256.as_deref(),
            after.as_deref(),
            limit,
            json_output,
            control_url.as_deref(),
        ),
        FindingCommands::Verify {
            file,
            id,
            trust_roots,
            evidence,
            recipe,
            integrity_only,
        } => cmd_finding_verify(
            file.as_deref(),
            id.as_deref(),
            trust_roots.as_deref(),
            evidence.as_deref(),
            recipe.as_deref(),
            integrity_only,
            json_output,
            control_url.as_deref(),
        ),
        FindingCommands::Buy {
            id,
            max_price,
            currency,
            payer,
            deadline_secs,
        } => cmd_finding_buy(
            &id,
            max_price,
            &currency,
            payer.as_deref(),
            deadline_secs,
            json_output,
            control_url.as_deref(),
            control_token.as_deref(),
        ),
        FindingCommands::Challenge {
            finding,
            class,
            evidence,
            challenger_key,
            venue_audit,
            dry_run,
        } => cmd_finding_challenge(
            &finding,
            class,
            &evidence,
            challenger_key.as_deref(),
            venue_audit,
            dry_run,
            json_output,
            control_url.as_deref(),
        ),
    }
}

/// The venue base URL every finding surface resolves against.
fn require_control_url(control_url: Option<&str>) -> Result<&str, CliError> {
    control_url.ok_or_else(|| {
        CliError::cli_other_error(
            "finding surfaces require --control-url pointing at the venue control plane"
                .to_string(),
        )
    })
}

fn finding_endpoint(control_url: &str, path: &str) -> String {
    format!("{}{path}", control_url.trim_end_matches('/'))
}

/// Finding ids are content addresses. Rejecting anything else locally
/// keeps a malformed id out of the request path entirely.
pub(super) fn require_finding_id(value: &str) -> Result<&str, CliError> {
    let well_formed = value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character));
    if well_formed {
        Ok(value)
    } else {
        Err(CliError::cli_other_error(format!(
            "finding id must be 64 lowercase hex characters, got `{value}`"
        )))
    }
}

fn http_status_error(status: u16, response: ureq::Response) -> CliError {
    let message = response
        .into_string()
        .ok()
        .filter(|body| !body.trim().is_empty())
        .unwrap_or_else(|| format!("request failed with status {status}"));
    CliError::transport_error(message)
}

/// Fetch the exact stored bytes of one artifact from the public
/// by-id surface. The venue serves what it accepted verbatim, so the
/// response body is the canonical artifact and never a reserialization.
pub(super) fn fetch_finding_bytes(control_url: &str, finding_id: &str) -> Result<String, CliError> {
    let url = finding_endpoint(control_url, &format!("/v1/findings/{finding_id}"));
    match ureq::get(&url).call() {
        Ok(response) => read_bounded_response(response, MAX_RAW_FINDING_BYTES, "finding response"),
        Err(ureq::Error::Status(status, _)) => Err(CliError::transport_error(format!(
            "finding request failed with status {status}"
        ))),
        Err(ureq::Error::Transport(error)) => Err(CliError::transport_error(format!(
            "transport request failed: {error}"
        ))),
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FindingPublishResponse {
    finding_id: String,
    artifact_sha256: String,
}

fn cmd_finding_publish(
    file: &Path,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let url = require_control_url(control_url)?;
    let token = require_control_token(control_token)?;

    let raw = fs::read(file)?;
    if raw.len() > FINDING_PUBLISH_MAX_BODY_BYTES {
        return Err(CliError::cli_other_error(format!(
            "{} is {} bytes, above the {FINDING_PUBLISH_MAX_BODY_BYTES} byte publish bound",
            file.display(),
            raw.len()
        )));
    }
    let artifact = String::from_utf8(raw).map_err(|error| {
        CliError::cli_other_error(format!("{} is not valid UTF-8: {error}", file.display()))
    })?;

    let endpoint = finding_endpoint(url, FINDING_PUBLISH_PATH);
    let response = match ureq::post(&endpoint)
        .set(AUTHORIZATION_HEADER, &format!("Bearer {token}"))
        .set("Content-Type", "application/json")
        .send_string(&artifact)
    {
        Ok(response) => response,
        Err(ureq::Error::Status(status, response)) => {
            return Err(http_status_error(status, response))
        }
        Err(ureq::Error::Transport(error)) => {
            return Err(CliError::transport_error(format!(
                "transport request failed: {error}"
            )))
        }
    };
    let published: FindingPublishResponse = serde_json::from_reader(response.into_reader())?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&published_json(&published))?
        );
    } else {
        println!("finding_id:      {}", terminal_safe(&published.finding_id));
        println!(
            "artifact_sha256: {}",
            terminal_safe(&published.artifact_sha256)
        );
    }
    Ok(())
}

fn published_json(published: &FindingPublishResponse) -> serde_json::Value {
    serde_json::json!({
        "finding_id": published.finding_id,
        "artifact_sha256": published.artifact_sha256,
    })
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingSearchQuery<'a> {
    topic_prefix: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    context_sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FindingSearchAdmissionRow {
    admission_id: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FindingSearchRow {
    finding_id: String,
    topic: String,
    expires_at: u64,
    #[serde(default)]
    admission: Option<FindingSearchAdmissionRow>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FindingSearchPage {
    results: Vec<FindingSearchRow>,
    #[serde(default)]
    next_cursor: Option<String>,
    count: usize,
}

fn cmd_finding_search(
    topic_prefix: &str,
    context_sha256: Option<&str>,
    after: Option<&str>,
    limit: Option<usize>,
    json_output: bool,
    control_url: Option<&str>,
) -> Result<(), CliError> {
    let url = require_control_url(control_url)?;
    if let Some(context) = context_sha256 {
        require_context_digest(context)?;
    }
    if let Some(cursor) = after {
        require_finding_id(cursor)?;
    }

    let query = FindingSearchQuery {
        topic_prefix,
        context_sha256,
        cursor: after,
        limit,
    };
    let encoded = serde_urlencoded::to_string(&query).map_err(|error| {
        CliError::transport_shape_error(format!("failed to encode finding search query: {error}"))
    })?;
    let endpoint = format!("{}?{encoded}", finding_endpoint(url, FINDING_SEARCH_PATH));

    let body = match ureq::get(&endpoint).call() {
        Ok(response) => response.into_string().map_err(|error| {
            CliError::transport_error(format!("failed to read search response body: {error}"))
        })?,
        Err(ureq::Error::Status(status, response)) => {
            return Err(http_status_error(status, response))
        }
        Err(ureq::Error::Transport(error)) => {
            return Err(CliError::transport_error(format!(
                "transport request failed: {error}"
            )))
        }
    };

    if json_output {
        let value: serde_json::Value = serde_json::from_str(&body)?;
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }

    let page: FindingSearchPage = serde_json::from_str(&body)?;
    println!(
        "{:<64}  {:<40}  {:<12}  ADMISSION",
        "FINDING_ID", "TOPIC", "EXPIRES_AT"
    );
    for row in &page.results {
        let admission = row
            .admission
            .as_ref()
            .map(|admission| admission.admission_id.as_str())
            .unwrap_or("-");
        println!(
            "{:<64}  {:<40}  {:<12}  {}",
            terminal_safe(&row.finding_id),
            terminal_safe(&row.topic),
            row.expires_at,
            terminal_safe(admission)
        );
    }
    println!("count:           {}", page.count);
    match page.next_cursor.as_deref() {
        Some(cursor) => println!("next_cursor:     {}", terminal_safe(cursor)),
        None => println!("next_cursor:     -"),
    }
    Ok(())
}

/// Context digests address the work a finding is about; the index
/// matches them exactly, so a malformed digest is a client error.
fn require_context_digest(value: &str) -> Result<(), CliError> {
    let well_formed = value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character));
    if well_formed {
        Ok(())
    } else {
        Err(CliError::cli_other_error(format!(
            "--context-sha256 must be 64 lowercase hex characters, got `{value}`"
        )))
    }
}

const FINDING_PURCHASE_ERROR_MAX_BYTES: usize = 64 * 1024;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FindingPurchaseErrorBody {
    schema: String,
    code: String,
    message: String,
}

fn purchase_http_status_error(status: u16, response: ureq::Response) -> CliError {
    let body = match read_bounded_response(
        response,
        FINDING_PURCHASE_ERROR_MAX_BYTES,
        "purchase error response",
    ) {
        Ok(body) => body,
        Err(_) => {
            return CliError::transport_error(format!(
                "purchase request failed with status {status}"
            ))
        }
    };
    let strict = chio_core::canonical::canonical_json_bytes_from_str(&body);
    let parsed = serde_json::from_str::<FindingPurchaseErrorBody>(&body);
    match (strict, parsed) {
        (Ok(strict), Ok(error))
            if strict.as_slice() == body.as_bytes()
                && error.schema
                    == chio_control_plane::trust_control::finding_purchase_routes::FINDING_PURCHASE_ERROR_SCHEMA
                && !error.code.is_empty()
                && error.code.len() <= 128
                && error
                    .code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
                && !error.message.is_empty()
                && error.message.len() <= 1_024
                && error.message.trim() == error.message
                && !error.message.chars().any(char::is_control) =>
        {
            CliError::transport_error(format!(
                "purchase request failed ({status}, {}): {}",
                error.code, error.message
            ))
        }
        _ => CliError::transport_error(format!(
            "purchase request failed with status {status}"
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_finding_buy(
    finding_id: &str,
    max_price: u64,
    currency: &str,
    payer: Option<&str>,
    deadline_secs: Option<u64>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let url = require_control_url(control_url)?;
    let token = require_control_token(control_token)?;
    let finding_id = require_finding_id(finding_id)?;
    let request = FindingPurchaseRequest::new(
        finding_id.to_owned(),
        max_price,
        currency.to_owned(),
        payer.map(ToOwned::to_owned),
        deadline_secs,
    )
    .map_err(CliError::cli_other_error)?;

    // Resolve and verify the signed commitment before asking the venue to
    // reserve anything. This is a buyer usability check; the kernel remains
    // the authority for the reveal digest and media type.
    let accepted = finding_verify::accept_finding_from_venue(url, finding_id)?;
    if accepted.finding.finding_id != finding_id {
        return Err(CliError::cli_other_error(
            "venue returned a different finding than the requested id".to_owned(),
        ));
    }

    let request_bytes = chio_core::canonical_json_bytes(&request)?;
    let endpoint = finding_endpoint(url, &format!("/v1/findings/{finding_id}/purchase"));
    let response = match ureq::post(&endpoint)
        .set(AUTHORIZATION_HEADER, &format!("Bearer {token}"))
        .set("Content-Type", "application/json")
        .send_bytes(&request_bytes)
    {
        Ok(response) => response,
        Err(ureq::Error::Status(status, response)) => {
            return Err(purchase_http_status_error(status, response))
        }
        Err(ureq::Error::Transport(error)) => {
            return Err(CliError::transport_error(format!(
                "transport request failed: {error}"
            )))
        }
    };
    let raw_result = read_bounded_response(
        response,
        FINDING_PURCHASE_MAX_RESULT_BYTES,
        "purchase response",
    )?;
    let result = parse_purchase_result(&raw_result, &request)?;
    verify_purchased_output(&accepted.finding, &result)?;
    emit_purchase_result(&result, json_output)
}

fn read_bounded_response(
    response: ureq::Response,
    max_bytes: usize,
    label: &str,
) -> Result<String, CliError> {
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| CliError::transport_error(format!("failed to read {label}: {error}")))?;
    if bytes.len() > max_bytes {
        return Err(CliError::transport_shape_error(format!(
            "{label} exceeds the {max_bytes} byte bound"
        )));
    }
    String::from_utf8(bytes)
        .map_err(|_| CliError::transport_shape_error(format!("{label} is not UTF-8")))
}

fn parse_purchase_result(
    raw: &str,
    request: &FindingPurchaseRequest,
) -> Result<FindingPurchaseResult, CliError> {
    let strict = chio_core::canonical::canonical_json_bytes_from_str(raw).map_err(|error| {
        CliError::transport_shape_error(format!(
            "purchase response is not strict canonical I-JSON: {error}"
        ))
    })?;
    if strict.as_slice() != raw.as_bytes() {
        return Err(CliError::transport_shape_error(
            "purchase response bytes are not canonical".to_owned(),
        ));
    }
    let result: FindingPurchaseResult = serde_json::from_str(raw)?;
    let typed = chio_core::canonical_json_bytes(&result)?;
    if typed != strict {
        return Err(CliError::transport_shape_error(
            "purchase response typed bytes drift from the accepted response".to_owned(),
        ));
    }
    result
        .validate_shape(request)
        .map_err(|error| CliError::transport_shape_error(format!("invalid purchase result: {error}")))?;
    Ok(result)
}

fn verify_purchased_output(
    finding: &chio_finding::Finding,
    result: &FindingPurchaseResult,
) -> Result<(), CliError> {
    let Some(output) = result.output.as_ref() else {
        if result.verdict == FindingPurchaseVerdict::Deny {
            return Ok(());
        }
        return Err(CliError::transport_shape_error(
            "allowed purchase omitted its revealed output".to_owned(),
        ));
    };
    if output.media_type != finding.payload_media_type {
        return Err(CliError::transport_shape_error(
            "purchased output media type does not match the finding".to_owned(),
        ));
    }
    let reveal = serde_json::json!({
        "media_type": output.media_type,
        "payload_b64": output.payload_b64,
    });
    let digest = chio_core::canonical_json_bytes(&reveal)
        .map(|bytes| chio_core::sha256_hex(&bytes))?;
    if digest != finding.payload_sha256 {
        return Err(CliError::transport_shape_error(
            "purchased output does not match the signed finding commitment".to_owned(),
        ));
    }
    Ok(())
}

fn emit_purchase_result(result: &FindingPurchaseResult, json_output: bool) -> Result<(), CliError> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(result)?);
        return Ok(());
    }
    println!("request_id:        {}", result.request_id);
    println!("finding_id:        {}", result.finding_id);
    println!("payer:             {}", result.payer);
    println!("payer_key:         {}", result.payer_key.to_hex());
    println!("verdict:           {}", match result.verdict {
        FindingPurchaseVerdict::Allow => "allow",
        FindingPurchaseVerdict::Deny => "deny",
    });
    println!("settlement:        {}", match result.settlement {
        chio_control_plane::trust_control::finding_purchase_routes::FindingPurchaseSettlementTerminal::Captured => "captured",
        chio_control_plane::trust_control::finding_purchase_routes::FindingPurchaseSettlementTerminal::Released => "released",
    });
    println!("reservation_id:    {}", result.reservation_id);
    println!("purchase_intent:   {}", result.purchase_intent_id);
    println!("delivery_receipt:  {}", result.delivery_receipt.id);
    println!(
        "accepted_price:    {} {}",
        result.accepted_price.units, result.accepted_price.currency
    );
    println!(
        "realized_spend:    {} {}",
        result.realized_spend.units, result.realized_spend.currency
    );
    if let Some(record) = result.purchase_record.as_ref() {
        println!("purchase_key:      {}", record.body.purchase_key);
    }
    if let Some(failed) = result.failed_delivery.as_ref() {
        println!("failed_delivery:   {}", failed.body.failed_delivery_id);
    }
    if let Some(output) = result.output.as_ref() {
        println!("media_type:        {}", output.media_type);
        println!("payload_b64:       {}", output.payload_b64);
    }
    Ok(())
}

const AUTHORIZATION_HEADER: &str = "Authorization";

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "finding/unit_tests.rs"]
mod unit_tests;
