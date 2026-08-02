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

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

/// Authenticated canonical-artifact ingress.
const FINDING_PUBLISH_PATH: &str = "/v1/findings/publish";
/// Public bounded descriptor index.
const FINDING_SEARCH_PATH: &str = "/v1/findings/search";

/// Publish body cap. The venue enforces the same bound at its route
/// layer; checking it here turns a truncated upload into a local
/// diagnostic instead of a remote 413.
const FINDING_PUBLISH_MAX_BODY_BYTES: usize = 256 * 1024;
/// Out-of-band status operator authorization file cap.
const FINDING_STATUS_AUTHORIZATION_MAX_BYTES: usize = 64 * 1024;
/// Aggregate status response cap, including the portable proof and the
/// separately projected signed epoch carrier.
const FINDING_STATUS_RESPONSE_MAX_BYTES: usize = 512 * 1024;
/// Durable CLI rollback-floor document cap.
const FINDING_STATUS_FLOOR_MAX_BYTES: usize = 16 * 1024;
const FINDING_STATUS_FLOOR_SCHEMA_V1: &str = "chio.finding.status-cli-floor.v1";

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
        FindingCommands::Status {
            id,
            feed,
            operator_authorization,
            rollback_floor,
            max_epoch_age_secs,
        } => cmd_finding_status(
            &id,
            &feed,
            &operator_authorization,
            &rollback_floor,
            max_epoch_age_secs,
            json_output,
            control_url.as_deref(),
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
            control_token.as_deref(),
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

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct FindingStatusProofResponse {
    feed_id: String,
    key_domain_nonce: u64,
    map_epoch: u64,
    epoch_id: String,
    root_hash: String,
    finding_id: String,
    proof_kind: String,
    proof_sha256: String,
    proof_input_b64: String,
    signed_epoch_sha256: String,
    signed_epoch_b64: String,
    checked_at: u64,
    valid_until: u64,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct FindingStatusCliFloor {
    schema: String,
    feed_id: String,
    operator_id: String,
    rotation_policy_ref: String,
    operator_key_epoch: u64,
    operator_authorization_sha256: String,
    key_domain_nonce: u64,
    map_epoch: u64,
    epoch_id: String,
    root_hash: String,
}

struct FindingStatusFloorLock {
    _file: std::fs::File,
}

impl FindingStatusFloorLock {
    fn acquire(floor_path: &Path) -> Result<Self, CliError> {
        let file_name = floor_path.file_name().ok_or_else(|| {
            CliError::cli_other_error("finding status rollback floor path has no file name".to_owned())
        })?;
        let mut lock_name = file_name.to_os_string();
        lock_name.push(".lock");
        let path = floor_path.with_file_name(lock_name);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to open finding status rollback-floor lock {}: {error}",
                    path.display()
                ))
            })?;
        file.try_lock().map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to acquire finding status rollback-floor lock {}: {error}",
                path.display()
            ))
        })?;
        Ok(Self { _file: file })
    }
}

fn require_feed_id(feed_id: &str) -> Result<&str, CliError> {
    if feed_id.is_empty()
        || feed_id.len() > 512
        || !feed_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/')
        })
    {
        return Err(CliError::cli_other_error(
            "status feed id contains characters outside [A-Za-z0-9._:/-]".to_string(),
        ));
    }
    Ok(feed_id)
}

fn load_status_operator_authorization(
    path: &Path,
    expected_feed: &str,
) -> Result<chio_finding::FindingStatusOperatorAuthorization, CliError> {
    let mut reader = std::fs::File::open(path)?
        .take((FINDING_STATUS_AUTHORIZATION_MAX_BYTES as u64).saturating_add(1));
    let mut bytes = Vec::with_capacity(FINDING_STATUS_AUTHORIZATION_MAX_BYTES.saturating_add(1));
    reader.read_to_end(&mut bytes)?;
    if bytes.len() > FINDING_STATUS_AUTHORIZATION_MAX_BYTES {
        return Err(CliError::cli_other_error(format!(
            "{} exceeds the finding status operator authorization bound",
            path.display()
        )));
    }
    let raw = std::str::from_utf8(&bytes).map_err(|error| {
        CliError::cli_other_error(format!("{} is not valid UTF-8: {error}", path.display()))
    })?;
    let canonical = chio_core::canonical::canonical_json_bytes_from_str(raw).map_err(|error| {
        CliError::cli_other_error(format!(
            "{} is not strict canonical I-JSON: {error}",
            path.display()
        ))
    })?;
    if canonical != bytes {
        return Err(CliError::cli_other_error(format!(
            "{} is not the canonical authorization serialization",
            path.display()
        )));
    }
    let authorization: chio_finding::FindingStatusOperatorAuthorization =
        serde_json::from_slice(&bytes)?;
    authorization.validate().map_err(|error| {
        CliError::cli_other_error(format!(
            "finding status operator authorization is invalid: {error}"
        ))
    })?;
    if authorization.feed_id != expected_feed {
        return Err(CliError::cli_other_error(
            "finding status operator authorization binds a different feed".to_owned(),
        ));
    }
    Ok(authorization)
}

fn verify_status_projection(
    response: &FindingStatusProofResponse,
    expected_feed: &str,
    expected_finding: &str,
    authorization: &chio_finding::FindingStatusOperatorAuthorization,
    max_epoch_age_secs: u64,
) -> Result<(), CliError> {
    if response.feed_id != expected_feed || response.finding_id != expected_finding {
        return Err(CliError::cli_other_error(
            "finding status response binds a different feed or finding".to_string(),
        ));
    }
    let max_proof_b64 = (chio_finding::MAX_FINDING_STATUS_PROOF_BYTES.saturating_add(2) / 3)
        .saturating_mul(4);
    let max_epoch_b64 = (chio_finding::MAX_FINDING_STATUS_EPOCH_BYTES.saturating_add(2) / 3)
        .saturating_mul(4);
    if response.proof_input_b64.len() > max_proof_b64
        || response.signed_epoch_b64.len() > max_epoch_b64
    {
        return Err(CliError::transport_shape_error(
            "finding status response carries an oversized encoded proof or epoch".to_owned(),
        ));
    }
    let proof_bytes = STANDARD.decode(&response.proof_input_b64).map_err(|_| {
        CliError::cli_other_error("finding status proof is not valid base64".to_string())
    })?;
    if chio_core::sha256_hex(&proof_bytes) != response.proof_sha256 {
        return Err(CliError::cli_other_error(
            "finding status proof digest does not match its exact bytes".to_string(),
        ));
    }
    let proof = chio_finding::parse_status_proof_input(&proof_bytes).map_err(|error| {
        CliError::cli_other_error(format!("finding status proof is not strict canonical input: {error}"))
    })?;
    let (
        proof_kind,
        feed_id,
        key_domain_nonce,
        map_epoch,
        finding_id,
        epoch_id,
        epoch_sha256,
        epoch_b64,
        root_hash,
        checked_at,
    ) = match &proof {
        chio_finding::FindingStatusProofInput::NonInclusion(value) => (
            "non_inclusion",
            value.feed_id.as_str(),
            value.key_domain_nonce,
            value.map_epoch,
            value.finding_id.as_str(),
            value.status_epoch_id.as_str(),
            value.status_epoch_sha256.as_str(),
            value.signed_status_epoch_b64.as_str(),
            value.root_hash.as_str(),
            value.checked_at,
        ),
        chio_finding::FindingStatusProofInput::Inclusion(value) => (
            "inclusion",
            value.feed_id.as_str(),
            value.key_domain_nonce,
            value.map_epoch,
            value.finding_id.as_str(),
            value.status_epoch_id.as_str(),
            value.status_epoch_sha256.as_str(),
            value.signed_status_epoch_b64.as_str(),
            value.root_hash.as_str(),
            value.checked_at,
        ),
    };
    if response.proof_kind != proof_kind
        || response.feed_id != feed_id
        || response.key_domain_nonce != key_domain_nonce
        || response.map_epoch != map_epoch
        || response.finding_id != finding_id
        || response.epoch_id != epoch_id
        || response.signed_epoch_sha256 != epoch_sha256
        || response.signed_epoch_b64 != epoch_b64
        || response.root_hash != root_hash
        || response.checked_at != checked_at
    {
        return Err(CliError::cli_other_error(
            "finding status response fields differ from the strict portable proof".to_string(),
        ));
    }
    let epoch_bytes = STANDARD.decode(&response.signed_epoch_b64).map_err(|_| {
        CliError::cli_other_error("finding status epoch is not valid base64".to_string())
    })?;
    if chio_core::sha256_hex(&epoch_bytes) != response.signed_epoch_sha256 {
        return Err(CliError::cli_other_error(
            "finding status epoch digest does not match its exact bytes".to_string(),
        ));
    }
    let epoch = chio_finding::parse_signed_status_epoch(&epoch_bytes).map_err(|error| {
        CliError::cli_other_error(format!("finding status epoch is not strict canonical input: {error}"))
    })?;
    if epoch.body.feed_id != response.feed_id
        || epoch.body.key_domain_nonce != response.key_domain_nonce
        || epoch.body.map_epoch != response.map_epoch
        || epoch.body.status_epoch_id != response.epoch_id
        || epoch.body.root_hash != response.root_hash
        || epoch.body.valid_until != response.valid_until
        || epoch.signer_key != epoch.body.operator_key
        || !epoch.verify_signature().map_err(|error| {
            CliError::cli_other_error(format!("finding status epoch signature check failed: {error}"))
        })?
    {
        return Err(CliError::cli_other_error(
            "finding status epoch signature or response binding is invalid".to_string(),
        ));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| CliError::cli_other_error(format!("system clock is invalid: {error}")))?
        .as_secs();
    let verified_epoch = chio_finding::verify_status_proof_input(
        &proof,
        authorization,
        chio_finding::FindingStatusFreshnessPolicy {
            now,
            max_epoch_age_secs,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "finding status signature, freshness, or sparse path is invalid: {error}"
        ))
    })?;
    if verified_epoch != epoch {
        return Err(CliError::cli_other_error(
            "finding status proof resolved a different signed epoch".to_string(),
        ));
    }
    Ok(())
}

fn read_status_floor(path: &Path) -> Result<Option<FindingStatusCliFloor>, CliError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CliError::cli_other_error(format!(
            "{} is not a regular rollback-floor file",
            path.display()
        )));
    }
    let mut reader = std::fs::File::open(path)?
        .take((FINDING_STATUS_FLOOR_MAX_BYTES as u64).saturating_add(1));
    let mut bytes = Vec::with_capacity(FINDING_STATUS_FLOOR_MAX_BYTES.saturating_add(1));
    reader.read_to_end(&mut bytes)?;
    if bytes.len() > FINDING_STATUS_FLOOR_MAX_BYTES {
        return Err(CliError::cli_other_error(format!(
            "{} exceeds the finding status rollback-floor bound",
            path.display()
        )));
    }
    let raw = std::str::from_utf8(&bytes).map_err(|error| {
        CliError::cli_other_error(format!("{} is not valid UTF-8: {error}", path.display()))
    })?;
    let canonical = chio_core::canonical::canonical_json_bytes_from_str(raw).map_err(|error| {
        CliError::cli_other_error(format!(
            "{} is not strict canonical I-JSON: {error}",
            path.display()
        ))
    })?;
    if canonical != bytes {
        return Err(CliError::cli_other_error(format!(
            "{} is not the canonical rollback-floor serialization",
            path.display()
        )));
    }
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn write_status_floor(path: &Path, floor: &FindingStatusCliFloor) -> Result<(), CliError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(CliError::cli_other_error(format!(
            "finding status rollback-floor directory {} does not exist",
            parent.display()
        )));
    }
    let file_name = path.file_name().ok_or_else(|| {
        CliError::cli_other_error("finding status rollback floor path has no file name".to_owned())
    })?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| CliError::cli_other_error(format!("system clock is invalid: {error}")))?
        .as_nanos();
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(file_name);
    temp_name.push(format!(".tmp-{}-{nonce}", std::process::id()));
    let temp_path = parent.join(temp_name);
    let bytes = chio_core::canonical_json_bytes(floor)?;
    let write_result = (|| -> Result<(), CliError> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp_path, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result
}

fn advance_status_floor(
    path: &Path,
    status: &FindingStatusProofResponse,
    authorization: &chio_finding::FindingStatusOperatorAuthorization,
    authorization_sha256: &str,
) -> Result<(), CliError> {
    let _lock = FindingStatusFloorLock::acquire(path)?;
    if let Some(current) = read_status_floor(path)? {
        if current.schema != FINDING_STATUS_FLOOR_SCHEMA_V1
            || current.feed_id != status.feed_id
            || current.operator_id != authorization.operator.authority_id
            || current.rotation_policy_ref != authorization.operator.rotation_policy_ref
            || current.key_domain_nonce != status.key_domain_nonce
        {
            return Err(CliError::cli_other_error(
                "finding status rollback floor binds a different feed or operator".to_owned(),
            ));
        }
        if authorization.operator.key_epoch < current.operator_key_epoch
            || (authorization.operator.key_epoch == current.operator_key_epoch
                && authorization_sha256 != current.operator_authorization_sha256)
        {
            return Err(CliError::cli_other_error(
                "finding status operator authorization regressed or equivocated".to_owned(),
            ));
        }
        if status.map_epoch < current.map_epoch {
            return Err(CliError::cli_other_error(
                "finding status response is below the durable rollback floor".to_owned(),
            ));
        }
        if status.map_epoch == current.map_epoch
            && (status.epoch_id != current.epoch_id || status.root_hash != current.root_hash)
        {
            return Err(CliError::cli_other_error(
                "finding status response equivocates at the durable rollback floor".to_owned(),
            ));
        }
    }
    write_status_floor(
        path,
        &FindingStatusCliFloor {
            schema: FINDING_STATUS_FLOOR_SCHEMA_V1.to_owned(),
            feed_id: status.feed_id.clone(),
            operator_id: authorization.operator.authority_id.clone(),
            rotation_policy_ref: authorization.operator.rotation_policy_ref.clone(),
            operator_key_epoch: authorization.operator.key_epoch,
            operator_authorization_sha256: authorization_sha256.to_owned(),
            key_domain_nonce: status.key_domain_nonce,
            map_epoch: status.map_epoch,
            epoch_id: status.epoch_id.clone(),
            root_hash: status.root_hash.clone(),
        },
    )
}

fn cmd_finding_status(
    finding_id: &str,
    feed_id: &str,
    operator_authorization: &Path,
    rollback_floor: &Path,
    max_epoch_age_secs: u64,
    json_output: bool,
    control_url: Option<&str>,
) -> Result<(), CliError> {
    let url = require_control_url(control_url)?;
    let finding_id = require_finding_id(finding_id)?;
    let feed_id = require_feed_id(feed_id)?;
    if max_epoch_age_secs == 0 {
        return Err(CliError::cli_other_error(
            "--max-epoch-age-secs must be greater than zero".to_owned(),
        ));
    }
    let authorization = load_status_operator_authorization(operator_authorization, feed_id)?;
    let authorization_sha256 = chio_core::sha256_hex(&chio_core::canonical_json_bytes(&authorization)?);
    let encoded_feed = utf8_percent_encode(feed_id, NON_ALPHANUMERIC);
    let endpoint = finding_endpoint(
        url,
        &format!("/v1/findings/status/{encoded_feed}/proof/{finding_id}"),
    );
    let response = match ureq::get(&endpoint).call() {
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
    let raw_status = read_bounded_response(
        response,
        FINDING_STATUS_RESPONSE_MAX_BYTES,
        "finding status response",
    )?;
    let status: FindingStatusProofResponse = serde_json::from_str(&raw_status)?;
    verify_status_projection(
        &status,
        feed_id,
        finding_id,
        &authorization,
        max_epoch_age_secs,
    )?;
    advance_status_floor(
        rollback_floor,
        &status,
        &authorization,
        &authorization_sha256,
    )?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        let finding_status = if status.proof_kind == "non_inclusion" {
            "live"
        } else {
            "retracted"
        };
        println!("finding_id:      {}", status.finding_id);
        println!("feed_id:         {}", status.feed_id);
        println!("status:          {finding_status}");
        println!("map_epoch:       {}", status.map_epoch);
        println!("root_hash:       {}", status.root_hash);
        println!("checked_at:      {}", status.checked_at);
        println!("valid_until:     {}", status.valid_until);
        println!("proof_sha256:    {}", status.proof_sha256);
    }
    Ok(())
}

const AUTHORIZATION_HEADER: &str = "Authorization";

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "finding/unit_tests.rs"]
mod unit_tests;
