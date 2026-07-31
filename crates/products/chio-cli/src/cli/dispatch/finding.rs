use super::*;

#[path = "finding/verify.rs"]
mod finding_verify;
use finding_verify::cmd_finding_verify;

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
        FindingCommands::Buy { .. } => cmd_finding_buy(),
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
        Ok(response) => response.into_string().map_err(|error| {
            CliError::transport_error(format!("failed to read finding response body: {error}"))
        }),
        Err(ureq::Error::Status(status, response)) => Err(http_status_error(status, response)),
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

/// Purchase settles a buyer-blind reveal, which needs the reveal
/// coordinator seam this surface does not yet reach.
fn cmd_finding_buy() -> Result<(), CliError> {
    Err(CliError::cli_other_error(
        "finding purchase requires the reveal coordinator wiring that this workspace revision does not expose to the CLI"
            .to_string(),
    ))
}

const AUTHORIZATION_HEADER: &str = "Authorization";

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "finding/unit_tests.rs"]
mod unit_tests;
