use chio_core::session::CreateElicitationOperation;
use chio_kernel::KernelError;
use url::Url;

pub(crate) fn parse_url_elicitation_required_error(
    message: String,
    data: Option<serde_json::Value>,
) -> Result<KernelError, String> {
    let data = data
        .ok_or_else(|| "upstream MCP URL-required error is missing structured data".to_string())?;
    let elicitations = data.get("elicitations").cloned().ok_or_else(|| {
        "upstream MCP URL-required error is missing data.elicitations".to_string()
    })?;
    let elicitations: Vec<CreateElicitationOperation> = serde_json::from_value(elicitations)
        .map_err(|error| format!("failed to parse upstream URL-required elicitations: {error}"))?;
    if elicitations.is_empty() {
        return Err(
            "upstream MCP URL-required error must include at least one elicitation".to_string(),
        );
    }
    validate_url_required_elicitations(&elicitations)?;

    Ok(KernelError::UrlElicitationsRequired {
        message,
        elicitations,
    })
}

fn validate_url_required_elicitations(
    elicitations: &[CreateElicitationOperation],
) -> Result<(), String> {
    for (index, elicitation) in elicitations.iter().enumerate() {
        let CreateElicitationOperation::Url {
            message,
            url,
            elicitation_id,
            ..
        } = elicitation
        else {
            return Err(
                "upstream MCP URL-required error must include only URL-mode elicitations"
                    .to_string(),
            );
        };

        validate_unpadded_text(&format!("data.elicitations[{index}].message"), message)?;
        validate_unpadded_text(&format!("data.elicitations[{index}].url"), url)?;
        validate_unpadded_text(
            &format!("data.elicitations[{index}].elicitationId"),
            elicitation_id,
        )?;
        validate_browser_url(&format!("data.elicitations[{index}].url"), url)?;
    }
    Ok(())
}

fn validate_unpadded_text(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.trim() != value {
        return Err(format!(
            "{field} must not include leading or trailing whitespace"
        ));
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Err(format!("{field} must not include control characters"));
    }
    Ok(())
}

fn validate_browser_url(field: &str, value: &str) -> Result<(), String> {
    let parsed =
        Url::parse(value).map_err(|error| format!("{field} is not a valid URL: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!("{field} must use http or https"));
    }
    if parsed.host_str().is_none() {
        return Err(format!("{field} must include a host"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!("{field} must not include userinfo"));
    }
    Ok(())
}
