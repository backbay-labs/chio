use super::super::*;

pub(super) fn validate_control_token(control_token: &str) -> Result<(), CliError> {
    validate_control_secret(control_token, "control token")
}

pub(super) fn normalize_control_endpoint(endpoint: &str) -> Result<String, CliError> {
    let parsed = Url::parse(endpoint).map_err(|error| {
        CliError::cli_other_error(format!(
            "control URL `{endpoint}` must be a valid URL: {error}"
        ))
    })?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(CliError::cli_other_error(format!(
                "control URL `{endpoint}` scheme `{scheme}` must be http or https"
            )));
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CliError::cli_other_error(format!(
            "control URL `{endpoint}` must not contain username or password material"
        )));
    }
    if parsed.query().is_some() {
        return Err(CliError::cli_other_error(format!(
            "control URL `{endpoint}` must not contain a query string"
        )));
    }
    if parsed.fragment().is_some() {
        return Err(CliError::cli_other_error(format!(
            "control URL `{endpoint}` must not contain a fragment"
        )));
    }
    Ok(endpoint.trim_end_matches('/').to_string())
}

pub(crate) fn encode_path_segment(segment: &str) -> String {
    utf8_percent_encode(segment, NON_ALPHANUMERIC).to_string()
}

pub(crate) fn path_with_encoded_param(template: &str, param_name: &str, value: &str) -> String {
    template.replace(&format!("{{{param_name}}}"), &encode_path_segment(value))
}

pub(crate) fn certification_marketplace_search_path(
    query: &CertificationMarketplaceSearchQuery,
) -> String {
    let mut serializer = UrlFormSerializer::new(String::new());
    if let Some(tool_server_id) = query.filters.tool_server_id.as_deref() {
        serializer.append_pair("toolServerId", tool_server_id);
    }
    if let Some(criteria_profile) = query.filters.criteria_profile.as_deref() {
        serializer.append_pair("criteriaProfile", criteria_profile);
    }
    if let Some(evidence_profile) = query.filters.evidence_profile.as_deref() {
        serializer.append_pair("evidenceProfile", evidence_profile);
    }
    if let Some(status) = query.filters.status {
        serializer.append_pair("status", status.label());
    }
    if let Some(operator_ids) = query.operator_ids.as_deref() {
        serializer.append_pair("operatorIds", operator_ids);
    }
    let encoded = serializer.finish();
    if encoded.is_empty() {
        CERTIFICATION_DISCOVERY_SEARCH_PATH.to_string()
    } else {
        format!("{CERTIFICATION_DISCOVERY_SEARCH_PATH}?{encoded}")
    }
}

pub(crate) fn certification_marketplace_transparency_path(
    query: &CertificationMarketplaceTransparencyQuery,
) -> String {
    let mut serializer = UrlFormSerializer::new(String::new());
    if let Some(tool_server_id) = query.filters.tool_server_id.as_deref() {
        serializer.append_pair("toolServerId", tool_server_id);
    }
    if let Some(operator_ids) = query.operator_ids.as_deref() {
        serializer.append_pair("operatorIds", operator_ids);
    }
    let encoded = serializer.finish();
    if encoded.is_empty() {
        CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH.to_string()
    } else {
        format!("{CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH}?{encoded}")
    }
}

pub(crate) fn should_retry_status(status: u16) -> bool {
    matches!(status, 500 | 502 | 503 | 504)
}
