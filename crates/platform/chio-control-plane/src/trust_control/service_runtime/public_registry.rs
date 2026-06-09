use super::client::path_with_encoded_param;
use super::*;

pub fn resolve_public_certification(
    registry_url: &str,
    tool_server_id: &str,
) -> Result<CertificationResolutionResponse, CliError> {
    let endpoint = registry_url.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(CliError::cli_other_error(
            "public certification registry URL must not be empty".to_string(),
        ));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    let path = path_with_encoded_param(
        PUBLIC_CERTIFICATION_RESOLVE_PATH,
        "tool_server_id",
        tool_server_id,
    );
    let response = agent
        .get(&format!("{endpoint}{path}"))
        .call()
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to query public certification registry {endpoint}: {error}"
            ))
        })?;
    response.into_json().map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to parse public certification response from {endpoint}: {error}"
        ))
    })
}

pub fn resolve_public_certification_metadata(
    registry_url: &str,
) -> Result<CertificationPublicMetadata, CliError> {
    public_certification_get_json(registry_url, PUBLIC_CERTIFICATION_METADATA_PATH)
}

pub fn resolve_public_generic_namespace(
    registry_url: &str,
) -> Result<SignedGenericNamespace, CliError> {
    public_registry_get_json(registry_url, PUBLIC_GENERIC_NAMESPACE_PATH)
}

pub fn search_public_generic_listings(
    registry_url: &str,
    query: &GenericListingQuery,
) -> Result<GenericListingReport, CliError> {
    public_registry_get_json_with_query(registry_url, PUBLIC_GENERIC_LISTINGS_PATH, query)
}

pub fn search_public_certifications(
    registry_url: &str,
    query: &CertificationPublicSearchQuery,
) -> Result<CertificationPublicSearchResponse, CliError> {
    public_certification_get_json_with_query(registry_url, PUBLIC_CERTIFICATION_SEARCH_PATH, query)
}

pub fn resolve_public_certification_transparency(
    registry_url: &str,
    query: &CertificationTransparencyQuery,
) -> Result<CertificationTransparencyResponse, CliError> {
    public_certification_get_json_with_query(
        registry_url,
        PUBLIC_CERTIFICATION_TRANSPARENCY_PATH,
        query,
    )
}

fn public_certification_get_json<T: for<'de> Deserialize<'de>>(
    registry_url: &str,
    path: &str,
) -> Result<T, CliError> {
    let endpoint = registry_url.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(CliError::cli_other_error(
            "public certification registry URL must not be empty".to_string(),
        ));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    let response = agent
        .get(&format!("{endpoint}{path}"))
        .call()
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to query public certification registry {endpoint}: {error}"
            ))
        })?;
    response.into_json().map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to parse public certification response from {endpoint}: {error}"
        ))
    })
}

fn public_registry_get_json<T: for<'de> Deserialize<'de>>(
    registry_url: &str,
    path: &str,
) -> Result<T, CliError> {
    let endpoint = registry_url.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(CliError::cli_other_error(
            "public registry URL must not be empty".to_string(),
        ));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    let response = agent
        .get(&format!("{endpoint}{path}"))
        .call()
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to query public registry {endpoint}: {error}"
            ))
        })?;
    response.into_json().map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to parse public registry response from {endpoint}: {error}"
        ))
    })
}

fn public_registry_get_json_with_query<Q: Serialize, T: for<'de> Deserialize<'de>>(
    registry_url: &str,
    path: &str,
    query: &Q,
) -> Result<T, CliError> {
    let endpoint = registry_url.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(CliError::cli_other_error(
            "public registry URL must not be empty".to_string(),
        ));
    }
    let encoded_query = serde_urlencoded::to_string(query).map_err(|error| {
        CliError::cli_other_error(format!("failed to encode public registry query: {error}"))
    })?;
    let url = if encoded_query.is_empty() {
        format!("{endpoint}{path}")
    } else {
        format!("{endpoint}{path}?{encoded_query}")
    };
    let agent = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    let response = agent.get(&url).call().map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to query public registry {endpoint}: {error}"
        ))
    })?;
    response.into_json().map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to parse public registry response from {endpoint}: {error}"
        ))
    })
}

fn public_certification_get_json_with_query<Q: Serialize, T: for<'de> Deserialize<'de>>(
    registry_url: &str,
    path: &str,
    query: &Q,
) -> Result<T, CliError> {
    let endpoint = registry_url.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(CliError::cli_other_error(
            "public certification registry URL must not be empty".to_string(),
        ));
    }
    let encoded_query = serde_urlencoded::to_string(query).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to encode public certification query: {error}"
        ))
    })?;
    let url = if encoded_query.is_empty() {
        format!("{endpoint}{path}")
    } else {
        format!("{endpoint}{path}?{encoded_query}")
    };
    let agent = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    let response = agent.get(&url).call().map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to query public certification registry {endpoint}: {error}"
        ))
    })?;
    response.into_json().map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to parse public certification response from {endpoint}: {error}"
        ))
    })
}
