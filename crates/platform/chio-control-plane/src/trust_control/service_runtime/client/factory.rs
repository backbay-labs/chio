use super::super::super::report_validation::normalize_cluster_url;
use super::super::*;
use super::validation::{normalize_control_endpoint, validate_control_token};

pub fn build_client(
    control_url: &str,
    control_token: &str,
) -> Result<TrustControlClient, CliError> {
    build_client_with_cluster_peer(
        control_url,
        control_token,
        None,
        ControlClientAuthKind::Service,
    )
}

pub fn build_public_client(control_url: &str) -> Result<TrustControlClient, CliError> {
    build_client_with_cluster_peer(control_url, "", None, ControlClientAuthKind::Public)
}

pub(crate) fn build_cluster_peer_client(
    control_url: &str,
    control_token: &str,
    node_id: &str,
) -> Result<TrustControlClient, CliError> {
    build_client_with_cluster_peer(
        control_url,
        control_token,
        Some(ClusterPeerClientAuth {
            node_id: Arc::<str>::from(normalize_cluster_url(node_id)?),
        }),
        ControlClientAuthKind::Service,
    )
}

#[derive(Clone, Copy)]
enum ControlClientAuthKind {
    Service,
    Public,
}

fn build_client_with_cluster_peer(
    control_url: &str,
    control_token: &str,
    cluster_peer_auth: Option<ClusterPeerClientAuth>,
    auth_kind: ControlClientAuthKind,
) -> Result<TrustControlClient, CliError> {
    if matches!(auth_kind, ControlClientAuthKind::Service) {
        validate_control_token(control_token)?;
    }
    let endpoints = control_url
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_control_endpoint)
        .collect::<Result<Vec<_>, _>>()?;
    if endpoints.is_empty() {
        return Err(CliError::cli_other_error(
            "control URL must not be empty".to_string(),
        ));
    }
    let http = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    Ok(TrustControlClient {
        endpoints: Arc::new(endpoints),
        preferred_index: Arc::new(Mutex::new(0)),
        token: Arc::<str>::from(control_token.to_string()),
        http,
        cluster_peer_auth,
    })
}
