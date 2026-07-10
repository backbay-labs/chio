use super::super::super::report_validation::cluster_peer_auth_signature;
use super::super::*;

impl TrustControlClient {
    pub(super) fn build_internal_get_request(
        &self,
        client: &Agent,
        url: &str,
        endpoint: &str,
        term: Option<u64>,
    ) -> Result<ureq::Request, CliError> {
        let Some(cluster_peer_auth) = self.cluster_peer_auth.as_ref() else {
            return Ok(client
                .get(url)
                .set(AUTHORIZATION.as_str(), &format!("Bearer {}", self.token)));
        };
        let issued_at = unix_timestamp_now() as i64;
        let signature = cluster_peer_auth_signature(
            &self.token,
            cluster_peer_auth.node_id.as_ref(),
            endpoint,
            issued_at,
            term,
        )?;
        let mut request = client
            .get(url)
            .set(CLUSTER_NODE_ID_HEADER, cluster_peer_auth.node_id.as_ref())
            .set(CLUSTER_AUTH_ISSUED_AT_HEADER, &issued_at.to_string())
            .set(CLUSTER_AUTH_SIGNATURE_HEADER, &signature);
        if let Some(term) = term {
            request = request.set(CLUSTER_AUTH_TERM_HEADER, &term.to_string());
        }
        Ok(request)
    }

    pub(super) fn build_internal_post_request(
        &self,
        client: &Agent,
        url: &str,
        endpoint: &str,
        term: Option<u64>,
    ) -> Result<ureq::Request, CliError> {
        let Some(cluster_peer_auth) = self.cluster_peer_auth.as_ref() else {
            return Ok(client
                .post(url)
                .set(AUTHORIZATION.as_str(), &format!("Bearer {}", self.token)));
        };
        let issued_at = unix_timestamp_now() as i64;
        let signature = cluster_peer_auth_signature(
            &self.token,
            cluster_peer_auth.node_id.as_ref(),
            endpoint,
            issued_at,
            term,
        )?;
        let mut request = client
            .post(url)
            .set(CLUSTER_NODE_ID_HEADER, cluster_peer_auth.node_id.as_ref())
            .set(CLUSTER_AUTH_ISSUED_AT_HEADER, &issued_at.to_string())
            .set(CLUSTER_AUTH_SIGNATURE_HEADER, &signature);
        if let Some(term) = term {
            request = request.set(CLUSTER_AUTH_TERM_HEADER, &term.to_string());
        }
        Ok(request)
    }
}
