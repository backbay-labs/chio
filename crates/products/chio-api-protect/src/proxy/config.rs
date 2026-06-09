use super::*;

/// Configuration for the protect proxy.
pub struct ProtectConfig {
    /// Upstream URL to proxy to.
    pub upstream: String,
    /// Optional in-memory OpenAPI spec content (YAML or JSON).
    pub spec_content: Option<String>,
    /// Optional OpenAPI spec path. When omitted, the proxy auto-discovers the spec.
    pub spec_path: Option<String>,
    /// Address to listen on (e.g., "127.0.0.1:9090").
    pub listen_addr: String,
    /// Optional SQLite path for receipt persistence.
    pub receipt_db: Option<String>,
    /// Optional bearer token that authorizes remote sidecar control requests.
    pub sidecar_control_token: Option<String>,
    /// Optional seed used to keep the sidecar signer stable across restarts.
    pub signer_seed_hex: Option<String>,
    /// Explicit capability issuers trusted by the HTTP authority.
    pub trusted_capability_issuers: Vec<PublicKey>,
}

impl std::fmt::Debug for ProtectConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectConfig")
            .field("upstream", &self.upstream)
            .field(
                "spec_content",
                &self.spec_content.as_ref().map(|_| "<inline>"),
            )
            .field("spec_path", &self.spec_path)
            .field("listen_addr", &self.listen_addr)
            .field("receipt_db", &self.receipt_db)
            .field(
                "sidecar_control_token",
                &self.sidecar_control_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "signer_seed_hex",
                &self.signer_seed_hex.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "trusted_capability_issuers",
                &self.trusted_capability_issuers,
            )
            .finish()
    }
}
