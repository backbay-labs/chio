use super::*;
use std::time::Duration;

/// Default wall-clock ceiling on a single upstream proxy hop, including reading
/// the full response body. Kept below the serve site's drain window so an
/// in-flight hop is resolved and receipted before a shutdown force-closes the
/// connection.
pub const DEFAULT_UPSTREAM_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

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
    /// Explicit opt-in to run without a durable receipt store. A durable audit
    /// log is the product's core promise, so a `None` `receipt_db` is refused at
    /// startup unless this is set, mirroring the CLI boot gate. When set, the
    /// proxy runs with in-memory receipts and revocations that are lost on every
    /// restart. Leave it `false` for durable-by-default embedding.
    pub allow_ephemeral_receipts: bool,
    /// Optional bearer token that authorizes remote sidecar control requests.
    pub sidecar_control_token: Option<String>,
    /// Optional seed used to keep the sidecar signer stable across restarts.
    pub signer_seed_hex: Option<String>,
    /// Explicit capability issuers trusted by the HTTP authority.
    pub trusted_capability_issuers: Vec<PublicKey>,
    /// Control-plane URL. When set, budget holds go through a `RemoteBudgetStore`.
    pub control_url: Option<String>,
    /// Bearer token for the control-plane budget endpoints.
    pub control_token: Option<String>,
    /// Local SQLite budget-store path used when no `control_url` is configured.
    pub budget_db: Option<String>,
    /// Optional durable SQLite revocation-store path. When set, the sidecar
    /// loads its revoked capability ids at startup so operator revocations
    /// recorded through `chio trust revoke --revocation-db <path>` are enforced
    /// on `/v1/evaluate` and every other path that consults the revoked set.
    /// Opening or reading a configured store that fails is fatal (fail-closed):
    /// the sidecar refuses to start rather than run without the revocations it
    /// was told to enforce.
    pub revocation_db: Option<String>,
    /// Retained for API compatibility. The kernel-mediated `/v1/evaluate`
    /// route is a pre-execution authorization gate and always runs the
    /// mediation kernel in execution-nonce strict mode, so this flag no
    /// longer changes mediation behavior.
    pub require_nonce: bool,
    /// When true, the `/v1/evaluate/advisory` route is active.
    /// Defaults to false; production deployments should leave this off to
    /// prevent agents from receiving advisory receipts and bypassing the
    /// kernel-mediated route.
    pub allow_advisory: bool,
    /// Wall-clock ceiling on a single upstream proxy hop, including reading the
    /// full response body. Raise it for upstreams with legitimately slow calls or
    /// large bounded responses; the serve site widens its drain window to match so
    /// an in-flight hop is still receipted before shutdown force-closes it.
    /// Defaults to [`DEFAULT_UPSTREAM_REQUEST_TIMEOUT`].
    pub upstream_request_timeout: Duration,
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
            .field("allow_ephemeral_receipts", &self.allow_ephemeral_receipts)
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
            .field("control_url", &self.control_url)
            .field("budget_db", &self.budget_db)
            .field("revocation_db", &self.revocation_db)
            .field("require_nonce", &self.require_nonce)
            .field("allow_advisory", &self.allow_advisory)
            .field("upstream_request_timeout", &self.upstream_request_timeout)
            .finish()
    }
}
