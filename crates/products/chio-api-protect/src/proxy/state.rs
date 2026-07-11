use super::*;

use chio_http_serve::{
    apply_server_hygiene, run_until_drained, ServeError, ServeHygieneConfig, ShutdownController,
};
use std::time::Duration;

/// Extra window the drain holds open beyond the upstream hop ceiling so a hop
/// that trips its own deadline still has time to record its receipt before the
/// forced drain closes the connection.
const PROXY_DRAIN_MARGIN: Duration = Duration::from_secs(5);

/// Drain window for the proxy serve site, derived from the configured upstream
/// hop ceiling.
///
/// The proxy records its receipt inside the request handler, after the upstream
/// call returns (success or failure), and runs with no generic request timeout:
/// that outer layer would drop the handler mid-hop and skip the receipt entirely.
/// Bounding the upstream call is what keeps a stalled upstream from becoming an
/// unbounded handler, and holding the drain a margin above that ceiling is what
/// lets an in-flight hop resolve and record its receipt before a shutdown
/// force-closes the connection. Deriving the drain from the (configurable) hop
/// ceiling preserves that ordering for any configured value, not just the default.
fn proxy_drain_timeout(upstream_request_timeout: Duration) -> Duration {
    upstream_request_timeout.saturating_add(PROXY_DRAIN_MARGIN)
}

/// Stored receipts for inspection and querying.
pub(crate) struct ReceiptLog {
    pub(crate) receipts: Vec<HttpReceipt>,
}

/// Stored Chio receipts for tool-call sidecar aliases.
pub(crate) struct ToolReceiptLog {
    pub(crate) receipts: Vec<ChioReceipt>,
}

pub(crate) struct SqliteReceiptStore {
    connection: Connection,
}

impl SqliteReceiptStore {
    pub(crate) fn open(path: &str) -> Result<Self, ProtectError> {
        let connection = Connection::open(path)
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        connection
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS http_receipts (
                    id TEXT PRIMARY KEY,
                    receipt_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tool_receipts (
                    id TEXT PRIMARY KEY,
                    receipt_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS revoked_capabilities (
                    capability_id TEXT PRIMARY KEY
                );
                ",
            )
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        Ok(Self { connection })
    }

    pub(crate) fn load_receipts(&self) -> Result<Vec<HttpReceipt>, ProtectError> {
        let mut statement = self
            .connection
            .prepare("SELECT receipt_json FROM http_receipts ORDER BY rowid ASC")
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;

        let mut receipts = Vec::new();
        for row in rows {
            let receipt_json =
                row.map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
            let receipt: HttpReceipt = serde_json::from_str(&receipt_json)
                .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    pub(crate) fn load_tool_receipts(&self) -> Result<Vec<ChioReceipt>, ProtectError> {
        let mut statement = self
            .connection
            .prepare("SELECT receipt_json FROM tool_receipts ORDER BY rowid ASC")
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;

        let mut receipts = Vec::new();
        for row in rows {
            let receipt_json =
                row.map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
            let receipt: ChioReceipt = serde_json::from_str(&receipt_json)
                .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    pub(crate) fn append(&mut self, receipt: &HttpReceipt) -> Result<(), ProtectError> {
        let receipt_json = serde_json::to_string(receipt)
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        self.connection
            .execute(
                "INSERT OR REPLACE INTO http_receipts (id, receipt_json) VALUES (?1, ?2)",
                params![receipt.id, receipt_json],
            )
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        Ok(())
    }

    pub(crate) fn append_tool_receipt(
        &mut self,
        receipt: &ChioReceipt,
    ) -> Result<(), ProtectError> {
        let receipt_json = serde_json::to_string(receipt)
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        self.connection
            .execute(
                "INSERT OR REPLACE INTO tool_receipts (id, receipt_json) VALUES (?1, ?2)",
                params![receipt.id, receipt_json],
            )
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        Ok(())
    }

    pub(crate) fn load_revoked_capability_ids(&self) -> Result<HashSet<String>, ProtectError> {
        let mut statement = self
            .connection
            .prepare("SELECT capability_id FROM revoked_capabilities ORDER BY rowid ASC")
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;

        let mut capability_ids = HashSet::new();
        for row in rows {
            let capability_id =
                row.map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
            capability_ids.insert(capability_id);
        }
        Ok(capability_ids)
    }

    pub(crate) fn revoke_capability(&mut self, capability_id: &str) -> Result<(), ProtectError> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO revoked_capabilities (capability_id) VALUES (?1)",
                params![capability_id],
            )
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        Ok(())
    }
}

/// Shared proxy state.
pub(crate) struct ProxyState {
    pub(crate) evaluator: RequestEvaluator,
    pub(crate) signer_keypair: Keypair,
    pub(crate) upstream: String,
    pub(crate) http_client: reqwest::Client,
    pub(crate) egress_contract: HttpEgressContract,
    pub(crate) approval_admin: ApprovalAdmin,
    pub(crate) receipt_log: Mutex<ReceiptLog>,
    pub(crate) tool_receipt_log: Mutex<ToolReceiptLog>,
    pub(crate) receipt_store: Option<Mutex<SqliteReceiptStore>>,
    pub(crate) revoked_capability_ids: Mutex<HashSet<String>>,
    pub(crate) trusted_capability_issuers: Vec<PublicKey>,
    pub(crate) trusted_receipt_signers: Vec<PublicKey>,
    pub(crate) sidecar_control_token: Option<String>,
}

/// The protect proxy.
pub struct ProtectProxy {
    config: ProtectConfig,
}

impl ProtectProxy {
    pub fn new(config: ProtectConfig) -> Self {
        Self { config }
    }

    async fn load_spec_content(&self) -> Result<String, ProtectError> {
        if let Some(spec_content) = &self.config.spec_content {
            return Ok(spec_content.clone());
        }
        if let Some(spec_path) = &self.config.spec_path {
            return load_spec_from_file(spec_path);
        }
        discover_spec(&self.config.upstream).await
    }

    /// Build the route table from the OpenAPI spec.
    /// Parses the spec directly to preserve path and method information.
    fn build_routes(spec_content: &str) -> Result<Vec<RouteEntry>, ProtectError> {
        let spec = chio_openapi::OpenApiSpec::parse(spec_content)?;
        let mut routes = Vec::new();

        for (path, path_item) in &spec.paths {
            for (method_str, operation) in &path_item.operations {
                let method = match method_str.as_str() {
                    "GET" => HttpMethod::Get,
                    "POST" => HttpMethod::Post,
                    "PUT" => HttpMethod::Put,
                    "PATCH" => HttpMethod::Patch,
                    "DELETE" => HttpMethod::Delete,
                    "HEAD" => HttpMethod::Head,
                    "OPTIONS" => HttpMethod::Options,
                    _ => continue,
                };

                let extensions = ChioExtensions::from_operation(&operation.raw);
                let policy = DefaultPolicy::for_method_with_extensions(method, &extensions);
                routes.push(RouteEntry {
                    pattern: path.clone(),
                    method,
                    operation_id: operation.operation_id.clone(),
                    policy,
                });
            }
        }

        Ok(routes)
    }

    /// Start the proxy server. This blocks until the server shuts down.
    pub async fn run(self) -> Result<(), ProtectError> {
        self.run_with_observer(|_| {}).await
    }

    /// Start the proxy server, invoking `observer` once the listener is
    /// bound (with the resolved local `SocketAddr`).
    ///
    /// Used by `chio start` so the friendly banner can report the actual
    /// bound port when the operator passes `--listen 127.0.0.1:0`. The
    /// observer fires before `axum::serve` enters its accept loop, so
    /// callers can forward the address to stdout, write a sentinel file,
    /// or signal readiness over an out-of-band channel.
    pub async fn run_with_observer<F>(self, observer: F) -> Result<(), ProtectError>
    where
        F: FnOnce(SocketAddr),
    {
        let spec_content = self.load_spec_content().await?;
        let routes = Self::build_routes(&spec_content)?;
        let route_count = routes.len();

        let keypair = match &self.config.signer_seed_hex {
            Some(seed_hex) => Keypair::from_seed_hex(seed_hex)
                .map_err(|error| ProtectError::Config(error.to_string()))?,
            None => Keypair::generate(),
        };
        let policy_hash = chio_core_types::sha256_hex(spec_content.as_bytes());

        let approval_store: Arc<dyn ApprovalStore> = if let Some(path) = &self.config.receipt_db {
            Arc::new(
                SqliteApprovalStore::open(path)
                    .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?,
            )
        } else {
            Arc::new(InMemoryApprovalStore::new())
        };

        let mut trusted_capability_issuers = self.config.trusted_capability_issuers.clone();
        let signer_public_key = keypair.public_key();
        if !trusted_capability_issuers.contains(&signer_public_key) {
            trusted_capability_issuers.push(signer_public_key.clone());
        }
        let trusted_receipt_signers = vec![signer_public_key];

        let evaluator = RequestEvaluator::new_with_approval_store_and_trusted_capability_issuers(
            routes,
            keypair.clone(),
            policy_hash,
            Arc::clone(&approval_store),
            self.config.trusted_capability_issuers.clone(),
        );

        let (receipt_log, tool_receipt_log, receipt_store, revoked_capability_ids) =
            if let Some(path) = &self.config.receipt_db {
                let store = SqliteReceiptStore::open(path)?;
                let receipts = store.load_receipts()?;
                let tool_receipts = store.load_tool_receipts()?;
                let revoked_capability_ids = store.load_revoked_capability_ids()?;
                (
                    ReceiptLog { receipts },
                    ToolReceiptLog {
                        receipts: tool_receipts,
                    },
                    Some(Mutex::new(store)),
                    revoked_capability_ids,
                )
            } else {
                (
                    ReceiptLog {
                        receipts: Vec::new(),
                    },
                    ToolReceiptLog {
                        receipts: Vec::new(),
                    },
                    None,
                    HashSet::new(),
                )
            };

        let egress_contract = default_upstream_egress_contract(&self.config.upstream)?;
        let http_client = client_builder_with_contract(&egress_contract)
            .timeout(self.config.upstream_request_timeout)
            .build()?;
        let state = Arc::new(ProxyState {
            evaluator,
            signer_keypair: keypair,
            upstream: self.config.upstream.clone(),
            http_client,
            egress_contract,
            approval_admin: ApprovalAdmin::new(approval_store),
            receipt_log: Mutex::new(receipt_log),
            tool_receipt_log: Mutex::new(tool_receipt_log),
            receipt_store,
            revoked_capability_ids: Mutex::new(revoked_capability_ids),
            trusted_capability_issuers,
            trusted_receipt_signers,
            sidecar_control_token: self.config.sidecar_control_token.clone(),
        });

        let app = build_app(Arc::clone(&state));

        let listener = tokio::net::TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(|e| {
                ProtectError::Config(format!("cannot bind {}: {e}", self.config.listen_addr))
            })?;

        let local_addr = listener.local_addr().map_err(|error| {
            ProtectError::Config(format!("cannot resolve bound address: {error}"))
        })?;

        info!(
            "chio api protect: proxying {} routes to {} on {}",
            route_count, self.config.upstream, local_addr
        );

        observer(local_addr);

        // No generic request timeout: every proxied call writes its receipt
        // synchronously in the handler after the upstream hop returns, and that
        // hop is already bounded by the configured upstream timeout. An outer
        // timeout layer would drop the handler while it awaits the upstream,
        // skipping receipt finalization for a call that may already have reached
        // the upstream. The drain window is held a margin above that upstream
        // ceiling so an in-flight hop is receipted before a forced drain closes
        // it. Body size, concurrency, and the connection cap still apply.
        let hygiene = ServeHygieneConfig {
            request_timeout: None,
            drain_timeout: proxy_drain_timeout(self.config.upstream_request_timeout),
            ..ServeHygieneConfig::default()
        };
        let app = apply_server_hygiene(app, &hygiene);
        let controller = ShutdownController::install();
        // Cap simultaneously accepted connections at the accept loop so a slow or
        // idle connection flood cannot exhaust file descriptors before any request
        // reaches the concurrency limit. The peer address stays available to the
        // sidecar-control loopback/bearer checks via `CappedPeerAddr`.
        let listener =
            MaxConnListener::new(listener, hygiene.max_connections.unwrap_or(usize::MAX));
        let server = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<CappedPeerAddr>(),
        )
        .with_graceful_shutdown(controller.signalled());

        // Every proxied call writes its receipt synchronously inside the request
        // handler, so completing the in-flight requests during the drain is the
        // whole durability guarantee: there is nothing queued to flush afterward.
        run_until_drained(
            server,
            controller.subscribe(),
            hygiene.drain_timeout,
            async { Ok::<(), String>(()) },
        )
        .await
        .map(|_outcome| ())
        .map_err(protect_serve_error)?;

        Ok(())
    }

    /// Build routes from spec content for testing.
    pub fn routes_from_spec(spec_content: &str) -> Result<Vec<RouteEntry>, ProtectError> {
        Self::build_routes(spec_content)
    }
}

fn protect_serve_error(error: ServeError) -> ProtectError {
    match error {
        ServeError::Io(source) => ProtectError::Io(source),
        ServeError::Flush(message) => ProtectError::Io(std::io::Error::other(message)),
    }
}

#[cfg(test)]
mod tests {
    use super::{proxy_drain_timeout, PROXY_DRAIN_MARGIN};
    use crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT;
    use chio_http_serve::DEFAULT_DRAIN_TIMEOUT;
    use std::time::Duration;

    /// The drain window must always outlast the upstream hop ceiling so a hop that
    /// is still in flight at shutdown resolves and records its receipt before the
    /// forced drain closes the connection. This must hold for any configured
    /// timeout, including values raised above the default drain window.
    #[test]
    fn drain_window_always_outlasts_the_configured_upstream_timeout() {
        for secs in [1u64, 20, 30, 60, 300] {
            let upstream = Duration::from_secs(secs);
            assert!(
                proxy_drain_timeout(upstream) > upstream,
                "drain window must outlast a {secs}s upstream timeout"
            );
            assert_eq!(proxy_drain_timeout(upstream), upstream + PROXY_DRAIN_MARGIN);
        }
    }

    /// The default configuration keeps the historical 20s hop / 25s drain pairing,
    /// so making the timeout configurable does not shift default behavior.
    #[test]
    fn default_upstream_timeout_preserves_the_default_drain_window() {
        assert_eq!(
            proxy_drain_timeout(DEFAULT_UPSTREAM_REQUEST_TIMEOUT),
            DEFAULT_DRAIN_TIMEOUT
        );
    }
}
