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
        let http_client = client_builder_with_contract(&egress_contract).build()?;
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

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(ProtectError::Io)?;

        Ok(())
    }

    /// Build routes from spec content for testing.
    pub fn routes_from_spec(spec_content: &str) -> Result<Vec<RouteEntry>, ProtectError> {
        Self::build_routes(spec_content)
    }
}
