use super::*;

use chio_http_serve::{
    apply_server_hygiene, run_until_drained, ServeError, ServeHygieneConfig, ShutdownController,
};
use std::time::Duration;

/// Interval between reserved-hold reaper sweeps. A hold reserved on
/// `/v1/evaluate` but never reconciled is released once its execution-nonce TTL
/// lapses; sweeping on this cadence bounds how long abandoned budget stays held.
const RESERVED_HOLD_REAP_INTERVAL_SECS: u64 = 30;

/// Spawn the reserved-hold reaper and retain its `JoinHandle` on the shared
/// state so the task can be aborted when the server stops. Dropping a
/// `JoinHandle` only detaches the task (it keeps running); retaining it is what
/// binds the reaper's lifetime to the server's. A no-op without a mediation
/// kernel, since nothing reserves holds there.
pub(crate) async fn spawn_reserved_hold_reaper(state: &Arc<ProxyState>) {
    if state.mediation_kernel.is_none() {
        return;
    }
    let reaper_state = Arc::clone(state);
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
            RESERVED_HOLD_REAP_INTERVAL_SECS,
        ));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let now = chrono::Utc::now().timestamp();
            match reap_expired_reserved_holds_once(&reaper_state, now).await {
                Ok(0) => {}
                Ok(released) => {
                    info!(released, "reaped expired reserved budget holds");
                }
                Err(error) => {
                    warn!("reserved-hold reaper failed: {error}");
                }
            }
        }
    });
    *state.reaper_handle.lock().await = Some(handle);
}

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

/// Derive the revocation store path that sits beside a receipt store path.
///
/// The revocation store lives in a sibling database so a revoked capability
/// survives a restart. When the receipt path is a SQLite URI carrying query
/// parameters (for example `file:/var/lib/chio/receipts.db?mode=rwc`), the
/// `.revocations` suffix must land on the database filename, not inside the
/// query string, or the revocation store opens the wrong URI. Split any URI
/// query off first and re-attach it after the suffix, matching how the receipt
/// store itself interprets the path, so a plain filesystem path and a URI both
/// resolve to a distinct sibling database.
fn revocation_sibling_path(receipt_path: &str) -> String {
    match receipt_path.split_once('?') {
        Some((base, query)) => format!("{base}.revocations?{query}"),
        None => format!("{receipt_path}.revocations"),
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

/// Reserved primary key the readiness probe writes and immediately rolls back,
/// so exercising the receipt write path never leaves a durable row.
const RECEIPT_READINESS_PROBE_ID: &str = "__chio_readiness_probe__";

pub(crate) struct SqliteReceiptStore {
    connection: Connection,
}

impl SqliteReceiptStore {
    pub(crate) fn open(path: &str) -> Result<Self, ProtectError> {
        let connection = Connection::open(path)
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        // `chio api protect` co-locates the approval store, the kernel receipt
        // store, and this HTTP receipt table in one SQLite file. The kernel
        // receipt store runs that file in WAL mode with a busy timeout; a writer
        // on the same file without a busy timeout turns a lock another writer
        // holds for a moment into an immediate SQLITE_BUSY error, so this
        // connection matches the same durability and timeout pragmas.
        connection
            .execute_batch(
                "
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;
                PRAGMA foreign_keys = ON;
                ",
            )
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

    /// Reachability check of the receipt write path, for the readiness probe.
    /// A bare `SELECT 1` answers even when the receipt tables have been dropped or
    /// the database has gone read-only or full, so it would keep an instance in
    /// rotation while every append fails after an already-allowed upstream call.
    /// This exercises the real receipt tables and the write path inside a
    /// transaction that is always rolled back: a dropped table, a read-only mount,
    /// or a full disk fails readiness, and no probe row is ever persisted.
    pub(crate) fn is_reachable(&self) -> bool {
        self.probe_receipt_write_path().is_ok()
    }

    fn probe_receipt_write_path(&self) -> Result<(), rusqlite::Error> {
        let tx = self.connection.unchecked_transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO http_receipts (id, receipt_json) VALUES (?1, ?2)",
            params![RECEIPT_READINESS_PROBE_ID, "{}"],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO tool_receipts (id, receipt_json) VALUES (?1, ?2)",
            params![RECEIPT_READINESS_PROBE_ID, "{}"],
        )?;
        tx.rollback()
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

/// Bounded, TTL-keyed set of request ids claimed for a live reservation window.
///
/// A request id must be unique only for the lifetime of the reservation it
/// backs: the kernel derives the durable budget-hold identity from it, so a
/// reused id inside the window would collapse into an idempotent authorize with
/// no fresh reservation and defeat the over-subscription guard. Once the
/// execution-nonce TTL lapses the hold is reconciled or reaped, so the id may be
/// reused. Each entry carries that expiry and is pruned lazily on every
/// mutation, bounding the set to the reservations opened within one TTL window
/// instead of growing without limit.
pub(crate) struct MintedRequestIdWindow {
    ttl_secs: i64,
    expiries: HashMap<String, i64>,
}

impl MintedRequestIdWindow {
    pub(crate) fn new(ttl_secs: u64) -> Self {
        Self {
            ttl_secs: ttl_secs as i64,
            expiries: HashMap::new(),
        }
    }

    /// Claim `request_id` for a reservation opening at `now`. Prunes expired
    /// entries first, then admits the id only when it is not already live inside
    /// its window. Returns `false` for a reuse inside a live window, which the
    /// caller maps to a fail-closed 409.
    pub(crate) fn claim(&mut self, request_id: &str, now: i64) -> bool {
        self.prune(now);
        if self.expiries.contains_key(request_id) {
            return false;
        }
        self.expiries
            .insert(request_id.to_string(), now.saturating_add(self.ttl_secs));
        true
    }

    /// Release a claimed id. Called when the authorization placed no durable
    /// hold (denied, pending, or errored) so a failed attempt does not
    /// permanently burn the id.
    pub(crate) fn release(&mut self, request_id: &str) {
        self.expiries.remove(request_id);
    }

    fn prune(&mut self, now: i64) {
        self.expiries.retain(|_, expiry| *expiry > now);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.expiries.len()
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
    /// Revocation store shared with the embedded kernel. With a receipt database
    /// it is the durable sibling file, so releases persist and a sibling replica
    /// on the same volume observes them even though its in-memory set is loaded
    /// once at boot and never reloaded. In ephemeral mode it is an in-memory
    /// store, so a release is still honored in-process rather than leaving the
    /// token live until it expires.
    pub(crate) revocation_store: Option<Arc<dyn chio_kernel::RevocationStore>>,
    pub(crate) revoked_capability_ids: Mutex<HashSet<String>>,
    pub(crate) trusted_capability_issuers: Vec<PublicKey>,
    pub(crate) trusted_receipt_signers: Vec<PublicKey>,
    pub(crate) sidecar_control_token: Option<String>,
    pub(crate) budget_store: Option<Arc<dyn chio_kernel::budget_store::BudgetStore>>,
    /// Whether the configured `budget_store` implements the pre-execution hold
    /// APIs the mediated reservation path depends on. `true` for the local SQLite
    /// store, `false` for the remote control-plane store (which forwards only
    /// charge/reverse/reconcile and cannot persist a durable reserved hold). The
    /// mediated `/v1/evaluate` and `/v1/reconcile` routes reject fail-closed when
    /// this is `false`, rather than mint a reserved nonce that can never be
    /// reconciled by nonce or reclaimed by the TTL reaper.
    pub(crate) mediation_hold_capable: bool,
    /// The process-lifetime kernel-mediation authority, built once when a budget
    /// store is configured. Held behind a `Mutex` because admitting the
    /// caller-named tool server (registration) needs `&mut self`, and reused
    /// across requests so the approval-token and DPoP replay stores stay
    /// authoritative, and so the nonce it mints on `/v1/evaluate` is the one it
    /// verifies and consumes on `/v1/reconcile`.
    pub(crate) mediation_kernel: Option<Mutex<chio_kernel::ChioKernel>>,
    /// Request ids claimed for a live reservation window on `/v1/evaluate`. The
    /// kernel derives the durable budget hold identity from the request id, so
    /// each id is admitted at most once inside its window; a reuse is rejected
    /// fail-closed (409) to preserve the over-subscription guard. Entries expire
    /// with the reservation (execution-nonce) TTL and are pruned lazily, so the
    /// set stays bounded rather than growing on every request.
    pub(crate) minted_request_ids: Mutex<MintedRequestIdWindow>,
    /// Retained `JoinHandle` for the reserved-hold reaper task. Held so the
    /// reaper can be aborted when the server stops accepting; a dropped
    /// `JoinHandle` only detaches the task (it keeps running) rather than
    /// aborting it. `None` until the reaper is spawned (and when no mediation
    /// kernel is configured, since nothing reserves holds).
    pub(crate) reaper_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub(crate) allow_advisory: bool,
    pub(crate) receipt_backend: &'static str,
    pub(crate) revocation_backend: &'static str,
}

impl ProxyState {
    /// Whether a capability has been revoked. The in-memory set is loaded once at
    /// boot, so a revocation a sibling replica recorded after this process
    /// started is only visible in the shared durable store; consult it as well.
    /// Fails closed: if the durable store cannot be queried, treat the capability
    /// as revoked rather than admit one that may have been released.
    pub(crate) async fn capability_is_revoked(&self, capability_id: &str) -> bool {
        if self
            .revoked_capability_ids
            .lock()
            .await
            .contains(capability_id)
        {
            return true;
        }
        if let Some(revocation_store) = &self.revocation_store {
            match revocation_store.is_revoked(capability_id) {
                Ok(false) => {}
                Ok(true) => return true,
                Err(error) => {
                    warn!("failed to query durable revocation store: {error}");
                    return true;
                }
            }
        }
        false
    }
}

impl ProxyState {
    /// Dependency-aware readiness for the `/chio/health` probe.
    ///
    /// Unlike liveness, this reports the state of the runtime dependencies the
    /// sidecar needs to serve honestly. When the durable receipt store's supervised
    /// commit writer has stopped serving, every mediated call would be denied fail
    /// closed, so readiness reports unhealthy and a platform probe pulls the instance
    /// from rotation rather than routing traffic to a sidecar that can only deny.
    pub(crate) async fn readiness_status(&self) -> SidecarStatus {
        if let Some(store) = &self.receipt_store {
            let store = store.lock().await;
            if !store.is_reachable() {
                return SidecarStatus::Unhealthy;
            }
        }
        SidecarStatus::Healthy
    }
}

/// The protect proxy.
pub struct ProtectProxy {
    config: ProtectConfig,
    /// Operator-configured payment rail for the kernel-mediated authorization
    /// path. Installed on the mediation kernel so a governed `MustPrepay`
    /// (x402/ACP) quote is authorized before a reserved nonce is minted. `None`
    /// by default, which keeps governed `MustPrepay` denied fail-closed: only a
    /// configured adapter enables prepayment.
    payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
}

impl ProtectProxy {
    pub fn new(config: ProtectConfig) -> Self {
        Self {
            config,
            payment_adapter: None,
        }
    }

    /// Install the operator's payment adapter for the kernel-mediated route.
    ///
    /// The sidecar CLI resolves this from the operator's payment configuration
    /// and threads it here before `run`. With an adapter installed, an approved
    /// governed `MustPrepay`/x402 request authorizes (the quote is prepaid before
    /// a reserved nonce is minted); with `None` it stays denied fail-closed.
    #[must_use]
    pub fn with_payment_adapter(
        mut self,
        payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
    ) -> Self {
        self.payment_adapter = payment_adapter;
        self
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
        // Durable-by-default: a missing receipt store means in-memory receipts
        // and revocations that are lost on every restart, so refuse to start
        // unless the embedder explicitly opted into ephemeral operation. This
        // mirrors the CLI boot gate for library callers that construct
        // `ProtectConfig` directly and would otherwise silently lose audit
        // evidence.
        //
        // An in-memory SQLite path (`:memory:` or a `file:...?mode=memory` URI)
        // opens a database that vanishes on restart just like a missing path, so
        // it is filtered out here. The gate and every store opened below key off
        // this durable path; treating an in-memory path as durable would open
        // in-memory stores yet advertise a durable receipt backend and silently
        // lose audit evidence.
        let durable_receipt_db: Option<&str> = self
            .config
            .receipt_db
            .as_deref()
            .filter(|path| !chio_store_sqlite::is_in_memory_sqlite_path(path));

        if durable_receipt_db.is_none() && !self.config.allow_ephemeral_receipts {
            return Err(ProtectError::Config(
                "refusing to start without a durable receipt store: set receipt_db to a durable \
                 SQLite path, or set allow_ephemeral_receipts to run with in-memory receipts that \
                 are lost on every restart"
                    .to_string(),
            ));
        }

        let spec_content = self.load_spec_content().await?;
        let routes = Self::build_routes(&spec_content)?;
        let route_count = routes.len();

        let keypair = match &self.config.signer_seed_hex {
            Some(seed_hex) => Keypair::from_seed_hex(seed_hex)
                .map_err(|error| ProtectError::Config(error.to_string()))?,
            None => Keypair::generate(),
        };
        let policy_hash = chio_core_types::sha256_hex(spec_content.as_bytes());

        // Open the durable receipt store first so it owns the shared sidecar
        // file's provenance anchor; the approval store then co-locates onto that
        // file. Opening receipt-first fails closed on a path mistargeted at a
        // foreign approval database: it carries no receipt anchor, so the receipt
        // store refuses it here instead of adopting it and commingling receipt
        // tables into another store's file.
        let durable_receipt_store: Option<Arc<dyn chio_kernel::ReceiptStore>> =
            match durable_receipt_db {
                Some(path) => Some(Arc::new(
                    chio_store_sqlite::SqliteReceiptStore::open(path)
                        .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?,
                )),
                None => None,
            };

        let approval_store: Arc<dyn ApprovalStore> = if let Some(path) = durable_receipt_db {
            Arc::new(
                SqliteApprovalStore::open_colocated_with_receipt_store(path)
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

        // The revocation store lives in a sibling file so a revoked capability
        // survives a restart. In ephemeral mode there is no durable file, but a
        // shared in-memory store still makes a release effective for the running
        // process: the same handle backs the embedded kernel's mediated checks
        // and the sidecar's release endpoint, so a token can be revoked in-process
        // rather than staying live until it expires.
        let revocation_store: Option<Arc<dyn chio_kernel::RevocationStore>> =
            match durable_receipt_db {
                Some(path) => Some(Arc::new(
                    chio_store_sqlite::SqliteRevocationStore::open(revocation_sibling_path(path))
                        .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?,
                )),
                None => Some(Arc::new(chio_kernel::InMemoryRevocationStore::new())),
            };

        let evaluator = RequestEvaluator::new_with_durable_stores(
            routes,
            keypair.clone(),
            policy_hash,
            Arc::clone(&approval_store),
            self.config.trusted_capability_issuers.clone(),
            durable_receipt_store,
            revocation_store.clone(),
            self.config.allow_ephemeral_receipts,
        )
        .map_err(|error| ProtectError::Config(error.to_string()))?;
        let receipt_backend = evaluator.receipt_backend();
        let revocation_backend = evaluator.revocation_backend();

        let (receipt_log, tool_receipt_log, receipt_store, mut revoked_capability_ids) =
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

        // Enforce operator revocations recorded through the durable revocation
        // store that `chio trust revoke --revocation-db <path>` writes. Merging
        // them into the shared revoked set covers every path that consults it
        // (mediated `/v1/evaluate`, validate, proxy, advisory) uniformly. This
        // load is fail-closed: `load_revocation_db_ids` returns an error and the
        // sidecar refuses to start if the configured store cannot be read.
        if let Some(path) = self.config.revocation_db.as_deref() {
            let durable = load_revocation_db_ids(&self.config)?;
            let loaded = durable.len();
            revoked_capability_ids.extend(durable);
            info!(
                revocation_db = path,
                loaded,
                enforced = revoked_capability_ids.len(),
                "chio api protect: loaded durable revocations from --revocation-db; \
                 enforced on /v1/evaluate and every revoked-capability path. \
                 Revocations recorded after startup are not observed here: they \
                 require a sidecar restart or the in-process \
                 /v1/capabilities/release (or --control-url) channel"
            );
        }

        let egress_contract = default_upstream_egress_contract(&self.config.upstream)?;
        let http_client = client_builder_with_contract(&egress_contract)
            .timeout(self.config.upstream_request_timeout)
            .build()?;
        let configured_budget_store = build_budget_store(&self.config)?;
        let mediation_hold_capable = configured_budget_store
            .as_ref()
            .map(|configured| configured.hold_capable)
            .unwrap_or(false);
        let budget_store = configured_budget_store.map(|configured| configured.store);

        // Automatic reconcile/reverse of open holds requires the durable receipt
        // log (ADR-0013) to build the realized-spend arbitration map. Without
        // that map, calling reap_orphaned_holds with an empty map would reverse
        // every open hold, enabling double-spend: a hold left open by a crash
        // after the spend but before reconcile represents real spent budget.
        // Holds are left reserved (fail-closed) until receipt-log arbitration
        // is wired at this startup point. Use reap_orphaned_holds via the
        // control plane with a realized-spend map from the durable receipt log
        // to reconcile crash-orphaned holds.
        if let Some(store) = budget_store.as_ref() {
            match store.count_open_holds() {
                Ok(0) => {}
                Ok(count) => {
                    warn!(
                        count,
                        "startup: open budget hold(s) left reserved pending \
                         receipt-log arbitration; automatic reconcile requires \
                         the durable receipt log (ADR-0013) arbitration map"
                    );
                }
                Err(error) => {
                    warn!("startup: failed to count open budget holds: {error}");
                }
            }
        }

        // Build the kernel-mediation authority once, for the process lifetime, so
        // the approval-token and DPoP replay stores it carries stay authoritative
        // across `/v1/evaluate` requests and the nonce it mints is the one it
        // verifies and consumes on `/v1/reconcile`. It exists exactly when a
        // budget store is configured; without one, `/v1/evaluate` and
        // `/v1/reconcile` deny fail-closed.
        let payment_adapter = self.payment_adapter;
        let mediation_kernel = match budget_store.as_ref() {
            Some(store) => Some(Mutex::new(build_mediation_kernel(
                &keypair,
                Arc::clone(store),
                &trusted_capability_issuers,
                Vec::new(),
                payment_adapter,
            )?)),
            None => None,
        };

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
            revocation_store,
            revoked_capability_ids: Mutex::new(revoked_capability_ids),
            trusted_capability_issuers,
            trusted_receipt_signers,
            sidecar_control_token: self.config.sidecar_control_token.clone(),
            budget_store,
            mediation_hold_capable,
            mediation_kernel,
            minted_request_ids: Mutex::new(MintedRequestIdWindow::new(
                chio_kernel::DEFAULT_EXECUTION_NONCE_TTL_SECS,
            )),
            reaper_handle: Mutex::new(None),
            allow_advisory: self.config.allow_advisory,
            receipt_backend,
            revocation_backend,
        });

        // Release expired, unreconciled reserved budget holds on an interval so a
        // caller that authorizes but never reconciles does not permanently burn
        // budget. The reaper's JoinHandle is retained on the shared state and
        // aborted once the server stops accepting (below), bounding the task's
        // lifetime to the server's.
        spawn_reserved_hold_reaper(&state).await;

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
            has_budget_store = state.budget_store.is_some(),
            "chio api protect: mediation layer ready"
        );
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
        let serve_result = run_until_drained(
            server,
            controller.subscribe(),
            hygiene.drain_timeout,
            async { Ok::<(), String>(()) },
        )
        .await
        .map(|_outcome| ())
        .map_err(protect_serve_error);

        // The reaper holds a clone of the shared state; abort it now the server
        // has stopped so the task does not outlive the serving lifetime (a
        // dropped JoinHandle would only detach it, leaving it running).
        if let Some(handle) = state.reaper_handle.lock().await.take() {
            handle.abort();
        }

        serve_result?;

        Ok(())
    }

    /// Build routes from spec content for testing.
    pub fn routes_from_spec(spec_content: &str) -> Result<Vec<RouteEntry>, ProtectError> {
        Self::build_routes(spec_content)
    }
}

#[cfg(test)]
mod proxy_builder_tests {
    use super::*;

    fn minimal_config() -> ProtectConfig {
        ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some("{}".to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: None,
            allow_ephemeral_receipts: true,
            sidecar_control_token: None,
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: None,
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        }
    }

    #[test]
    fn with_payment_adapter_threads_adapter_and_defaults_none() {
        // The sidecar CLI threads the operator's resolved payment adapter here so
        // the proxy installs it on the mediation kernel and governed MustPrepay
        // can be prepaid. Absent the builder call the adapter defaults to `None`,
        // which keeps governed MustPrepay denied fail-closed.
        let default = ProtectProxy::new(minimal_config());
        assert!(
            default.payment_adapter.is_none(),
            "a proxy defaults to no payment adapter, keeping governed MustPrepay denied"
        );

        let configured = ProtectProxy::new(minimal_config())
            .with_payment_adapter(Some(Box::new(chio_kernel::SimPaymentAdapter::new())));
        assert!(
            configured.payment_adapter.is_some(),
            "with_payment_adapter must thread the configured adapter into the proxy"
        );
    }
}

fn protect_serve_error(error: ServeError) -> ProtectError {
    match error {
        ServeError::Io(source) => ProtectError::Io(source),
        ServeError::Flush(message) => ProtectError::Io(std::io::Error::other(message)),
    }
}

#[cfg(test)]
mod durability_tests {
    use super::{revocation_sibling_path, SqliteReceiptStore};
    use chio_test_support::prelude::*;

    #[test]
    fn revocation_sibling_path_appends_suffix_to_a_plain_path() {
        assert_eq!(
            revocation_sibling_path("/var/lib/chio/receipts.db"),
            "/var/lib/chio/receipts.db.revocations"
        );
    }

    #[test]
    fn revocation_sibling_path_keeps_the_uri_query_after_the_suffix() {
        // The suffix must land on the database filename, not inside the query,
        // so the revocation store opens a distinct sibling database rather than
        // a bad `mode=rwc.revocations` URI or the receipt database itself.
        assert_eq!(
            revocation_sibling_path("file:/var/lib/chio/receipts.db?mode=rwc"),
            "file:/var/lib/chio/receipts.db.revocations?mode=rwc"
        );
    }

    #[test]
    fn http_receipt_store_open_configures_wal_and_a_busy_timeout() {
        let mut path = std::env::temp_dir();
        path.push(format!("chio-http-receipts-{}.db", uuid::Uuid::now_v7()));
        let path_str = path.to_string_lossy().into_owned();

        let store = SqliteReceiptStore::open(&path_str).test_unwrap();

        let busy_timeout: i64 = store
            .connection
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .test_unwrap();
        assert!(
            busy_timeout >= 5000,
            "the http receipt writer must share the receipt store busy timeout, got {busy_timeout}"
        );

        let journal_mode: String = store
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .test_unwrap();
        assert!(
            journal_mode.eq_ignore_ascii_case("wal"),
            "the http receipt writer must run in WAL mode, got {journal_mode}"
        );

        let _ = std::fs::remove_file(&path);
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
