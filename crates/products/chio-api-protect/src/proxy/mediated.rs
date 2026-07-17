use super::*;

use chio_core_types::capability::governance::GovernedTransactionIntent;
use chio_kernel::budget_store::BudgetStore;
use chio_kernel::dpop::{DpopConfig, DpopNonceStore, DpopProof};
use chio_kernel::execution_nonce::{
    ExecutionNonceConfig, InMemoryExecutionNonceStore, SignedExecutionNonce,
};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, ToolCallRequest, ToolInvocationCost,
    ToolServerConnection, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};

/// A configured budget store together with whether it supports the pre-execution
/// hold APIs the mediated reservation path depends on.
///
/// The local SQLite store implements `get_budget_hold`, `mark_hold_reserved`, and
/// `reap_expired_reserved_holds`, so a reserved hold can be resolved by nonce on
/// `/v1/reconcile` and reclaimed by the TTL reaper. The remote control-plane
/// store forwards only charge/reverse/reconcile and falls back to the no-op trait
/// defaults for those hold APIs, so a reservation minted against it could never
/// be reconciled by nonce or reaped. Tracking hold-capability at the point of
/// construction lets the mediated routes fail closed rather than mint an
/// unreconcilable reserved nonce.
pub(crate) struct ConfiguredBudgetStore {
    pub(crate) store: Arc<dyn BudgetStore>,
    pub(crate) hold_capable: bool,
}

/// Build the sidecar's budget store, preferring the hold-capable local SQLite
/// store (`--budget-db`) over the remote control-plane store (`--control-url`)
/// when both are configured; falling back to the remote store; else `None` (the
/// mediated route then denies fail-closed).
///
/// Only the local SQLite store is hold-capable. The mediated authorization and
/// reconcile routes need a hold-capable store to persist and resolve a durable
/// reserved hold, so when both are configured the local store is chosen and
/// mediation keeps working; a remote-only deployment stays not hold-capable and
/// those routes reject fail-closed rather than mint an unreconcilable reserved
/// nonce.
pub(crate) fn build_budget_store(
    config: &ProtectConfig,
) -> Result<Option<ConfiguredBudgetStore>, ProtectError> {
    if let Some(path) = config.budget_db.as_deref() {
        let store = chio_store_sqlite::budget_store::SqliteBudgetStore::open(path)
            .map_err(|error| ProtectError::Config(error.to_string()))?;
        return Ok(Some(ConfiguredBudgetStore {
            store: Arc::new(store),
            hold_capable: true,
        }));
    }
    if let Some(control_url) = config.control_url.as_deref() {
        let token = config.control_token.as_deref().unwrap_or("");
        let store =
            chio_control_plane::trust_control::service_runtime::budget::build_remote_budget_store(
                control_url,
                token,
            )
            .map_err(|error| ProtectError::Config(error.to_string()))?;
        return Ok(Some(ConfiguredBudgetStore {
            store: Arc::from(store),
            hold_capable: false,
        }));
    }
    Ok(None)
}

/// Load the durable revocation store's revoked capability ids so operator
/// revocations recorded through `chio trust revoke --revocation-db <path>` are
/// enforced on `/v1/evaluate` and every other path that consults the sidecar's
/// revoked set. Returns an empty set when no revocation-db is configured.
///
/// Opening or reading a configured store that fails is fatal (fail-closed): the
/// caller must not start the sidecar advertising revocation enforcement it
/// cannot provide. The whole table is paged into memory once at startup;
/// revocations recorded after startup require a sidecar restart or the
/// in-process `/v1/capabilities/release` (or `--control-url`) channel.
pub(crate) fn load_revocation_db_ids(
    config: &ProtectConfig,
) -> Result<std::collections::HashSet<String>, ProtectError> {
    let Some(path) = config.revocation_db.as_deref() else {
        return Ok(std::collections::HashSet::new());
    };
    let store = chio_store_sqlite::SqliteRevocationStore::open(path).map_err(|error| {
        ProtectError::Config(format!("cannot open revocation-db `{path}`: {error}"))
    })?;

    const PAGE_SIZE: usize = 1024;
    let mut ids = std::collections::HashSet::new();
    let mut cursor: Option<(i64, String)> = None;
    loop {
        let (after_revoked_at, after_capability_id) = match &cursor {
            Some((revoked_at, capability_id)) => (Some(*revoked_at), Some(capability_id.as_str())),
            None => (None, None),
        };
        let page = store
            .list_revocations_after(PAGE_SIZE, after_revoked_at, after_capability_id)
            .map_err(|error| {
                ProtectError::Config(format!("cannot read revocation-db `{path}`: {error}"))
            })?;
        let page_len = page.len();
        for record in page {
            cursor = Some((record.revoked_at, record.capability_id.clone()));
            ids.insert(record.capability_id);
        }
        if page_len < PAGE_SIZE {
            break;
        }
    }
    Ok(ids)
}

/// Build a `ChioKernel` for tool-call mediation with the budget store, a strict
/// execution-nonce config, and DPoP verification state installed.
///
/// The mediated `/v1/evaluate` route is a PURE pre-execution authorization gate.
/// Strict execution-nonce mode is always on, so every request reaches the
/// authorization preflight: the kernel verifies the capability (plus any DPoP
/// proof, governed intent, and approval token), reserves the pre-execution
/// budget hold and KEEPS IT OPEN, and mints a fresh execution nonce. It never
/// dispatches a tool server, never consumes a presented nonce, and never signs
/// a completed or settled spend. The caller presents the minted nonce to the
/// real tool server, which verifies and consumes it and reconciles the reserved
/// hold at the execution site.
///
/// A SINGLE kernel is built once at sidecar startup and reused for the process
/// lifetime (held behind a `Mutex` in `ProxyState`). Reuse is load-bearing for
/// security: the kernel's approval-token replay store and DPoP-nonce store live
/// on the instance, so a per-request kernel would reset them every call and let
/// an approval token or DPoP proof be replayed within its TTL. One instance
/// keeps both replay stores authoritative across `/v1/evaluate` requests, and it
/// is the same nonce store that mints on `/v1/evaluate` and verifies+consumes on
/// `/v1/reconcile`, so a reconciled nonce cannot be replayed. The route never
/// registers the caller-named `server_id`: the reserve-for-caller authorization
/// path never dispatches a tool on this kernel and so no longer requires the
/// target to be registered, which keeps the kernel's tool-server map from
/// growing on every caller-arbitrary request.
///
/// `trusted_capability_issuers` are trusted as capability authorities in
/// addition to the sidecar signer, so an externally minted capability that the
/// sidecar's other endpoints accept is not rejected here as untrusted.
///
/// `payment_adapter` is the operator-configured payment rail. When present it is
/// installed on the kernel so a governed `MustPrepay` (x402/ACP) quote is
/// authorized and captured before the reserve-for-caller path mints a nonce.
/// When `None` the kernel carries no adapter, so the governed prepayment gate
/// denies `MustPrepay` fail-closed: only a configured adapter enables it.
pub(crate) fn build_mediation_kernel(
    signer: &Keypair,
    budget_store: Arc<dyn BudgetStore>,
    trusted_capability_issuers: &[PublicKey],
    tool_servers: Vec<Box<dyn ToolServerConnection>>,
    payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
) -> Result<ChioKernel, ProtectError> {
    let mut ca_public_keys = vec![signer.public_key()];
    for issuer in trusted_capability_issuers {
        if !ca_public_keys.contains(issuer) {
            ca_public_keys.push(issuer.clone());
        }
    }
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: signer.clone(),
        ca_public_keys,
        max_delegation_depth: 5,
        policy_hash: "chio_api_protect_mediation_v1".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        // Revocation is enforced sidecar-side over the durable revoked set (the
        // revoked-ancestor walk below); this kernel's internal store is
        // intentionally empty, so its durability gate must not deny mediation.
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        // The dispatch-intent payment journal is off on this reserve-only kernel.
        // Its money-path durability is the reserved-hold TTL reaper plus settle
        // by reconcile-by-nonce, not the in-process HoldPlaced -> Authorized ->
        // Settled journal that the dispatching kernels (`chio mcp serve`, `chio
        // run`) use: this kernel reserves a hold and mints a nonce but never
        // dispatches or settles in-process, so it never writes the HoldPlaced row
        // an Authorized advance would require. A MustPrepay prepayment is still
        // authorized through the adapter before a nonce is minted.
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    });
    kernel.set_budget_store_handle(budget_store);
    let nonce_cfg = ExecutionNonceConfig {
        require_nonce: true,
        ..ExecutionNonceConfig::default()
    };
    kernel.set_execution_nonce_store(
        nonce_cfg,
        Box::new(InMemoryExecutionNonceStore::from_config(
            &ExecutionNonceConfig::default(),
        )),
    );
    // Install DPoP verification state so a grant with `dpop_required` can verify
    // a presented proof. Without it every dpop_required capability denies
    // fail-closed with no way to present a proof.
    kernel.set_dpop_store(
        DpopNonceStore::new(
            DpopConfig::default().nonce_store_capacity,
            std::time::Duration::from_secs(DpopConfig::default().proof_ttl_secs),
        ),
        DpopConfig::default(),
    );
    // Install the operator's payment rail so the governed prepayment gate can
    // authorize and capture a MustPrepay (x402/ACP) quote before the
    // reserve-for-caller path mints a nonce. Absent an adapter the gate denies
    // MustPrepay fail-closed, so only a configured adapter enables prepayment.
    if let Some(payment_adapter) = payment_adapter {
        kernel
            .set_payment_adapter(payment_adapter)
            .map_err(|error| {
                ProtectError::Config(format!(
                    "failed to install payment adapter on the mediation kernel: {error}"
                ))
            })?;
    }
    for server in tool_servers {
        kernel.register_tool_server(server);
    }
    // Rebuild the delegated reserve-for-caller accounting from the durable budget
    // store. A delegated reservation keeps its child's sibling-sum share admitted
    // against the parent while its hold stays open, but that admission is
    // in-memory only, so a kernel built fresh over a populated store (a restart)
    // would otherwise admit a sibling against the parent as if the still-open
    // reservation consumed nothing. Since the durable hold record does not carry
    // the parent capability id or the shares needed to rebuild the reservation,
    // this arms a fail-closed gate that denies delegated admission while any such
    // hold from a prior process remains open. Fail-closed: a store read error here
    // aborts startup so the sidecar refuses to mediate over a store it could not
    // inspect.
    kernel
        .arm_restart_reserved_hold_gate()
        .map_err(|error| ProtectError::Config(error.to_string()))?;
    Ok(kernel)
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct SidecarEvaluateToolCallMediatedRequest {
    capability: chio_core_types::capability::token::CapabilityToken,
    tool_server: String,
    tool_name: String,
    #[serde(default)]
    parameters: serde_json::Value,
    #[serde(default)]
    agent_id: Option<String>,
    /// Optional caller-chosen request identifier. When present it is forwarded
    /// verbatim so the caller can bind a governed approval token to this exact
    /// request (the kernel requires `approval_token.request_id == request_id`).
    /// When absent the sidecar mints one; that is fine for capabilities that do
    /// not carry an approval-gated governed intent.
    #[serde(default)]
    request_id: Option<String>,
    /// Optional governed transaction intent bound to this invocation. Forwarded
    /// so a grant carrying `GovernedIntentRequired` (or an approval threshold)
    /// can be authorized instead of denied.
    #[serde(default)]
    governed_intent: Option<GovernedTransactionIntent>,
    /// Optional approval token authorizing this governed invocation, forwarded
    /// alongside `governed_intent` so an approval-gated grant can be authorized.
    #[serde(default)]
    approval_token: Option<GovernedApprovalToken>,
    /// Optional DPoP proof-of-possession. Forwarded so a grant carrying
    /// `dpop_required` can verify the proof instead of denying fail-closed.
    #[serde(default)]
    dpop_proof: Option<DpopProof>,
    /// A signed execution nonce. This endpoint MINTS nonces; it does not settle
    /// presented ones. The field is parsed only so a caller that mistakenly
    /// presents a nonce here is rejected explicitly (fail-closed) rather than
    /// having the nonce silently ignored.
    #[serde(default)]
    execution_nonce: Option<SignedExecutionNonce>,
}

pub(crate) async fn sidecar_evaluate_tool_call_mediated_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read mediated evaluate body: {error}");
            return sidecar_bad_request("failed to read evaluate body").into_response();
        }
    };
    let parsed: SidecarEvaluateToolCallMediatedRequest = match serde_json::from_slice(&body_bytes) {
        Ok(parsed) => parsed,
        Err(error) => {
            return sidecar_bad_request(&format!("invalid mediated payload: {error}"))
                .into_response();
        }
    };
    // This endpoint is a pre-execution authorization gate: it mints an execution
    // nonce for the caller to present downstream. It does not consume or settle a
    // presented nonce. Reject one fail-closed so a caller cannot mistake this for
    // a completion endpoint (and so the sidecar never consumes the downstream
    // nonce, which would make the real tool server reject the caller as a
    // replay).
    if parsed.execution_nonce.is_some() {
        return sidecar_bad_request(
            "/v1/evaluate issues execution nonces; it does not accept a presented nonce. \
             Present the minted nonce to the tool server, not to this endpoint",
        )
        .into_response();
    }
    let Some(mediation_kernel) = state.mediation_kernel.as_ref() else {
        return internal_json_error_response(
            "chio_mediation_unavailable",
            "mediated tool-call route requires a configured budget store (--control-url or --budget-db)",
        );
    };
    // A mediated reservation requires a hold-capable budget store. The remote
    // control-plane store forwards only charge/reverse/reconcile and falls back to
    // the no-op hold-API defaults, so a reservation minted against it could never
    // be reconciled by nonce or reclaimed by the TTL reaper. Reject fail-closed
    // rather than mint an unreconcilable reserved nonce.
    if !state.mediation_hold_capable {
        return internal_json_error_response(
            "chio_mediation_requires_local_budget_store",
            "mediated authorization requires a hold-capable local budget store (--budget-db); \
             a remote control-plane budget store (--control-url) cannot persist a reserved hold",
        );
    }
    // A reserved hold is settled only through `/v1/reconcile`, which the
    // reconcile control gate restricts to the trusted tool server presenting the
    // sidecar-control token. Without a configured token every reconcile is
    // rejected, so a reservation minted here could only expire and forfeit
    // budget. The reconcile gate trims the configured token and treats a
    // whitespace-only value as unconfigured, so an unconfigured OR blank token
    // is rejected here identically. Reject fail-closed before reserving budget or
    // minting a nonce, mirroring the reconcile gate's own configured-token
    // requirement.
    if state
        .sidecar_control_token
        .as_deref()
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        return internal_json_error_response(
            "chio_mediation_requires_reconcile_token",
            "mediated authorization requires a configured sidecar-control token so the reserved \
             hold can be settled on /v1/reconcile; without one the reservation could only expire \
             and forfeit budget",
        );
    }
    // Fail-closed: reject the presented capability when its own id OR any ancestor
    // in its delegation chain is revoked, so a delegated child of a revoked root
    // cannot keep earning mediated reservations until expiry. `capability_is_revoked`
    // consults the in-memory release set first (no I/O for a known-revoked id) and
    // then the durable revocation store, failing closed if that store cannot be
    // read, so a revocation a sibling replica or `chio trust revoke --revocation-db`
    // recorded after this process booted is honored here exactly as it is on the
    // proxy and validate paths. The kernel's own revocation store starts empty, so
    // this sidecar-side walk is the authority.
    //
    // Bound the chain before the per-ancestor durable walk: the capability
    // signature is not verified until the kernel below, so cap the ancestors
    // consulted to keep an unverified, caller-supplied token from forcing one
    // durable store read per fabricated ancestor. A legitimate chain never
    // approaches this bound (the kernel caps delegation depth far under it) and a
    // longer one is rejected by the kernel regardless.
    const MAX_MEDIATED_DELEGATION_CHAIN: usize = 32;
    if parsed.capability.delegation_chain.len() > MAX_MEDIATED_DELEGATION_CHAIN {
        return sidecar_bad_request("capability delegation chain is too long").into_response();
    }
    let mut revoked = state.capability_is_revoked(&parsed.capability.id).await;
    if !revoked {
        for ancestor in &parsed.capability.delegation_chain {
            if state.capability_is_revoked(&ancestor.capability_id).await {
                revoked = true;
                break;
            }
        }
    }
    if revoked {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": "chio_capability_revoked",
                "message": "capability has been revoked",
            })),
        )
            .into_response();
    }
    let agent_id = parsed
        .agent_id
        .unwrap_or_else(|| parsed.capability.subject.to_hex());
    let request_id = parsed
        .request_id
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
    // Durable reuse guard that survives a restart, which the in-memory window
    // below cannot: after a restart the window is empty, but a reservation opened
    // before it persists as a budget hold. Rejecting the reuse fail-closed (409)
    // is load-bearing because a reused id would either collapse into an idempotent
    // authorize that mints a second nonce against one reservation without
    // reserving more budget, or (for a closed, settled-or-reaped hold) make the
    // kernel reject the duplicate hold id on creation and turn an otherwise valid
    // later authorization into a 500 instead of the documented bounded-reuse 409.
    let Some(budget_store) = state.budget_store.as_ref() else {
        return internal_json_error_response(
            "chio_mediation_requires_local_budget_store",
            "mediated authorization requires a configured hold-capable budget store",
        );
    };
    // Bound the pre-verification durable lookup: the capability signature is
    // verified inside the kernel below, so cap the number of grants scanned to a
    // sane maximum and reject an oversized scope fail-closed, rather than fan out
    // one store read per grant for an unverified, caller-supplied capability.
    const MAX_MEDIATED_SCOPE_GRANTS: usize = 64;
    if parsed.capability.scope.grants.len() > MAX_MEDIATED_SCOPE_GRANTS {
        return sidecar_bad_request("capability scope carries too many grants").into_response();
    }
    // Prefer the capability-agnostic durable probe. The kernel derives each hold
    // id from (request_id, capability id, grant index), so the per-grant exact-id
    // lookup below only sees a reuse under the SAME capability: a caller that
    // replays this request_id under a DIFFERENT capability token would miss the
    // existing `budget-hold:{request_id}:{other_cap}:..` row and win a second
    // reservation once a restart cleared the in-memory window. When the store can
    // enumerate holds by the `budget-hold:{request_id}:` prefix it rejects the
    // reuse regardless of which capability opened the hold; when it cannot
    // (`Ok(None)`), fall back to the per-grant exact-id probe.
    match budget_store.request_id_has_reserved_hold(&request_id) {
        Ok(Some(true)) => {
            return (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({
                    "error": "chio_request_id_reused",
                    "message": "request_id already backs a reservation; choose a fresh request_id",
                })),
            )
                .into_response();
        }
        Ok(Some(false)) => {}
        Ok(None) => {
            for grant_index in 0..parsed.capability.scope.grants.len() {
                let hold_id = format!(
                    "budget-hold:{}:{}:{}",
                    request_id, parsed.capability.id, grant_index
                );
                match budget_store.get_budget_hold(&hold_id) {
                    Ok(Some(_)) => {
                        return (
                            StatusCode::CONFLICT,
                            axum::Json(serde_json::json!({
                                "error": "chio_request_id_reused",
                                "message": "request_id already backs a reservation; choose a fresh request_id",
                            })),
                        )
                            .into_response();
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!("durable hold lookup failed: {error}");
                        return internal_json_error_response(
                            "chio_mediation_failed",
                            &error.to_string(),
                        );
                    }
                }
            }
        }
        Err(error) => {
            warn!("durable hold lookup failed: {error}");
            return internal_json_error_response("chio_mediation_failed", &error.to_string());
        }
    }
    // Fail-closed over-subscription guard: the kernel derives the durable budget
    // hold identity from `request_id`, so a reused id inside a live reservation
    // window would collapse into an idempotent authorize with no fresh
    // reservation. Claim the id for this window before authorizing and reject a
    // reuse with 409. The claim is released below when the authorization places
    // no durable hold, so a denied or failed attempt does not permanently burn
    // the id; claimed ids expire with the reservation TTL, keeping the set
    // bounded.
    let now_unix = chrono::Utc::now().timestamp();
    if !state
        .minted_request_ids
        .lock()
        .await
        .claim(&request_id, now_unix)
    {
        return (
            StatusCode::CONFLICT,
            axum::Json(serde_json::json!({
                "error": "chio_request_id_reused",
                "message":
                    "request_id has already been used for a reservation; choose a fresh request_id",
            })),
        )
            .into_response();
    }
    let kernel_request = ToolCallRequest {
        request_id: request_id.clone(),
        capability: parsed.capability,
        tool_name: parsed.tool_name,
        server_id: parsed.tool_server,
        agent_id,
        arguments: parsed.parameters,
        dpop_proof: parsed.dpop_proof,
        // The route mints the nonce; it never forwards a presented one (rejected
        // above), so the kernel always takes the authorization-reserve path.
        execution_nonce: None,
        governed_intent: parsed.governed_intent,
        approval_token: parsed.approval_token,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    // Single-phase authorization on the shared, process-lifetime kernel: verify +
    // reserve the budget hold (kept open) + mint a fresh execution nonce. The
    // reserve-for-caller path never dispatches, so it does not require the
    // caller-named server to be registered; the route therefore never registers
    // it and holds the kernel behind a shared (non-mut) lock. No dispatch, no
    // reconcile, no settlement. The lock is released at the end of the block,
    // before any await, so authorizations serialize without holding the kernel
    // across receipt-persistence I/O.
    let response = {
        let kernel = mediation_kernel.lock().await;
        match kernel.authorize_tool_call_reserving_blocking_with_metadata(&kernel_request, None) {
            Ok(response) => response,
            Err(error) => {
                // The reservation did not open; release the claimed id so a
                // failed authorization does not permanently burn it.
                state.minted_request_ids.lock().await.release(&request_id);
                warn!("mediated authorization error: {error}");
                return internal_json_error_response("chio_mediation_failed", &error.to_string());
            }
        }
    };
    // Only a successful reservation (Verdict::Allow) keeps its request-id claim: a
    // denied or pending verdict placed no durable hold, so release the id to let
    // the caller retry it without a spurious 409.
    if !matches!(response.verdict, chio_kernel::Verdict::Allow) {
        state.minted_request_ids.lock().await.release(&request_id);
    }
    if let Err(error) = record_tool_receipt(&state, &response.receipt).await {
        // The reserve receipt persisted here is a local audit entry, not the
        // authoritative record. When the reserve SUCCEEDED (Verdict::Allow with a
        // minted nonce) the reservation is durable in the budget store and the
        // caller holds the signed nonce, which reconciles at /v1/reconcile (that
        // route persists its own authoritative receipt). Any governed MustPrepay
        // prepayment was already captured to back this exact reservation. Tearing
        // the reservation down here would refund nothing on the prepaid path (direct
        // financial loss) and strand the caller without the nonce it paid for, so
        // return the nonce and log the persistence failure, mirroring the accepted
        // /v1/reconcile behavior. A denied or pending verdict placed no hold and
        // minted no nonce, so its unpersisted receipt still fails closed.
        if !matches!(
            (&response.verdict, response.execution_nonce.as_deref()),
            (chio_kernel::Verdict::Allow, Some(_))
        ) {
            warn!("failed to persist mediated receipt: {error}");
            return internal_json_error_response(
                "chio_receipt_persistence_failed",
                &error.to_string(),
            );
        }
        warn!(
            "mediated reserve receipt persistence failed; returning minted nonce to caller: {error}"
        );
    }
    // A successful authorization is `Verdict::Allow` with an incomplete terminal
    // state (the tool has not run) and a minted nonce. It maps to the wire
    // status "authorized": the reserved hold enforces budget and the caller
    // presents the minted nonce to the real tool server. This route never
    // completes or settles a spend, so no wire status implies a completed spend.
    let status_str = match &response.verdict {
        chio_kernel::Verdict::Allow => "authorized",
        chio_kernel::Verdict::Deny => "deny",
        chio_kernel::Verdict::PendingApproval => "pending_approval",
    };
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": status_str,
            "receipt": response.receipt,
            "execution_nonce": response.execution_nonce,
        })),
    )
        .into_response()
}

/// `POST /v1/reconcile` request shape. The caller presents the execution nonce
/// minted by `/v1/evaluate`, the exact `arguments` that nonce authorized, and
/// the measured `realized_cost`. The kernel settles the reserved hold the nonce
/// names at `min(realized, reserved)` and returns an authoritative
/// mediated-spend receipt.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct SidecarReconcileRequest {
    execution_nonce: SignedExecutionNonce,
    #[serde(default)]
    arguments: serde_json::Value,
    realized_cost: ToolInvocationCost,
}

/// Settle a reserved authorization by the execution nonce that names its hold.
///
/// This route is gated by the reconcile control middleware: only the trusted
/// tool server, presenting the sidecar-control token, reconciles. The controlled
/// agent that called `/v1/evaluate` must not reach this endpoint, or it could
/// settle its own reservation at cost zero and defeat the cumulative spend cap.
///
/// The presented nonce is the credential: the shared kernel that minted it
/// verifies it (signature under the sidecar key, expiry, single-use replay),
/// settles the exact reserved hold at `min(realized, reserved)`, releases the
/// difference back to the grant, and signs a completed authoritative receipt.
/// The `realized_cost` is the tool server's own report of what the call cost;
/// binding it to an attested oracle cost is a later concern. Fail-closed: a
/// forged, tampered, replayed, or argument-mismatched nonce, or a hold that is
/// already closed, is rejected with a 4xx and never settles.
pub(crate) async fn sidecar_reconcile_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read reconcile body: {error}");
            return sidecar_bad_request("failed to read reconcile body").into_response();
        }
    };
    let parsed: SidecarReconcileRequest = match serde_json::from_slice(&body_bytes) {
        Ok(parsed) => parsed,
        Err(error) => {
            return sidecar_bad_request(&format!("invalid reconcile payload: {error}"))
                .into_response();
        }
    };
    let Some(mediation_kernel) = state.mediation_kernel.as_ref() else {
        return internal_json_error_response(
            "chio_mediation_unavailable",
            "reconcile route requires a configured budget store (--control-url or --budget-db)",
        );
    };
    // A reserved hold can only be resolved by nonce when the budget store
    // implements the hold APIs. The remote control-plane store cannot, so a
    // reconcile against it could never settle the reserved hold the nonce names.
    // Reject fail-closed rather than attempt a settle that cannot succeed.
    if !state.mediation_hold_capable {
        return internal_json_error_response(
            "chio_mediation_requires_local_budget_store",
            "mediated reconcile requires a hold-capable local budget store (--budget-db); \
             a remote control-plane budget store (--control-url) cannot resolve a reserved hold",
        );
    }
    // Settle on the shared kernel. The same instance minted the nonce, so its
    // execution-nonce store is the single-use authority here: a forged, tampered,
    // or already-reconciled nonce is rejected. The lock releases at the end of
    // the block, before receipt-persistence I/O.
    let reconciled = {
        let kernel = mediation_kernel.lock().await;
        kernel.reconcile_reserved_authorization_by_nonce(
            &parsed.execution_nonce,
            &parsed.arguments,
            &parsed.realized_cost,
        )
    };
    let reconciled = match reconciled {
        Ok(response) => response,
        Err(error) => {
            warn!("reconcile rejected: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "chio_reconcile_rejected",
                    "message": error.to_string(),
                })),
            )
                .into_response();
        }
    };
    // The settle already consumed the nonce and closed the reserved hold, and that
    // is irreversible: a retry cannot recreate this authoritative receipt. If
    // durable persistence then fails, returning 500 would discard the only proof
    // of a settled spend, leaving the tool server and operator audit with nothing
    // to reconcile against. Log the failure and return the signed receipt so the
    // caller can persist or retry it. This is the opposite of /v1/evaluate, whose
    // reservation is still open and reversible when persistence fails; here the
    // spend is done, so the receipt must reach the caller.
    if let Err(error) = record_tool_receipt(&state, &reconciled.receipt).await {
        warn!("reconcile settled but receipt persistence failed; returning authoritative receipt to caller: {error}");
    }
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": "reconciled",
            "receipt": reconciled.receipt,
        })),
    )
        .into_response()
}

/// Release expired, unreconciled reserved budget holds on the shared kernel so a
/// caller that authorizes but never reconciles cannot permanently burn budget.
/// Returns the number of holds released; a sidecar without a configured budget
/// store (no mediation kernel) releases nothing. Factored out of the startup
/// interval task so it is directly unit-testable with a controlled clock.
pub(crate) async fn reap_expired_reserved_holds_once(
    state: &Arc<ProxyState>,
    now_unix_secs: i64,
) -> Result<usize, KernelError> {
    let Some(mediation_kernel) = state.mediation_kernel.as_ref() else {
        return Ok(0);
    };
    let kernel = mediation_kernel.lock().await;
    kernel.reap_expired_reserved_budget_holds(now_unix_secs)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore};
    use chio_test_support::prelude::*;
    use tower::ServiceExt;

    /// Build an ephemeral kernel used only to mint capabilities in tests. It
    /// shares the budget store with the state's mediation kernel; cost is never
    /// resolved through an injected tool server, so capabilities carry their own
    /// monetary constraints.
    fn issuing_kernel(
        signer: &Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: &[PublicKey],
    ) -> Arc<ChioKernel> {
        Arc::new(
            build_mediation_kernel(signer, budget, trusted_capability_issuers, Vec::new(), None)
                .test_unwrap(),
        )
    }

    fn issue_cost_bearing_capability(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        server: &str,
        tool: &str,
        max_per: u64,
        max_total: u64,
        currency: &str,
    ) -> CapabilityToken {
        use chio_core_types::capability::scope::MonetaryAmount;
        let grant = ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: max_per,
                currency: currency.to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: max_total,
                currency: currency.to_string(),
            }),
            dpop_required: None,
        };
        let scope = ChioScope {
            grants: vec![grant],
            ..ChioScope::default()
        };
        kernel
            .issue_capability(&agent.public_key(), scope, 3600)
            .test_unwrap()
    }

    /// Issue a capability whose single grant caps invocations only, with no
    /// monetary ceiling. The mediated reserve path debits an invocation but
    /// authorizes no monetary hold, so its reversal on tear-down and TTL reap is
    /// exercised separately from the monetary reserve.
    fn issue_invocation_capability(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        server: &str,
        tool: &str,
        max_invocations: u32,
    ) -> CapabilityToken {
        let grant = ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(max_invocations),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let scope = ChioScope {
            grants: vec![grant],
            ..ChioScope::default()
        };
        kernel
            .issue_capability(&agent.public_key(), scope, 3600)
            .test_unwrap()
    }

    /// Control token the mediated test state configures so `/v1/reconcile`, now
    /// behind the reconcile control gate, admits the trusted tool server that
    /// presents it. `/v1/evaluate` is not gated, so evaluate tests are unaffected.
    const MEDIATED_CONTROL_TOKEN: &str = "tool-server-control-token";

    /// Build proxy state for the mediated route with the standard reconcile
    /// control token configured.
    fn mediated_test_state(
        signer: Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: Vec<PublicKey>,
    ) -> Arc<ProxyState> {
        mediated_test_state_with_control_token(
            signer,
            budget,
            trusted_capability_issuers,
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
        )
    }

    /// Build proxy state for the mediated route. `signer` is the sidecar signer
    /// the shared mediation kernel is built from (so capabilities minted by it
    /// are trusted), and `trusted_capability_issuers` are additional external
    /// issuers to trust. `sidecar_control_token` gates `/v1/reconcile`; `None`
    /// leaves the sidecar with no configured token, so reconcile fails closed.
    fn mediated_test_state_with_control_token(
        signer: Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: Vec<PublicKey>,
        sidecar_control_token: Option<String>,
    ) -> Arc<ProxyState> {
        // The default in-memory budget store implements the hold APIs, so it is
        // treated as hold-capable (matching a local `--budget-db` deployment).
        mediated_test_state_inner(
            signer,
            budget,
            trusted_capability_issuers,
            sidecar_control_token,
            None,
            true,
        )
    }

    /// Build proxy state for the mediated route with an explicit hold-capability
    /// flag. `hold_capable == false` models a remote `--control-url` budget store
    /// whose hold APIs fall back to the no-op trait defaults, so the mediated
    /// routes must fail closed rather than mint an unreconcilable reserved nonce.
    fn mediated_test_state_inner(
        signer: Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: Vec<PublicKey>,
        sidecar_control_token: Option<String>,
        receipt_store: Option<SqliteReceiptStore>,
        hold_capable: bool,
    ) -> Arc<ProxyState> {
        // No payment adapter by default, so governed MustPrepay stays denied
        // fail-closed; the prepayment tests build the mediation kernel with one.
        mediated_test_state_core(
            signer,
            budget,
            trusted_capability_issuers,
            sidecar_control_token,
            receipt_store,
            hold_capable,
            None,
            None,
        )
    }

    /// Build proxy state for the mediated route with an explicit payment adapter
    /// for the shared mediation kernel. A configured adapter lets an approved
    /// governed `MustPrepay` request authorize (the quote is prepaid before a
    /// reserved nonce is minted); `None` keeps it denied fail-closed.
    #[allow(clippy::too_many_arguments)]
    fn mediated_test_state_core(
        signer: Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: Vec<PublicKey>,
        sidecar_control_token: Option<String>,
        receipt_store: Option<SqliteReceiptStore>,
        hold_capable: bool,
        payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
        revocation_store: Option<Arc<dyn chio_kernel::RevocationStore>>,
    ) -> Arc<ProxyState> {
        let approval_store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
        let signer_public_key = signer.public_key();
        let mut trusted_capability_issuers = trusted_capability_issuers;
        if !trusted_capability_issuers.contains(&signer_public_key) {
            trusted_capability_issuers.push(signer_public_key.clone());
        }
        let trusted_receipt_signers = vec![signer_public_key];
        let evaluator = RequestEvaluator::new_ephemeral_with_approval_store(
            Vec::new(),
            signer.clone(),
            "test-policy".to_string(),
            Arc::clone(&approval_store),
        );
        let egress_contract = default_upstream_egress_contract("http://127.0.0.1:1").test_unwrap();
        let http_client = client_builder_with_contract(&egress_contract)
            .build()
            .test_unwrap();
        // One shared mediation kernel for the process, matching production wiring:
        // reuse keeps the approval-token and DPoP replay stores authoritative and
        // makes the nonce minted on `/v1/evaluate` the one settled on
        // `/v1/reconcile`.
        let mediation_kernel = Mutex::new(
            build_mediation_kernel(
                &signer,
                Arc::clone(&budget),
                &trusted_capability_issuers,
                Vec::new(),
                payment_adapter,
            )
            .test_unwrap(),
        );
        Arc::new(ProxyState {
            evaluator,
            signer_keypair: signer,
            upstream: "http://127.0.0.1:1".to_string(),
            http_client,
            egress_contract,
            approval_admin: ApprovalAdmin::new(approval_store),
            receipt_log: Mutex::new(ReceiptLog {
                receipts: Vec::new(),
            }),
            tool_receipt_log: Mutex::new(ToolReceiptLog {
                receipts: Vec::new(),
            }),
            receipt_store: receipt_store.map(Mutex::new),
            revocation_store,
            revoked_capability_ids: Mutex::new(std::collections::HashSet::new()),
            trusted_capability_issuers,
            trusted_receipt_signers,
            sidecar_control_token,
            budget_store: Some(budget),
            mediation_hold_capable: hold_capable,
            mediation_kernel: Some(mediation_kernel),
            minted_request_ids: Mutex::new(MintedRequestIdWindow::new(
                chio_kernel::DEFAULT_EXECUTION_NONCE_TTL_SECS,
            )),
            reaper_handle: Mutex::new(None),
            allow_advisory: false,
            receipt_backend: "ephemeral",
            revocation_backend: "ephemeral",
        })
    }

    fn with_loopback_peer(request: axum::http::Request<Body>) -> axum::http::Request<Body> {
        use axum::extract::ConnectInfo;
        let mut request = request;
        request
            .extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                4100,
            ))));
        request
    }

    // --- Scaffolding for governed and DPoP authorization tests ---

    use chio_core_types::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        GovernedTransactionIntent, MeteredBillingContext, MeteredBillingQuote,
        MeteredSettlementMode,
    };
    use chio_core_types::capability::scope::{Constraint, MonetaryAmount};
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;
    use chio_kernel::dpop::{DpopProof, DpopProofBody, DPOP_SCHEMA};

    fn issue_governed_capability(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        server: &str,
        tool: &str,
        max_per: u64,
        currency: &str,
        approval_threshold_units: u64,
    ) -> CapabilityToken {
        let grant = ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![
                Constraint::GovernedIntentRequired,
                Constraint::RequireApprovalAbove {
                    threshold_units: approval_threshold_units,
                },
            ],
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: max_per,
                currency: currency.to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: max_per,
                currency: currency.to_string(),
            }),
            dpop_required: None,
        };
        let scope = ChioScope {
            grants: vec![grant],
            ..ChioScope::default()
        };
        kernel
            .issue_capability(&agent.public_key(), scope, 3600)
            .test_unwrap()
    }

    fn issue_dpop_capability(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        server: &str,
        tool: &str,
        max_per: u64,
        currency: &str,
    ) -> CapabilityToken {
        issue_dpop_capability_with_total(kernel, agent, server, tool, max_per, max_per, currency)
    }

    fn issue_dpop_capability_with_total(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        server: &str,
        tool: &str,
        max_per: u64,
        max_total: u64,
        currency: &str,
    ) -> CapabilityToken {
        let grant = ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: max_per,
                currency: currency.to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: max_total,
                currency: currency.to_string(),
            }),
            dpop_required: Some(true),
        };
        let scope = ChioScope {
            grants: vec![grant],
            ..ChioScope::default()
        };
        kernel
            .issue_capability(&agent.public_key(), scope, 3600)
            .test_unwrap()
    }

    fn governed_intent(
        id: &str,
        server: &str,
        tool: &str,
        units: u64,
        currency: &str,
    ) -> GovernedTransactionIntent {
        GovernedTransactionIntent {
            id: id.to_string(),
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            purpose: "invoice-settlement".to_string(),
            max_amount: Some(MonetaryAmount {
                units,
                currency: currency.to_string(),
            }),
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
        }
    }

    /// A governed intent that mandates prepayment: it carries a metered-billing
    /// context in `MustPrepay` settlement mode with a quote for `units`. The
    /// kernel denies it unless a payment adapter is configured to prepay the
    /// quote before the reserve-for-caller path mints a nonce.
    fn governed_mustprepay_intent(
        id: &str,
        server: &str,
        tool: &str,
        units: u64,
        currency: &str,
    ) -> GovernedTransactionIntent {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_unwrap()
            .as_secs();
        let mut intent = governed_intent(id, server, tool, units, currency);
        intent.metered_billing = Some(MeteredBillingContext {
            settlement_mode: MeteredSettlementMode::MustPrepay,
            quote: MeteredBillingQuote {
                quote_id: format!("quote-{id}"),
                provider: "billing.chio".to_string(),
                billing_unit: "call".to_string(),
                quoted_units: 1,
                quoted_cost: MonetaryAmount {
                    units,
                    currency: currency.to_string(),
                },
                issued_at: now.saturating_sub(5),
                expires_at: Some(now + 300),
            },
            max_billed_units: Some(2),
        });
        intent
    }

    fn governed_approval_token(
        approver: &Keypair,
        subject: &PublicKey,
        intent: &GovernedTransactionIntent,
        request_id: &str,
    ) -> GovernedApprovalToken {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_unwrap()
            .as_secs();
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: format!("approval-{request_id}"),
                approver: approver.public_key(),
                subject: subject.clone(),
                governed_intent_hash: intent.binding_hash().test_unwrap(),
                request_id: request_id.to_string(),
                issued_at: now.saturating_sub(1),
                expires_at: now + 300,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .test_unwrap()
    }

    fn dpop_proof_for(
        agent: &Keypair,
        cap: &CapabilityToken,
        server: &str,
        tool: &str,
        parameters: &serde_json::Value,
    ) -> DpopProof {
        // Match the kernel's action-hash computation exactly: SHA-256 hex over
        // the canonical JSON of the tool arguments.
        let args_bytes = chio_core_types::canonical::canonical_json_bytes(parameters).test_unwrap();
        let action_hash = chio_core_types::crypto::sha256_hex(&args_bytes);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_unwrap()
            .as_secs();
        DpopProof::sign(
            DpopProofBody {
                schema: DPOP_SCHEMA.to_string(),
                capability_id: cap.id.clone(),
                tool_server: server.to_string(),
                tool_name: tool.to_string(),
                action_hash,
                nonce: uuid::Uuid::now_v7().to_string(),
                issued_at: now,
                agent_key: agent.public_key(),
            },
            agent,
        )
        .test_unwrap()
    }

    /// POST a body to `/v1/evaluate` and return the status and parsed JSON.
    async fn post_evaluate(
        state: Arc<ProxyState>,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        post_json(state, "/v1/evaluate", body).await
    }

    /// POST a body to `/v1/reconcile` presenting the standard control token, so
    /// the reconcile control gate admits it, and return the status and JSON.
    async fn post_reconcile(
        state: Arc<ProxyState>,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        post_json_with_bearer(state, "/v1/reconcile", body, Some(MEDIATED_CONTROL_TOKEN)).await
    }

    async fn post_json(
        state: Arc<ProxyState>,
        uri: &str,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        post_json_with_bearer(state, uri, body, None).await
    }

    async fn post_json_with_bearer(
        state: Arc<ProxyState>,
        uri: &str,
        body: &serde_json::Value,
        bearer: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(bearer) = bearer {
            builder = builder.header("authorization", format!("Bearer {bearer}"));
        }
        let request = with_loopback_peer(
            builder
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        );
        let response = build_app(state).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_reserves_hold_and_mints_non_authoritative_receipt() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        let signer_pub = signer.public_key();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);

        // Single-phase authorization: wire status "authorized", a minted nonce
        // object, and a non-authoritative reserved receipt. The route never
        // dispatches, never consumes a nonce, never settles a spend.
        assert_eq!(json["status"], "authorized");
        assert!(
            json["execution_nonce"].is_object(),
            "authorization must mint an execution nonce object"
        );
        assert_eq!(
            json["receipt"]["decision"]["verdict"], "incomplete",
            "a reserved authorization is not a completed-spend decision"
        );

        // The receipt records the reserved hold's authorize block with NO
        // terminal reconcile disposition: reserved, not reconciled.
        let budget_authority = &json["receipt"]["metadata"]["budget_authority"];
        assert_eq!(budget_authority["authorize"]["exposure_units"], 100);
        assert!(
            budget_authority.get("terminal").is_none(),
            "a reserved (not reconciled) hold must carry no terminal disposition"
        );

        // The receipt is rejected as an authoritative spend: the hold is
        // reserved, not reconciled.
        let receipt: ChioReceipt = serde_json::from_value(json["receipt"].clone()).unwrap();
        let nonce: SignedExecutionNonce =
            serde_json::from_value(json["execution_nonce"].clone()).unwrap();
        assert!(
            is_authoritative_spend_receipt(&receipt, &[signer_pub], &nonce).is_err(),
            "a reserved authorization receipt must not be an authoritative spend"
        );

        // The pre-execution hold is RESERVED (open), not reversed. The
        // budget store shows the worst-case exposure committed against the grant,
        // so the caller's downstream execution is backed by a real reservation.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        let usage = usage.expect("the reserved hold must be recorded in the budget store");
        assert_eq!(
            usage.committed_cost_units().unwrap(),
            100,
            "the pre-execution hold must remain reserved (open), not reversed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_durable_reuse_guard_rejects_reused_request_id_across_capabilities() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap_a =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_b =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        assert_ne!(
            cap_a.id, cap_b.id,
            "the two capabilities must carry distinct ids"
        );

        // First reservation under capability A binds request_id R to a durable
        // hold whose id embeds A.
        let state_before = mediated_test_state(signer.clone(), Arc::clone(&budget), Vec::new());
        let body_a = serde_json::json!({
            "capability": cap_a,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "request_id": "shared-request-id",
            "parameters": { "invoice": "inv-1" }
        });
        let (status_a, json_a) = post_evaluate(Arc::clone(&state_before), &body_a).await;
        assert_eq!(status_a, StatusCode::OK, "{json_a}");
        assert_eq!(json_a["status"], "authorized");

        // Simulate a restart: a fresh sidecar state (empty minted-request-id
        // window and approval replay cache) over the SAME durable budget store, so
        // only the durable prefix guard can catch a reused request_id.
        let state_after = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        // Replaying the SAME request_id under a DIFFERENT capability is rejected by
        // the durable prefix guard, even though no `budget-hold:R:{capB}:..` row
        // exists for capability B.
        let body_b = serde_json::json!({
            "capability": cap_b,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "request_id": "shared-request-id",
            "parameters": { "invoice": "inv-2" }
        });
        let (status_b, json_b) = post_evaluate(Arc::clone(&state_after), &body_b).await;
        assert_eq!(status_b, StatusCode::CONFLICT, "{json_b}");
        assert_eq!(json_b["error"], "chio_request_id_reused");

        // A fresh request_id under capability B still proceeds.
        let body_fresh = serde_json::json!({
            "capability": cap_b,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "request_id": "fresh-request-id",
            "parameters": { "invoice": "inv-3" }
        });
        let (status_fresh, json_fresh) = post_evaluate(Arc::clone(&state_after), &body_fresh).await;
        assert_eq!(status_fresh, StatusCode::OK, "{json_fresh}");
        assert_eq!(json_fresh["status"], "authorized");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_reserved_hold_blocks_oversubscription() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // max_cost_per_invocation == max_total_cost == 100: one authorization
        // reserves the entire grant budget.
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 100, "USD");
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });

        // First authorization reserves the hold.
        let (_, first) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(first["status"], "authorized");

        // Because the reserved hold is NOT reversed, a second
        // authorization for the same fully-reserved grant is DENIED. Sequential
        // mediated authorizations respect max_total_cost; no over-subscription.
        let (_, second) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(
            second["status"], "deny",
            "the reserved hold must block a second authorization past max_total_cost"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_presented_execution_nonce_is_rejected() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        // Obtain a genuine minted nonce from a first authorization.
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        let minted_nonce = authorized["execution_nonce"].clone();
        assert!(minted_nonce.is_object());

        // Presenting that nonce back to /v1/evaluate is rejected
        // fail-closed. This endpoint mints nonces; it does not settle them, so
        // the sidecar never consumes the downstream nonce (which would make the
        // real tool server reject the caller as a replay).
        let settle_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" },
            "execution_nonce": minted_nonce
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &settle_body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_ne!(json["status"], "authorized");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_revoked_capability_is_rejected() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        // Record the capability id as revoked, mirroring a prior
        // `/v1/capabilities/release`.
        state
            .revoked_capability_ids
            .lock()
            .await
            .insert(cap_id.clone());

        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        // A revoked capability is rejected fail-closed rather than authorized.
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_ne!(json["status"], "authorized");
        assert_eq!(json["error"], "chio_capability_revoked");

        // The revoked capability never reaches the kernel, so no hold is placed.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    /// Build a well-formed capability whose single delegation-chain link names
    /// `ancestor_id` as the delegated ancestor. The leaf is signed by `issuer`
    /// and the link by `delegator`, so the token is structurally valid; the
    /// presented leaf carries a fresh, distinct id.
    fn delegated_child_capability(
        issuer: &Keypair,
        delegator: &Keypair,
        subject: &Keypair,
        ancestor_id: &str,
        server: &str,
        tool: &str,
    ) -> CapabilityToken {
        use chio_core_types::capability::attenuation::{DelegationLink, DelegationLinkBody};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_unwrap()
            .as_secs();
        let grant = ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        };
        let scope = ChioScope {
            grants: vec![grant],
            ..ChioScope::default()
        };
        let link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: ancestor_id.to_string(),
                delegator: delegator.public_key(),
                delegatee: subject.public_key(),
                attenuations: vec![],
                timestamp: now,
                scope_hash: None,
            },
            delegator,
        )
        .test_unwrap();
        let body = CapabilityTokenBody {
            id: uuid::Uuid::now_v7().to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope,
            issued_at: now,
            expires_at: now + 3600,
            delegation_chain: vec![link],
        };
        CapabilityToken::sign(body, issuer).test_unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_revoked_delegation_ancestor_rejects_delegated_child() {
        let signer = Keypair::generate();
        let root = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        // Revoke only the ROOT ancestor; the presented leaf id is never revoked,
        // so a leaf-only guard would admit this delegated child.
        let ancestor_id = "cap-root-revoked".to_string();
        let child =
            delegated_child_capability(&signer, &root, &agent, &ancestor_id, "cost-srv", "compute");
        let child_id = child.id.clone();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        state
            .revoked_capability_ids
            .lock()
            .await
            .insert(ancestor_id.clone());
        assert!(
            !state
                .revoked_capability_ids
                .lock()
                .await
                .contains(&child_id),
            "the presented leaf id must not itself be revoked"
        );

        let body = serde_json::json!({
            "capability": child,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        // A delegated child of a revoked ancestor is rejected fail-closed before
        // the kernel, exactly as a revoked leaf is.
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_ne!(json["status"], "authorized");
        assert_eq!(json["error"], "chio_capability_revoked");

        // The severed child never reserved a hold under its own id.
        let usage = budget.get_usage(&child_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_route_honors_a_durable_only_revocation() {
        // A revocation a sibling replica (or `chio trust revoke --revocation-db`)
        // records after this process boots lives in the shared durable store but
        // never in this process's in-memory release set, which is loaded once at
        // boot. The mediated money path must still reject it fail-closed, matching
        // the proxy and validate paths, or a revoked capability keeps reserving
        // budget and minting execution nonces until it expires.
        let signer = Keypair::generate();
        let root = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let child =
            delegated_child_capability(&signer, &root, &agent, "cap-root", "cost-srv", "compute");
        let child_id = child.id.clone();

        // Revoke the presented leaf id in the DURABLE store only.
        let durable: Arc<dyn chio_kernel::RevocationStore> =
            Arc::new(chio_kernel::InMemoryRevocationStore::new());
        chio_kernel::RevocationStore::revoke(durable.as_ref(), &child_id).test_unwrap();

        let state = mediated_test_state_core(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            true,
            None,
            Some(Arc::clone(&durable)),
        );
        assert!(
            !state
                .revoked_capability_ids
                .lock()
                .await
                .contains(&child_id),
            "the in-memory release set must not carry the durable-only revocation"
        );

        let body = serde_json::json!({
            "capability": child,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json["error"], "chio_capability_revoked");

        // The revoked capability never reserved a hold.
        let usage = budget.get_usage(&child_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_admits_caller_named_server_id() {
        // The operator does not pre-register tool servers; the mediated route
        // registers a placeholder under whatever server id the caller names, so
        // an authorization for an arbitrary server is authorized rather than
        // denied `ToolNotRegistered` by the kernel's pre-dispatch registration
        // check.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_cost_bearing_capability(
            &kernel,
            &agent,
            "arbitrary-srv",
            "invoke",
            100,
            1000,
            "USD",
        );
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "arbitrary-srv",
            "tool_name": "invoke",
            "parameters": {}
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "authorized");
        assert!(json["execution_nonce"].is_object());
        assert_eq!(json["receipt"]["decision"]["verdict"], "incomplete");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_trusts_configured_external_capability_issuers() {
        let signer = Keypair::generate();
        let external_signer = Keypair::generate();
        let agent = Keypair::generate();

        // A capability minted by an operator-configured external issuer.
        let issuer_budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let issuer = issuing_kernel(&external_signer, issuer_budget, &[]);
        let cap =
            issue_cost_bearing_capability(&issuer, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();

        // Trusting the external issuer: the mediated route authorizes rather than
        // rejecting the capability as untrusted.
        let trusting_budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let trusting_state = mediated_test_state(
            signer.clone(),
            trusting_budget,
            vec![external_signer.public_key()],
        );
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": {}
        });
        let (_, json) = post_evaluate(trusting_state, &body).await;
        assert_eq!(json["status"], "authorized");
        assert!(json["execution_nonce"].is_object());

        // Control: without the configured issuer the same capability is denied,
        // proving the trust set is load-bearing.
        let untrusting_budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let untrusting_state = mediated_test_state(signer, untrusting_budget, Vec::new());
        let (_, json) = post_evaluate(untrusting_state, &body).await;
        assert_eq!(json["status"], "deny");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_deny_leaves_committed_cost_zero() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // max_cost_per_invocation (100) exceeds max_total_cost (40), so the
        // pre-execution hold is refused before the authorization check.
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 40, "USD");
        let cap_id = cap.id.clone();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let body = serde_json::json!({ "capability": cap, "tool_server": "cost-srv",
            "tool_name": "compute", "parameters": {} });
        let (_, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(json["status"], "deny");
        assert_ne!(json["receipt"]["decision"]["verdict"], "allow");
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_governed_capability_requires_intent_and_approval() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // The grant requires a governed intent and approval above 50 units; the
        // worst-case charge (100) crosses the threshold, so an approval token is
        // required.
        let cap = issue_governed_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD", 50);
        let cap_value = serde_json::to_value(&cap).unwrap();
        let approver = signer.clone();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        // Without a governed intent + approval token, the governed
        // grant is DENIED (the forwarded fields are load-bearing).
        let bare_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let (_, denied) = post_evaluate(Arc::clone(&state), &bare_body).await;
        assert_eq!(
            denied["status"], "deny",
            "a governed grant without a forwarded intent must be denied"
        );

        // With a valid governed intent + approval token bound to the caller-chosen
        // request_id, the same grant is AUTHORIZED.
        let request_id = "req-governed-1";
        let intent = governed_intent("intent-gov-1", "cost-srv", "compute", 100, "USD");
        let approval = governed_approval_token(&approver, &agent.public_key(), &intent, request_id);
        let governed_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" },
            "request_id": request_id,
            "governed_intent": intent,
            "approval_token": approval
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &governed_body).await;
        assert_eq!(
            authorized["status"], "authorized",
            "a governed grant with a valid intent and approval must be authorized"
        );
        assert!(authorized["execution_nonce"].is_object());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_governed_mustprepay_authorizes_with_payment_adapter() {
        // An approved governed MustPrepay request authorizes only because a payment
        // adapter is installed on the mediation kernel: the kernel prepays the
        // quoted cost through the adapter before the reserve-for-caller path mints
        // a nonce.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // Worst-case charge (100) crosses the approval threshold (50), so an
        // approval token is required alongside the governed intent.
        let cap = issue_governed_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD", 50);
        let cap_value = serde_json::to_value(&cap).unwrap();
        let approver = signer.clone();
        let state = mediated_test_state_core(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            true,
            Some(Box::new(chio_kernel::SimPaymentAdapter::new())),
            None,
        );

        let request_id = "req-mustprepay-adapter";
        let intent =
            governed_mustprepay_intent("intent-prepay-1", "cost-srv", "compute", 100, "USD");
        let approval = governed_approval_token(&approver, &agent.public_key(), &intent, request_id);
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" },
            "request_id": request_id,
            "governed_intent": intent,
            "approval_token": approval,
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["status"], "authorized",
            "a configured payment adapter must let an approved governed MustPrepay authorize"
        );
        assert!(
            json["execution_nonce"].is_object(),
            "an authorized MustPrepay reservation must mint an execution nonce"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_governed_mustprepay_denied_without_payment_adapter() {
        // The same approved governed MustPrepay request is denied fail-closed when
        // no payment adapter is configured: the kernel has no rail to prepay the
        // quote, so the prepayment gate rejects it before any reservation.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_governed_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD", 50);
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let approver = signer.clone();
        // No payment adapter is installed on the mediation kernel.
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        let request_id = "req-mustprepay-no-adapter";
        let intent =
            governed_mustprepay_intent("intent-prepay-2", "cost-srv", "compute", 100, "USD");
        let approval = governed_approval_token(&approver, &agent.public_key(), &intent, request_id);
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" },
            "request_id": request_id,
            "governed_intent": intent,
            "approval_token": approval,
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["status"], "deny",
            "governed MustPrepay must deny fail-closed without a configured payment adapter"
        );
        assert!(
            json["execution_nonce"].is_null(),
            "a denied MustPrepay must not mint a reserved nonce"
        );

        // The governed prepayment gate denies before any reserve, so no budget is
        // committed against the grant.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_dpop_capability_requires_valid_proof() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_dpop_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        // Without a DPoP proof, a dpop_required grant is DENIED
        // fail-closed.
        let bare_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params.clone()
        });
        let (_, denied) = post_evaluate(Arc::clone(&state), &bare_body).await;
        assert_eq!(
            denied["status"], "deny",
            "a dpop_required grant without a proof must be denied"
        );

        // With a valid DPoP proof bound to the exact call, the mediation kernel's
        // installed DPoP state verifies it and the grant is AUTHORIZED.
        let proof = dpop_proof_for(&agent, &cap, "cost-srv", "compute", &params);
        let dpop_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "dpop_proof": proof
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &dpop_body).await;
        assert_eq!(
            authorized["status"], "authorized",
            "a valid DPoP proof must authorize the dpop_required grant"
        );
        assert!(authorized["execution_nonce"].is_object());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_dpop_proof_replay_is_rejected_across_requests() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // max_total (1000) far exceeds a single reservation (100), so the second
        // request cannot be denied for budget: the only reason to reject it is a
        // DPoP replay store that persists across requests. That persistence only
        // holds if a single kernel is reused for the process lifetime.
        let cap = issue_dpop_capability_with_total(
            &kernel, &agent, "cost-srv", "compute", 100, 1000, "USD",
        );
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        // A single DPoP proof, presented twice under distinct request ids.
        let proof = dpop_proof_for(&agent, &cap, "cost-srv", "compute", &params);
        let first_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "dpop-req-1",
            "dpop_proof": proof,
        });
        let (_, first) = post_evaluate(Arc::clone(&state), &first_body).await;
        assert_eq!(
            first["status"], "authorized",
            "the first presentation of a valid DPoP proof must authorize"
        );

        let second_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "dpop-req-2",
            "dpop_proof": proof,
        });
        let (_, second) = post_evaluate(Arc::clone(&state), &second_body).await;
        assert_eq!(
            second["status"], "deny",
            "replaying the DPoP proof must be rejected by the shared kernel's persistent nonce store"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_reused_request_id_is_conflict() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" },
            "request_id": "fixed-req-id",
        });
        let (status, first) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["status"], "authorized");

        // Reusing the caller-supplied request_id is rejected fail-closed with 409
        // before authorizing, so it cannot collapse into an idempotent no-op
        // reservation that defeats the over-subscription guard.
        let (status, second) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_ne!(second["status"], "authorized");
        assert_eq!(second["error"], "chio_request_id_reused");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_requires_hold_capable_budget_store() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        // hold_capable == false models a remote `--control-url` budget store whose
        // hold APIs fall back to the no-op trait defaults, so a reserved hold can
        // never be reconciled by nonce or reclaimed by the TTL reaper.
        let state = mediated_test_state_inner(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            false,
        );
        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        // Fail-closed: the mediated route rejects rather than mint an
        // unreconcilable reserved nonce.
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"], "chio_mediation_requires_local_budget_store");
        assert_ne!(json["status"], "authorized");
        assert!(
            json["execution_nonce"].is_null(),
            "a fail-closed rejection must not mint a reserved nonce"
        );

        // No hold is placed against the grant: the route fails closed before any
        // budget interaction.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_requires_reconcile_control_token() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        // A hold-capable store but NO sidecar-control token: every /v1/reconcile
        // is rejected by the reconcile control gate, so a minted reservation could
        // only expire and forfeit budget. The evaluate route must fail closed
        // before reserving budget or minting a nonce.
        let state =
            mediated_test_state_with_control_token(signer, Arc::clone(&budget), Vec::new(), None);
        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"], "chio_mediation_requires_reconcile_token");
        assert_ne!(json["status"], "authorized");
        assert!(
            json["execution_nonce"].is_null(),
            "a fail-closed rejection must not mint a reserved nonce"
        );

        // No hold is placed against the grant: the route fails closed before any
        // budget interaction.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_rejects_blank_reconcile_control_token() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        // A whitespace-only sidecar-control token is a misconfiguration: the
        // reconcile control gate trims the presented token and rejects a blank
        // configured token, so every /v1/reconcile is refused and a minted
        // reservation could only expire and forfeit budget. The evaluate route
        // must treat a blank token as unconfigured and fail closed before
        // reserving budget or minting a nonce.
        let state = mediated_test_state_with_control_token(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some("   ".to_string()),
        );
        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"], "chio_mediation_requires_reconcile_token");
        assert_ne!(json["status"], "authorized");
        assert!(
            json["execution_nonce"].is_null(),
            "a fail-closed rejection must not mint a reserved nonce"
        );

        // No hold is placed against the grant: the route fails closed before any
        // budget interaction.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_requires_hold_capable_budget_store() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let params = serde_json::json!({ "invoice": "inv-1" });

        // Mint a genuine reserved nonce on a hold-capable sidecar so the reconcile
        // body deserializes; the reconcile is then attempted against a
        // non-hold-capable sidecar.
        let hold_capable = mediated_test_state(signer.clone(), Arc::clone(&budget), Vec::new());
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-remote",
        });
        let (_, authorized) = post_evaluate(hold_capable, &body).await;
        let nonce_json = authorized["execution_nonce"].clone();
        assert!(nonce_json.is_object());

        // A remote (non-hold-capable) sidecar cannot resolve the reserved hold the
        // nonce names, so reconcile fails closed rather than attempt a settle.
        let remote = mediated_test_state_inner(
            signer,
            budget,
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            false,
        );
        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        let (status, json) = post_reconcile(remote, &reconcile_body).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"], "chio_mediation_requires_local_budget_store");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_durable_hold_rejects_request_id_reuse_across_restart() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        // The durable budget store survives a restart; the ProxyState (and its
        // in-memory request-id window) is rebuilt fresh.
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();

        // Pre-restart sidecar: reserve a hold under a caller-chosen request_id. The
        // kernel derives the durable hold id from it and marks the hold reserved.
        let before = mediated_test_state(signer.clone(), Arc::clone(&budget), Vec::new());
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" },
            "request_id": "restart-req",
        });
        let (status, authorized) = post_evaluate(Arc::clone(&before), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(authorized["status"], "authorized");

        // Restart: a fresh ProxyState with an EMPTY in-memory window, sharing only
        // the durable budget store. The seeded sidecar signer survives, so the
        // rebuilt mediation kernel still trusts the capability.
        let after = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        // Reusing the same request_id must be rejected fail-closed via the DURABLE
        // check: the in-memory fast path is empty after the restart, so only the
        // open hold recorded in the budget store closes the gap. Without it the
        // reused id would collapse into an idempotent authorize that mints a second
        // nonce against the same open reservation.
        let (status, replay) = post_evaluate(Arc::clone(&after), &body).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_ne!(replay["status"], "authorized");
        assert!(
            replay["execution_nonce"].is_null(),
            "no second nonce is minted against the open hold"
        );
        assert_eq!(replay["error"], "chio_request_id_reused");

        // A fresh request_id still authorizes on the restarted sidecar: the durable
        // check rejects only a reused id that already backs an open hold.
        let fresh_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-2" },
            "request_id": "restart-req-fresh",
        });
        let (status, fresh) = post_evaluate(after, &fresh_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fresh["status"], "authorized");
        assert!(fresh["execution_nonce"].is_object());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_settles_reserved_hold_and_frees_budget() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let signer_pub = signer.public_key();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // max_per 100, max_total 150: one reservation reserves 100, a second
        // (needing 100 more -> 200 > 150) is blocked until the first frees slack.
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        // Reserve the worst-case 100 and capture the minted nonce.
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-reserve",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(authorized["status"], "authorized");
        let nonce_json = authorized["execution_nonce"].clone();
        assert!(nonce_json.is_object());

        // A second authorization is blocked while the slack is reserved.
        let blocked_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-blocked",
        });
        let (_, blocked) = post_evaluate(Arc::clone(&state), &blocked_body).await;
        assert_eq!(blocked["status"], "deny");

        // Reconcile at realized 30 (< reserved 100): settle down, free 70.
        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json.clone(),
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        let (status, reconciled) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reconciled["status"], "reconciled");

        // The returned receipt is an authoritative mediated spend bound to the nonce.
        let receipt: ChioReceipt = serde_json::from_value(reconciled["receipt"].clone()).unwrap();
        let nonce: SignedExecutionNonce = serde_json::from_value(nonce_json).unwrap();
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[signer_pub], &nonce),
            Ok(())
        );

        // The freed difference admits an authorization that was blocked before.
        let after_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-after",
        });
        let (_, after) = post_evaluate(Arc::clone(&state), &after_body).await;
        assert_eq!(
            after["status"], "authorized",
            "the budget freed by reconcile must admit a new authorization"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_rejects_replayed_nonce() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-replay",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        let nonce_json = authorized["execution_nonce"].clone();

        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        // First reconcile settles the hold.
        let (status, _) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);

        // Replaying the same nonce is rejected fail-closed: the shared kernel's
        // nonce store already consumed it and the reserved hold is closed.
        let (status, replay) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(replay["error"], "chio_reconcile_rejected");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_rejects_argument_mismatch() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-mismatch",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        let nonce_json = authorized["execution_nonce"].clone();

        // Arguments that do not match the nonce's signed parameter binding are
        // rejected: the realized-cost claim must be tied to the exact authorized
        // call, so a forged reconcile cannot settle a different action.
        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": { "invoice": "tampered" },
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        let (status, rejected) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(rejected["error"], "chio_reconcile_rejected");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reaper_forfeits_expired_hold_at_worst_case() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // One reservation reserves the whole grant.
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 100, "USD");
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        let reserve_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "reap-reserve",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &reserve_body).await;
        assert_eq!(authorized["status"], "authorized");

        // The whole grant is reserved: a second authorization is blocked.
        let blocked_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "reap-blocked",
        });
        let (_, blocked) = post_evaluate(Arc::clone(&state), &blocked_body).await;
        assert_eq!(blocked["status"], "deny");

        // Sweep with a far-future clock: the abandoned reserved hold is past its
        // execution-nonce TTL and is settled at its reserved worst-case.
        let settled = reap_expired_reserved_holds_once(&state, i64::MAX)
            .await
            .unwrap();
        assert_eq!(settled, 1, "the expired reserved hold must be settled");

        // Fail-closed: reaping FORFEITS the reserved worst-case to realized spend
        // (an abandoned reservation may correspond to a call that ran), so the
        // grant stays fully committed and a new authorization is still denied.
        // The reaper's job is to convert a lingering open hold into a settled
        // spend, not to free budget for the caller who never reconciled.
        let after_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "reap-after",
        });
        let (_, after) = post_evaluate(Arc::clone(&state), &after_body).await;
        assert_eq!(
            after["status"], "deny",
            "a forfeited reserved hold must keep the grant committed, not free it"
        );

        // The forfeited worst-case remains committed against the grant.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        let usage = usage.expect("the forfeited hold must remain recorded in the budget store");
        assert_eq!(
            usage.committed_cost_units().unwrap(),
            100,
            "reaping settles the reserved worst-case as realized spend (fail-closed)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_works_with_both_control_url_and_budget_db() {
        // With BOTH a control plane and a local budget DB configured,
        // `build_budget_store` hands mediation the hold-capable local SQLite
        // store, so `/v1/evaluate` authorizes (minting a reserved nonce) and
        // `/v1/reconcile` settles, instead of failing closed. This exercises the
        // exact store the sidecar would select from that configuration.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let dir =
            std::env::temp_dir().join(format!("chio-budget-both-e2e-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("budget.sqlite");
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some("{}".to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: None,
            allow_ephemeral_receipts: true,
            sidecar_control_token: None,
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            control_url: Some("http://127.0.0.1:1".to_string()),
            control_token: Some("token".to_string()),
            budget_db: Some(db.to_string_lossy().to_string()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let configured = build_budget_store(&config)
            .unwrap()
            .expect("a budget store must be built");
        assert!(configured.hold_capable);
        let budget = configured.store;

        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state_inner(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            configured.hold_capable,
        );
        let params = serde_json::json!({ "invoice": "inv-both" });

        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "both-configured",
        });
        let (status, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            authorized["status"], "authorized",
            "both configured must authorize via the local hold-capable store"
        );
        let nonce_json = authorized["execution_nonce"].clone();
        assert!(nonce_json.is_object());

        // Reconcile settles the reserved hold the local store persisted.
        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        let (status, reconciled) = post_reconcile(state, &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reconciled["status"], "reconciled");
    }

    /// Open a temporary receipt store backed by a fresh SQLite database.
    fn open_temp_receipt_store() -> (std::path::PathBuf, SqliteReceiptStore) {
        let dir = std::env::temp_dir().join(format!("chio-receipt-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("receipts.sqlite");
        let store = SqliteReceiptStore::open(&db.to_string_lossy()).unwrap();
        (db, store)
    }

    /// A receipt store whose `append_tool_receipt` fails deterministically: the
    /// backing `tool_receipts` table is dropped through a second connection to
    /// the same database, so every append errors.
    fn failing_receipt_store() -> SqliteReceiptStore {
        let (db, store) = open_temp_receipt_store();
        let dropper = rusqlite::Connection::open(&db).unwrap();
        dropper.execute("DROP TABLE tool_receipts", []).unwrap();
        drop(dropper);
        store
    }

    /// A payment adapter that counts each rail action, so a test can assert a
    /// captured MustPrepay prepayment is neither refunded nor re-charged. The
    /// settlement behavior is delegated to the deterministic sim adapter.
    #[derive(Clone, Default)]
    struct RecordingPaymentAdapter {
        inner: chio_kernel::SimPaymentAdapter,
        captures: Arc<std::sync::atomic::AtomicUsize>,
        releases: Arc<std::sync::atomic::AtomicUsize>,
        refunds: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl chio_kernel::PaymentAdapter for RecordingPaymentAdapter {
        fn authorize(
            &self,
            request: &chio_kernel::PaymentAuthorizeRequest,
        ) -> Result<chio_kernel::PaymentAuthorization, chio_kernel::PaymentError> {
            self.inner.authorize(request)
        }

        fn capture(
            &self,
            authorization_id: &str,
            amount_units: u64,
            currency: &str,
            reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.captures
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner
                .capture(authorization_id, amount_units, currency, reference)
        }

        fn release(
            &self,
            authorization_id: &str,
            reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.releases
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.release(authorization_id, reference)
        }

        fn refund(
            &self,
            transaction_id: &str,
            amount_units: u64,
            currency: &str,
            reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.refunds
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner
                .refund(transaction_id, amount_units, currency, reference)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_receipt_persistence_failure_returns_nonce_and_keeps_reservation() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 100, "USD");
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state_inner(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(failing_receipt_store()),
            true,
        );
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" },
            "request_id": "persist-fail",
        });

        // The kernel Allowed (reserved) and minted a nonce, but the local receipt
        // append fails. The reservation is durable in the budget store and the caller
        // reconciles it at /v1/reconcile (which persists its own authoritative
        // receipt), so the handler returns 200 with the nonce rather than a 500 that
        // would strand a reservation the caller can never use.
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "authorized");
        assert!(
            json["execution_nonce"].is_object(),
            "a persistence failure after a successful reserve must still return the nonce"
        );

        // The reserved hold stays OPEN with its budget committed: the caller holds a
        // real reservation backing the downstream execution.
        let hold_id = format!("budget-hold:persist-fail:{cap_id}:0");
        let hold = budget.get_budget_hold(&hold_id).unwrap();
        assert!(
            hold.map(|hold| hold.disposition.is_open()).unwrap_or(false),
            "a returned reservation must keep its reserved hold open"
        );
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        let usage = usage.expect("the reserved hold must remain recorded in the budget store");
        assert_eq!(
            usage.committed_cost_units().unwrap(),
            100,
            "the returned reservation must keep its reserved budget committed"
        );

        // The request-id claim is retained: the id backs a live reservation, so a
        // reuse must still collide rather than mint a second nonce.
        assert_eq!(
            state.minted_request_ids.lock().await.len(),
            1,
            "a returned reservation must retain its request-id claim"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_receipt_persistence_success_keeps_reservation() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 100, "USD");
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let (_db, receipt_store) = open_temp_receipt_store();
        let state = mediated_test_state_inner(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(receipt_store),
            true,
        );
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" },
            "request_id": "persist-ok",
        });

        // The happy path: the receipt append succeeds, so the caller receives the
        // minted nonce and the reservation is kept for a real reconcile.
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "authorized");
        assert!(json["execution_nonce"].is_object());

        let usage = budget.get_usage(&cap_id, 0).unwrap();
        let usage = usage.expect("the reserved hold must remain recorded in the budget store");
        assert_eq!(
            usage.committed_cost_units().unwrap(),
            100,
            "a persisted authorization must keep its reserved hold"
        );
        assert_eq!(
            state.minted_request_ids.lock().await.len(),
            1,
            "a persisted authorization must retain its request-id claim"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_invocation_receipt_persistence_failure_returns_nonce_and_keeps_reservation() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state_inner(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(failing_receipt_store()),
            true,
        );
        let params = serde_json::json!({ "invoice": "inv-1" });
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "invoke-persist-fail",
        });

        // An invocation-only reserve debits the single invocation and mints a nonce.
        // The receipt append fails, but the caller can still present the nonce and
        // reconcile downstream, so the handler returns 200 with the nonce and keeps
        // the invocation reserved instead of a 500 that would permanently burn the
        // invocation for a caller that never received the nonce.
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "authorized");
        let nonce_json = json["execution_nonce"].clone();
        assert!(
            nonce_json.is_object(),
            "an invocation reserve whose receipt fails to persist must still return the nonce"
        );

        // The invocation stays consumed and the reserved hold stays open: the caller
        // holds the nonce that backs it.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert_eq!(
            usage.map(|usage| usage.invocation_count).unwrap_or(0),
            1,
            "the returned invocation reservation stays consumed against the grant"
        );
        let hold_id = format!("budget-hold:invoke-persist-fail:{cap_id}:0");
        let hold = budget.get_budget_hold(&hold_id).unwrap();
        assert!(
            hold.map(|hold| hold.disposition.is_open()).unwrap_or(false),
            "the returned invocation reservation must keep its reserved hold open"
        );

        // The returned nonce is usable: reconciling it downstream settles the
        // reservation and produces a `reconciled` receipt.
        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 0, "currency": "USD" },
        });
        let (recon_status, reconciled) = post_reconcile(state, &reconcile_body).await;
        assert_eq!(recon_status, StatusCode::OK);
        assert_eq!(reconciled["status"], "reconciled");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_mustprepay_receipt_persistence_failure_returns_nonce_without_refund() {
        // Money-loss guard: a governed MustPrepay reserve authorizes AND captures the
        // quoted prepayment before minting the nonce. If the sidecar's local receipt
        // append then fails, tearing the reservation down would leave the captured
        // prepayment charged for a reservation the caller never received (direct
        // financial loss). The handler must return 200 with the nonce so the captured
        // prepayment backs a usable authorization, and must not refund or re-charge.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_governed_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD", 50);
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let approver = signer.clone();

        let captures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refunds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let adapter = RecordingPaymentAdapter {
            inner: chio_kernel::SimPaymentAdapter::new(),
            captures: Arc::clone(&captures),
            releases: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            refunds: Arc::clone(&refunds),
        };
        let state = mediated_test_state_core(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(failing_receipt_store()),
            true,
            Some(Box::new(adapter)),
            None,
        );

        let request_id = "req-mustprepay-persist-fail";
        let intent =
            governed_mustprepay_intent("intent-prepay-persist", "cost-srv", "compute", 100, "USD");
        let approval = governed_approval_token(&approver, &agent.public_key(), &intent, request_id);
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" },
            "request_id": request_id,
            "governed_intent": intent,
            "approval_token": approval,
        });

        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a captured MustPrepay reserve whose receipt fails to persist must not 500"
        );
        assert_eq!(json["status"], "authorized");
        assert!(
            json["execution_nonce"].is_object(),
            "the caller must receive the nonce the captured prepayment backs"
        );

        // The prepayment was captured exactly once and never refunded: the payer is
        // billed for the authorization the caller now holds, with no money lost to a
        // torn-down reservation.
        assert_eq!(
            captures.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the MustPrepay quote must be captured exactly once"
        );
        assert_eq!(
            refunds.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the captured prepayment must not be refunded: it backs the returned nonce"
        );

        // The reservation is intact: the reserved hold stays open.
        let hold_id = format!("budget-hold:{request_id}:{cap_id}:0");
        let hold = budget.get_budget_hold(&hold_id).unwrap();
        assert!(
            hold.map(|hold| hold.disposition.is_open()).unwrap_or(false),
            "the captured MustPrepay reservation must stay open, backing the returned nonce"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_invocation_reconcile_keeps_invocation_consumed() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        let reserve_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "invoke-reconcile",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &reserve_body).await;
        assert_eq!(authorized["status"], "authorized");
        let nonce_json = authorized["execution_nonce"].clone();

        // A legitimate reconcile settles the invocation reservation: the debited
        // invocation stays consumed (the call ran), it is not refunded.
        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 0, "currency": "USD" },
        });
        let (status, reconciled) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reconciled["status"], "reconciled");

        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert_eq!(
            usage.map(|usage| usage.invocation_count).unwrap_or(0),
            1,
            "a legitimate reconcile must keep the invocation consumed, not refund it"
        );

        // The single invocation stays consumed: a later authorization is denied.
        let after_body = serde_json::json!({
            "capability": serde_json::to_value(&cap).unwrap(),
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "invoke-reconcile-after",
        });
        let (_, after) = post_evaluate(state, &after_body).await;
        assert_eq!(
            after["status"], "deny",
            "a reconciled invocation stays consumed against max_invocations"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reaper_forfeits_expired_invocation_reserve() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        let reserve_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "invoke-reap",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &reserve_body).await;
        assert_eq!(authorized["status"], "authorized");

        // Sweep with a far-future clock: the abandoned invocation reservation is
        // past its execution-nonce TTL and is settled at its (zero-money)
        // worst-case, forfeiting the invocation the same way the monetary reaper
        // forfeits reserved money.
        let settled = reap_expired_reserved_holds_once(&state, i64::MAX)
            .await
            .unwrap();
        assert_eq!(
            settled, 1,
            "the expired invocation reservation must be settled"
        );

        // Fail-closed: the forfeited invocation stays consumed, so a new
        // authorization on the single-invocation grant is still denied.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert_eq!(
            usage.map(|usage| usage.invocation_count).unwrap_or(0),
            1,
            "reaping an abandoned invocation reservation forfeits it (stays consumed)"
        );
        let after_body = serde_json::json!({
            "capability": serde_json::to_value(&cap).unwrap(),
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "invoke-reap-after",
        });
        let (_, after) = post_evaluate(state, &after_body).await;
        assert_eq!(
            after["status"], "deny",
            "a forfeited invocation reservation must keep the grant committed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_open_invocation_reserve_blocks_oversubscription() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        let first_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "invoke-open-1",
        });
        let (_, first) = post_evaluate(Arc::clone(&state), &first_body).await;
        assert_eq!(first["status"], "authorized");

        // While the first invocation reservation is OPEN (debited, not yet
        // reconciled or reaped), a second reserve that would exceed
        // max_invocations is denied: an in-flight reservation still counts, so
        // there is no over-subscription.
        let second_body = serde_json::json!({
            "capability": serde_json::to_value(&cap).unwrap(),
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "invoke-open-2",
        });
        let (_, second) = post_evaluate(state, &second_body).await;
        assert_eq!(
            second["status"], "deny",
            "an open invocation reservation must block a second reserve past max_invocations"
        );
    }

    #[test]
    fn build_budget_store_local_sqlite_when_no_control_url() {
        let dir = std::env::temp_dir().join(format!("chio-budget-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("budget.sqlite");
        let config = ProtectConfig {
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
            budget_db: Some(db.to_string_lossy().to_string()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let configured = build_budget_store(&config).unwrap();
        let configured = configured.expect("local sqlite budget store must be built");
        assert!(
            configured.hold_capable,
            "the local sqlite budget store implements the hold APIs and must be hold-capable"
        );
    }

    #[test]
    fn build_budget_store_remote_is_not_hold_capable() {
        // A remote control-plane budget store forwards only
        // charge/reverse/reconcile and falls back to the no-op hold-API defaults,
        // so it must be flagged not hold-capable; the mediated routes then fail
        // closed rather than mint a reservation it can never reconcile or reap.
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some("{}".to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: None,
            allow_ephemeral_receipts: true,
            sidecar_control_token: None,
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            control_url: Some("http://127.0.0.1:1".to_string()),
            control_token: Some("token".to_string()),
            budget_db: None,
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let configured = build_budget_store(&config).unwrap();
        let configured = configured.expect("remote budget store must be built");
        assert!(
            !configured.hold_capable,
            "the remote control-plane budget store does not implement the hold APIs"
        );
    }

    #[test]
    fn build_budget_store_prefers_local_hold_capable_when_both_configured() {
        // An operator who configures BOTH a control plane and a local budget DB
        // must get the hold-capable local SQLite store for mediation: the remote
        // store cannot persist a reserved hold, so choosing it would disable
        // mediated authorization and reconcile. Prefer the local store.
        let dir = std::env::temp_dir().join(format!("chio-budget-both-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("budget.sqlite");
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some("{}".to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: None,
            allow_ephemeral_receipts: true,
            sidecar_control_token: None,
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            control_url: Some("http://127.0.0.1:1".to_string()),
            control_token: Some("token".to_string()),
            budget_db: Some(db.to_string_lossy().to_string()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let configured = build_budget_store(&config).unwrap();
        let configured = configured.expect("a budget store must be built when both are configured");
        assert!(
            configured.hold_capable,
            "with both configured, mediation must use the hold-capable local store"
        );
        // The returned store is the working local SQLite store: it answers the
        // hold-inventory query rather than a remote endpoint that is never reached.
        assert_eq!(
            configured.store.count_open_holds().unwrap(),
            0,
            "the preferred store must be the functional local hold-capable store"
        );
    }

    fn revocation_db_config(revocation_db: Option<String>) -> ProtectConfig {
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
            revocation_db,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        }
    }

    #[test]
    fn load_revocation_db_ids_is_empty_without_configured_store() {
        let ids = load_revocation_db_ids(&revocation_db_config(None)).unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn load_revocation_db_ids_reads_operator_revocations() {
        let dir = std::env::temp_dir().join(format!("chio-revocation-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("revocations.sqlite3");
        let db_path = db.to_string_lossy().to_string();

        // Mirror `chio trust revoke --revocation-db <path>`: an operator writes
        // the revocation to the durable store the sidecar never used to read.
        let store = chio_store_sqlite::SqliteRevocationStore::open(&db).unwrap();
        assert!(chio_kernel::RevocationStore::revoke(&store, "cap-operator-revoked").unwrap());
        drop(store);

        let ids = load_revocation_db_ids(&revocation_db_config(Some(db_path))).unwrap();
        assert!(
            ids.contains("cap-operator-revoked"),
            "durable operator revocation must be loaded into the enforced set"
        );
    }

    #[test]
    fn load_revocation_db_ids_fails_closed_on_unreadable_store() {
        let dir =
            std::env::temp_dir().join(format!("chio-revocation-bad-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("not-a-db.sqlite3");
        std::fs::write(&db, b"this is not a sqlite database").unwrap();

        let result = load_revocation_db_ids(&revocation_db_config(Some(
            db.to_string_lossy().to_string(),
        )));
        assert!(
            result.is_err(),
            "an unreadable revocation-db must fail closed rather than start with no revocations"
        );
    }

    #[test]
    fn mediation_kernel_installs_budget_store_and_strict_nonce_config() {
        let signer = Keypair::generate();
        let budget: Arc<dyn BudgetStore> =
            Arc::new(chio_kernel::budget_store::InMemoryBudgetStore::new());
        let kernel =
            build_mediation_kernel(&signer, Arc::clone(&budget), &[], Vec::new(), None).unwrap();
        // Strict nonce mode is what routes every mediated request through the
        // authorization-reserve path. DPoP verification state is installed here
        // too; the `mediated_dpop_capability_requires_valid_proof` integration
        // test exercises it end to end.
        assert!(
            kernel.execution_nonce_required(),
            "mediation kernel must always run execution-nonce strict mode"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_requires_sidecar_control_token() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-auth-gate",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(authorized["status"], "authorized");
        let nonce_json = authorized["execution_nonce"].clone();

        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });

        // The controlled agent could self-reconcile at cost zero when
        // reconcile was on the public router. Without the sidecar-control token
        // the reconcile is rejected by the trusted-caller gate before it can
        // settle the hold; the gate runs ahead of the handler, so the nonce is
        // not consumed by the rejected attempt.
        let (status, denied) =
            post_json(Arc::clone(&state), "/v1/reconcile", &reconcile_body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(denied["error"], "chio_control_forbidden");

        // Presenting the control token (the tool server's trust boundary) settles.
        let (status, reconciled) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reconciled["status"], "reconciled");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_without_configured_control_token_is_rejected() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let params = serde_json::json!({ "invoice": "inv-1" });

        // Mint a genuine reserved nonce on a control-token-bearing sidecar so the
        // reconcile body deserializes; the reconcile is then attempted against a
        // sidecar with no configured control token. Evaluate itself fails closed
        // without a control token, so the nonce must come from a configured one.
        let with_token = mediated_test_state(signer.clone(), Arc::clone(&budget), Vec::new());
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-no-token",
        });
        let (_, authorized) = post_evaluate(with_token, &body).await;
        let nonce_json = authorized["execution_nonce"].clone();
        assert!(nonce_json.is_object());

        // No sidecar-control token configured on this sidecar.
        let state = mediated_test_state_with_control_token(signer, budget, Vec::new(), None);

        // Fail-closed: with no control token configured there is no trusted
        // caller, so reconcile is rejected outright rather than left open.
        // Presenting any bearer cannot help because none is configured to match.
        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 0, "currency": "USD" },
        });
        let (status, denied) = post_reconcile(state, &reconcile_body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(denied["error"], "chio_control_forbidden");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_needs_no_tool_server_registration() {
        // The reserve-for-caller path no longer requires the target
        // tool server to be registered, so the route registers nothing. Many
        // distinct caller-arbitrary server ids each authorize, and because the
        // handler holds the kernel behind a shared (non-mut) lock it cannot
        // register a server or otherwise grow the kernel's tool-server map.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        for index in 0..8 {
            let server = format!("arbitrary-srv-{index}");
            let cap =
                issue_cost_bearing_capability(&kernel, &agent, &server, "invoke", 100, 1000, "USD");
            let body = serde_json::json!({
                "capability": cap,
                "tool_server": server,
                "tool_name": "invoke",
                "parameters": {},
                "request_id": format!("noreg-{index}"),
            });
            let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                json["status"], "authorized",
                "an arbitrary caller server id must authorize without any registration"
            );
            assert!(json["execution_nonce"].is_object());
        }
    }

    #[test]
    fn minted_request_id_window_bounds_reuse_and_expiry() {
        let mut window = MintedRequestIdWindow::new(30);
        // A fresh id is claimed; an immediate reuse inside the window is rejected.
        assert!(window.claim("req-a", 1_000));
        assert!(!window.claim("req-a", 1_000));
        assert_eq!(window.len(), 1);

        // Releasing an id (a denied/failed authorization) makes it reusable at once.
        window.release("req-a");
        assert_eq!(window.len(), 0);
        assert!(window.claim("req-a", 1_000));

        // Distinct live ids accumulate, but a later claim prunes entries whose
        // reservation TTL has lapsed, so the set stays bounded and an expired id
        // is reusable again.
        assert!(window.claim("req-b", 1_010));
        assert_eq!(window.len(), 2);
        // At 1_031, "req-a" (expires 1_030) is pruned; "req-b" (expires 1_040)
        // is still live.
        assert!(window.claim("req-c", 1_031));
        assert_eq!(window.len(), 2);
        assert!(window.claim("req-a", 1_031));
        assert_eq!(window.len(), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_denied_authorization_does_not_burn_request_id() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // max_cost_per_invocation (100) exceeds max_total_cost (40): the
        // reservation is refused, so the authorization is denied and places no
        // durable hold.
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 40, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": {},
            "request_id": "denied-then-retry",
        });

        let (status, first) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["status"], "deny");

        // A denied authorization must not permanently burn the id.
        // Reusing it is NOT a 409 conflict; it is evaluated again (and denied
        // again), proving the claim was released.
        let (status, second) = post_evaluate(Arc::clone(&state), &body).await;
        assert_ne!(
            status,
            StatusCode::CONFLICT,
            "a denied authorization must release its request-id claim"
        );
        assert_eq!(second["status"], "deny");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reserved_hold_reaper_handle_is_retained_not_detached() {
        let signer = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let state = mediated_test_state(signer, budget, Vec::new());

        // No reaper before spawn.
        assert!(state.reaper_handle.lock().await.is_none());

        // The reaper's JoinHandle is retained on the shared state,
        // not dropped/detached, so it can be aborted on shutdown.
        spawn_reserved_hold_reaper(&state).await;
        {
            let guard = state.reaper_handle.lock().await;
            let handle = guard
                .as_ref()
                .expect("the reaper handle must be retained on the state");
            assert!(
                !handle.is_finished(),
                "the retained reaper handle must reference a live, abortable task"
            );
        }

        // The retained handle is abortable; aborting cancels the reaper task.
        let handle = state.reaper_handle.lock().await.take().unwrap();
        handle.abort();
        assert!(
            handle.await.is_err(),
            "aborting the retained handle must cancel the reaper task"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_returns_authoritative_receipt_when_persistence_fails() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let signer_pub = signer.public_key();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();

        // A working receipt store so the evaluate that mints the nonce persists.
        let (db, receipt_store) = open_temp_receipt_store();
        let state = mediated_test_state_inner(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(receipt_store),
            true,
        );
        let params = serde_json::json!({ "invoice": "inv-1" });

        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-persist-fail",
        });
        let (status, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(authorized["status"], "authorized");
        let nonce_json = authorized["execution_nonce"].clone();
        assert!(nonce_json.is_object());

        // The reconcile consumes the nonce and settles the reserved hold
        // IRREVERSIBLY before persisting its receipt. Drop the receipt table so the
        // post-settle append fails: unlike a reversible reservation, the settled
        // spend cannot be undone, so the authoritative receipt is the only proof.
        let dropper = rusqlite::Connection::open(&db).unwrap();
        dropper.execute("DROP TABLE tool_receipts", []).unwrap();
        drop(dropper);

        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json.clone(),
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        let (status, reconciled) = post_reconcile(Arc::clone(&state), &reconcile_body).await;

        // The settlement already happened, so the caller must receive the
        // authoritative receipt rather than a 500 that discards the only proof.
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reconciled["status"], "reconciled");
        let receipt: ChioReceipt = serde_json::from_value(reconciled["receipt"].clone()).unwrap();
        let nonce: SignedExecutionNonce = serde_json::from_value(nonce_json).unwrap();
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[signer_pub], &nonce),
            Ok(()),
            "a persistence failure after settlement must still return the authoritative receipt"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_still_fails_closed_on_replayed_nonce_when_persistence_fails() {
        // The receipt-persistence carve-out is scoped to a SUCCESSFUL settle: a
        // real reconcile ERROR (here a replayed, already-consumed nonce) must still
        // fail closed, never reaching receipt persistence.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let (db, receipt_store) = open_temp_receipt_store();
        let state = mediated_test_state_inner(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(receipt_store),
            true,
        );
        let params = serde_json::json!({ "invoice": "inv-1" });

        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-replay-persist-fail",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        let nonce_json = authorized["execution_nonce"].clone();

        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        // First reconcile settles the hold and consumes the nonce.
        let (status, _) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);

        // Even with receipt persistence broken, a replayed nonce is a reconcile
        // ERROR: it is rejected 4xx and never returns a receipt.
        let dropper = rusqlite::Connection::open(&db).unwrap();
        dropper.execute("DROP TABLE tool_receipts", []).unwrap();
        drop(dropper);
        let (status, replay) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(replay["error"], "chio_reconcile_rejected");
        assert!(replay.get("receipt").is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_durable_hold_rejects_request_id_reuse_after_settle() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        // The durable budget store survives a restart; the ProxyState (and its
        // in-memory request-id window) is rebuilt fresh.
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer.clone(), Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        // Reserve a hold under a caller-chosen request_id, then settle it: the
        // durable hold row persists but is no longer open.
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "settled-reuse",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(authorized["status"], "authorized");
        let nonce_json = authorized["execution_nonce"].clone();

        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        let (status, _) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);

        // Restart: a fresh ProxyState with an EMPTY in-memory window sharing only
        // the durable budget store, so the durable reuse guard is the only defense.
        let after = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        // Reusing the settled request_id must be rejected 409: the durable hold id
        // is already spent, so passing it through would let the kernel reject the
        // duplicate hold id and turn a valid later authorization into a 500.
        let (status, replay) = post_evaluate(Arc::clone(&after), &body).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(replay["error"], "chio_request_id_reused");
        assert_ne!(replay["status"], "authorized");
        assert!(
            replay["execution_nonce"].is_null(),
            "a reused settled request_id must not mint a second nonce"
        );

        // A fresh request_id still authorizes on the restarted sidecar.
        let fresh_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-2" },
            "request_id": "settled-reuse-fresh",
        });
        let (status, fresh) = post_evaluate(after, &fresh_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fresh["status"], "authorized");
        assert!(fresh["execution_nonce"].is_object());
    }
}
