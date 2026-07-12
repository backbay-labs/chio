//! Tower service wrapper for kernel tool-call dispatch.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tower::limit::{ConcurrencyLimit, ConcurrencyLimitLayer};
use tower::load_shed::{LoadShed, LoadShedLayer};
use tower::timeout::TimeoutLayer;
use tower::Service;
use tower_layer::Layer;

/// Tenant identifier carried for tower-side admission layers.
///
/// The kernel remains responsible for capability validation and receipt
/// semantics. This value is only used by tower middleware that needs an
/// external partition key, such as later per-tenant limits.
pub type TenantId = String;

/// Default maximum number of tenant limiter buckets retained by a service.
pub const DEFAULT_MAX_TENANT_CONCURRENCY_BUCKETS: usize = 1024;

/// Tower service that dispatches tool-call requests through a shared kernel.
#[derive(Clone)]
pub struct KernelService {
    kernel: Arc<chio_kernel::ChioKernel>,
}

impl KernelService {
    /// Create a new kernel dispatch service.
    pub fn new(kernel: Arc<chio_kernel::ChioKernel>) -> Self {
        Self { kernel }
    }

    /// Return the shared kernel used by this service.
    pub fn kernel(&self) -> &Arc<chio_kernel::ChioKernel> {
        &self.kernel
    }
}

/// Request accepted by [`KernelService`].
pub struct KernelRequest {
    /// Tool-call request evaluated by the kernel.
    pub call: chio_kernel::ToolCallRequest,
    /// Tenant partition key for tower middleware. Capability semantics stay
    /// inside `chio-kernel`.
    pub tenant_id: TenantId,
}

impl KernelRequest {
    /// Create a new kernel service request.
    pub fn new(call: chio_kernel::ToolCallRequest, tenant_id: impl Into<TenantId>) -> Self {
        Self {
            call,
            tenant_id: tenant_id.into(),
        }
    }
}

/// Response produced by [`KernelService`].
pub type KernelResponse = chio_kernel::ToolCallResponse;

/// Errors returned by the kernel service stack.
#[derive(Debug, thiserror::Error)]
pub enum KernelServiceError {
    /// Inner kernel evaluation failed.
    #[error("kernel: {0}")]
    Kernel(#[from] chio_kernel::KernelError),
    /// Tenant or global service saturation caused load shedding.
    #[error("overloaded")]
    Overloaded,
    /// The per-tenant bucket table is at capacity and this tenant has no bucket.
    /// Distinct from `Overloaded` (a per-tenant concurrency shed) so a full table
    /// is observable separately; maps to the same shed edge.
    #[error("tenant bucket table is full")]
    TenantTableFull,
    /// Request exceeded the configured tower timeout.
    #[error("timeout")]
    Timeout,
    /// Middleware returned an unexpected error shape.
    #[error("middleware: {0}")]
    Middleware(String),
}

impl Service<KernelRequest> for KernelService {
    type Response = KernelResponse;
    type Error = KernelServiceError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: KernelRequest) -> Self::Future {
        let kernel = Arc::clone(&self.kernel);

        Box::pin(async move {
            // Translate the kernel error explicitly rather than via the blanket
            // `?`/`From` conversion so an RSS soft-ceiling shed surfaces as the
            // retryable service overload variant (see `map_kernel_error`).
            let response = kernel
                .evaluate_tool_call(&req.call)
                .await
                .map_err(map_kernel_error)?;
            Ok(response)
        })
    }
}

/// Translate a kernel evaluation error into the tower service error.
///
/// The RSS soft ceiling sheds new admissions with
/// [`chio_kernel::KernelError::Overloaded`]. The blanket `From<KernelError>` maps
/// that into the opaque [`KernelServiceError::Kernel`], which callers keying
/// retry/backpressure on [`KernelServiceError::Overloaded`] (the variant tower
/// load shedding produces) would treat as an ordinary kernel failure. Map
/// `Overloaded` explicitly to the retryable service overload variant so an RSS
/// shed reaches the same shed edge as tower-side load shedding. Every other
/// kernel error keeps the `Kernel` shape.
fn map_kernel_error(error: chio_kernel::KernelError) -> KernelServiceError {
    match error {
        chio_kernel::KernelError::Overloaded { .. } => KernelServiceError::Overloaded,
        other => KernelServiceError::Kernel(other),
    }
}

/// Trace layer for kernel service calls.
#[derive(Clone, Debug, Default)]
pub struct KernelTraceLayer;

impl<S> Layer<S> for KernelTraceLayer {
    type Service = KernelTraceService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        KernelTraceService { inner }
    }
}

/// Trace service emitted by [`KernelTraceLayer`].
#[derive(Clone, Debug)]
pub struct KernelTraceService<S> {
    inner: S,
}

impl<S> Service<KernelRequest> for KernelTraceService<S>
where
    S: Service<KernelRequest, Response = KernelResponse, Error = KernelServiceError>
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = KernelResponse;
    type Error = KernelServiceError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: KernelRequest) -> Self::Future {
        let request_id = req.call.request_id.clone();
        let tenant_id = req.tenant_id.clone();
        let tool_name = req.call.tool_name.clone();
        let server_id = req.call.server_id.clone();
        let started = Instant::now();
        let future = self.inner.call(req);

        Box::pin(async move {
            tracing::debug!(
                request_id = %request_id,
                tenant_id = %tenant_id,
                tool_name = %tool_name,
                server_id = %server_id,
                "kernel service request started"
            );

            let result = future.await;
            match &result {
                Ok(response) => {
                    tracing::debug!(
                        request_id = %response.request_id,
                        tenant_id = %tenant_id,
                        verdict = ?response.verdict,
                        elapsed_ms = started.elapsed().as_millis(),
                        "kernel service request finished"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        request_id = %request_id,
                        tenant_id = %tenant_id,
                        elapsed_ms = started.elapsed().as_millis(),
                        error = %error,
                        "kernel service request failed"
                    );
                }
            }
            result
        })
    }
}

/// Default idle window after which an unused tenant bucket may be reaped to make
/// room for a new tenant.
const DEFAULT_TENANT_IDLE_REAP_SECS: u64 = 3600;

/// Per-tenant concurrency limiter for kernel requests.
///
/// Each tenant key gets its own bounded tower concurrency service. Waiting for
/// capacity in one tenant partition does not consume readiness for another
/// tenant partition.
#[derive(Clone, Debug)]
pub struct TenantConcurrencyLimitLayer {
    per_tenant_limit: usize,
    max_tenants: usize,
    tenant_idle_reap_secs: u64,
}

impl TenantConcurrencyLimitLayer {
    /// Create a new per-tenant concurrency limit layer.
    pub fn new(per_tenant_limit: usize) -> Self {
        Self {
            per_tenant_limit,
            max_tenants: DEFAULT_MAX_TENANT_CONCURRENCY_BUCKETS,
            tenant_idle_reap_secs: DEFAULT_TENANT_IDLE_REAP_SECS,
        }
    }

    /// Set the maximum number of tenant limiter buckets retained at once.
    pub fn with_max_tenants(mut self, max_tenants: usize) -> Self {
        self.max_tenants = max_tenants;
        self
    }

    /// Set the idle window after which an unused tenant bucket may be reaped so
    /// a new tenant is not permanently blocked by a full table.
    pub fn with_tenant_idle_reap_secs(mut self, secs: u64) -> Self {
        self.tenant_idle_reap_secs = secs;
        self
    }
}

impl<S> Layer<S> for TenantConcurrencyLimitLayer {
    type Service = TenantConcurrencyLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TenantConcurrencyLimitService {
            inner,
            per_tenant_limit: self.per_tenant_limit,
            max_tenants: self.max_tenants,
            tenant_idle_reap_secs: self.tenant_idle_reap_secs,
            tenants: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// Service emitted by [`TenantConcurrencyLimitLayer`].
#[derive(Clone, Debug)]
pub struct TenantConcurrencyLimitService<S> {
    inner: S,
    per_tenant_limit: usize,
    max_tenants: usize,
    tenant_idle_reap_secs: u64,
    tenants: Arc<Mutex<HashMap<TenantId, TenantBucketEntry<S>>>>,
}

type TenantBucketService<S> = LoadShed<ConcurrencyLimit<S>>;
/// A tenant's bucket service, its last-use instant (for idle reap), and a live
/// in-flight-call counter so a bucket with active calls is never reaped.
type TenantBucketEntry<S> = (TenantBucketService<S>, std::time::Instant, Arc<AtomicUsize>);

/// RAII guard that decrements a tenant bucket's in-flight counter when a
/// dispatched call finishes (or its future is dropped/cancelled). Held for the
/// full duration of `call` so an idle-reap sweep skips buckets with active
/// calls: reaping an active bucket and recreating a fresh semaphore would let a
/// tenant exceed `per_tenant_limit`.
#[derive(Debug)]
struct InFlightGuard(Arc<AtomicUsize>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl<S> TenantConcurrencyLimitService<S>
where
    S: Clone,
{
    fn service_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> Result<(TenantBucketService<S>, InFlightGuard), KernelServiceError> {
        let mut tenants = self.tenants.lock().map_err(|_| {
            KernelServiceError::Middleware("tenant concurrency limit state poisoned".to_string())
        })?;

        if let Some((service, last_use, in_flight)) = tenants.get_mut(tenant_id) {
            *last_use = std::time::Instant::now();
            in_flight.fetch_add(1, Ordering::SeqCst);
            return Ok((service.clone(), InFlightGuard(Arc::clone(in_flight))));
        }

        if tenants.len() >= self.max_tenants {
            // Reap the most-idle tenant so a new tenant is not permanently
            // blocked; only then declare the table full. Never reap a bucket that
            // still has in-flight calls: recreating its
            // semaphore would let that tenant exceed `per_tenant_limit`.
            let idle = std::time::Duration::from_secs(self.tenant_idle_reap_secs);
            let victim = tenants
                .iter()
                .filter(|(_, (_, last, in_flight))| {
                    last.elapsed() >= idle && in_flight.load(Ordering::SeqCst) == 0
                })
                .max_by_key(|(_, (_, last, _))| last.elapsed())
                .map(|(k, _)| k.clone());
            match victim {
                Some(v) => {
                    tenants.remove(&v);
                }
                None => return Err(KernelServiceError::TenantTableFull),
            }
        }

        let service = ConcurrencyLimitLayer::new(self.per_tenant_limit).layer(self.inner.clone());
        let service = LoadShedLayer::new().layer(service);
        let in_flight = Arc::new(AtomicUsize::new(1));
        let guard = InFlightGuard(Arc::clone(&in_flight));
        tenants.insert(
            tenant_id.clone(),
            (service.clone(), std::time::Instant::now(), in_flight),
        );
        Ok((service, guard))
    }
}

impl<S> Service<KernelRequest> for TenantConcurrencyLimitService<S>
where
    S: Service<KernelRequest, Error = KernelServiceError> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
{
    type Response = S::Response;
    type Error = KernelServiceError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: KernelRequest) -> Self::Future {
        let acquired = self.service_for_tenant(&req.tenant_id);

        Box::pin(async move {
            // Hold the in-flight guard for the whole call so a concurrent
            // idle-reap sweep never evicts this tenant's active bucket.
            let (mut service, _in_flight) = acquired?;
            poll_ready_once(&mut service)?;
            service.call(req).await.map_err(normalize_tower_error)
        })
    }
}

fn poll_ready_once<S>(service: &mut TenantBucketService<S>) -> Result<(), KernelServiceError>
where
    TenantBucketService<S>: Service<KernelRequest, Error = tower::BoxError>,
{
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    match service.poll_ready(&mut cx) {
        Poll::Ready(Ok(())) => Ok(()),
        Poll::Ready(Err(error)) => Err(normalize_tower_error(error)),
        Poll::Pending => Err(KernelServiceError::Overloaded),
    }
}

#[derive(Clone, Debug, Default)]
struct KernelTimeoutErrorLayer;

impl<S> Layer<S> for KernelTimeoutErrorLayer {
    type Service = KernelTimeoutErrorService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        KernelTimeoutErrorService { inner }
    }
}

#[derive(Clone, Debug)]
struct KernelTimeoutErrorService<S> {
    inner: S,
}

impl<S, Request> Service<Request> for KernelTimeoutErrorService<S>
where
    S: Service<Request, Error = tower::BoxError>,
    S::Future: Send + 'static,
    Request: Send + 'static,
{
    type Response = S::Response;
    type Error = KernelServiceError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(normalize_tower_error)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let future = self.inner.call(request);
        Box::pin(async move { future.await.map_err(normalize_tower_error) })
    }
}

fn normalize_tower_error(error: tower::BoxError) -> KernelServiceError {
    let error = match error.downcast::<KernelServiceError>() {
        Ok(kernel_error) => return *kernel_error,
        Err(error) => error,
    };

    if error.is::<tower::timeout::error::Elapsed>() {
        return KernelServiceError::Timeout;
    }

    if error.is::<tower::load_shed::error::Overloaded>() {
        return KernelServiceError::Overloaded;
    }

    KernelServiceError::Middleware(error.to_string())
}

/// Build the layered kernel service stack.
///
/// Request flow is trace, then timeout, then per-tenant load shedding and
/// concurrency, then kernel dispatch. Auth prechecks wrap around this stack.
pub fn build_layered(
    kernel: Arc<chio_kernel::ChioKernel>,
    per_tenant_limit: usize,
    request_timeout: Duration,
) -> impl Service<KernelRequest, Response = KernelResponse, Error = KernelServiceError> + Clone {
    let service = KernelService::new(kernel);
    let service = TenantConcurrencyLimitLayer::new(per_tenant_limit).layer(service);
    let service = TimeoutLayer::new(request_timeout).layer(service);
    let service = KernelTimeoutErrorLayer.layer(service);
    KernelTraceLayer.layer(service)
}

#[cfg(test)]
mod tests {
    use super::*;

    use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
    use chio_core_types::crypto::Keypair;
    use chio_kernel::{
        ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallOutput, ToolCallRequest,
        ToolServerConnection, ToolServerStreamResult, DEFAULT_CHECKPOINT_BATCH_SIZE,
        DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };
    use tower::ServiceExt;

    struct EchoServer;

    #[async_trait::async_trait]
    impl ToolServerConnection for EchoServer {
        fn server_id(&self) -> &str {
            "srv-a"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["echo".to_string()]
        }

        async fn invoke(
            &self,
            tool_name: &str,
            arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            Ok(serde_json::json!({
                "tool": tool_name,
                "arguments": arguments,
            }))
        }

        async fn invoke_stream(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Option<ToolServerStreamResult>, KernelError> {
            Ok(None)
        }
    }

    #[test]
    fn table_full_is_distinct_from_per_tenant_overload() {
        // At cap, a third distinct tenant sees the distinct TenantTableFull (not
        // the per-tenant Overloaded), and a non-idle table does not reap, so the
        // third tenant is refused rather than admitted.
        #[derive(Clone, Debug)]
        struct MockInner;

        let service = TenantConcurrencyLimitLayer::new(1)
            .with_max_tenants(2)
            .layer(MockInner);
        assert!(service.service_for_tenant(&"tenant-a".to_string()).is_ok());
        assert!(service.service_for_tenant(&"tenant-b".to_string()).is_ok());
        match service.service_for_tenant(&"tenant-c".to_string()) {
            Err(KernelServiceError::TenantTableFull) => {}
            other => panic!("expected TenantTableFull, got {other:?}"),
        }
    }

    #[test]
    fn idle_tenant_is_reaped_to_admit_a_new_tenant() {
        // With a zero idle window every existing tenant is immediately reapable,
        // so a full table admits a new tenant by evicting the most-idle one.
        #[derive(Clone, Debug)]
        struct MockInner;

        let service = TenantConcurrencyLimitLayer::new(1)
            .with_max_tenants(2)
            .with_tenant_idle_reap_secs(0)
            .layer(MockInner);
        assert!(service.service_for_tenant(&"tenant-a".to_string()).is_ok());
        assert!(service.service_for_tenant(&"tenant-b".to_string()).is_ok());
        assert!(
            service.service_for_tenant(&"tenant-c".to_string()).is_ok(),
            "an idle tenant should be reaped to admit a new one"
        );
    }

    #[test]
    fn in_flight_tenant_is_not_reaped_even_when_idle_timed() {
        // A bucket with an in-flight call must never be reaped. Recreating its
        // semaphore would let the tenant exceed per_tenant_limit.
        #[derive(Clone, Debug)]
        struct MockInner;

        let service = TenantConcurrencyLimitLayer::new(1)
            .with_max_tenants(1)
            .with_tenant_idle_reap_secs(0)
            .layer(MockInner);

        // Hold tenant-a's in-flight guard so its bucket has an active call.
        let held = match service.service_for_tenant(&"tenant-a".to_string()) {
            Ok(acquired) => acquired,
            Err(error) => panic!("tenant-a should be admitted: {error:?}"),
        };

        // Table is full (max_tenants=1). Even with a zero idle window
        // (time-reapable), tenant-a has an in-flight call, so it must NOT be
        // reaped and the new tenant is refused.
        match service.service_for_tenant(&"tenant-b".to_string()) {
            Err(KernelServiceError::TenantTableFull) => {}
            other => {
                panic!("expected TenantTableFull (active tenant not reaped), got {other:?}")
            }
        }

        // Once the in-flight call finishes, the idle tenant becomes reapable.
        drop(held);
        assert!(
            service.service_for_tenant(&"tenant-b".to_string()).is_ok(),
            "an idle tenant with no in-flight call should be reaped"
        );
    }

    fn make_config() -> KernelConfig {
        KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "test-policy-hash".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        }
    }

    fn make_grant() -> ToolGrant {
        ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "echo".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }
    }

    fn make_scope() -> ChioScope {
        ChioScope {
            grants: vec![make_grant()],
            ..ChioScope::default()
        }
    }

    fn make_kernel_request(kernel: &ChioKernel) -> KernelRequest {
        let agent_keypair = Keypair::generate();
        let capability = kernel
            .issue_capability(&agent_keypair.public_key(), make_scope(), 60)
            .unwrap_or_else(|error| panic!("issue capability failed: {error}"));
        let call = ToolCallRequest {
            request_id: "req-kernel-service".to_string(),
            capability,
            tool_name: "echo".to_string(),
            server_id: "srv-a".to_string(),
            agent_id: agent_keypair.public_key().to_hex(),
            arguments: serde_json::json!({ "message": "hello" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        KernelRequest::new(call, "tenant-a")
    }

    #[tokio::test]
    async fn kernel_service_dispatches_through_kernel() {
        let mut kernel = ChioKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer));
        let request = make_kernel_request(&kernel);
        let mut service = build_layered(Arc::new(kernel), 16, Duration::from_secs(5));

        let response = service
            .ready()
            .await
            .unwrap_or_else(|error| panic!("service ready failed: {error}"))
            .call(request)
            .await
            .unwrap_or_else(|error| panic!("service call failed: {error}"));

        assert_eq!(response.verdict, chio_kernel::Verdict::Allow);
        match response.output {
            Some(ToolCallOutput::Value(value)) => {
                assert_eq!(value["tool"], "echo");
                assert_eq!(value["arguments"]["message"], "hello");
            }
            other => panic!("expected value output, got {other:?}"),
        }
        assert_eq!(response.receipt.body().tool_name, "echo");
    }

    #[tokio::test]
    async fn timeout_layer_maps_elapsed_error() {
        let inner = tower::service_fn(|_request: KernelRequest| async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok::<(), KernelServiceError>(())
        });
        let timeout = TimeoutLayer::new(Duration::from_millis(1)).layer(inner);
        let mut service = KernelTimeoutErrorLayer.layer(timeout);
        let kernel = ChioKernel::new(make_config());
        let request = make_kernel_request(&kernel);

        let result = service
            .ready()
            .await
            .unwrap_or_else(|error| panic!("service ready failed: {error}"))
            .call(request)
            .await;
        let Err(error) = result else {
            panic!("timeout should fail");
        };

        assert!(matches!(error, KernelServiceError::Timeout));
    }

    #[test]
    fn rss_shed_kernel_overload_maps_to_service_overloaded() {
        // An RSS soft-ceiling shed surfaces as KernelError::Overloaded and must
        // reach the RETRYABLE service overload variant, not the opaque Kernel
        // wrapper, so callers keying retry/backpressure on Overloaded treat the
        // shed as backpressure.
        let mapped = map_kernel_error(KernelError::Overloaded {
            resource: chio_kernel::OverloadResource::Allocation,
        });
        assert!(
            matches!(mapped, KernelServiceError::Overloaded),
            "an RSS shed must map to the retryable Overloaded variant, got {mapped:?}"
        );

        // The blanket `From`/`?` conversion maps the same shed to the opaque
        // Kernel variant, which is why call() must use map_kernel_error instead.
        let via_from: KernelServiceError = KernelError::Overloaded {
            resource: chio_kernel::OverloadResource::Allocation,
        }
        .into();
        assert!(
            matches!(via_from, KernelServiceError::Kernel(_)),
            "the blanket From maps Overloaded to Kernel; call() must use map_kernel_error"
        );

        // Every other kernel error keeps the Kernel shape.
        let other = map_kernel_error(KernelError::Internal("boom".to_string()));
        assert!(matches!(other, KernelServiceError::Kernel(_)));
    }

    struct ParkingServer {
        invoked: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl ToolServerConnection for ParkingServer {
        fn server_id(&self) -> &str {
            "srv-a"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["echo".to_string()]
        }

        async fn invoke(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            self.invoked
                .store(true, std::sync::atomic::Ordering::SeqCst);
            std::future::pending::<Result<serde_json::Value, KernelError>>().await
        }

        async fn invoke_stream(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Option<ToolServerStreamResult>, KernelError> {
            Ok(None)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn build_layered_timeout_drop_records_cancellation_receipt() {
        let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut kernel = ChioKernel::new(make_config());
        kernel.register_tool_server(Box::new(ParkingServer {
            invoked: Arc::clone(&invoked),
        }));
        let request = make_kernel_request(&kernel);
        let kernel = Arc::new(kernel);
        let mut service = build_layered(Arc::clone(&kernel), 16, Duration::from_millis(1));

        let result = service
            .ready()
            .await
            .unwrap_or_else(|error| panic!("service ready failed: {error}"))
            .call(request)
            .await;
        let Err(error) = result else {
            panic!("a parked dispatch must time out");
        };
        assert!(matches!(error, KernelServiceError::Timeout));
        assert!(
            invoked.load(std::sync::atomic::Ordering::SeqCst),
            "tool dispatch must have been entered before the timeout elapsed"
        );

        let receipt_log = kernel.receipt_log();
        assert_eq!(
            receipt_log.len(),
            1,
            "build_layered timeout must record exactly one cancellation receipt"
        );
        let Some(receipt) = receipt_log.get(0) else {
            panic!("cancellation receipt missing from the kernel receipt log");
        };
        assert!(receipt.is_cancelled());
    }
}
