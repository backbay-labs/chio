//! Tower service wrapper for kernel tool-call dispatch.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
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
            let response = kernel.evaluate_tool_call(&req.call).await?;
            Ok(response)
        })
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

/// Per-tenant concurrency limiter for kernel requests.
///
/// Each tenant key gets its own bounded tower concurrency service. Waiting for
/// capacity in one tenant partition does not consume readiness for another
/// tenant partition.
#[derive(Clone, Debug)]
pub struct TenantConcurrencyLimitLayer {
    per_tenant_limit: usize,
    max_tenants: usize,
}

impl TenantConcurrencyLimitLayer {
    /// Create a new per-tenant concurrency limit layer.
    pub fn new(per_tenant_limit: usize) -> Self {
        Self {
            per_tenant_limit,
            max_tenants: DEFAULT_MAX_TENANT_CONCURRENCY_BUCKETS,
        }
    }

    /// Set the maximum number of tenant limiter buckets retained at once.
    pub fn with_max_tenants(mut self, max_tenants: usize) -> Self {
        self.max_tenants = max_tenants;
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
    tenants: Arc<Mutex<HashMap<TenantId, TenantBucketService<S>>>>,
}

type TenantBucketService<S> = LoadShed<ConcurrencyLimit<S>>;

impl<S> TenantConcurrencyLimitService<S>
where
    S: Clone,
{
    fn service_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> Result<TenantBucketService<S>, KernelServiceError> {
        let mut tenants = self.tenants.lock().map_err(|_| {
            KernelServiceError::Middleware("tenant concurrency limit state poisoned".to_string())
        })?;
        if !tenants.contains_key(tenant_id) && tenants.len() >= self.max_tenants {
            return Err(KernelServiceError::Overloaded);
        }

        let service = tenants
            .entry(tenant_id.clone())
            .or_insert_with(|| {
                let service =
                    ConcurrencyLimitLayer::new(self.per_tenant_limit).layer(self.inner.clone());
                LoadShedLayer::new().layer(service)
            })
            .clone();
        Ok(service)
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
        let service = self.service_for_tenant(&req.tenant_id);

        Box::pin(async move {
            let mut service = service?;
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

/// Build the M05 P3 kernel service stack.
///
/// Request flow is trace, then timeout, then per-tenant load shedding and
/// concurrency, then kernel dispatch. Later P3 tickets add auth prechecks
/// around this stack.
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

    use chio_core_types::capability::{ChioScope, Operation, ToolGrant};
    use chio_core_types::crypto::Keypair;
    use chio_kernel::{
        ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallOutput, ToolCallRequest,
        ToolServerConnection, ToolServerStreamResult, DEFAULT_CHECKPOINT_BATCH_SIZE,
        DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };
    use tower::ServiceExt;

    struct EchoServer;

    impl ToolServerConnection for EchoServer {
        fn server_id(&self) -> &str {
            "srv-a"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["echo".to_string()]
        }

        fn invoke(
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

        fn invoke_stream(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Option<ToolServerStreamResult>, KernelError> {
            Ok(None)
        }
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
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
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
}
