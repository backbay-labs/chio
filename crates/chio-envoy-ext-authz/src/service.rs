//! gRPC service implementation for Envoy's `envoy.service.auth.v3.Authorization`
//! interface. Each `Check` RPC is translated into a Chio
//! [`crate::translate::ToolCallRequest`], routed through the
//! [`EnvoyKernel`] abstraction, and the returned [`Verdict`] is mapped back
//! onto an Envoy `CheckResponse`.

use async_trait::async_trait;
use tonic::{Request, Response, Status};
use tracing::{debug, warn};

use crate::error::KernelError;
use crate::proto::envoy::service::auth::v3::{
    authorization_server::Authorization, CheckRequest, CheckResponse,
};
use crate::response::{fail_closed_response, verdict_to_response};
use crate::translate::{check_request_to_tool_call, ToolCallRequest, Verdict};

/// Kernel abstraction used by [`ChioExtAuthzService`]. Real deployments supply
/// an implementation that delegates to `chio-kernel` (or `HttpAuthority` in
/// `chio-http-core`); tests can stub this trait to verify the adapter's
/// request/response plumbing in isolation.
#[async_trait]
pub trait EnvoyKernel: Send + Sync + 'static {
    /// Evaluate a translated tool call. Implementations must be fail-closed:
    /// return [`KernelError`] rather than panicking on internal faults so the
    /// adapter can deny with a 500 response.
    async fn evaluate(&self, request: ToolCallRequest) -> Result<Verdict, KernelError>;
}

/// Canonical `Authorization` service implementation. Construct it with the
/// concrete [`EnvoyKernel`] you want to route checks through, then register
/// it with a `tonic::transport::Server` via
/// [`authorization_server::AuthorizationServer::new`][asn].
///
/// [asn]: crate::proto::envoy::service::auth::v3::authorization_server::AuthorizationServer::new
pub struct ChioExtAuthzService<K: EnvoyKernel> {
    kernel: K,
}

impl<K: EnvoyKernel> ChioExtAuthzService<K> {
    /// Create a new service bound to `kernel`.
    pub fn new(kernel: K) -> Self {
        Self { kernel }
    }
}

#[async_trait]
impl<K: EnvoyKernel> Authorization for ChioExtAuthzService<K> {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let check = request.into_inner();

        let tool_call = match check_request_to_tool_call(&check) {
            Ok(call) => call,
            Err(err) => {
                warn!(error = %err, "ext_authz translation failed");
                return Ok(Response::new(fail_closed_response()));
            }
        };

        debug!(
            tool = %tool_call.tool,
            request_id = %tool_call.request_id,
            "evaluating ext_authz check"
        );

        match self.kernel.evaluate(tool_call).await {
            Ok(verdict) => Ok(Response::new(verdict_to_response(&verdict))),
            Err(err) => {
                warn!(error = %err, "ext_authz kernel evaluation failed");
                Ok(Response::new(fail_closed_response()))
            }
        }
    }
}
