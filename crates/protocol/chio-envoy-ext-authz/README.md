# chio-envoy-ext-authz

Chio adapter for Envoy's `ext_authz` gRPC filter. It implements
`envoy.service.auth.v3.Authorization/Check` as a shim that translates each
Envoy `CheckRequest` into a Chio `ToolCallRequest`, hands it to a pluggable
`EnvoyKernel`, and maps the returned `Verdict` back onto a `CheckResponse`.

The crate has no dependency on `chio-kernel` or `chio-http-core`. `EnvoyKernel`
is the seam a deployment implements to plug in a real policy engine, so the
adapter can be linked into any Envoy-fronted service without pulling in the
rest of the Chio substrate.

## Responsibilities

- Implement the `envoy.service.auth.v3.Authorization/Check` RPC and coordinate
  translate -> evaluate -> respond for each call.
- Translate a `CheckRequest` into a `ToolCallRequest`: derive an
  `http.<method>.<path>` tool identity, split path from query, allowlist
  policy-relevant headers, and extract caller identity (capability header,
  then bearer token, then mTLS principal, then anonymous).
- Strip raw secrets before they leave the translation layer: bearer tokens and
  request bodies are reduced to SHA-256 hex digests, never forwarded intact.
- Map a `Verdict` onto a compliant `CheckResponse`, including Envoy status-code
  mapping, denial headers, and `chio.*` dynamic metadata for access logs.
- Fail closed on translation or kernel errors with a stable, generic 500
  response; internal fault detail is logged, never returned to the caller.
- Vendor the minimal Envoy ext_authz v3 proto subset and compile it at build
  time, using a vendored `protoc` when the `PROTOC` environment variable is
  unset.

## Public API

- `EnvoyKernel` - trait a deployment implements to evaluate a `ToolCallRequest`
  and return a `Verdict`. The extension point; no implementation ships in this
  crate.
- `ChioExtAuthzService<K: EnvoyKernel>` - the tonic `Authorization` service
  implementation, constructed with `ChioExtAuthzService::new(kernel)`.
- `translate::check_request_to_tool_call` - `&CheckRequest -> Result<ToolCallRequest, TranslateError>`.
- `translate::{ToolCallRequest, CallerIdentity, AuthMethod, HttpMethod, Verdict, ENVOY_SERVER_ID}`.
- `error::{TranslateError, KernelError}`.
- `proto::envoy::*`, `proto::google::rpc::*` - generated protobuf bindings,
  module tree mirrors the `.proto` package hierarchy.

## Usage

```rust
use async_trait::async_trait;
use chio_envoy_ext_authz::{
    proto::envoy::service::auth::v3::authorization_server::AuthorizationServer,
    translate::{ToolCallRequest, Verdict},
    ChioExtAuthzService, EnvoyKernel, KernelError,
};

struct MyKernel;

#[async_trait]
impl EnvoyKernel for MyKernel {
    async fn evaluate(&self, request: ToolCallRequest) -> Result<Verdict, KernelError> {
        // Delegate to chio-kernel, chio-http-core's HttpAuthority, or a
        // custom policy engine here.
        Ok(Verdict::Allow)
    }
}

let svc = ChioExtAuthzService::new(MyKernel);
tonic::transport::Server::builder()
    .add_service(AuthorizationServer::new(svc))
    .serve("0.0.0.0:9091".parse()?)
    .await?;
```

## Testing

`cargo test -p chio-envoy-ext-authz`

## See also

- `chio-kernel` - one of the policy engines a deployment's `EnvoyKernel`
  implementation typically delegates to.
- `chio-http-core` - owns `HttpAuthority`, an alternative delegation target
  named in this crate's own doc comments.
- `examples/istio-ext-authz` - Kubernetes manifests and a walkthrough wiring
  this adapter into an Istio mesh's `extensionProviders`.
