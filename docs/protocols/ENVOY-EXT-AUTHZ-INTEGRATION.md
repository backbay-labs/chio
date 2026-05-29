# Envoy ext_authz Integration: Chio as External Authorization Backend

> **Status**: Tier 0 -- proposed April 2026
> **Priority**: P0 -- highest-leverage network integration. One adapter puts
> Chio into every Istio, Consul Connect, and standalone Envoy deployment.
> Approximately 80% of enterprise service meshes run Envoy as the data plane.

## 1. Why This Is P0

Chio's existing integrations (framework middleware, sidecar HTTP, Lambda
extension) each target a single runtime or language. Envoy ext_authz is
different: it is a **multiplier**. A single ext_authz adapter makes Chio
available to every service in every mesh that runs Envoy, regardless of the
service's language, framework, or deployment model.

The reach is enormous:

| Mesh / Platform | Data Plane | ext_authz Support |
|-----------------|------------|-------------------|
| Istio | Envoy | Native (AuthorizationPolicy CUSTOM action) |
| Consul Connect | Envoy | Native (envoy_extensions.ext_authz) |
| AWS App Mesh | Envoy | Supported via filter chain |
| Gloo Edge / Solo.io | Envoy | Native |
| Standalone Envoy | Envoy | Built-in HTTP filter |
| Cilium (L7 policy) | Envoy (embedded) | Supported |

Chio's `/evaluate` endpoint already returns a verdict (allow/deny) with a
receipt ID and guard evidence. The ext_authz protocol expects the same
structure: check a request, return allow or deny, optionally inject headers.
The gap is small -- primarily protobuf marshalling for the gRPC variant and
header mapping conventions.

### Strategic Position

Every other tool-security or API-gateway product requires its own proxy or
sidecar. Chio with ext_authz requires **zero new infrastructure** -- it
plugs into the proxy the mesh already runs. This eliminates the "another
sidecar" objection and makes Chio adoption a configuration change, not an
architecture change.

## 2. The ext_authz Protocol

Envoy's external authorization filter intercepts every request (or a
configured subset) and sends a **check request** to an external service
before forwarding upstream. The external service returns allow or deny,
optionally modifying headers in either direction.

### 2.1 Request Flow

```
Client
  |
  v
Envoy Proxy
  |
  |-- ext_authz filter intercepts request
  |-- Sends CheckRequest to external auth service
  |      (method, path, headers, optional body)
  |
  |   +-----------------------------+
  |-->| External Auth Service (Chio) |
  |   | Evaluate capability token   |
  |   | Run guard pipeline          |
  |   | Sign receipt                |
  |   | Return verdict + receipt ID |
  |   +-----------------------------+
  |
  |<-- CheckResponse (allow/deny + header mutations)
  |
  |-- If allowed: forward to upstream with injected headers
  |-- If denied: return error to client
  v
Upstream Service
```

### 2.2 Two Modes

ext_authz supports two transport modes:

| Mode | Transport | Protobuf | Latency | Complexity |
|------|-----------|----------|---------|------------|
| gRPC | HTTP/2 | `envoy.service.auth.v3.Authorization/Check` | Lower (binary, persistent connection) | Higher (proto codegen) |
| HTTP | HTTP/1.1 | None (raw HTTP request forwarded) | Higher (text, per-request connection) | Lower (plain HTTP) |

Chio implements both. The gRPC adapter is the primary production path.
The HTTP adapter is a zero-code option that reuses Chio's existing
`/evaluate` endpoint with minimal configuration.

### 2.3 Envoy Filter Configuration

```yaml
# Envoy bootstrap or LDS configuration
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      # gRPC mode (preferred)
      grpc_service:
        envoy_grpc:
          cluster_name: chio_ext_authz
        timeout: 0.25s
      # What to send to Chio
      with_request_body:
        max_request_bytes: 8192
        allow_partial_message: true
        pack_as_bytes: true
      # Forward these headers to Chio for identity extraction
      allowed_headers:
        patterns:
          - exact: authorization
          - exact: x-chio-capability-token
          - exact: x-chio-session-id
          - exact: x-request-id
          - prefix: x-chio-
      # Status on ext_authz connection failure
      failure_mode_allow: false  # Fail-closed (Chio default)
      # Include peer certificate in check request (for mTLS identity)
      include_peer_certificate: true

clusters:
  - name: chio_ext_authz
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
    load_assignment:
      cluster_name: chio_ext_authz
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: 127.0.0.1
                    port_value: 9091
```

## 3. Mapping Chio to ext_authz

### 3.1 CheckRequest to Chio Evaluation

The ext_authz `CheckRequest` carries the downstream request's attributes.
Chio maps these to its `ChioHttpRequest` model:

| ext_authz `AttributeContext` field | Chio `ChioHttpRequest` field | Notes |
|------------------------------------|---------------------------|-------|
| `request.http.method` | `method` | Direct mapping via `HttpMethod` |
| `request.http.path` | `path` | Raw path; route resolver normalizes to `route_pattern` |
| `request.http.headers["authorization"]` | `caller.auth_method` | Bearer token extraction |
| `request.http.headers["x-chio-capability-token"]` | `capability_id` | Chio capability token ID |
| `request.http.headers["x-chio-session-id"]` | `session_id` | Session binding |
| `request.http.headers["x-request-id"]` | `request_id` | Envoy's request ID or generated |
| `request.http.body` | `body_hash` (SHA-256) | Body hashed, never stored |
| `source.principal` | `caller.subject` | mTLS identity from peer cert |
| `request.http.headers` (selected) | `headers` | Only policy-relevant headers forwarded |

### 3.2 Chio Verdict to CheckResponse

Chio's `Verdict` maps directly to ext_authz responses:

```
Chio Verdict::Allow
  -> CheckResponse { status: OK (0) }
     + OkHttpResponse {
         headers: [
           { "x-chio-receipt-id": "<receipt-id>" },
           { "x-chio-policy-hash": "<policy-hash>" },
         ]
       }

Chio Verdict::Deny { reason, guard, http_status }
  -> CheckResponse { status: PermissionDenied (7) }
     + DeniedHttpResponse {
         status: { code: StatusCode(<http_status>) },
         headers: [
           { "x-chio-receipt-id": "<receipt-id>" },
           { "x-chio-denial-reason": "<reason>" },
           { "x-chio-denial-guard": "<guard>" },
         ],
         body: "<structured JSON error>"
       }

Chio Verdict::Cancel / Verdict::Incomplete
  -> CheckResponse { status: Unavailable (14) }
     (Envoy applies failure_mode_allow policy)
```

### 3.3 Header Injection

On allow, Chio injects headers into the upstream request so the backend
service can consume receipt metadata without calling Chio directly:

| Header | Value | Direction |
|--------|-------|-----------|
| `x-chio-receipt-id` | Receipt UUID | Request to upstream |
| `x-chio-policy-hash` | SHA-256 of the evaluated policy | Request to upstream |
| `x-chio-verdict` | `allow` or `deny` | Request to upstream |
| `x-chio-session-id` | Session ID (if present) | Request to upstream |

On deny, Chio sets headers and a JSON body on the response returned to the
client. The receipt ID is always included so the client can reference it
in appeals or debugging.

### 3.4 Capability Token Extraction

Chio capability tokens travel in the `x-chio-capability-token` header or as
a Bearer token in the `Authorization` header. The ext_authz adapter
extracts the token using the same `CallerIdentity` / `AuthMethod` logic
as `chio-tower` and `chio-http-core`:

1. Check `x-chio-capability-token` header (preferred, explicit).
2. Fall back to `Authorization: Bearer <token>` (standard OAuth2 flow).
3. If neither is present, evaluate as `AuthMethod::Anonymous`.

The adapter never forwards raw tokens upstream. It forwards the receipt ID
and a hash of the token, consistent with Chio's never-store-secrets policy.

## 4. gRPC Adapter

The gRPC adapter implements `envoy.service.auth.v3.Authorization/Check`
as a thin shim over Chio's existing `HttpAuthority` evaluation engine.

### 4.1 Protobuf Service Definition

```protobuf
// From envoy/service/auth/v3/external_auth.proto
service Authorization {
  rpc Check(CheckRequest) returns (CheckResponse);
}

message CheckRequest {
  AttributeContext attributes = 1;
}

message CheckResponse {
  google.rpc.Status status = 1;
  oneof http_response {
    OkHttpResponse ok_response = 2;
    DeniedHttpResponse denied_response = 3;
  }
  // Dynamic metadata for access logging
  google.protobuf.Struct dynamic_metadata = 4;
}
```

### 4.2 Rust Implementation Sketch

```rust
use tonic::{Request, Response, Status};

use envoy_auth_v3::{
    authorization_server::Authorization,
    CheckRequest, CheckResponse, OkHttpResponse, DeniedHttpResponse,
};
use chio_http_core::{
    ChioHttpRequest, CallerIdentity, HttpAuthority, HttpMethod, Verdict,
};

pub struct ChioExtAuthzService {
    authority: HttpAuthority,
}

#[tonic::async_trait]
impl Authorization for ChioExtAuthzService {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let check_req = request.into_inner();
        let attrs = check_req.attributes
            .ok_or_else(|| Status::invalid_argument("missing attributes"))?;
        let http_req = attrs.request
            .and_then(|r| r.http)
            .ok_or_else(|| Status::invalid_argument("missing HTTP request"))?;

        // Map ext_authz attributes to Chio request model.
        let chio_request = self.map_check_request(&http_req, &attrs.source)?;

        // Evaluate through the Chio kernel.
        let prepared = self.authority.evaluate(&chio_request)
            .map_err(|e| Status::internal(format!("evaluation error: {e}")))?;

        // Sign receipt.
        let receipt = self.authority.finalize_receipt(&prepared)
            .map_err(|e| Status::internal(format!("receipt error: {e}")))?;

        // Map verdict to CheckResponse.
        let response = match &prepared.verdict {
            Verdict::Allow => self.allow_response(&receipt),
            Verdict::Deny { reason, guard, http_status } => {
                self.deny_response(&receipt, reason, guard, *http_status)
            }
            Verdict::Cancel { .. } | Verdict::Incomplete { .. } => {
                return Err(Status::unavailable("evaluation incomplete"));
            }
        };

        Ok(Response::new(response))
    }
}
```

### 4.3 Dynamic Metadata

The gRPC adapter populates `CheckResponse.dynamic_metadata` with Chio
evaluation data so Envoy access logs can include it:

```json
{
  "chio.receipt_id": "01917a3b-...",
  "chio.verdict": "allow",
  "chio.policy_hash": "sha256:abc123...",
  "chio.guard_count": 3,
  "chio.evaluation_ms": 12
}
```

This metadata is accessible in Envoy's access log format via
`%DYNAMIC_METADATA(...)%` and in downstream filters via the metadata API.

## 5. HTTP Adapter

For deployments that want to avoid protobuf complexity, ext_authz supports
an HTTP mode where Envoy forwards the request (or a subset of it) to an
HTTP endpoint. Chio's existing `/evaluate` endpoint is nearly compatible.

### 5.1 HTTP Mode Filter Configuration

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      http_service:
        server_uri:
          uri: http://127.0.0.1:9090/evaluate
          cluster: chio_http_sidecar
          timeout: 0.25s
        authorization_request:
          allowed_headers:
            patterns:
              - exact: authorization
              - exact: x-chio-capability-token
              - exact: x-chio-session-id
              - prefix: x-chio-
        authorization_response:
          allowed_upstream_headers:
            patterns:
              - exact: x-chio-receipt-id
              - exact: x-chio-policy-hash
              - exact: x-chio-verdict
          allowed_client_headers:
            patterns:
              - exact: x-chio-receipt-id
              - exact: x-chio-denial-reason

clusters:
  - name: chio_http_sidecar
    type: STATIC
    load_assignment:
      cluster_name: chio_http_sidecar
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: 127.0.0.1
                    port_value: 9090
```

### 5.2 What Changes in the /evaluate Endpoint

Chio's existing `/evaluate` endpoint needs minor adjustments for ext_authz
HTTP mode compatibility:

| Requirement | Current State | Change Needed |
|-------------|--------------|---------------|
| Return 200 for allow | `/evaluate` returns JSON with verdict | Return 200 status code when verdict is allow |
| Return 403 for deny | Returns 200 with deny verdict in body | Return 403 status code when verdict is deny |
| Header injection on allow | Receipt ID in response body | Also set `x-chio-receipt-id` as response header |
| Accept forwarded request | Expects POST with JSON body | Add mode that reads method/path/headers from the forwarded request itself |

The cleanest approach: add an `/ext_authz` endpoint to the sidecar HTTP
server that speaks ext_authz HTTP conventions natively while delegating to
the same `HttpAuthority` evaluation engine. This avoids contorting the
existing `/evaluate` semantics.

## 6. Istio Integration

Istio is the most common Envoy-based mesh. Chio integrates via Istio's
`AuthorizationPolicy` with the `CUSTOM` action, which delegates to an
ext_authz provider.

### 6.1 Layered Security Model

Istio and Chio serve complementary roles:

| Concern | Istio (native RBAC) | Chio (ext_authz) |
|---------|--------------------|--------------------|
| Service identity | mTLS, SPIFFE IDs | Consumes Istio identity as `CallerIdentity` |
| Per-service access | `AuthorizationPolicy` ALLOW/DENY | N/A (defer to Istio) |
| Per-tool capability | N/A | Capability tokens, scope-bounded grants |
| Audit trail | Access logs | Signed, Merkle-committed receipts |
| Policy language | Istio RBAC rules | Guard pipeline (Wasm, Rego, built-in) |
| Budget governance | N/A | Per-capability cost tracking and limits |

Chio layers **on top of** Istio's RBAC. Istio handles "can service A talk
to service B?" Chio handles "does this agent have a valid capability token
for this specific tool invocation, and does the guard pipeline approve?"

### 6.2 Istio MeshConfig: Register Chio as ext_authz Provider

```yaml
# istio-configmap or IstioOperator overlay
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  meshConfig:
    extensionProviders:
      - name: chio-ext-authz
        envoyExtAuthzGrpc:
          service: chio-ext-authz.chio-system.svc.cluster.local
          port: 9091
          # Timeout for Chio evaluation
          timeout: 0.25s
          # Forward headers Chio needs for identity and capability extraction
          includeRequestHeadersInCheck:
            - authorization
            - x-chio-capability-token
            - x-chio-session-id
            - x-request-id
```

### 6.3 AuthorizationPolicy: Route to Chio

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: chio-tool-authorization
  namespace: agent-tools
spec:
  # Apply to all tool server workloads in this namespace
  selector:
    matchLabels:
      chio.world/secured: "true"
  action: CUSTOM
  provider:
    name: chio-ext-authz
  rules:
    # Evaluate all requests to labeled workloads
    - to:
        - operation:
            # All paths -- Chio's guard pipeline handles fine-grained decisions
            paths: ["/*"]
```

### 6.4 Per-Workload Opt-In

Not every service needs Chio. The `chio.world/secured: "true"` label
gates which workloads are evaluated. Services without the label use
standard Istio RBAC only.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: code-execution-tool
  namespace: agent-tools
spec:
  template:
    metadata:
      labels:
        app: code-execution-tool
        chio.world/secured: "true"  # Opt into Chio evaluation
      annotations:
        chio.world/policy: "high-risk-tool"
        chio.world/fail-mode: "closed"
```

## 7. Consul Connect Integration

Consul Connect uses Envoy as its data plane, so ext_authz works the same
way. The configuration surface differs (HCL instead of YAML, Consul
service defaults instead of Istio CRDs).

### 7.1 Service Defaults with ext_authz

```hcl
# consul-service-defaults.hcl
Kind = "service-defaults"
Name = "agent-tool-server"
Protocol = "http"

EnvoyExtensions = [
  {
    Name = "builtin/ext-authz"
    Arguments = {
      ProxyType = "connect-proxy"
      ListenerType = "inbound"
      Config = {
        GrpcService = {
          Target = {
            URI = "127.0.0.1:9091"
          }
          Timeout = "0.25s"
        }
        IncludePeerCertificate = true
        WithRequestBody = {
          MaxRequestBytes = 8192
          AllowPartialMessage = true
        }
      }
    }
  }
]
```

### 7.2 Consul Intentions + Chio

Like the Istio model, Consul Intentions handle service-to-service
authorization (L4 identity) while Chio handles capability-level
authorization (L7 tool policy):

```
Consul Intention: "agent-orchestrator -> code-execution-tool" = allow
  |
  v (request reaches Envoy sidecar)
ext_authz filter -> Chio
  |
  Chio: does the capability token grant access to execute_code?
  Chio: does the guard pipeline approve (rate limit, budget, scope)?
  Chio: sign receipt and inject x-chio-receipt-id
  |
  v
code-execution-tool receives request with receipt header
```

### 7.3 Chio Sidecar Registration

In Consul, register the Chio service as a sidecar alongside the Envoy
sidecar within the same task or pod:

```hcl
# consul-service-registration.hcl
service {
  name = "agent-tool-server"
  port = 8080

  connect {
    sidecar_service {
      proxy {
        # Envoy proxy config handled by Consul
      }
    }
  }

  # Chio runs as a separate process on localhost
  # Registered for health checking but not in the mesh data plane
  checks = [
    {
      name = "Chio sidecar health"
      http = "http://127.0.0.1:9090/health"
      interval = "10s"
      timeout = "2s"
    }
  ]
}
```

## 8. What Chio Adds That Envoy and Istio Do Not Have

Envoy's built-in authorization and Istio's RBAC are powerful but operate
at the service and path level. Chio adds four capabilities that do not
exist in any service mesh:

### 8.1 Per-Tool Capability Scoping

Envoy/Istio RBAC:
```yaml
# "Service A can call Service B on path /api/*"
# No concept of what the call DOES or what SCOPE it has
```

Chio capability tokens:
```json
{
  "capability_id": "cap-01917a3b",
  "tool": "code_execution",
  "scopes": ["sandbox", "read_only"],
  "expires_at": "2026-04-15T12:00:00Z",
  "max_invocations": 50,
  "budget_remaining_usd": 2.50
}
```

Envoy sees "service A calls POST /execute on service B." Chio sees "agent
X is invoking the code_execution tool with sandbox+read_only scope, has
37 invocations remaining, and $1.80 of budget left."

### 8.2 Signed Receipts (Not Just Access Logs)

Envoy access logs record what happened. Chio receipts **prove** what
happened:

| Property | Envoy Access Log | Chio Receipt |
|----------|-----------------|-------------|
| Signed | No | Ed25519 signature from kernel keypair |
| Tamper-evident | No | Merkle tree commitment |
| Content-bound | No (logs the path) | SHA-256 hash of request body included |
| Verifiable by third party | No | Yes, with kernel's public key |
| Structured evidence | No | Per-guard evidence array |

A receipt is a cryptographic attestation: "at time T, agent X invoked
tool Y with scope Z, guards G1/G2/G3 evaluated to allow, and the kernel
with public key K signed this statement." No access log provides this.

### 8.3 Guard Pipeline (Not Just Allow/Deny Rules)

Envoy/Istio authorization is rule-based: match request attributes against
a policy, return allow or deny. Chio's guard pipeline is a programmable
evaluation chain:

- **Built-in guards**: rate limiting, budget enforcement, scope validation
- **Wasm guards**: custom logic compiled to WebAssembly, sandboxed
- **Rego guards**: Open Policy Agent policies
- **External guards**: call out to arbitrary policy services

Guards produce **evidence**, not just verdicts. A rate-limit guard returns
"allowed, 37 of 50 invocations remaining." A budget guard returns "allowed,
$1.80 of $5.00 budget consumed." This evidence is included in the signed
receipt.

### 8.4 Budget and Cost Governance

No service mesh has any concept of cost. Chio tracks per-capability budgets:

- Each capability token has an optional spending limit
- Guards can check estimated cost before allowing invocation
- Receipts record actual cost after invocation
- Budget exhaustion triggers automatic capability revocation

This is critical for agent systems where a single compromised agent could
rack up unbounded API costs.

## 9. Deployment Topology

### 9.1 Sidecar Model (Per-Pod)

Chio runs as a sidecar container alongside Envoy in the same pod. This is
the lowest-latency option -- ext_authz calls go over localhost.

```
Pod
+----------------------------------------------------------+
|                                                          |
|  +-----------------+    +------------------+             |
|  | Application     |    | Envoy Proxy      |             |
|  | Container       |    | (Istio/Consul)   |             |
|  |                 |    |                  |             |
|  | Receives        |<---| ext_authz ------>|---------+   |
|  | requests with   |    | filter           |         |   |
|  | receipt headers |    +------------------+         |   |
|  +-----------------+                                 |   |
|                                                      |   |
|  +---------------------------------------------------+   |
|  | Chio Sidecar Container                             |   |
|  |                                                   |   |
|  | gRPC :9091  (ext_authz)                           |   |
|  | HTTP  :9090  (sidecar API, health)                |   |
|  |                                                   |   |
|  | Capability | Guard Pipeline | Receipt Signing     |   |
|  +---------------------------------------------------+   |
|                                                          |
+----------------------------------------------------------+
```

Advantages:
- Sub-millisecond ext_authz latency (localhost loopback)
- Per-pod policy isolation
- No shared-state contention
- Pod failure boundary matches Chio failure boundary

Disadvantages:
- One Chio container per pod (resource overhead)
- Policy distribution to every sidecar

### 9.2 Cluster-Wide Service Model

Chio runs as a centralized Deployment (or DaemonSet) that all Envoy proxies
call via the cluster network.

```
+------------------+     +------------------+
| Pod A            |     | Pod B            |
| +------+ +-----+|     | +------+ +-----+|
| | App  | | Envoy||     | | App  | | Envoy||
| +------+ +--+--+|     | +------+ +--+--+|
+--------------|---+     +--------------|---+
               |                        |
               +----------+-------------+
                          |
               +----------v-----------+
               | Chio ext_authz        |
               | Service (Deployment) |
               |                      |
               | gRPC :9091           |
               | Replicas: 3          |
               | HPA: CPU/latency     |
               +----------------------+
```

Advantages:
- Single policy source of truth
- Lower total resource usage
- Centralized receipt aggregation
- Simpler upgrades (one Deployment, not N sidecars)

Disadvantages:
- Network hop for each evaluation (typically 1-5ms in-cluster)
- Shared service is a potential bottleneck
- Requires high availability (multiple replicas, HPA)

### 9.3 Hybrid: DaemonSet

A middle ground: Chio runs as a DaemonSet with one instance per node. Envoy
sidecars call the node-local Chio instance. Latency stays low (node-local
network) without the per-pod overhead.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: chio-ext-authz
  namespace: chio-system
spec:
  selector:
    matchLabels:
      app: chio-ext-authz
  template:
    metadata:
      labels:
        app: chio-ext-authz
    spec:
      containers:
        - name: chio-ext-authz
          image: ghcr.io/chio-protocol/chio-ext-authz:latest
          ports:
            - containerPort: 9091
              name: grpc
            - containerPort: 9090
              name: http
          env:
            - name: CHIO_POLICY_PATH
              value: /etc/chio/policy.yaml
            - name: CHIO_KEYPAIR_PATH
              value: /etc/chio/keypair.pem
            - name: CHIO_RECEIPT_STORE
              value: sqlite:///var/chio/receipts.db
          volumeMounts:
            - name: chio-policy
              mountPath: /etc/chio
              readOnly: true
            - name: chio-data
              mountPath: /var/chio
          resources:
            requests:
              cpu: 100m
              memory: 64Mi
            limits:
              cpu: 500m
              memory: 256Mi
          livenessProbe:
            httpGet:
              path: /health
              port: 9090
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            grpc:
              port: 9091
            initialDelaySeconds: 3
            periodSeconds: 5
      volumes:
        - name: chio-policy
          configMap:
            name: chio-policy
        - name: chio-data
          emptyDir: {}
```

### 9.4 Choosing a Topology

| Factor | Sidecar | Cluster Service | DaemonSet |
|--------|---------|-----------------|-----------|
| Latency | < 1ms | 1-5ms | < 1ms |
| Resource overhead | High (per-pod) | Low (shared) | Medium (per-node) |
| Policy isolation | Per-pod | Cluster-wide | Per-node |
| Failure blast radius | Single pod | All pods | All pods on node |
| Operational complexity | High (many instances) | Low (one Deployment) | Medium |
| Best for | High-security, multi-tenant | Dev/staging, low-traffic | Production, single-tenant |

## 10. Crate Structure: `chio-envoy-ext-authz`

### 10.1 Crate Layout

```
crates/chio-envoy-ext-authz/
  Cargo.toml
  build.rs                    # protobuf codegen for envoy ext_authz v3
  proto/
    envoy/
      service/auth/v3/
        external_auth.proto
      type/v3/
        http_status.proto
    google/rpc/
      status.proto
  src/
    lib.rs                    # Public API, re-exports
    server.rs                 # tonic gRPC server: Authorization impl
    mapping.rs                # CheckRequest -> ChioHttpRequest conversion
    response.rs               # Verdict -> CheckResponse conversion
    metadata.rs               # Dynamic metadata population
    config.rs                 # Server configuration
    health.rs                 # gRPC health check service
```

### 10.2 Dependencies

```toml
[package]
name = "chio-envoy-ext-authz"
version = "0.1.0"
edition = "2021"

[dependencies]
chio-http-core = { path = "../chio-http-core" }
chio-core-types = { path = "../chio-core-types" }
tonic = { version = "0.12", features = ["tls"] }
prost = "0.13"
prost-types = "0.13"
tokio = { version = "1", features = ["full"] }
tracing = "0.1"

[build-dependencies]
tonic-build = "0.12"
```

### 10.3 Key Mapping Functions

```rust
// mapping.rs

use chio_http_core::{ChioHttpRequest, CallerIdentity, AuthMethod, HttpMethod};
use crate::proto::envoy::service::auth::v3::CheckRequest;

/// Convert an ext_authz CheckRequest to Chio's protocol-agnostic request model.
pub fn check_request_to_chio_request(
    check: &CheckRequest,
) -> Result<ChioHttpRequest, MappingError> {
    let attrs = check.attributes.as_ref()
        .ok_or(MappingError::MissingAttributes)?;
    let http = attrs.request.as_ref()
        .and_then(|r| r.http.as_ref())
        .ok_or(MappingError::MissingHttpRequest)?;

    let method = HttpMethod::from_str(&http.method)?;
    let path = http.path.split('?').next().unwrap_or(&http.path);
    let query = parse_query_string(http.path.split('?').nth(1).unwrap_or(""));

    // Extract caller identity from headers and source context.
    let caller = extract_caller_identity(
        &http.headers,
        attrs.source.as_ref(),
    );

    let body_hash = if http.body.is_empty() {
        None
    } else {
        Some(sha256_hex(&http.body))
    };

    Ok(ChioHttpRequest {
        request_id: extract_request_id(&http.headers),
        method,
        route_pattern: path.to_string(), // Route resolver normalizes
        path: path.to_string(),
        query,
        headers: extract_policy_headers(&http.headers),
        caller,
        body_hash,
        body_length: http.body.len() as u64,
        session_id: http.headers.get("x-chio-session-id").cloned(),
        capability_id: http.headers.get("x-chio-capability-token").cloned(),
        timestamp: attrs.context_extensions
            .get("request.time")
            .and_then(|t| t.parse().ok())
            .unwrap_or_else(|| chrono::Utc::now().timestamp() as u64),
    })
}
```

### 10.4 Binary

The crate also produces a standalone binary for deployments that do not
embed Chio in another process:

```rust
// src/main.rs (in a separate chio-ext-authz-server binary crate or via
// cargo features)

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::init();

    let config = ChioExtAuthzConfig::from_env()?;
    let authority = HttpAuthority::new(config.keypair, config.policy_hash);
    let service = ChioExtAuthzService::new(authority);

    let addr = config.listen_addr.parse()?;
    tracing::info!("Chio ext_authz gRPC server listening on {addr}");

    tonic::transport::Server::builder()
        .add_service(AuthorizationServer::new(service))
        .add_service(HealthServer::new(ChioHealthService::new()))
        .serve(addr)
        .await?;

    Ok(())
}
```

## 11. Performance Considerations

ext_authz sits in the critical path of every request. Latency matters.

### 11.1 Latency Budget

| Component | Target | Notes |
|-----------|--------|-------|
| Envoy filter overhead | < 0.1ms | Negligible (in-process) |
| Network to Chio | < 0.5ms | Localhost (sidecar) or node-local (DaemonSet) |
| Chio evaluation | < 2ms | Policy match + guard pipeline |
| Receipt signing | < 0.5ms | Ed25519 signature (fast) |
| Total ext_authz | < 3ms | P99 target |

### 11.2 Optimization Strategies

- **Connection pooling**: Envoy maintains persistent gRPC connections to Chio.
  No per-request connection setup.
- **Policy caching**: Chio caches compiled policy in memory. Policy reloads
  are hot-swapped without restarting.
- **Guard result caching**: Idempotent guards (scope checks, static policy)
  can cache results keyed on capability token + route.
- **Async receipt persistence**: Receipt signing is synchronous (must
  complete before responding), but writing the receipt to durable storage
  is async. The response does not block on disk I/O.
- **Body avoidance**: Configure `with_request_body` conservatively. Most
  Chio evaluations do not need the body -- they evaluate based on method,
  path, headers, and capability token. Only enable body forwarding for
  guards that inspect request content.

### 11.3 Failure Modes

| Failure | Envoy Behavior | Chio Recommendation |
|---------|---------------|-------------------|
| Chio unreachable | `failure_mode_allow` setting | `false` (fail-closed) for production |
| Chio timeout (> 250ms) | Envoy returns 403 or passes through | Tune timeout per environment |
| Chio returns error | Treated as denied (gRPC) or 5xx (HTTP) | Chio returns `Unavailable` status |
| Envoy circuit breaker trips | Stops calling Chio, applies failure mode | Configure circuit breaker thresholds |

## 12. Migration Path

### 12.1 From No Auth to Chio

1. Deploy Chio as a cluster-wide service in `chio-system` namespace.
2. Register Chio as an ext_authz provider in the mesh config.
3. Apply `AuthorizationPolicy` with `CUSTOM` action to a single test workload.
4. Verify receipts are being generated. Verify allow/deny behavior.
5. Gradually expand to additional workloads via label selectors.

### 12.2 From OPA/Envoy to Chio

Organizations already using OPA with ext_authz can migrate incrementally:

1. Run Chio alongside OPA as a second ext_authz provider.
2. Port OPA policies to Chio guards (Rego guards run OPA policies natively).
3. Chio adds receipts and capability scoping that OPA alone does not provide.
4. Once parity is confirmed, remove the OPA ext_authz provider.

### 12.3 Shadow Mode

For risk-averse migrations, Chio supports shadow evaluation:

1. Configure Chio in shadow mode: evaluate every request but always return allow.
2. Chio logs verdicts and signs receipts without blocking traffic.
3. Analyze shadow receipts to validate policy before enforcing.
4. Switch from shadow to enforcing with a configuration toggle.

## 13. Open Questions

- **Body forwarding policy**: should Chio define a standard for which
  content types trigger body forwarding in ext_authz? Large request bodies
  add latency and memory pressure.
- **Rate limiting coordination**: if Chio's guard pipeline enforces rate
  limits, and Envoy also has rate limiting filters, how should they
  coordinate? Chio's rate limits are per-capability; Envoy's are per-route
  or per-client. They are complementary but could confuse operators.
- **Multi-cluster receipt aggregation**: in a multi-cluster mesh, receipts
  from different Chio instances need a federation protocol to maintain a
  unified audit trail. This is the `chio-federation` crate's domain but
  must be designed alongside the ext_authz deployment model.
