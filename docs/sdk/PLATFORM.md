# Platform-Level SDKs

This document covers Chio's platform-level SDK integrations: middleware and
controllers that embed Chio evaluation into infrastructure rather than
application code.

All platform SDKs communicate with the Chio Rust kernel running as a localhost
sidecar. They send evaluation requests to `POST /chio/evaluate`, enforce the
returned verdict, and attach the signed receipt to the response. The normative
sidecar protocol is defined in `spec/HTTP-SUBSTRATE.md`.

---

## 1. chio-tower (Rust)

**Location:** `crates/chio-tower`

A `tower::Layer` that wraps any Tower-compatible HTTP service with Chio
capability validation and receipt signing. Works with Axum (HTTP) and
Tower-compatible HTTP/2 services. The current body-binding qualification is
strongest on replayable body types such as Axum's `Body`; the gRPC/Tonic lane
is still exercised through the generic Tower/HTTP2 contract rather than a
separate `tonic::body::Body` replay proof.

### API Surface

```rust
use chio_tower::ChioLayer;
use chio_core_types::crypto::Keypair;
use tower::Layer;

// Generate or load a kernel keypair.
let keypair = Keypair::generate();

// Create the Chio layer with a keypair and policy hash.
let layer = ChioLayer::new(keypair, "policy-hash-abc".to_string());

// Wrap any tower::Service.
let service = layer.layer(inner_service);
```

### Evaluator Configuration

The `ChioEvaluator` supports builder-style configuration:

```rust
use chio_tower::{ChioEvaluator, ChioLayer};
use chio_core_types::crypto::Keypair;

let keypair = Keypair::generate();
let evaluator = ChioEvaluator::new(keypair, "policy-hash".to_string())
    .with_identity_extractor(custom_extractor)
    .with_route_resolver(custom_resolver)
    .with_fail_open(false); // fail-closed by default

let layer = ChioLayer::from_evaluator(evaluator);
```

### What It Does

- Extracts caller identity from request headers (Bearer tokens, API keys,
  mTLS certificates)
- Evaluates each request against the Chio kernel policy
- Safe methods (GET, HEAD, OPTIONS) are allowed with session-scoped receipts
- Side-effect methods (POST, PUT, PATCH, DELETE) require a capability token
  in the `X-Chio-Capability` header or `chio_capability` query parameter
- Buffers and hashes raw request bytes for replayable body types before
  evaluation, preserving the original bytes for downstream handlers
- Signs an `HttpReceipt` for every request (allow or deny)
- Attaches the receipt ID as the `X-Chio-Receipt-Id` response header

### Axum Example

```rust
use axum::{Router, routing::get};
use chio_tower::ChioLayer;
use chio_core_types::crypto::Keypair;

let keypair = Keypair::generate();
let chio_layer = ChioLayer::new(keypair, "my-policy".to_string());

let app = Router::new()
    .route("/pets", get(list_pets).post(create_pet))
    .layer(chio_layer);
```

### Exports

| Export | Purpose |
|--------|---------|
| `ChioLayer` | Tower `Layer` implementation |
| `ChioService` | Tower `Service` wrapper |
| `ChioEvaluator` | Core evaluation logic (capability check, receipt signing) |
| `EvaluationResult` | Verdict + signed receipt + guard evidence |
| `ChioTowerError` | Error type for evaluation failures |
| `extract_identity` | Default identity extraction from HTTP headers |
| `IdentityExtractor` | Function type for custom identity extraction |

---

## 2. Kubernetes Controller

**Location:** `sdks/k8s/`

A Kubernetes admission controller that enforces Chio capability policies at
pod deployment time and optionally injects the Chio sidecar container.

### Components

| Component | Path | Purpose |
|-----------|------|---------|
| Validating webhook | `webhooks/validating-webhook.yaml` | Rejects pods without trusted Chio capability tokens |
| Mutating webhook | `webhooks/mutating-webhook.yaml` | Injects the `chio-sidecar` container into annotated pods |
| ChioPolicy CRD | `crds/chiopolicy-crd.yaml` | Namespace-scoped policy defining required scopes and sidecar config |
| Controller | `controller/main.go` | Go binary serving `/validate` and `/mutate` endpoints |

### Validating Webhook

The validating webhook rejects pods that lack the required
`chio.world/capability-token` annotation, unless the pod carries an
explicit `chio.world/exempt: "true"` exemption. Presented tokens are
parsed as Chio capability tokens, verified cryptographically, checked for time
validity, and matched against any required scopes before the pod is allowed.
The controller only trusts issuers configured through
`CHIO_TRUSTED_ISSUER_KEY` or `CHIO_TRUSTED_ISSUER_KEYS` (comma-separated for key
rotation). If neither is configured, non-exempt pods fail closed.

The webhook is scoped to namespaces with the `chio.world/enforce: "true"`
label. It runs on pod CREATE and UPDATE operations.

### Mutating Webhook

The mutating webhook injects an `chio-sidecar` container when a pod has the
`chio.world/inject: "true"` annotation. The sidecar runs `chio api protect`
and proxies HTTP traffic through the Chio kernel on port 9090.

### Pod Annotations

| Annotation | Required | Description |
|------------|----------|-------------|
| `chio.world/capability-token` | Yes (unless exempt) | Chio capability token for the workload, signed by a controller-trusted Chio issuer |
| `chio.world/required-scopes` | No | Comma-separated required Chio scopes using the grammar below |
| `chio.world/exempt` | No | Set to `"true"` to skip capability validation |
| `chio.world/inject` | No | Set to `"true"` to trigger sidecar injection |
| `chio.world/sidecar-image` | No | Override the default sidecar image (default: `ghcr.io/backbay-labs/chio-sidecar:latest`) |
| `chio.world/upstream` | No | Upstream URL the sidecar proxies to (default: `http://127.0.0.1:8080`) |
| `chio.world/spec-path` | No | Path to the OpenAPI spec file inside the pod |
| `chio.world/receipt-store` | No | Receipt storage backend URI |

### Required Scope Grammar

Prefer explicit forms:

- `tool:<server_id>:<tool_name>:<operation>`
- `resource:<uri_pattern>:<operation>`
- `prompt:<prompt_name>:<operation>`

Supported operations are `invoke`, `read`, `read_result`, `subscribe`, `get`,
and `delegate`, plus operator-friendly aliases such as `call`, `exec`,
`execute`, and `watch`. The controller also accepts a legacy shorthand
`<tool_name>:<verb>` for tool-oriented policy, mapping `read`/`write` style
verbs onto tool invocation.

### Trust Anchor Configuration

Set one of these environment variables on the admission controller deployment:

- `CHIO_TRUSTED_ISSUER_KEY`: a single hex-encoded Ed25519 public key for the
  Chio authority that signs workload capability tokens
- `CHIO_TRUSTED_ISSUER_KEYS`: a comma-separated list of trusted issuer keys for
  rotation or multi-authority deployments

If both are present, the controller trusts the union of those keys.

### ChioPolicy CRD

The `ChioPolicy` custom resource defines namespace-level capability requirements:

```yaml
apiVersion: chio.world/v1alpha1
kind: ChioPolicy
metadata:
  name: production-policy
  namespace: my-app
spec:
  requiredScopes:
    - "tool:*:db:invoke"
    - "tool:*:deploy:invoke"
  selector:
    matchLabels:
      app: my-service
  enforcement: enforce   # enforce | audit | disabled
  sidecarConfig:
    image: ghcr.io/backbay-labs/chio-sidecar:v1.0
    upstream: http://127.0.0.1:8080
    autoInject: true
```

### Deployment

```bash
# Install CRDs
kubectl apply -f sdks/k8s/crds/

# Install webhooks
kubectl apply -f sdks/k8s/webhooks/

# Label namespaces for enforcement
kubectl label namespace my-app chio.world/enforce=true
kubectl label namespace my-app chio.world/inject=true
```

---

## 3. JVM (chio-spring-boot)

**Location:** `sdks/jvm/chio-spring-boot/`

A Spring Boot starter that auto-configures the Chio servlet filter. Add
the dependency and Chio protection is active with zero code changes.

### Configuration

In `application.properties` or `application.yml`:

```properties
chio.sidecar-url=http://127.0.0.1:9090
chio.timeout-seconds=5
chio.on-sidecar-error=deny
chio.enabled=true
chio.url-patterns=/*
chio.filter-order=1
```

Or via `application.yml`:

```yaml
chio:
  sidecar-url: http://127.0.0.1:9090
  timeout-seconds: 5
  on-sidecar-error: deny
  enabled: true
  url-patterns:
    - "/*"
```

### @ConfigurationProperties

The `ChioProperties` class maps the `chio.*` prefix:

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `chio.sidecar-url` | String | `CHIO_SIDECAR_URL` env or `http://127.0.0.1:9090` | Sidecar kernel URL |
| `chio.timeout-seconds` | Long | 5 | HTTP timeout for sidecar calls |
| `chio.on-sidecar-error` | String | `deny` | `deny` (fail-closed) or `allow` (fail-open passthrough without Chio receipt) |
| `chio.enabled` | Boolean | true | Enable/disable Chio protection |
| `chio.url-patterns` | List | `["/*"]` | URL patterns to protect |
| `chio.filter-order` | Int | 1 | Servlet filter ordering |

### ChioFilter

The `ChioFilter` is a standard Jakarta Servlet `Filter` that:

1. Extracts caller identity from request headers
2. Resolves the route pattern
3. Hashes the raw request body bytes (SHA-256) while preserving the body for downstream handlers
4. Builds an `ChioHttpRequest` and sends it to `POST /chio/evaluate`
5. Attaches `X-Chio-Receipt-Id` to the response
6. Returns a structured JSON error on deny (403) or sidecar failure (502)

### Auto-Configuration

`ChioAutoConfiguration` registers the filter automatically when:
- `ChioFilter` is on the classpath (`@ConditionalOnClass`)
- `chio.enabled` is `true` or absent (`@ConditionalOnProperty`, `matchIfMissing = true`)

No `@Bean` declarations are needed in application code.

### Minimal Spring Boot Example

```kotlin
// build.gradle.kts
dependencies {
    implementation("world.chio:chio-spring-boot:1.0")
}

// application.properties
// chio.sidecar-url=http://127.0.0.1:9090

// That's it. ChioFilter is auto-registered.
```

---

## 4. .NET (ChioMiddleware)

**Location:** `sdks/dotnet/ChioMiddleware/`

ASP.NET Core middleware for Chio capability validation and receipt signing.
Two extension methods cover registration and pipeline insertion.

### Setup

```csharp
var builder = WebApplication.CreateBuilder(args);

// Register Chio services with optional configuration.
builder.Services.AddChioProtection(options =>
{
    options.SidecarUrl = "http://127.0.0.1:9090";
    options.TimeoutSeconds = 5;
    options.OnSidecarError = "deny"; // fail-closed
});

var app = builder.Build();

// Insert Chio middleware into the request pipeline.
app.UseChioProtection();

app.MapGet("/pets", () => Results.Ok(new[] { "dog", "cat" }));
app.Run();
```

### ChioMiddlewareOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `SidecarUrl` | string | `CHIO_SIDECAR_URL` env or `http://127.0.0.1:9090` | Sidecar kernel URL |
| `TimeoutSeconds` | int | 5 | HTTP timeout for sidecar calls |
| `OnSidecarError` | string | `deny` | `deny` (fail-closed) or `allow` (fail-open passthrough without Chio receipt) |
| `IdentityExtractor` | delegate | Header-based extraction | Custom identity extraction function |
| `RouteResolver` | delegate | Raw path passthrough | Custom route pattern resolver |

### Extension Methods

| Method | Purpose |
|--------|---------|
| `services.AddChioProtection()` | Register Chio services and options in the DI container |
| `app.UseChioProtection()` | Insert `ChioProtectMiddleware` into the ASP.NET Core pipeline |

### What the Middleware Does

1. Validates the HTTP method
2. Extracts caller identity (Bearer token, API key, or custom extractor)
3. Resolves the route pattern
4. Hashes the raw request body bytes (SHA-256) with buffering enabled
5. Sends an `ChioHttpRequest` to `POST /chio/evaluate` on the sidecar
6. Attaches `X-Chio-Receipt-Id` to the response
7. Returns structured JSON errors on deny (403) or sidecar failure (502)
8. Calls `next(context)` on allow

### Minimal Example

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddChioProtection();

var app = builder.Build();
app.UseChioProtection();
app.MapGet("/hello", () => "world");
app.Run();
```

---

## 5. C++ Drogon (chio-drogon)

**Location:** `sdks/cpp/chio-drogon/`

C++17 middleware for Drogon applications. The package exports
`ChioDrogon::chio_drogon` when CMake can find both `Drogon::Drogon` and the
Chio C++ SDK target.

### CMake Setup

```cmake
find_package(ChioDrogon CONFIG REQUIRED)

target_link_libraries(app PRIVATE ChioDrogon::chio_drogon)
```

For in-repo examples, [`examples/hello-drogon/`](../../examples/hello-drogon/)
adds `sdks/cpp/chio-drogon` as a subdirectory and skips clearly when
Drogon is not installed locally.

### Minimal Example

```cpp
#include <drogon/drogon.h>
#include "chio/drogon.hpp"

int main() {
  chio::drogon::Options options;
  options.sidecar_url = "http://127.0.0.1:9090";
  options.sidecar_failure_mode = chio::drogon::SidecarFailureMode::FailClosed;
  chio::drogon::configure(options);

  drogon::app().registerHandler(
      "/hello",
      [](const drogon::HttpRequestPtr& req,
         std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
        Json::Value body(Json::objectValue);
        body["message"] = "hello";
        body["receipt_id"] = chio::drogon::receipt_id(req);
        callback(drogon::HttpResponse::newHttpJsonResponse(body));
      },
      {drogon::Get, "chio::drogon::ChioMiddleware"});

  drogon::app().addListener("127.0.0.1", 8080);
  drogon::app().run();
}
```

### What the Middleware Does

1. Reads the raw Drogon request body and hashes it before handler execution
2. Copies only configured non-sensitive headers into the Chio evaluation request
3. Extracts a capability token from `X-Chio-Capability` or `chio_capability`
4. Sends an `ChioHttpRequest` to `POST /chio/evaluate` on the sidecar
5. Stores the receipt id on allowed requests for `chio::drogon::receipt_id(req)`
6. Returns structured JSON errors on deny or sidecar failure

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `sidecar_url` | `CHIO_SIDECAR_URL`, then `http://127.0.0.1:9090` | Chio sidecar URL |
| `timeout_ms` | `5000` | Sidecar evaluation timeout hint |
| `sidecar_failure_mode` | `FailClosed` | `FailClosed`, `FailOpenWithoutReceipt`, or `AllowWithoutReceipt` |
| `selected_headers` | accept, content-type, x-request-id, x-correlation-id | Header allowlist copied into Chio evaluation |
| `skip_paths` | empty | Exact request paths that bypass Chio evaluation |
| `route_pattern_resolver` | unset | Optional resolver for policy route patterns such as `/orders/{id}` |

---

## Common Patterns

All five platform SDKs share the same operational model:

1. **Sidecar communication.** Every SDK talks to the Chio Rust kernel at
   `POST /chio/evaluate` on localhost. The kernel handles capability validation,
   guard evaluation, and receipt signing.

2. **Fail-closed by default.** If the sidecar is unreachable or returns an
   error, the request is denied. Fail-open mode is available as an explicit
   opt-in for each SDK, but it forwards the request without Chio evidence and
   exposes explicit passthrough state instead of synthesizing a receipt.

3. **Receipt attachment.** Every evaluated request (allow or deny) produces a
   signed receipt. The receipt ID is attached as `X-Chio-Receipt-Id` on the
   HTTP response. Fail-open passthroughs do not attach a synthetic receipt.

4. **Degraded-state visibility.** Representative SDKs expose a receiptless
   passthrough marker on the request/context surface:
   `req.chioPassthrough` (TypeScript Express), `chio.GetChioPassthrough(r)` (Go),
   `request.state.chio_passthrough` or `request.chio_passthrough` (Python),
   Servlet request attribute `chioPassthrough` (JVM), and
   `HttpContext.Items["ChioPassthrough"]` (.NET). The Drogon package exposes
   allowed receipt ids through `chio::drogon::receipt_id(req)` and uses a
   receiptless fail-open mode when explicitly configured.

5. **Identity extraction.** Each SDK extracts caller identity from standard
   HTTP headers (Authorization, X-Api-Key, etc.) and supports custom
   extractors for application-specific identity models.

6. **Capability presentation.** Side-effect methods (POST, PUT, PATCH,
   DELETE) require a valid capability token presented in the
   `X-Chio-Capability` request header or the `chio_capability` query
   parameter. Safe methods (GET, HEAD, OPTIONS) are allowed with
   session-scoped audit receipts.

For the normative sidecar evaluation protocol, see `spec/HTTP-SUBSTRATE.md`.
