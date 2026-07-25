# Chio Configuration

**Version:** 1.0
**Date:** 2026-04-14
**Status:** Normative

This specification defines the `chio.yaml` configuration file format for Chio
runtimes. Implementations MUST accept configuration conforming to this schema
and MUST reject configuration that violates the rules described herein.

The design rationale and migration guide are in
`docs/protocols/UNIFIED-CONFIGURATION.md`.

---

## 1. File Format

The configuration file is YAML and MUST be named `chio.yaml` by convention.
The file is consumed by Chio runtimes and commands that explicitly opt into
`chio.yaml` configuration via their own flags or programmatic APIs. This
repository does not currently ship a universal `chio start` entrypoint, so
implementations MUST NOT document `chio start --config chio.yaml` as a required
or normative command path.

Implementations MUST apply `deny_unknown_fields` semantics to every section.
Any key not defined in this specification MUST cause a parse-time error.

---

## 2. Root Structure

The root object contains the following sections:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `kernel` | KernelConfig | Yes | -- | Kernel signing and runtime settings |
| `adapters` | AdapterConfig[] | Yes (min 1) | `[]` | Upstream API adapter definitions |
| `edges` | EdgeConfig[] | No | `[]` | Protocol edges that expose adapters |
| `receipts` | ReceiptsConfig | No | See defaults | Receipt store configuration |
| `logging` | LoggingConfig | No | See defaults | Log level and format |
| `telemetry` | TelemetrySection | No | See defaults | OpenTelemetry export settings |
| `guards` | GuardsConfig | No | See defaults | Guard pipeline configuration |
| `wasm_guards` | WasmGuardEntry[] | No | `[]` | WASM guard module definitions |

A valid configuration MUST include the `kernel` section and at least one
entry in `adapters`. All other sections are optional and use documented
defaults when omitted.

---

## 3. kernel

The `kernel` section is always required and configures the runtime's signing
identity and receipt storage.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `signing_key` | string | Yes | -- | Ed25519 signing key in hex, or the literal `"generate"` for dev mode |
| `receipt_store` | string | No | `"sqlite:///var/chio/receipts.db"` | URI for the receipt store backend |
| `log_level` | string | No | `"info"` | Log level override for the kernel subsystem |

The `signing_key` field MUST NOT be empty. The value `"generate"` instructs
the runtime to create an ephemeral keypair at startup; this mode is intended
for development only and MUST NOT be used in production deployments.

---

## 4. adapters[]

Each adapter entry connects the kernel to a single upstream API.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | string | Yes | -- | Unique identifier referenced by edges and receipts |
| `protocol` | string | Yes | -- | Protocol type: `"openapi"`, `"grpc"`, `"graphql"` |
| `upstream` | string | Yes | -- | URL of the upstream API being protected |
| `spec` | string | No | `null` | Path to the API specification file (e.g., OpenAPI YAML) |
| `auth` | AdapterAuthConfig | No | `null` | Authentication configuration for the upstream |

### 4.1 auth

The `auth` block configures how the adapter authenticates to its upstream.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `type` | string | Yes | -- | One of: `"bearer"`, `"api_key"`, `"cookie"`, `"mtls"`, `"none"` |
| `header` | string | Conditional | `null` | Header name; required when `type` is `"bearer"` or `"api_key"` |

Validation rules:

- The `type` field MUST be one of the five enumerated values. Unknown types
  MUST be rejected.
- When `type` is `"bearer"` or `"api_key"`, the `header` field MUST be
  present and non-empty.
- When `type` is `"cookie"`, `"mtls"`, or `"none"`, the `header` field MAY
  be omitted.

---

## 5. edges[]

Each edge exposes tools from an adapter through a different protocol surface.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | string | Yes | -- | Unique identifier for this edge |
| `protocol` | string | Yes | -- | Edge protocol: `"mcp"`, `"a2a"`, etc. |
| `expose_from` | string | Yes | -- | Adapter ID that this edge exposes |

The `expose_from` value MUST reference an `id` declared in the `adapters`
array. A broken reference MUST be rejected at validation time.

---

## 6. receipts

Receipt store configuration controls where signed receipts are persisted and
how long they are retained.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `store` | string | No | `"sqlite:///var/chio/receipts.db"` | Store URI |
| `checkpoint_interval` | u64 | No | `100` | Number of receipts between Merkle checkpoints |
| `retention_days` | u64 | No | `90` | Days to retain receipts before expiry |

The `checkpoint_interval` controls how frequently the runtime computes and
stores Merkle tree checkpoints over the receipt log. A value of `0` disables
automatic checkpointing.

---

## 7. logging

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `level` | string | No | `"info"` | One of: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"` |
| `format` | string | No | `"json"` | Output format: `"json"` or `"text"` |

The `level` field MUST be one of the five enumerated values. The `format`
field MUST be either `"json"` or `"text"`. Invalid values MUST be rejected
at validation time.

---

## 8. telemetry

OpenTelemetry span export configuration.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | bool | No | `false` | Whether OTel export is active |
| `endpoint` | string | No | `""` | Collector endpoint (e.g., `"http://localhost:4317"`) |
| `service_name` | string | No | `"chio-acp-proxy"` | Service name reported to the collector |
| `include_parameters` | bool | No | `false` | Include receipt parameters in span attributes |
| `batch_size` | usize | No | `0` | Span batch size; `0` exports each span immediately |

When `enabled` is `true`, the `endpoint` field SHOULD be set to a valid
OTel collector URL. The `include_parameters` flag is disabled by default to
avoid leaking sensitive data in span attributes.

---

## 9. guards

Guard pipeline configuration applies to the global guard evaluation chain.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `allow_advisory_promotion` | bool | No | `false` | Whether advisory signals can be promoted to deterministic guards |
| `required` | string[] | No | `[]` | Guard names that MUST pass for every request |

Guards listed in `required` are evaluated on every request in addition to
any guards declared on individual routes or tools. If any required guard
returns a deny verdict, the request MUST be denied.

The `allow_advisory_promotion` flag, when `true`, permits advisory-only
guard verdicts to be treated as deterministic (blocking) via configuration
overlay. When `false` (the default), advisory guards remain non-blocking
regardless of configuration.

---

## 10. wasm_guards[]

WASM guard modules are loaded at runtime and participate in the guard
evaluation pipeline alongside built-in guards.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | -- | Human-readable name used in receipts and logs |
| `path` | string | Yes | -- | Filesystem path to the `.wasm` module |
| `fuel_limit` | u64 | No | `10000000` | Maximum fuel units the guest may consume per invocation |
| `priority` | u32 | No | `1000` | Evaluation priority; lower values run first |
| `advisory` | bool | No | `false` | If `true`, failures are logged but not blocking |

When `advisory` is `false` (the default), a WASM guard failure MUST deny
the request (fail-closed). When `advisory` is `true`, the guard failure is
recorded in the receipt evidence but does not block the request.

Example:

```yaml
wasm_guards:
  - name: custom-pii-guard
    path: /etc/chio/guards/pii_guard.wasm
    fuel_limit: 5000000
    priority: 100
  - name: audit-logger
    path: /etc/chio/guards/audit.wasm
    advisory: true
```

---

## 11. Environment Variable Interpolation

The configuration loader MUST support environment variable interpolation on
the raw YAML text before typed deserialization.

### 11.1 Syntax

| Pattern | Behavior |
|---------|----------|
| `${VAR}` | Replace with the value of environment variable `VAR`. Error if unset. |
| `${VAR:-default}` | Replace with `VAR` if set, otherwise use `default`. |

Variable names MUST match `[A-Za-z_][A-Za-z0-9_]*`.

### 11.2 Resolution

Interpolation runs on the raw YAML string before parsing. This means every
string-typed field benefits automatically. Non-string fields (integers,
booleans) cannot contain variable references after interpolation.

If a referenced variable is not set and no default is provided, the loader
MUST return an error listing all unresolved variables. Multiple missing
variables MUST be reported in a single error to avoid whack-a-mole
debugging.

### 11.3 Examples

```yaml
kernel:
  signing_key: "${CHIO_SIGNING_KEY}"
  log_level: "${CHIO_LOG_LEVEL:-info}"

adapters:
  - id: petstore
    protocol: openapi
    upstream: "http://${API_HOST}:${API_PORT:-8080}/api"
    auth:
      type: bearer
      header: Authorization
```

---

## 12. Validation Rules

Validation runs after environment variable interpolation and YAML
deserialization. All errors MUST be collected and reported together so the
operator can fix all problems in one pass.

### 12.1 Structural Requirements

- The `kernel` section MUST be present.
- `kernel.signing_key` MUST NOT be empty.
- At least one adapter MUST be defined.

### 12.2 ID Uniqueness

- All adapter `id` values MUST be unique. Duplicate adapter IDs MUST be
  rejected.
- All edge `id` values MUST be unique. Duplicate edge IDs MUST be rejected.
- Adapter and edge IDs MUST NOT be empty strings.

### 12.3 Reference Integrity

- Every `expose_from` value in an edge MUST reference a declared adapter
  `id`. A broken reference MUST be rejected.

### 12.4 Auth Completeness

- `auth.type` MUST be one of: `"bearer"`, `"api_key"`, `"cookie"`,
  `"mtls"`, `"none"`.
- `auth.type` values `"bearer"` and `"api_key"` MUST include a non-null
  `header` field.

### 12.5 Logging Validation

- `logging.level` MUST be one of: `"trace"`, `"debug"`, `"info"`, `"warn"`,
  `"error"`.
- `logging.format` MUST be one of: `"json"`, `"text"`.

### 12.6 deny_unknown_fields

All configuration structs apply `deny_unknown_fields` semantics. Any key not
defined in this specification MUST cause a parse error. This catches typos
and unsupported fields at load time rather than silently ignoring them.

---

## 13. Minimal Configuration

The smallest valid `chio.yaml` requires only a kernel and one adapter:

```yaml
kernel:
  signing_key: "generate"

adapters:
  - id: "petstore"
    protocol: "openapi"
    upstream: "http://localhost:8000"
```

All optional sections use their documented defaults. The logging level
defaults to `"info"` with `"json"` format. The receipt store defaults to
`sqlite:///var/chio/receipts.db` with 100-receipt checkpoint intervals and
90-day retention. Telemetry export is disabled. No guards or WASM modules
are loaded.

---

## 14. Full Configuration Example

```yaml
kernel:
  signing_key: "${CHIO_SIGNING_KEY}"
  receipt_store: "sqlite:///var/chio/receipts.db"
  log_level: "debug"

adapters:
  - id: petstore
    protocol: openapi
    upstream: "http://localhost:8000"
    spec: "./petstore.yaml"
    auth:
      type: bearer
      header: Authorization

  - id: internal-api
    protocol: grpc
    upstream: "http://localhost:9000"
    auth:
      type: api_key
      header: X-API-Key

edges:
  - id: mcp-bridge
    protocol: mcp
    expose_from: petstore

  - id: a2a-bridge
    protocol: a2a
    expose_from: internal-api

receipts:
  store: "sqlite:///var/chio/receipts.db"
  checkpoint_interval: 50
  retention_days: 30

logging:
  level: debug
  format: text

telemetry:
  enabled: true
  endpoint: "http://localhost:4317"
  service_name: "my-chio-deployment"
  include_parameters: false
  batch_size: 100

guards:
  allow_advisory_promotion: true
  required:
    - internal-network
    - agent-velocity

wasm_guards:
  - name: custom-pii-guard
    path: /etc/chio/guards/pii_guard.wasm
    fuel_limit: 5000000
    priority: 100
  - name: audit-logger
    path: /etc/chio/guards/audit.wasm
    advisory: true
```

---

## 15. Error Reporting

The configuration loader MUST report errors with enough context for the
operator to locate and fix the problem:

- Interpolation errors MUST list all unresolved variable names.
- Parse errors (including `deny_unknown_fields` violations) MUST include the
  field path and line number when available.
- Validation errors MUST be collected exhaustively and reported as a list so
  that multiple problems can be fixed in one pass.

Error categories:

| Category | Cause |
|----------|-------|
| IO | Configuration file could not be read |
| Interpolation | Unset environment variable with no default |
| Parse | Invalid YAML syntax or unknown field |
| Validation | Structural rule violation (duplicate IDs, broken references, incomplete auth) |
