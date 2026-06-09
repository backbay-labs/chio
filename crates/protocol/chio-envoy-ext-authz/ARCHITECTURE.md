# chio-envoy-ext-authz architecture note

## Boundaries

- `lib.rs` owns the public surface, generated proto re-exports, and stable adapter types re-exported for downstream wiring.
- `translate.rs` owns the trust-boundary projection from Envoy `CheckRequest` into the local `ToolCallRequest`. It strips raw secrets, hashes bearer and body bytes, derives `http.<method>.<path>` tool identities, and returns `TranslateError` for malformed Envoy input.
- `service.rs` owns the tonic `Authorization` implementation and should only coordinate translation, kernel evaluation, logging, and response conversion.
- `error.rs` owns public error types. `TranslateError` is part of the crate API, so new variants are avoided unless the security value justifies a public compatibility break.

## Pain points

- `service.rs` currently mixes RPC orchestration with Envoy `CheckResponse` construction. That makes the RPC boundary harder to audit because allow, deny, and fail-closed response semantics are embedded beside tonic plumbing.
- Fail-closed responses include the internal translation or kernel error text in the client-visible denial body and header. Logs should carry the specific fault; ext_authz clients should only receive a stable fail-closed reason.
- `translate.rs` is the largest file and contains multiple private concerns. It is still cohesive enough to leave intact for this slice because changing translation shape would carry broader API and compatibility risk.

## Constraints

- Fail closed on malformed input and kernel errors.
- Do not forward raw bearer tokens or capability tokens.
- Preserve the public `EnvoyKernel`, `ToolCallRequest`, `Verdict`, and `TranslateError` API in this slice.
- Preserve existing deny verdict behavior: policy denial reason and guard name remain visible to the downstream client.
- Do not edit generated protobuf output directly.

## Dependents

- `examples/istio-ext-authz` depends on the adapter's header names and fail-closed behavior, but not on private response helpers.
- Research and operations docs describe the adapter as the Envoy HTTP ext_authz boundary. This slice does not alter the documented crate role.
- No Rust crate currently imports private `service.rs` response helpers.

## Planned improvement

Split Envoy response construction into its own internal module and make fail-closed response bodies and headers use a stable generic reason. This is architectural because it narrows `service.rs` to RPC orchestration, creates a distinct response boundary for audit, and prevents internal kernel or translation faults from crossing the ext_authz trust boundary while preserving public API shape.

## Dynamic Metadata Boundary Slice

### Boundary

`response.rs` owns Envoy `CheckResponse` construction, while a dedicated internal metadata module should own the `google.protobuf.Struct` payload attached to those responses. `service.rs` must remain unaware of metadata field names.

### Pain point

The protocol integration doc describes `CheckResponse.dynamic_metadata` as the access-log surface for Chio verdict data, but the current crate returns `None` for allow, deny, and fail-closed responses. That makes the adapter harder to operate in Envoy because downstream logging and filters cannot observe even the stable verdict class without parsing headers or bodies.

### Security and API constraints

- Do not expose raw bearer tokens, capability tokens, request bodies, translation errors, or kernel error strings through metadata.
- Preserve public API compatibility: no changes to `EnvoyKernel`, `ToolCallRequest`, `Verdict`, or `TranslateError`.
- Preserve fail-closed behavior and stable generic fail-closed client-visible reason.
- Keep denial verdict behavior visible: policy denial reason, guard name, and HTTP status remain available to Envoy.

### Affected dependents

No Rust dependent imports response helpers or metadata builders because both remain crate-private. Envoy deployments gain structured metadata fields for logging and filter chaining without any required configuration or public API migration.

### Material improvement planned

Add an internal dynamic metadata module and attach stable Chio metadata to every response: verdict class for allow, denial reason/guard/status for policy denies, and fail-closed markers for translation or kernel faults. This is architectural because it separates the observability contract from response plumbing and makes the documented Envoy integration behavior true without widening the public surface.

## Deny Status Metadata Slice

### Boundary

`response.rs` owns the conversion from local Chio verdicts to Envoy
`CheckResponse` messages, including the HTTP status Envoy will actually return
and the dynamic metadata Envoy may expose to access logs or follow-on filters.
`metadata.rs` owns field construction, but it must receive already-admitted
wire facts rather than raw, unrepresentable verdict data.

### Pain Point Addressed

`Verdict::Deny` carries a caller-supplied `http_status`. Envoy's generated
`StatusCode` enum cannot represent every `u16`, so `response.rs` maps unknown
or non-denial values to `403 Forbidden`. The denied response already uses that
mapped status, but dynamic metadata records the original value. A downstream
filter or access-log pipeline could therefore observe `chio.http_status=200`
or `999` while Envoy actually denies with 403.

### Security And API Constraints

- Preserve the public `Verdict` shape and `EnvoyKernel` API.
- Preserve fail-closed translation and kernel-error behavior.
- Preserve explicit supported denial statuses such as 401, 403, 429, and 503.
- Do not expose an unsupported or non-denial status as applied policy state in
  dynamic metadata.

### Affected Dependents

No Rust dependent imports the private response or metadata helpers. Envoy
deployments that read dynamic metadata gain consistency: `chio.http_status`
tracks the actual denied HTTP status Envoy receives, not the raw status the
kernel attempted to request.

### Material Improvement Planned

Make deny response construction compute the admitted Envoy status once and use
that same value for the `DeniedHttpResponse` and dynamic metadata. Add a
focused regression proving unsupported deny statuses report 403 in both places.

## Verification Focus

Tests should cover translation rejection for malformed Envoy requests, stable
fail-closed response bodies for translation and kernel faults, deny-status
metadata matching the admitted Envoy status, absence of raw bearer tokens and
request bodies in metadata, and preservation of supported policy deny statuses
such as 401, 403, 429, and 503.
