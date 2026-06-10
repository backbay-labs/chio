# chio-envoy-ext-authz architecture note

## Boundaries

- `lib.rs` owns the public surface, generated proto re-exports, and stable adapter types re-exported for downstream wiring.
- `translate.rs` owns the trust-boundary projection from Envoy `CheckRequest` into the local `ToolCallRequest`. It strips raw secrets, hashes bearer and body bytes, derives `http.<method>.<path>` tool identities, and returns `TranslateError` for malformed Envoy input.
- `service.rs` owns the tonic `Authorization` implementation. It coordinates translation, kernel evaluation, logging, and response conversion, and is unaware of metadata field names.
- `response.rs` owns Envoy `CheckResponse` construction, including the HTTP status Envoy returns and the dynamic metadata attached to responses.
- `metadata.rs` owns dynamic-metadata field construction from already-admitted wire facts.
- `error.rs` owns public error types. `TranslateError` is part of the crate API, so new variants are avoided unless the security value justifies a public compatibility break.

## Fail-Closed Response Boundary

Fail-closed responses carry a stable generic client-visible reason. The specific
translation or kernel fault is logged, not returned in the denial body or header,
so internal faults do not cross the ext_authz trust boundary.

## Dynamic Metadata

`CheckResponse.dynamic_metadata` is the access-log surface for Chio verdict data.
Every response attaches stable metadata: verdict class for allow,
reason/guard/status for policy denies, and fail-closed markers for translation or
kernel faults. Raw bearer tokens, capability tokens, request bodies, translation
errors, and kernel error strings are never exposed through metadata.

`Verdict::Deny` carries a caller-supplied `http_status`, but Envoy's generated
`StatusCode` enum cannot represent every `u16`. Deny response construction
computes the admitted Envoy status once and uses that same value for the
`DeniedHttpResponse` and the `chio.http_status` metadata field, so dynamic
metadata never reports an unsupported or non-denial status as applied policy
state (an unsupported deny status reports 403 in both places).

## Constraints

- Fail closed on malformed input and kernel errors.
- Do not forward raw bearer tokens or capability tokens.
- Preserve the public `EnvoyKernel`, `ToolCallRequest`, `Verdict`, and `TranslateError` API.
- Preserve deny verdict behavior: policy denial reason, guard name, and HTTP status (401, 403, 429, 503, and other supported denial statuses) remain visible to the downstream client.
- Do not edit generated protobuf output directly.

## Dependents

- `examples/istio-ext-authz` depends on the adapter's header names and fail-closed behavior, but not on private response or metadata helpers.
- Research and operations docs describe the adapter as the Envoy HTTP ext_authz boundary.
- No Rust crate imports the private `service.rs`, `response.rs`, or `metadata.rs` helpers.

## Verification Focus

Tests cover translation rejection for malformed Envoy requests, stable
fail-closed response bodies for translation and kernel faults, deny-status
metadata matching the admitted Envoy status, absence of raw bearer tokens and
request bodies in metadata, and preservation of supported policy deny statuses
such as 401, 403, 429, and 503.
