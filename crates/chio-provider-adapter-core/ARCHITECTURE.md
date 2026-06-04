# chio-provider-adapter-core Architecture

## Boundaries

- `lib.rs` is the public adapter-core facade. It exposes provider identity, loaded-weights helpers, streaming gate helpers, deny-reason text, and SSE parsing types.
- `http.rs` owns shared provider HTTP transport, mock transport, auth configuration, status classification, and NDJSON parsing.
- Provider adapters depend on this crate for fail-closed stream parsing, common HTTP error taxonomy, and test transport seams.

## Pain Points

- The public facade now keeps SSE parsing behind an internal `sse` module while preserving public re-exports and CRLF byte fidelity for `SseFrame::raw`.
- `HttpTransportConfig::base_url` is public and caller supplied. Today `HttpTransport::new` accepts blank strings, surrounding whitespace, unsupported schemes, URL userinfo, query strings, and fragments, deferring most failures until a request is sent.
- Provider adapters inject auth through `AuthScheme` and provider-specific headers. Allowing credentials or query material in `base_url` creates a second ambient authority path and makes request-target construction harder to audit.

## Constraints

- Preserve public API compatibility for `SseFrame`, `SseParseOptions`, `UnknownSseFieldPolicy`, and `parse_sse_frames`.
- Preserve fail-closed parsing for invalid UTF-8, malformed JSON data, unknown-field rejection, event/type mismatch, and missing event names under cross-check mode.
- Preserve done-sentinel semantics: terminator frames expose `done = true`, `data = None`, and retain the original bytes for forwarding.
- Preserve public API compatibility for `HttpTransportConfig`, `HttpTransportError`, `ProviderHttpTransport`, `MockHttpTransport`, and status/transport error mapping.
- Keep provider secrets flowing through `AuthScheme`, never through URL userinfo or opaque base URL query strings.
- Do not change provider adapters unless the public compatibility tests prove a dependent regression.

## Affected Dependents

- `chio-openai`, `chio-groq-tools-adapter`, `chio-mistral-tools-adapter`, `chio-cohere-tools-adapter`, and `chio-gemini-tools-adapter` call the shared SSE parser.
- Provider replay and conformance tests rely on the shared `ProviderError` taxonomy and byte-stable stream gating behavior.

## Planned Improvement

Validate the configured HTTP base URL when constructing `HttpTransport`: reject empty or padded values, non-HTTP(S) schemes, embedded userinfo, query strings, and fragments before any request can be built. This is architectural because it tightens the shared outbound trust boundary for every provider adapter while preserving the existing config and transport trait surface.

## Query Auth Name Validation Slice

### Current Boundary

- `http.rs` owns `AuthScheme`, `HttpTransportConfig`, and the shared
  `HttpTransport` construction boundary for provider-native adapters.
- `validate_auth_scheme` checks caller-supplied auth material before the
  `reqwest::Client` transport is returned.
- Query-parameter auth is currently applied later in `HttpTransport::send`
  through `request.query(&[(name.as_str(), value.as_str())])`.

### Pain Point

`AuthScheme::QueryParam` validates the API key value but does not validate the
parameter name. A direct config with an empty, padded, or control-byte-bearing
name can build a transport and only fail or misroute when a request is sent,
which weakens the shared provider-auth trust boundary.

### Security And API Constraints

- Preserve the public `AuthScheme`, `HttpTransportConfig`,
  `HttpTransportError`, and `ProviderHttpTransport` API surface.
- Keep valid Gemini query auth behavior unchanged.
- Reject malformed query-auth names at transport construction before any
  provider request can be built.
- Do not include query-auth secret values in diagnostics.
- Do not change provider-specific adapters unless a dependent gate proves a
  real compatibility break.

### Affected Dependents

- `chio-gemini-tools-adapter` is the direct query-auth dependent and uses the
  stable `key` parameter name, so no transitive source change is planned.
- Other provider adapters use bearer or header auth through the same shared
  construction boundary and should remain behaviorally unchanged.

### Planned Material Improvement

Add an internal query-auth name validator to the shared transport construction
path and cover it with focused tests for direct and environment-backed
`AuthScheme::QueryParam` construction. This is architectural because every
provider-native adapter relying on this shared transport inherits the stronger
fail-closed outbound auth boundary.

## Bearer Auth Secret Grammar Slice

### Current Boundary

- `http.rs` owns `AuthScheme` validation before shared provider HTTP transport
  construction.
- Bearer auth secrets become `Authorization: Bearer <token>` default headers.
- Custom header and query auth values keep their existing generic secret
  validation.

### Pain Point

`AuthScheme::Bearer` rejects empty and padded tokens, but accepts internal
whitespace such as `abc def`. `HeaderValue::from_str` accepts that value after
formatting, so the shared transport can send malformed bearer credentials.

### Security And API Constraints

- Preserve public `AuthScheme`, `HttpTransportConfig`, and transport APIs.
- Preserve valid bearer token behavior.
- Reject malformed bearer tokens before a provider request can be built.
- Do not broaden validation for custom header or query auth values unless their
  existing tests require it.

### Affected Dependents

- Bearer-token provider adapters inherit the stricter construction boundary.
- Query-auth and custom-header auth dependents keep their current value grammar.

### Planned Material Improvement

Add a bearer-only auth-secret validator that reuses the generic secret checks and
also rejects internal whitespace or control bytes before inserting the
Authorization header.
