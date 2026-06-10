# chio-provider-adapter-core Architecture

## Boundaries

- `lib.rs` is the public adapter-core facade. It exposes provider identity, loaded-weights helpers, streaming gate helpers, deny-reason text, and SSE parsing types. SSE parsing lives behind an internal `sse` module while the public re-exports and CRLF byte fidelity for `SseFrame::raw` are preserved.
- `http.rs` owns shared provider HTTP transport, mock transport, auth configuration, status classification, and NDJSON parsing.
- Provider adapters depend on this crate for fail-closed stream parsing, common HTTP error taxonomy, and test transport seams.

## Outbound Trust Boundary

`HttpTransport::new` validates the caller-supplied `HttpTransportConfig::base_url`
before any request can be built: empty or padded values, non-HTTP(S) schemes,
embedded userinfo, query strings, and fragments fail closed. Provider secrets
flow through `AuthScheme` and provider-specific headers, never through URL
userinfo or opaque base-URL query strings, so request-target construction has a
single ambient-authority path.

`validate_auth_scheme` checks all auth material at transport construction, before
a `reqwest::Client` is returned:

- `AuthScheme::QueryParam` validates both the API key value and the parameter
  name, rejecting empty, padded, or control-byte-bearing names. Query-auth secret
  values are not included in diagnostics.
- `AuthScheme::Bearer` rejects empty, padded, internal-whitespace, and
  control-byte tokens before the `Authorization: Bearer <token>` default header
  is formed.
- Custom header and query auth values keep the generic secret validation.

## Constraints

- Preserve public API compatibility for `SseFrame`, `SseParseOptions`, `UnknownSseFieldPolicy`, `parse_sse_frames`, `HttpTransportConfig`, `HttpTransportError`, `ProviderHttpTransport`, `MockHttpTransport`, and status/transport error mapping.
- Preserve fail-closed parsing for invalid UTF-8, malformed JSON data, unknown-field rejection, event/type mismatch, and missing event names under cross-check mode.
- Preserve done-sentinel semantics: terminator frames expose `done = true`, `data = None`, and retain the original bytes for forwarding.

## Affected Dependents

- `chio-openai`, `chio-groq-tools-adapter`, `chio-mistral-tools-adapter`, `chio-cohere-tools-adapter`, and `chio-gemini-tools-adapter` call the shared SSE parser; `chio-gemini-tools-adapter` is the direct query-auth dependent and uses the stable `key` parameter name. Other provider adapters use bearer or header auth through the same shared construction boundary.
- Provider replay and conformance tests rely on the shared `ProviderError` taxonomy and byte-stable stream gating behavior.
