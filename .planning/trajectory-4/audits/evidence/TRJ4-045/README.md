# TRJ4-045 Evidence - ssrf_via_http_substrate Threat Test

## Scope

`crates/chio-conformance/tests/threats/ssrf_via_http_substrate.rs` now uses the
shared `chio-http-core::HttpEgressContract` API. It asserts that substrate HTTP
egress denies the SSRF classes called out by TRJ4-023.

## Validation

- `cargo test -p chio-conformance --test threats ssrf_via_http_substrate`
  passed: 1 test.
- `bash scripts/check-threat-coverage.sh` passed: 12 covered, 0 partial, 8
  pending, 0 uncovered.
- `cargo clippy -p chio-http-core -p chio-tee-frame -p chio-conformance --tests -- -D warnings`
  passed.

## Negative Cases

- Loopback IPv4.
- Link-local metadata IPv4.
- IPv6 unique-local address.
- Redirect chain overflow.
- Oversized response.
