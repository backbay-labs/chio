# TRJ4-023 Evidence - HttpEgressContract

## Scope

`chio-http-core` now exports `HttpEgressContract`, `HttpEgressError`, and
`ValidatedHttpEgressTarget`. The contract requires:

- `tenant_egress_namespace`
- `allowed_schemes`
- `allowed_authority_set`
- `deny_loopback`
- `deny_link_local`
- `deny_ipv6_ula`
- `max_redirect_chain`
- `max_response_bytes`

Missing contracts fail closed through `HttpEgressContract::enforce_required`.

## Validation

- `cargo test -p chio-http-core --test http_egress_contract` passed: 9 tests.
- `cargo check -p chio-http-core -p chio-tee-frame -p chio-conformance`
  passed.
- `cargo clippy -p chio-http-core -p chio-tee-frame -p chio-conformance --tests -- -D warnings`
  passed.

## Negative Cases

- Missing contract.
- Loopback IPv4.
- IPv4-mapped IPv6 loopback.
- Link-local IPv4.
- IPv6 unique-local address.
- Redirect chain overflow.
- Oversized response.
- Undeclared authority.
