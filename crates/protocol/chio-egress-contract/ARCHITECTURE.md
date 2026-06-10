# chio-egress-contract Architecture

## Boundary

`chio-egress-contract` owns the typed HTTP egress policy boundary for substrate
adapters. It does not know Chio capabilities, kernel receipts, tool manifests,
or adapter protocols. Its job is to decide whether an outbound HTTP target,
redirect hop, DNS answer, and response byte count satisfy a declared tenant
egress contract.

The crate stays dependency-light by default. The optional `reqwest-egress`
feature adds a dispatch wrapper and resolver, but the core contract remains
usable without `reqwest` or `tokio`.

## Module Boundaries

- `src/lib.rs` owns the core contract types, raw-policy validation, URL
  enforcement, DNS/address-class checks, and the test-only permissive contract
  constructor.
- `src/reqwest_helper.rs` owns the optional `reqwest-egress` dispatch wrapper,
  resolver, redirect handling, and capped response collection.
- `src/tests.rs` owns root-level contract and reqwest helper regression
  coverage.
- `HttpEgressContract` is the raw configured policy shape.
- `PreparedHttpEgressContract` is an immutable pre-validated contract handle. It
  separates config admission from per-attempt enforcement: the lifecycle is raw
  config -> prepared contract -> per-hop enforcement. Dispatch helpers avoid
  repeatedly revalidating raw policy shape while preserving the same fail-closed
  URL, DNS, redirect, and byte checks.
- `ValidatedHttpEgressTarget` is the URL authority result after enforcement.
- `HttpEgressError` is the fail-closed reason surface for config, URL, DNS,
  redirect, address-class, and byte-limit denials.
- Core enforcement validates schemes, userinfo, normalized authority, address
  classes, DNS answers, redirect depth, and response size.
- The optional `reqwest_helper` module turns those checks into a dispatch path
  that validates every hop, disables ambient proxy/redirect behavior, pins DNS
  through a contract-backed resolver, strips sensitive redirect headers, and
  caps streamed response bytes.

## Config Admission

Raw policy is validated against its canonical form before a contract can be
prepared, so bad configuration fails early at validation rather than producing
an unusable contract:

- Authority allow-list entries are exact normalized host or host:port. They are
  validated against their canonical representation, so trailing-dot domains,
  zero-padded ports, and non-canonical IPv6 literals are rejected while explicit
  default-port authorities (`example.com` or `example.com:443`) remain
  compatible and match HTTPS targets consistently.
- Scheme admission accepts only `http` and `https` after token syntax
  validation. Non-HTTP schemes (`ws`, `ftp`, others) fail closed during
  contract admission. This crate is not the wire mediation boundary for
  non-HTTP substrates; that policy belongs in a sibling boundary.

## Security And API Constraints

- Missing contracts fail closed.
- Existing public methods on `HttpEgressContract` stay compatible.
- DNS enforcement checks every resolved IP before a socket is opened.
- Private/special-use IPv4 and IPv6 addresses stay denied even when an
  authority entry was configured.
- Redirect limits, response byte ceilings, proxy disabling, and redirect
  self-management stay enforced.
- The default feature set stays free of optional `reqwest`/`tokio`
  dependencies.

## Affected Dependents

Direct dependents include `chio-http-core`, `chio-api-protect`,
`chio-mcp-remote`, `chio-openapi-mcp-bridge`, and `chio-a2a-adapter`. Existing
raw-contract APIs remain available; the optional reqwest helper uses the prepared
boundary internally without requiring downstream source changes.
