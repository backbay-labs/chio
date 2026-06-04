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

- `HttpEgressContract` is the raw configured policy shape.
- `ValidatedHttpEgressTarget` is the URL authority result after enforcement.
- `HttpEgressError` is the fail-closed reason surface for config, URL, DNS,
  redirect, address-class, and byte-limit denials.
- Core enforcement validates schemes, userinfo, normalized authority, address
  classes, DNS answers, redirect depth, and response size.
- The optional `reqwest_helper` module turns those checks into a dispatch path
  that validates every hop, disables ambient proxy/redirect behavior, pins DNS
  through a contract-backed resolver, strips sensitive redirect headers, and
  caps streamed response bytes.

## Pain Points

- The raw contract is both configuration data and the enforcement object.
- Each enforcement method validates the raw contract again, which blurs the
  boundary between deployment config admission and per-request checks.
- The reqwest helper currently receives a raw contract and re-enters validation
  across the request loop, redirect loop, DNS resolver, and response byte
  checks.

## Security And API Constraints

- Missing contracts must fail closed.
- Existing public methods on `HttpEgressContract` must remain compatible.
- Allowed authorities stay exact normalized host or host:port entries.
- DNS enforcement must check every resolved IP before a socket is opened.
- Private/special-use IPv4 and IPv6 addresses must remain denied even when an
  authority entry was configured.
- Redirect limits, response byte ceilings, proxy disabling, and redirect
  self-management must remain enforced.
- The default feature set must stay free of optional `reqwest`/`tokio`
  dependencies.

## Affected Dependents

Direct dependents include `chio-http-core`, `chio-api-protect`,
`chio-mcp-remote`, `chio-openapi-mcp-bridge`, and `chio-a2a-adapter`. This
slice is additive for callers: existing raw-contract APIs remain available.
The optional reqwest helper can use the prepared boundary internally without
requiring downstream source changes.

## Prepared Contract Lifecycle Slice

`PreparedHttpEgressContract` is an immutable pre-validated contract handle.
It separates config admission from per-attempt enforcement and lets dispatch
helpers avoid repeatedly validating raw policy shape while preserving the same
fail-closed URL, DNS, redirect, and byte checks.

The change is architectural because it introduces a distinct contract lifecycle:
raw config -> prepared contract -> per-hop enforcement.

## Canonical Authority Admission Slice

### Current Boundary

`allowed_authority_set` is the exact authority allow-list used after each
target URL has been normalized. Contract validation therefore owns both syntax
admission and canonical-form admission for authority entries.

### Pain Point Addressed

The authority validator rejects obvious malformed entries, but it can still
admit authorities that are parseable but not canonical, such as trailing-dot
domains, zero-padded ports, or non-compressed IPv6 literals. Those entries are
bad configuration: they pass admission but do not line up with the normalized
authority string produced during URL enforcement.

### Security And API Constraints

- Preserve exact normalized host or host:port allow-list semantics.
- Preserve default-port compatibility: callers may continue to allow either
  `example.com` or `example.com:443` and match HTTPS targets consistently.
- Preserve public API compatibility; tighten invalid raw policy admission
  without changing enforcement return types.
- Keep the optional `reqwest-egress` feature boundary unchanged.

### Affected Dependents

Downstream crates that already build authorities from parsed URLs should be
unchanged. Dependents with non-canonical hard-coded authorities should fail
early at config validation rather than silently producing an unusable contract.
Focused proof belongs in `cargo test -p chio-egress-contract`; no transitive
source edits are expected unless a dependent test exposes a real non-canonical
fixture.

### Material Improvement

Validate authority entries against their canonical representation before a raw
contract can be prepared. Regression tests should prove that trailing-dot
domains, zero-padded ports, and non-canonical IPv6 literals fail during
contract validation while explicit default-port authorities remain compatible.

## HTTP Scheme Admission Slice

### Current Boundary

`allowed_schemes` is part of the HTTP egress contract admitted before any URL,
DNS answer, redirect hop, or response body is accepted. The contract is not the
wire mediation boundary for WebSocket, FTP, database sockets, or other
non-HTTP substrates.

### Pain Point Addressed

The scheme validator currently admits any lowercase URI scheme token. That
makes a raw contract with `ftp`, `ws`, or another non-HTTP scheme validate even
though every enforcement rule in this crate is URL-shaped HTTP egress policy.

### Security And API Constraints

- Preserve the public `HttpEgressContract` shape and all existing enforcement
  return types.
- Preserve `http` and `https` contracts, including local loopback test
  contracts.
- Fail closed during contract admission for non-HTTP schemes instead of
  allowing an unusable or misleading egress policy to reach dispatch.
- Do not extend this crate into generic wire mediation; future non-HTTP policy
  belongs in a sibling boundary.

### Affected Dependents

Workspace callers already build HTTP egress contracts from `http` or `https`
URLs. Callers that accidentally pass `ws`, `ftp`, or another non-HTTP scheme
should receive an `InvalidContract` denial at validation time. No transitive
source edits are expected unless a dependent fixture was relying on an invalid
non-HTTP contract.

### Material Improvement

Constrain scheme admission to HTTP egress by accepting only `http` and `https`
after token syntax validation. Add focused regressions proving non-HTTP
schemes fail closed while existing HTTP contracts remain valid.
