# chio-control-plane Architecture Notes

## Module Boundaries

`lib.rs` exposes CLI-facing helpers for policy loading, kernel construction,
local store wiring, and authority seed management. The `trust_control` module
owns the HTTP trust service, remote clients, cluster replication, and report
endpoints. Its submodules split the broad route surface into service types,
service runtime, configuration/public registry helpers, domain handlers,
health projection, and cluster/report logic. Federation, SCIM lifecycle,
passport verifier, enterprise-provider, attestation, issuance, evidence export,
reputation, and certification support remain separate crate-local modules.

## Pain Points

`TrustServiceConfig` is the root authority boundary for the service, but its
security-sensitive invariants are currently scattered through lower handler
helpers. Empty service tokens, blank tenant-read tokens, tenant-token collisions,
and invalid cluster timing are only detected after route setup or during a
specific request path. That makes invalid trust-control state harder to audit
and lets different endpoints fail at different layers for the same bad config.

The remote trust-control client is the mirror boundary for `chio-cli`,
evidence export, reputation, and remote receipt/revocation/budget/authority
stores. `build_client` currently accepts any non-empty comma-separated endpoint
string after trimming list entries, and carries bearer-token material through
without rejecting blank or padded values. Malformed schemes, URL userinfo,
query strings, fragments, and padded tokens therefore become late transport or
auth failures instead of failing closed at client construction.

## Security and API Constraints

The trust-control service must fail closed before it starts serving authority,
revocation, receipt, budget, passport, federation, certification, or economic
report endpoints. Public APIs should stay source-compatible. Existing valid
configurations must keep their behavior, cluster peer authentication must keep
its existing signature material, and bearer-token comparison must stay constant
time where request auth is evaluated.

Remote clients have the same no-ambient-authority rule: service tokens travel
only in explicit bearer headers, never through endpoint URL userinfo or query
material. Local HTTP trust-control endpoints remain supported, HTTPS remains
supported, comma-separated failover endpoints remain supported, and the client
API keeps returning `CliError` without changing public method signatures.

## Affected Dependents

No transitive crate edits are expected. `chio-cli` and callers still construct
`TrustServiceConfig` with the same fields and call the same service/client
entrypoints. The intended behavior change is limited to invalid trust-control
configuration being rejected at the service boundary instead of surfacing later
as request-time internal errors.

No transitive crate edits are expected for the client boundary either. Existing
CLI helpers and store builders all call `build_client`, so the behavior change
is centralized: invalid remote control URLs or bearer tokens are rejected before
the remote client exists.

## Planned Material Improvement

Add a central `TrustServiceConfig` validation boundary and call it before
`serve_async` binds sockets or loads runtime state. The validator should reject
blank service tokens, blank tenant ids, blank tenant-read tokens, tenant tokens
that equal the admin service token, zero cluster sync intervals, and zero
public certification metadata TTLs.

Add a matching `TrustControlClient` construction validator. It should reject
blank or padded service tokens, empty endpoint lists, non-HTTP(S) endpoints,
userinfo, query strings, and fragments, then preserve the existing normalized
endpoint list for valid clients.

## Service Token Startup Validation Slice

### Current Boundary

`TrustServiceConfig::validate` is called before `serve_async` binds the
trust-control service and before cluster state is built. It owns service-token
and tenant read-token config validation. Remote and cluster client construction
separately validates control tokens before bearer headers or cluster peer
signatures are created.

### Pain Point

The client boundary rejects blank or padded control tokens, but service startup
only rejected secrets that become empty after trimming. A padded service token
could therefore start the authority service and later fail when the same token
is used to build remote or cluster clients. A padded tenant read token could
also start the service and then require whitespace-bearing bearer material at
read time. A padded tenant read-token id could start the service under a
whitespace-bearing tenant principal and then fail exact tenant read-boundary
authorization for the intended tenant.

### Security And API Constraints

- Preserve public `TrustServiceConfig` and `TrustControlClient` fields and
  constructors.
- Keep constant-time bearer comparison behavior in request authentication.
- Do not trim or normalize token material silently. Ambiguous secrets must be
  rejected before service startup or client construction.
- Preserve existing valid token behavior and existing error taxonomy through
  `CliError`.

### Affected Dependents

`chio-cli`, remote receipt/revocation/budget/authority stores, and cluster peer
sync continue to use the same public APIs. The behavior change is limited to
rejecting an invalid service configuration before the trust-control service can
start.

### Completed Material Improvement

Use a shared internal secret validator for service startup and client
construction. Add startup-config regressions proving padded `service_token` and
tenant read-token ids and values fail closed at `TrustServiceConfig::validate`.
Extend the same startup boundary to reject control characters in tenant
read-token ids and values before they enter service state or bearer-token
comparison.
Keep service-auth and public trust-control clients on separate constructors:
`build_client` continues to require validated service bearer material, while
`build_public_client` reuses the same endpoint normalization for intentionally
unauthenticated public endpoints.

## Public Certification Metadata TTL Slice

### Current Boundary

`TrustServiceConfig::validate` runs before the trust-control service binds its
listen socket or builds public certification discovery state. Public
certification metadata derives `expires_at` by adding
`certification_public_metadata_ttl_seconds` to the generated timestamp.

### Pain Point

The metadata builder accepted a zero TTL, which produced public discovery
metadata whose `expires_at` equaled `generated_at`. That let the service start
with immediately expired discovery metadata even though peer and client config
boundaries already reject invalid authority material before runtime state is
created.

### Security And API Constraints

- Preserve the public `TrustServiceConfig` field shape and default
  `PUBLIC_DISCOVERY_TTL_SECS`.
- Keep valid configured TTLs unchanged.
- Reject invalid public metadata lifetime before the service can publish
  registry discovery documents.

### Completed Material Improvement

Extend `TrustServiceConfig::validate` to reject zero
`certification_public_metadata_ttl_seconds`. Add a startup-config regression
proving immediately expired public certification metadata fails closed at the
service config boundary.

## Cluster Peer URL Boundary Slice

### Current Boundary

`build_cluster_state` normalizes `advertise_url` and `peer_urls` before the HA
trust-control runtime starts. The same normalized peer URLs become the cluster
allowlist, peer-sync targets, consensus identifiers, leader metadata, and
internal peer-auth node ids.

### Pain Point

Remote trust-control client endpoints already reject URL username/password
material, query strings, and fragments at construction. Cluster peer URLs use a
separate validator that only checks scheme and host safety. A peer URL with
userinfo, query, or fragment material can therefore enter the HA allowlist and
internal peer-auth signature material, turning an operator configuration field
into ambiguous authority-bearing or metadata-bearing URL material.

### Security And API Constraints

- Preserve the existing `TrustServiceConfig` fields and cluster URL
  normalization behavior for valid HTTP and HTTPS peers.
- Continue allowing loopback peer URLs only when `allow_local_peer_urls` is set.
- Do not silently strip userinfo, query strings, or fragments from cluster
  URLs. Reject them before cluster state is built.
- Preserve cluster peer-auth signature semantics for valid normalized peers.

### Affected Dependents

No transitive crate edits are expected. `chio-cli` still passes the same
cluster config fields into `chio-control-plane`; invalid HA peer configuration
now fails before the service builds cluster state instead of becoming internal
peer-sync or allowlist state.

### Completed Material Improvement

Strengthen the cluster URL validator to reject username/password material,
query strings, and fragments for both advertised self URLs and configured peer
URLs. Add a regression proving these ambiguous peer URLs fail before cluster
state can use them, even when local peer URLs are explicitly allowed.
