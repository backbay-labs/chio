# Distributed Control Rewrite

This document captures the first shared-control rewrite. For the follow-on HA
replication and shared-budget plan, see [HA_CONTROL_AUTH_PLAN.md](HA_CONTROL_AUTH_PLAN.md).
Hosted OAuth AS product work remains blocked pending a dedicated ADR or
equivalent decision note.

## Status

Shipped as the current E7 trust-plane architecture.

The control plane is now a shared HTTP service that centralizes:

- capability issuance
- authority status and rotation
- revocation query and mutation
- durable tool and child-request receipt ingestion and query

Hosted MCP nodes can now use that service through `--control-url` and `--control-token` instead of opening local receipt, revocation, and authority stores directly.

## Why this rewrite exists

The previous trust story was strong inside one process, but weak across a fleet:

- receipts were durable, but node-local
- revocations were durable, but node-local
- authority rotation could be shared with `--authority-db`, but only as an embedded SQLite primitive
- hosted admin APIs could inspect local trust state, but they were not a real shared control plane

That was enough for single-node hosting. It was not enough for a real distributed deployment.

The rewrite target was to move Chio from:

- embedded trust persistence attached to one runtime

to:

- a shared control service that every runtime can use as the source of truth

## Existing seams used by the rewrite

The codebase already had the right extension points:

- `CapabilityAuthority` in `crates/chio-kernel/src/authority.rs`
- `RevocationStore` in `crates/chio-kernel/src/lib.rs`
- `ReceiptStore` in `crates/chio-kernel/src/lib.rs`
- hosted admin surfaces in `crates/chio-mcp-remote/src/remote_mcp/`
- centralized CLI/runtime wiring in `crates/chio-cli/src/main.rs`

That meant the rewrite did not need a new kernel model. It needed a new control-plane implementation behind the existing interfaces.

## Target architecture

### 1. Shared trust-control service

The service lives in `crates/chio-control-plane/src/trust_control.rs` and exposes:

- `GET /health`
- `GET /v1/authority`
- `POST /v1/authority`
- `POST /v1/capabilities/issue`
- `GET /v1/revocations`
- `POST /v1/revocations`
- `GET /v1/receipts/tools`
- `POST /v1/receipts/tools`
- `GET /v1/receipts/children`
- `POST /v1/receipts/children`

Backing stores are still SQLite in this slice, but they are now service-owned rather than node-owned.

### 2. Remote-backed kernel interfaces

Hosted runtimes now attach remote-backed implementations for:

- `CapabilityAuthority`
- `RevocationStore`
- `ReceiptStore`

Those clients are also in `crates/chio-control-plane/src/trust_control.rs`.

The runtime selection rule is:

- local stores when `--receipt-db` / `--revocation-db` / `--authority-*` are used
- remote stores when `--control-url` and `--control-token` are used
- never both at the same time

### 3. Hosted-node admin proxy

`chio mcp serve-http` keeps its existing admin surface, but when a control service is configured it proxies trust-admin operations to the shared control plane.

That preserves a simple operator model:

- node-local admin URL shape stays stable
- shared trust state is still the source of truth

### 4. Authority rotation and trust continuity

The rewrite had one critical correctness requirement:

- rotating the authority for future sessions must not invalidate existing capabilities

To satisfy that, the authority backend now retains trusted public-key history, and kernel verification checks capability signatures against the full trusted set instead of only the current key.

Remote authority clients also refresh trusted-key state on a short TTL so rotated issuers propagate across nodes without requiring process restarts.

## Hard requirements

The rewrite was executed against these invariants:

1. Existing live sessions keep working after future-session authority rotation.
2. New sessions on other nodes can immediately observe the rotated authority.
3. Revoking a capability through one node or the control service is enforced by another node on the next request.
4. Tool and child receipts emitted by one node are queryable from another node.
5. The trust plane remains kernel-mediated. The control service stores and issues trust state; it does not bypass kernel checks.

## Execution plan

### Phase 1. Control-service core

Deliverables:

- authenticated HTTP service
- authority status and rotation endpoints
- capability issuance endpoint
- revocation query/mutation endpoints
- receipt append/query endpoints

Acceptance:

- service can be started with `chio trust serve`
- direct HTTP tests prove issuance, revocation, and receipt query behavior

### Phase 2. Kernel client adapters

Deliverables:

- remote `CapabilityAuthority`
- remote `RevocationStore`
- remote `ReceiptStore`
- CLI/runtime selection logic via `--control-url` and `--control-token`

Acceptance:

- `chio check` can issue capabilities and persist receipts through the control service
- hosted nodes can bootstrap sessions with the shared authority

### Phase 3. Hosted admin integration

Deliverables:

- remote admin proxying for authority status/rotation
- remote admin proxying for receipt queries
- remote admin proxying for revocation query/control
- remote admin session-trust inspection using shared revocation state

Acceptance:

- node admin APIs reflect shared trust state instead of local SQLite files when control mode is enabled

### Phase 4. Rotation correctness

Deliverables:

- authority trusted-key history
- kernel signature verification against trusted history
- remote authority cache refresh

Acceptance:

- old sessions still work after rotation
- new sessions see the new issuer
- cross-node rotation tests pass without restart

### Phase 5. Distributed validation

Deliverables:

- multi-node end-to-end tests
- CLI control-mode tests
- direct control-service tests

Acceptance:

- one node emits a receipt, another node can query it
- one node revokes, another node denies on the next request
- service rotation propagates across nodes

## Validation matrix

The implementation is validated in three layers.

### Direct control plane

- `chio trust serve` health and admin behavior
- `chio trust revoke/status` against `--control-url`

### CLI runtime path

- `chio check` issuing capabilities and persisting receipts through the control service

### Hosted distributed path

- two `chio mcp serve-http` nodes sharing one control service
- centralized receipt query
- cross-node revocation enforcement
- future-session authority rotation across nodes
- continued validity of old-session capabilities after rotation

## Operational model

For the current slice, the recommended production shape is:

- one trust-control service
- one shared authority database owned by the control service
- one shared receipt database owned by the control service
- one shared revocation database owned by the control service
- multiple hosted MCP edge nodes configured with `--control-url` and `--control-token`

Recommended operator stance:

- use `--authority-db` behind the control service for shared issuance and rotation history
- treat `--authority-seed-file` as a single-node or development mode
- keep node-local trust DB flags off when using the shared control plane

## What this does not solve yet

This rewrite closes the biggest distributed-control gap, but it does not yet provide:

- HA or replicated control-service topology
- non-SQLite replicated storage
- budget accounting across nodes
- token exchange or hosted OAuth authorization-server behavior
- key hierarchy, quorum rotation, or HSM integration

Those are the next trust-plane maturity steps. They are no longer blockers for having a real shared control service.

## Definition of done for this rewrite

The distributed-control rewrite is complete for this slice when:

- every runtime path can use the shared control plane
- hosted admin APIs proxy to the shared control plane
- multi-node tests prove cross-node receipts, revocations, and authority rotation
- authority rotation preserves trust continuity for already-issued capabilities
- the docs describe the shared-service architecture as the shipped path
