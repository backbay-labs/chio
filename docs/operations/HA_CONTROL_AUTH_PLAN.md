# HA Control, Auth, and Budget Plan

## Goal

Move Chio from:

- one shared trust-control service with optional OAuth metadata discovery

to:

- a replicated trust-control cluster with write failover and shared budget state
- hosted MCP edges that can advertise metadata while OAuth AS product work
  remains blocked pending ADR
- a deployment model that is usable across multiple MCP edge nodes without shared local files

## Current Baseline

As shipped before this rewrite:

- `chio trust serve` centralized authority, revocations, and receipts behind one HTTP service
- hosted MCP edges could use that service through `--control-url` and `--control-token`
- hosted MCP edges could advertise protected-resource and auth-server metadata
- hosted MCP edges could verify JWT bearer tokens
- invocation budgets still lived inside the kernel runtime, not the control plane
- control clients assumed a single base URL
- there was no replicated control-service topology
- there was no real `/authorize` or `/token` behavior

## Design Constraints

The code already has the right seams:

- kernel extension points for `CapabilityAuthority`, `ReceiptStore`, `RevocationStore`, and now `BudgetStore`
- CLI/runtime construction concentrated in `crates/chio-cli/src/main.rs`
- hosted HTTP auth and admin behavior concentrated in `crates/chio-mcp-remote/src/remote_mcp/`
- control-plane HTTP client and server behavior concentrated in `crates/chio-control-plane/src/trust_control.rs`

The rewrite should preserve those seams instead of inventing a second trust model.

## Architecture Decisions

### 1. Control cluster model

Chio will use a pragmatic replicated control cluster:

- every trust-control node owns local durable SQLite state
- every node knows its own `advertise_url` and a list of `peer_urls`
- every node computes a write leader from the healthy cluster membership
- all mutating control-plane operations route to the current leader
- followers replicate from peers on a short interval and can also serve reads

This is not full consensus. It is a deterministic leader plus repair loop. The goal is strong-enough operational HA for normal deployments, not Byzantine fault tolerance.

### 2. Leader rule

The write leader is the lexicographically smallest healthy advertised URL in the cluster membership set.

Why:

- deterministic
- no external coordinator
- easy to explain and test
- automatic failover when the current leader becomes unhealthy

Health is based on successful control-peer syncs and local self-health.

### 3. Replication model

Replication is state-specific:

- authority: replicated as signed authority snapshots including the current signing seed, generation, rotated timestamp, and trusted key history
- revocations: replicated as idempotent records
- tool receipts: replicated as idempotent append-only records
- child receipts: replicated as idempotent append-only records
- budgets: replicated as monotonic usage records keyed by capability/grant

The control plane keeps periodic repair syncs even after forwarding writes, so missed updates converge after transient peer failures.

### 4. Shared budget semantics

Invocation budgets move out of node-local kernel memory and into a pluggable `BudgetStore`.

Rules:

- local single-process mode can still use in-memory or local SQLite
- distributed mode uses the control-plane budget service
- budget increments are leader-routed so exhaustion semantics remain strong across nodes
- replicated followers merge budget usage by max observed invocation count per `(capability_id, grant_index)`

### 5. Hosted auth-server behavior

This section is reference scaffolding only. OAuth AS product work remains
blocked until a dedicated ADR or equivalent decision note is accepted. The
current runtime must stay feature-gated, seed-file gated, and scope-clamped.

`chio mcp serve-http` may gain a hosted OAuth authorization server when
configured with a local auth signing seed after that decision gate.

Supported flows:

- authorization code with PKCE (`S256`)
- token exchange
- JWKS publication
- protected-resource metadata
- authorization-server metadata

This auth server is intentionally self-hosted and single-subject by default:

- authorization approvals are operator-approved through a minimal browser form
- the resulting access token subject comes from explicit hosted auth configuration

That keeps the implementation self-contained while still giving MCP clients a real standards-aligned flow.

### 6. Token format

Access tokens remain Ed25519-signed JWTs.

Claims include:

- `iss`
- `sub`
- `aud`
- `scope`
- `client_id`
- `exp`
- `iat`
- optional `resource`

The hosted MCP resource server will enforce:

- signature
- issuer
- audience/resource binding
- expiry / not-before
- required scopes when configured

### 7. Client failover

`--control-url` will accept a comma-separated cluster endpoint list.

The trust-control client will:

- keep the last healthy endpoint as preferred
- retry requests across the configured endpoint set
- tolerate follower endpoints because followers forward writes to the current leader

## Concrete Work Breakdown

### A. Kernel and local stores

Deliverables:

- `BudgetStore` abstraction
- `SqliteBudgetStore`
- kernel budget enforcement through the store
- receipt-store idempotent append semantics
- authority snapshot export/apply helpers

Acceptance:

- local budget exhaustion persists across process restart
- receipts can be replayed safely during replication
- authority state can converge across independent store handles

### B. Control service cluster

Deliverables:

- `peer_urls` / `advertise_url` trust-service config
- health-aware leader selection
- follower write forwarding
- replication endpoints for authority, revocations, receipts, and budgets
- periodic peer repair sync
- health/status surface including current leader, peer state, and replication positions for debugging convergence

Acceptance:

- two trust services can converge without shared files
- writes through either node survive leader loss after failover
- a restarted follower catches up from the leader

### C. Control clients and runtime wiring

Deliverables:

- multi-endpoint trust client
- remote `BudgetStore`
- CLI/runtime selection logic for `--budget-db` and control-backed budgets
- hosted admin proxy for budget state

Acceptance:

- `chio check` and hosted MCP nodes enforce one shared budget across nodes
- the same CLI invocation can survive a dead first control URL

### D. Deferred hosted authorization server

Blocked follow-up. These deliverables are not part of the current accepted
plan until a dedicated OAuth AS ADR or equivalent decision note is accepted.

Deliverables:

- local auth signing seed configuration
- `/oauth/authorize`
- `/oauth/token`
- `/oauth/jwks.json`
- PKCE verification
- token-exchange verification and issuance
- scope enforcement during remote MCP admission

Acceptance:

- an auth-code flow produces a working access token for the hosted MCP resource
- token exchange produces a resource-bound access token
- wrong audience, missing scope, bad PKCE, and expired codes are rejected

### E. Distributed validation

Deliverables:

- two-node trust-control failover tests
- replication/catch-up tests
- shared-budget cross-node tests
- hosted auth-code flow tests after the ADR gate
- hosted token-exchange tests

Acceptance:

- full workspace tests pass
- the distributed-control service can lose one control node without losing correctness for subsequent requests

## Operational Model After This Rewrite

Recommended deployment shape:

- two or more `chio trust serve` nodes
- one local SQLite dataset per control node
- short peer replication interval
- hosted MCP nodes configured with a cluster `--control-url` list
- hosted auth enabled only after the ADR gate with a dedicated auth signing seed
  and public base URL

Recommended security stance:

- separate service and admin bearer tokens
- dedicated auth signing seed, distinct from the capability authority
- HTTPS in front of both the control plane and hosted MCP/auth plane
- shared budget state enabled for any multi-node deployment

## Explicit Non-Goals

This rewrite still does not attempt:

- multi-datacenter consensus
- byzantine quorum rotation
- HSM-backed signing
- dynamic user login / identity-provider federation

Those remain follow-on work. The current goal here is strong single-region HA
and shared-budget behavior; hosted OAuth AS behavior remains blocked pending
ADR.
