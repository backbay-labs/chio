# chio-control-plane architecture

## Overview

`chio-control-plane` has two trust positions in one crate. `lib.rs`,
`policy`, `issuance`, and `attestation` are local composition code: they run
inside the same process as the kernel they wire and are trusted to the same
degree as their caller. `trust_control` is a network-facing service (plus the
client that talks to it) that a Chio deployment runs standalone; its handlers
treat every inbound request as untrusted until bearer or cluster-peer
authentication and store-level checks pass. The crate owns no protocol types.
It composes `chio-kernel` with SQLite-backed local stores, HTTP-backed remote
store adapters, and roughly a dozen domain subsystems (attestation,
certification, evidence export, federation policy, passport issuance, SCIM,
risk/finance) behind one crate boundary, so that `chio-cli` and the other
product binaries have a single dependency for "run or talk to a Chio trust
plane."

## Module map

| Path | Responsibility |
|---|---|
| `src/lib.rs` | `CliError`, `JwtProviderProfile`, and the kernel/store wiring functions (`build_kernel`, `configure_*`) shared by every Chio CLI binary. |
| `src/policy.rs` + `policy/*` | Parse Chio-YAML or HushSpec policy files into a `LoadedPolicy`: guard pipeline, default capabilities, reputation/runtime-assurance issuance policy (HushSpec only). |
| `src/issuance.rs` + `issuance/*` | `wrap_capability_authority`: decorates a `CapabilityAuthority` with attestation verification, reputation-tier gating, and runtime-assurance-tier scope narrowing. |
| `src/attestation.rs` + `attestation/*` | `RuntimeAttestationVerifierAdapter` and its Azure MAA, AWS Nitro, Google Confidential VM, and enterprise-verifier implementations; each produces a `VerifiedRuntimeAttestation`. |
| `src/certify/` (`mod.rs` + siblings) | Build and sign MCP tool-server conformance certifications, a local registry, and a federated public discovery/marketplace network. |
| `src/evidence_export.rs` + `evidence_export/*` | Export/import signed evidence bundles (receipts, checkpoints, lineage) with tenant disclosure notices and federation-policy scoping. |
| `src/federation_policy.rs` | Permissionless federation open-admission policy registry with anti-sybil controls (proof-of-work, rate limit, bond-backed admission). |
| `src/passport_verifier.rs` | SQLite-backed OID4VCI issuance-offer and OID4VP challenge/transaction stores, plus the portable-passport lifecycle registry. |
| `src/enterprise_federation.rs` | Registries for enterprise IdPs (OIDC JWKS, OAuth introspection, SCIM, SAML) and certification-discovery-network operators. |
| `src/scim_lifecycle.rs` | SCIM 2.0 user resource to `EnterpriseIdentityContext` mapping and tracked-capability bookkeeping. |
| `src/reputation.rs` | CLI commands: local reputation inspection and local-vs-portable-passport comparison. |
| `src/transaction_passport_risk.rs` | Binds `TransactionPassport` verification to a graph-referenced signed `chio-risk-comptroller` report. |
| `src/trust_control.rs` + `trust_control/*` | The clustered trust-control HTTP service, its client, and cluster replication. Broken out below. |

### `trust_control` breakdown

`trust_control.rs` holds the shared import set (axum, the `chio_kernel`
domain types, `subtle::ConstantTimeEq`, `tower_http`, ...) that every child
module inherits via `use super::*;`, and controls what leaves the module:
`cluster`, `service_runtime`, and `reports` are declared `pub mod` (reachable
as `chio_control_plane::trust_control::{cluster,service_runtime,reports}`);
`report_rendering` and `report_validation` are `pub(crate) mod` (internal
only); the rest are private `mod`s whose items are flattened into
`trust_control::*` by `pub use self::X::*` for `capital_and_liability`,
`config_and_public`, `credit_and_loss`, `service_types`, and
`underwriting_and_support`, and by `pub(crate) use self::X::*` (HTTP-only,
not part of the Rust API) for `authority_handlers`, `budget_handlers`,
`certification_handlers`, `passport_handlers`, `receipt_handlers`, and
`risk_finance_handlers`.

| Path | Responsibility |
|---|---|
| `authority_handlers.rs` | Capability-authority admin: issue/rotate/revoke, SCIM, enterprise-provider and federation-admission-policy CRUD. |
| `budget_handlers.rs` | Budget increment/charge/reverse/reduce handlers with quorum-commit-aware event ids and compensating rollback. |
| `certification_handlers.rs` | Certification registry mutation plus the unauthenticated public discovery/marketplace surface. |
| `passport_handlers.rs` | OID4VCI/OID4VP passport issuance, verification, wallet exchange, and federated cross-service capability issuance (`handle_federated_issue`). |
| `receipt_handlers.rs` | Receipt read/write, analytics, evidence export/import, and the operator/economic/settlement report endpoints; enforces admin-vs-tenant read scoping. |
| `risk_finance_handlers/{attestation,capital,credit,exposure,liability,reputation,underwriting}.rs` | Credit, capital, exposure, liability, underwriting, reputation, and runtime-attestation-appraisal report and issuance endpoints. |
| `capital_and_liability.rs` + `capital_and_liability/liability.rs` | The subject-scoped capital-book ledger and capital-execution instructions; the full liability-insurance workflow (quote to bind to claim to settlement). |
| `credit_and_loss.rs` + `credit_and_loss/loss_lifecycle.rs` | Credit provider risk package, scorecard, facility/bond issuance, bonded-execution autonomy gating, and delinquency/recovery/write-off lifecycle accounting. |
| `underwriting_and_support.rs` + `underwriting_and_support/policy_support.rs` | Underwriting decisions and appeals, scorecard-dimension weighting, and shared store-opening/auth primitives used across the finance handlers. |
| `config_and_public.rs` + `config_and_public/generic_listing.rs` | The `serve()` process entrypoint, registry loaders, OID4VP/OID4VCI plumbing, and the public generic-listing/namespace discovery surface. |
| `reports.rs` | Builds the signed report/decision artifacts: exposure ledger, capital book, capital-allocation decisions, operator/behavioral-feed reports. |
| `report_rendering.rs` | HTTP response shaping and leader-forwarding for cluster writes. |
| `report_validation.rs` | Bearer and cluster-peer authentication, control-URL SSRF guarding, admin-vs-tenant read-principal resolution. |
| `health.rs` | Unauthenticated `GET` liveness/status endpoint; each subsystem snapshot degrades to `available: false` instead of failing the request. |
| `cluster/{consensus,deltas,partition,pull_budget,snapshots}.rs` | Quorum-gated leader designation, pull-based per-peer delta replication, partition simulation, and full-state snapshots. |
| `service_runtime/{budget,client,errors,init,issuance,public_registry,remote_authority,remote_stores,reputation,router}.rs` | Server bootstrap (`serve_async`), axum `Router` construction (`router::build_router`), and the remote adapters (`RemoteCapabilityAuthority`, `RemoteReceiptStore`, `RemoteRevocationStore`, `RemoteBudgetStore`) plus `TrustControlClient` and its `client/*` transport. |
| `service_types/{cluster_budget,config,paths,requests,responses,state}.rs` | Route-path constants, `TrustServiceConfig`, wire DTOs, and the `TrustServiceState` / `ClusterRuntimeState` app state. |

## Data flow

### Local kernel construction (CLI path)

1. `policy::load_policy` parses a policy file into a `LoadedPolicy`.
2. `build_kernel` constructs a `ChioKernel`, installing the default guard
   profile (`chio_guards::default_runtime_guard_profile`) and the policy's
   own guard/post-invocation pipelines.
3. `configure_receipt_store` / `configure_revocation_store` /
   `configure_budget_store` attach either a local `chio-store-sqlite` store or
   a `Remote*Store` built from `--control-url`.
4. `configure_capability_authority` attaches a `LocalCapabilityAuthority` or
   `SqliteCapabilityAuthority` - wrapped by `issuance::wrap_capability_authority`
   whenever a reputation or runtime-assurance policy is set - or a
   `RemoteCapabilityAuthority` for `--control-url`.

### Trust-control service request lifecycle

1. `trust_control::config_and_public::serve` builds a tokio runtime and calls
   `service_runtime::serve_async`.
2. `serve_async` binds the listener, builds `ClusterRuntimeState` when peers
   are configured, spawns `cluster::run_cluster_sync_loop`, and assembles the
   axum `Router` via `router::build_router`.
3. Each handler resolves an auth or read principal first
   (`report_validation::validate_service_auth` /
   `resolve_control_read_principal`) and fails closed (401/403) before
   touching store state.
4. On a clustered deployment, mutating handlers forward the write to the
   current leader and wait for it to become locally visible before responding
   (`report_rendering::forward_post_to_leader` and its authority/SCIM/budget
   variants).

### Cluster replication

1. `cluster::consensus::compute_cluster_consensus_locked` recomputes the
   leader on every status check: the lowest-sorted URL among peers that are
   reachable, unpartitioned, and inside the lease TTL. This is a deterministic
   pick over the locally observed peer set, not a voted election - there is no
   term voting, log replication, or election RPC.
2. `cluster::deltas::run_cluster_sync_loop` runs a serial per-peer pull round
   (via `tokio::task::spawn_blocking` around a synchronous `ureq` client) for
   cluster status, authority snapshot, and budget/tool-receipt/child-receipt/
   lineage/revocation deltas.
3. Delta pages enforce strict sequence contiguity (dense streams) or forward
   progress (gap-tolerant streams); a peer that falls behind or overflows the
   per-round pull budget is force-resynced from a full
   `cluster::snapshots::apply_cluster_snapshot`.
4. Every internal cluster endpoint authenticates the caller with
   `report_validation::validate_cluster_peer_auth`: a shared-secret keyed
   digest over canonical JSON (`{scheme, serviceToken, nodeId, endpoint,
   issuedAt, term}`, not a public-key signature), constant-time compared,
   allowlisted by node id against `peer_urls`, bounded to a 60-second skew
   window, and rate-limited on repeated failure.

## Invariants and failure modes

- `TrustServiceConfig::validate` runs before `serve_async` binds a socket: it
  rejects blank or padded service/tenant tokens, a tenant token equal to the
  admin service token, control characters in token material, a zero cluster
  sync interval, and a zero certification-metadata TTL.
- Bearer and cluster-peer authentication both compare secrets with
  `subtle::ConstantTimeEq`, never `==`.
- `issuance::enforce_runtime_assurance_policy` is the only place that narrows
  a granted capability scope: it denies requests above the resolved tier's
  ceiling and appends `Constraint::MinimumRuntimeAssurance` to economically
  sensitive grants. Reputation-tier gating (`issuance::enforce_tier_scope`) is
  deny-only; it never rewrites a grant.
- Reputation and runtime-assurance issuance gating are HushSpec-only:
  `policy::loader::load_policy` always sets both to `None` on the plain
  Chio-YAML path.
- `configure_receipt_store` refuses to attach an in-memory SQLite path as a
  durable receipt store - it would satisfy the kernel's persistence gate while
  losing every receipt on restart. An intentionally ephemeral receipt log
  requires the explicit `allow_ephemeral_receipt_log` policy flag instead.
- Single-currency-per-book enforcement recurs across `capital_and_liability`,
  `credit_and_loss`, and `underwriting_and_support`: mixed-currency state is
  rejected with a conflict, never blended or auto-netted.
- `trust_control::cluster` replication is pull-based and quorum-gated, not a
  consensus protocol. Budget-acknowledgment witnessing only shrinks on
  ambiguity, never grows, and a peer that force-snapshots is excluded from
  quorum witnessing until fully re-synced.
- `service_runtime::remote_stores::BoundedReceiptWriter` bounds concurrent
  blocking remote-receipt writes to a fixed 2-worker pool with a depth-2 queue
  and fails closed with a timeout rather than queuing unbounded work.
- `service_runtime::remote_authority::AuthorityKeyCache` fails closed on an
  unprimed cache: `deny_sentinel_public_key()` returns a freshly generated,
  immediately discarded key - a guaranteed-wrong denial rather than a panic.

## Dependencies

Internal: `chio-kernel` supplies `ChioKernel` and every store/authority trait
this crate implements locally (`chio-store-sqlite`) or over HTTP
(`service_runtime::remote_*`); `chio-core` supplies protocol types;
`chio-guards` supplies the default guard profile, `GuardPipeline`, and
`PostInvocationPipeline`; `chio-policy` supplies HushSpec parsing and
compilation for `policy::load_policy` (a dependency crate, distinct from this
crate's own `policy` module - not aliased, just same-named); `chio-data-guards`
and `chio-external-guards` supply the concrete guard adapters
`policy::build_guard_pipeline` assembles, and `chio-external-guards` also
supplies the SSRF IP-denial check `report_validation.rs` runs against cluster
peer URLs; `chio-credentials` supplies OID4VCI/OID4VP and passport types for
`passport_verifier` and the passport handlers; `chio-did` resolves `did:chio`
identities; `chio-reputation` supplies the scoring math `issuance` and
`reputation` wrap; `chio-conformance` supplies scenario/result loading for
`certify`; `chio-mcp-adapter` supplies adapter error types surfaced through
`CliError`; `chio-http-serve` supplies `ServeHygieneConfig` (body-size and
timeout limits applied in `service_runtime::init`/`router`); `chio-metrics-spec`
supplies the `/metrics` route's Prometheus rendering; `chio-errors` supplies
the registry-backed diagnostic codes `CliError` maps onto; `chio-risk-comptroller`,
`chio-transaction-passport`, `chio-trust-market-context`, `chio-commerce-order`,
`chio-enterprise-export`, and `chio-agent-web-interop` are re-exported as
facades rather than consumed internally.

External: `axum` and `tower-http` implement the trust-control HTTP service;
`ureq` (synchronous) implements `TrustControlClient` and every cluster-peer
and outbound public-registry call - `reqwest` is a dependency only for its
`Error` type in `CliError`'s `From` impl, not for making requests; `rsa`,
`p384`, `x509-cert`, and `ciborium` implement JWT/JWKS/COSE/certificate-chain
verification in `attestation`; `subtle` implements constant-time secret
comparison; `chrono`, `base64`, `percent-encoding`, `serde_urlencoded`, and
`url` support timestamp parsing, token encoding, and URL validation across the
service and client.

## Extension points

`RuntimeAttestationVerifierAdapter` (`attestation.rs`) is the trait a new
attestation backend implements: `adapter_name`, `verifier_family`, and
`verify_and_appraise(evidence, now) -> Result<VerifiedRuntimeAttestation,
Self::Error>`. The four adapters in this crate (Azure MAA, AWS Nitro, Google
Confidential VM, enterprise verifier) are the reference implementations, not
an exhaustive set.
