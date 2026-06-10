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
`attestation.rs` is the runtime-attestation API root. Its child modules keep
provider verification concerns focused: `attestation/model.rs` owns verifier
policies, adapters, and error types; `attestation/verification.rs` owns JWT,
JWKS, COSE, certificate-chain, appraisal, and vendor-claim helpers; and
`attestation/tests.rs` holds provider verifier branch coverage.

`policy.rs` owns policy YAML loading, HushSpec materialization, guard pipeline
construction, default capability synthesis, and policy identity hashing.
`policy/tests.rs` holds policy parser, guard-construction, capability, and
HushSpec regression coverage.

`evidence_export.rs` owns the CLI and trust-control orchestration surface for
evidence export, import, verification, signed federation policy creation,
package rendering, filesystem IO, and query preparation. Its
`evidence_export/verification.rs` child owns manifest hash verification,
receipt and checkpoint signature checks, transparency-claim boundary checks,
federation-policy attachment validation, import-package validation, verified
package loading, and federated-share import construction.
`evidence_export/tests.rs` holds export/import verification and disclosure
notice coverage.

`certify.rs` owns local certification artifact construction, registry state,
local registry commands, public metadata/search/transparency data contracts,
consumption request types, dispute handling, and entry rendering. Its
`certify/network.rs` child owns cross-operator discovery, marketplace search,
transparency, consumption, publish fan-out, and the corresponding network CLI
commands.

`trust_control/service_runtime.rs` is the trust-service boot and route
registration root. Its child modules own the remote runtime surfaces:
`client.rs` builds remote clients, normalizes endpoints, signs cluster-peer
requests, performs failover, and owns encoded path helpers; `public_registry.rs`
performs unauthenticated public certification and generic registry lookups;
`issuance.rs` signs and evaluates generic trust, governance, open-market, and
federation policy requests; `reputation.rs` signs and evaluates portable
reputation artifacts; `remote_stores.rs` adapts remote receipt and revocation
endpoints to kernel store traits; `remote_authority.rs` adapts remote authority
status and issuance to `CapabilityAuthority`; `budget.rs` adapts remote budget
endpoints to `BudgetStore`; and `errors.rs` contains internal store-error
conversion helpers.

`trust_control/service_types.rs` owns trust-control route constants, service
configuration, client/state structs, federation/passport/receipt HTTP payloads,
financial issue payloads, error adapters, and small request query structs. Its
`service_types/cluster_budget.rs` child owns cluster status and snapshot wire
views, cluster lease RPC payloads, replication delta payloads, and budget
mutation request/response wire adapters.

`trust_control/config_and_public.rs` owns trust-control service startup, registry
path resolution, admin registry loading, passport verifier challenge helpers,
OID4VP metadata and request construction, public issuer/verifier discovery, and
SCIM lifecycle response helpers. Its `config_and_public/generic_listing.rs`
child owns public generic registry publisher, namespace, listing projection, and
report construction helpers.

`trust_control/underwriting_and_support.rs` owns underwriting decision,
simulation, appeal, exposure-ledger, credit-bond, credit-scorecard, and
capital-book support builders. Its
`underwriting_and_support/policy_support.rs` child owns policy-input
construction, underwriting compliance evidence, risk signal derivation,
behavioral-feed signing key loading, budget utilization reporting, trust HTTP
error mapping, and trust-control store opening helpers.

The trust-control HA and reporting surface is split by responsibility:
`cluster.rs` owns cluster identity, peer state, membership, consensus,
replication loops, peer snapshots and deltas, and budget-quorum commit
metadata; `report_rendering.rs` owns JSON response metadata, snapshot and delta
view conversion, receipt kind rendering, and leader-forwarding helpers;
`report_validation.rs` owns URL normalization, cluster peer authentication,
service and authority auth validation, control read-principal resolution,
authority status loading, and metered-billing request validation; `reports.rs`
owns operator, behavioral, economic-completion, runtime-attestation, exposure
ledger, credit-scorecard, capital-book, and capital-issuance report builders.
`capital_and_liability.rs` owns capital book, capital execution, credit
facility, credit bond, credit loss, provider-risk, and credit backtest
surfaces. Its `capital_and_liability/liability.rs` child owns liability
provider registry, quote, placement, pricing authority, bound coverage,
auto-bind, claim, payout, and settlement workflow artifact construction.
`credit_and_loss.rs` owns provider-risk, scorecard, facility, bond, bonded
execution simulation, and backtest helpers. Its
`credit_and_loss/loss_lifecycle.rs` child owns credit loss lifecycle
accounting, report construction, and signed lifecycle issuance.
`cluster_and_reports.rs` remains a test-only regression aggregate for behavior
that crosses those split modules.

## Security and API Constraints

The trust-control service fails closed before it serves authority, revocation,
receipt, budget, passport, federation, certification, or economic report
endpoints. `TrustServiceConfig::validate` runs before `serve_async` binds
sockets or loads runtime state, and is the root authority boundary for the
service. It rejects blank or padded service tokens, blank tenant ids, blank or
padded tenant read-token ids and values, control characters in tenant
read-token ids and values, tenant tokens that equal the admin service token,
zero cluster sync intervals, and zero `certification_public_metadata_ttl_seconds`
(which would otherwise publish discovery metadata whose `expires_at` equals
`generated_at`). Token material is never trimmed or normalized silently;
ambiguous secrets are rejected rather than coerced. Bearer-token comparison is
constant time where request auth is evaluated.

Remote clients follow the same no-ambient-authority rule: service tokens travel
only in explicit bearer headers, never through endpoint URL userinfo or query
material. `build_client` requires validated service bearer material and rejects
blank or padded service tokens, empty endpoint lists, non-HTTP(S) endpoints,
userinfo, query strings, and fragments before the remote client exists, then
preserves the normalized endpoint list for valid clients. `build_public_client`
reuses the same endpoint normalization for intentionally unauthenticated public
endpoints. Local HTTP and HTTPS endpoints and comma-separated failover endpoints
are supported, and the client API returns `CliError` without changing public
method signatures.

`build_cluster_state` normalizes `advertise_url` and `peer_urls` before the HA
runtime starts; those normalized peer URLs become the cluster allowlist,
peer-sync targets, consensus identifiers, leader metadata, and internal
peer-auth node ids. The cluster URL validator rejects username/password
material, query strings, and fragments for both advertised self URLs and
configured peer URLs before cluster state is built, so an operator
configuration field cannot become ambiguous authority-bearing or metadata-bearing
URL material. Loopback peer URLs are allowed only when `allow_local_peer_urls`
is set, and cluster peer-auth signature semantics are preserved for valid
normalized peers.

## Affected Dependents

`chio-cli`, evidence export, reputation, remote receipt/revocation/budget/authority
stores, and cluster peer sync construct `TrustServiceConfig` with the same
fields and call the same service/client entrypoints. Invalid trust-control
configuration, invalid remote control URLs or bearer tokens, and invalid HA
peer configuration are rejected at the service and client boundaries rather than
surfacing later as request-time internal errors or peer-sync state.
