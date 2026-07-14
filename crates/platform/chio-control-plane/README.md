# chio-control-plane

Runtime-wiring layer for a Chio deployment. `lib.rs` assembles a
`chio_kernel::ChioKernel` from a loaded policy and a set of local or remote
stores; `trust_control` separately implements the clustered trust-control HTTP
service (and its client) that lets multiple Chio nodes share capability
authority, budget, receipt, and revocation state. The crate defines no
protocol types of its own - it composes `chio-kernel` with `chio-store-sqlite`,
`chio-guards`, `chio-policy`, `chio-credentials`, `chio-reputation`, and the
economic/trust domain crates behind about a dozen subsystem modules.

`[package.metadata.chio] public_entrypoint = true`: this is a supported
integration surface. `chio-cli`, `chio-wall`, and `chio-mercury` build their
`chio` binaries on it; `chio-mcp-remote` and `chio-hosted-mcp` re-export its
`CliError` and `JwtProviderProfile`.

## Responsibilities

- Build a `ChioKernel` from a `LoadedPolicy` and wire local (SQLite) or remote
  (`--control-url`) receipt, revocation, budget, and capability-authority
  stores (`build_kernel`, `configure_receipt_store`,
  `configure_revocation_store`, `configure_capability_authority`,
  `configure_budget_store`).
- Load Chio policy files (plain YAML or HushSpec) into a guard pipeline and a
  default capability set (`policy`).
- Gate capability issuance on reputation tier and runtime-attestation tier,
  narrowing the granted scope of economically sensitive grants (`issuance`).
- Verify runtime attestation evidence from Azure MAA, AWS Nitro, Google
  Confidential VM, and a signed generic "enterprise verifier" format
  (`attestation`).
- Host the trust-control HTTP service - capability authority, budget,
  revocation, receipts, evidence export, OID4VCI/OID4VP passports,
  certification marketplace, and credit/capital/liability/underwriting
  endpoints - and its HTTP client (`trust_control`).
- Replicate authority, budget, receipt, and revocation state across a cluster
  of trust-control nodes (`trust_control::cluster`).
- Export and import signed evidence bundles across tenants and federation
  partners (`evidence_export`, `federation_policy`).
- Certify MCP tool-server conformance and publish or discover certifications
  across a federated marketplace (`certify`).
- Map SCIM and enterprise IdP identities (OIDC, OAuth introspection, SAML)
  onto Chio enterprise identity context (`scim_lifecycle`,
  `enterprise_federation`).
- Verify OID4VCI/OID4VP portable passports and bind a `TransactionPassport` to
  its signed risk-comptroller evidence (`passport_verifier`,
  `transaction_passport_risk`).

## Public API

`src/lib.rs`:

- `CliError` - the unified error type for every CLI and service code path;
  `.report()` converts it to a `StructuredErrorReport`, mapping most
  subsystem errors onto `chio_errors` registry codes.
- `build_kernel(LoadedPolicy, &Keypair) -> ChioKernel` - installs the default
  and policy guard pipelines and post-invocation hooks.
- `configure_receipt_store` / `configure_revocation_store` /
  `configure_capability_authority` / `configure_budget_store` - attach a local
  SQLite store, a remote store built from `--control-url`, or (for the
  capability authority) a reputation/attestation-gated wrapper.
- `load_or_create_authority_keypair`, `rotate_authority_keypair`,
  `authority_public_key_from_seed_file` - authority seed-file lifecycle.
- `JwtProviderProfile` - enterprise JWT provider profile (`Generic`, `Auth0`,
  `Okta`, `AzureAd`).

Top-level modules:

| Module | Owns |
|---|---|
| `policy` | Policy loading (`load_policy`), guard pipeline construction, default capabilities |
| `issuance` | `wrap_capability_authority`: reputation- and attestation-gated capability issuance |
| `attestation` | Runtime attestation verifier adapters and their appraisal |
| `trust_control` | The trust-control HTTP service, client, and cluster replication - see [ARCHITECTURE.md](./ARCHITECTURE.md) for its own module map |
| `certify` | MCP conformance certification, local registry, federated marketplace |
| `evidence_export` | Signed evidence bundle export/import |
| `federation_policy` | Permissionless federation open-admission policy registry |
| `passport_verifier` | OID4VCI/OID4VP stores and the portable-passport lifecycle registry |
| `enterprise_federation` | Enterprise IdP and certification-discovery-network registries |
| `scim_lifecycle` | SCIM user provisioning mapped to Chio identity |
| `reputation` | CLI commands for local reputation inspection and passport comparison |
| `transaction_passport_risk` | Binds a transaction passport to its signed risk-comptroller report |

Re-exported facade crates: `agent_web` (`chio-agent-web-interop`),
`enterprise_export` (`chio-enterprise-export`), `risk_comptroller`
(`chio-risk-comptroller`), `commerce_order` (`chio-commerce-order`),
`transaction_passport` (`chio-transaction-passport`), `trust_market`
(`chio-trust-market-context`).

## Feature flags

| Flag | Effect |
|------|--------|
| `pq` | Enables post-quantum signing via `chio-core/pq`, `chio-kernel/pq`, and `chio-store-sqlite/pq`. |

## Testing

`cargo test -p chio-control-plane`

Integration tests under `tests/` exercise the re-exported facade modules
(`agent_web`, `enterprise_export`, `transaction_passport`, `trust_market`) and
a web3 anchor-ops qualification path. `trust_control/cluster_and_reports.rs`
(`#[cfg(test)]`) holds cluster- and report-endpoint regression coverage,
backed by `proptest-regressions/`.

## See also

- `chio-kernel` - supplies `ChioKernel` and the store/authority traits this
  crate wires locally and re-implements remotely over HTTP.
- `chio-store-sqlite` - the local SQLite store implementations this crate
  opens.
- `chio-policy` - HushSpec parsing and compilation consumed by
  `policy::load_policy` (not the same thing as this crate's own `policy`
  module - watch for the name collision).
- `chio-guards`, `chio-data-guards`, `chio-external-guards` - guard
  implementations assembled by `policy::build_guard_pipeline`.
- `chio-credentials` - OID4VCI/OID4VP and passport primitives underlying
  `passport_verifier` and `trust_control`'s passport handlers.
- `chio-cli` - the primary consumer binary (`chio trust serve`,
  `--control-url`).
