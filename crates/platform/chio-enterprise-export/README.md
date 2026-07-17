# chio-enterprise-export

Verifies enterprise evidence-export bundles: a transaction passport plus a
risk comptroller report, data-governance report, evidence-export bundle,
telemetry projection, approval case, and control-evidence map, all
digest-bound to each other and signed by independently trusted keys. It is a
pure offline verifier with no I/O; callers assemble the bundle and get back a
report of which enterprise claims verified.

## Responsibilities

- Verify the passport signature and baseline evidence-graph/verifier-policy
  shape by delegating to `chio-transaction-passport`, accepting either the
  full signed evidence graph or a scoped subset that must be a literal
  node/edge subset of a caller-supplied signed root graph.
- Parse the enterprise evidence graph and digest-bind every artifact it
  references before trusting its contents.
- Validate the five enterprise artifact types: data-governance report
  (region allow-list, legal hold, retention floor, PII redaction),
  evidence-export bundle (recomputed digest, required artifact roles,
  cross-links to the passport and risk report), telemetry projection
  (required event kinds, receipt-bound SIEM events), approval case (quorum,
  Ed25519 signature, expiry window), and control-evidence map (each control's
  claim tied to a graph node that actually proves it).
- Validate one or more risk comptroller reports and their evidence
  references by delegating to `chio-risk-comptroller`.
- Accumulate verified enterprise claims and fail if the bundle's own
  verifier policy requires one that was not proven.

## Public API

- `verify_enterprise_export(bundle: &EnterpriseExportBundle) ->
  Result<EnterpriseVerifierReport, TransactionPassportError>` - the single
  entry point.
- `EnterpriseExportBundle` - the passport, evidence-graph bytes (plus an
  optional signed root graph for scoped disclosure), verifier-policy bytes, a
  `BTreeMap<String, Vec<u8>>` of artifact path to bytes, and four trusted-key
  sets (passport signer, telemetry-receipt kernel, approval signer, risk
  comptroller signer).
- `EnterpriseVerifierReport` / `EnterpriseVerifierSections` - the verdict,
  verified claim list, and an artifact id reference for each enterprise
  section.

## Testing

`cargo test -p chio-enterprise-export`. The library target carries no unit
tests (`[lib] test = false`); coverage lives in `tests/enterprise_export.rs`,
which builds full bundles, including risk-comptroller lifecycle cases
(reserves, settlement, appeals, capital adequacy), through
`verify_enterprise_export`.

## See also

- `chio-transaction-passport` - passport, evidence-graph, and verifier-policy
  types plus the baseline signature and shape verification this crate builds
  on.
- `chio-risk-comptroller` - `RiskComptrollerReport` and its structural,
  portfolio, and evidence-reference validation.
- `chio-core-types` - canonical JSON, SHA-256 hashing, and signature
  primitives used for every digest and signature check.
