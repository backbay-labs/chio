# chio-enterprise-export architecture

## Overview

`chio-enterprise-export` is an offline verifier, not a service: it holds no
state between calls and performs no I/O, so the caller must assemble every
artifact (passport, evidence graph, verifier policy, and referenced
artifacts) into an `EnterpriseExportBundle` before calling
`verify_enterprise_export`. It layers enterprise-specific artifact types and
cross-references on top of `chio-transaction-passport`'s baseline passport
verification. Trust is segregated by role: passport, telemetry-receipt,
approval, and risk-comptroller signers are each pinned to an independent key
set supplied by the caller, so no single compromised key can forge a
complete bundle.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `verify_enterprise_export` orchestration; `EnterpriseExportBundle`, `EnterpriseVerifierReport`, `EnterpriseVerifierSections`; final claim-set enforcement. |
| `src/evidence.rs` | `EnterpriseEvidenceGraph` parsing and validation (schema, non-empty ids, duplicate-id and dangling-edge checks), digest-bound artifact loading (`parse_artifact`, `parse_signed_risk_comptroller_report`), and the shared bundle-relative-path and sha256-hex validators. |
| `src/artifacts.rs` | The five enterprise artifact types and their validators; risk-report/evidence-graph cross-reference matching. |
| `src/policy.rs` | `EnterpriseVerifierPolicy` (`required_claims`) parsing. |
| `src/claims.rs` | Canonical `claim.enterprise.*` / `claim.risk.comptroller_report_bound` id constants and the `push_claim_once` accumulator. |

## Bundle verification

1. Verify the transaction passport signature against the signed evidence-graph
   bytes (`root_evidence_graph_bytes` if supplied, otherwise
   `evidence_graph_bytes` directly). If a root was supplied, the scoped
   `evidence_graph_bytes` must be a literal node/edge subset of it, so the
   passport's signature covers a graph the caller need not fully disclose.
2. Run `chio_transaction_passport::verify_minimal_passport_artifacts` for its
   fail-closed schema and digest checks; its returned report is discarded.
3. Parse the enterprise evidence graph and the local verifier policy.
4. Locate each required node by role, then load, digest-check, and
   schema-check its artifact bytes: one or more risk comptroller reports
   (signature-verified against the trusted risk-comptroller keys at load
   time), and exactly one each of data-governance report, evidence-export
   bundle, telemetry projection, approval case, and control-evidence map.
5. Select the risk comptroller report every other artifact's
   `risk_comptroller_report_ref` agrees on.
6. Validate every risk report and the portfolio as a whole
   (`chio-risk-comptroller`), then data governance, evidence-export bundle,
   telemetry, approval, and control map in that order, pushing one claim per
   artifact once it passes.
7. Enforce that every `claim.enterprise.*` or
   `claim.risk.comptroller_report_bound` claim the local verifier policy
   requires was actually verified.
8. Build `EnterpriseVerifierReport` (schema `chio.transaction.verifier-report.v1`,
   shared with the base transaction verifier) from the passport and the five
   artifact ids.

## Verified claims

| Claim | Verified by |
|-------|-------------|
| `claim.risk.comptroller_report_bound` | every risk comptroller report, structurally and portfolio-wide |
| `claim.enterprise.data_governance_bound` | data-governance report |
| `claim.enterprise.evidence_export_digest_bound` | evidence-export bundle |
| `claim.enterprise.telemetry_projection_bound` | telemetry projection |
| `claim.enterprise.export_approval_bound` | approval case |
| `claim.enterprise.control_map_bound` | control-evidence map |

## Invariants and failure modes

- Every cross-artifact reference is digest-bound: an evidence-graph node's
  `sha256` and the export bundle's per-artifact `sha256` are recomputed from
  the actual bytes and compared, never trusted from the JSON alone.
- Trust is segregated into four independent key sets on
  `EnterpriseExportBundle`; nothing is fetched from a registry.
- Legal hold blocks export (`legal_hold_status` must be `"not_held"`);
  PII-classified fields must have `export_action == "redacted"`; retention
  class must parse as `audit-<n>d` with `n >= 365`.
- A `siem_export` telemetry event without a `receipt_ref` fails closed; a
  present `receipt_ref` must resolve to a `ChioReceipt` signed by a trusted
  receipt-kernel key whose `content_hash`, `tool_name`, and action
  parameters bind back to the event.
- Approval requires a `sig-ed25519:<pubkey>:<sig>` signature from a trusted
  approval key over a fixed field subset, `decision == "approved"` with
  `decision_subject == "evidence-export"`, a deduplicated non-empty approver
  set at least as large as `required_quorum`, and `expires_at` strictly
  after `issued_at`.
- Artifact paths are validated as bundle-relative (no absolute paths, `..`,
  backslashes, or Windows drive prefixes) before any lookup.
- The crate performs no I/O, creates no tenant exports, and does not run SIEM
  delivery; it only verifies bundles the caller has already assembled.

## Dependencies

Internal: `chio-transaction-passport` supplies `TransactionPassport`,
`TransactionPassportError`, and the baseline signature, evidence-graph, and
verifier-policy verification this crate builds on. `chio-risk-comptroller`
supplies `RiskComptrollerReport` and its structural, portfolio, and
evidence-reference validation. `chio-core-types` supplies canonical JSON,
SHA-256 hashing, and Ed25519 signature verification. External: `chrono` for
RFC 3339 timestamp parsing; `serde`/`serde_json` for artifact deserialization.
