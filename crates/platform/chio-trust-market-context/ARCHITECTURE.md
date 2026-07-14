# chio-trust-market-context architecture

## Overview

`chio-trust-market-context` is a pure verification library: no I/O, no
network calls, no runtime state, and no dependency on the request-evaluation
kernel (`chio-kernel`). It sits downstream of `chio-transaction-passport`,
which establishes the passport and evidence-graph signature chain, and is
composed by product crates such as `chio-proof-room` alongside other
claim-family verifiers over the same proof bundle. Every byte it reads is
untrusted until it passes a digest, schema, and signature check, in a fixed
dependency order from discovery through jurisdiction; it verifies a bundle
after the fact and does not select providers, update reputation, enforce
SLAs live, or authorize settlement.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public API (`TrustMarketBundle`, `TrustMarketVerifierReport`, `verify_trust_market_context`). Orchestrates passport delegation, policy checks, and the artifact validation sequence. |
| `src/artifacts.rs` | The nine trust-market artifact types (discovery, selection, scorecard, reputation import, SLA commitment, SLA performance, collateral, guarantee, jurisdiction) and their field-level and cross-artifact validators. |
| `src/evidence.rs` | Evidence graph schema and reference validation, bundle-relative path safety, signed-artifact resolution (digest match plus `sig-ed25519:` signature check), and the receipt/risk-evidence lookup predicates `lib.rs` wires into the artifact validators as callbacks. |
| `src/policy.rs` | `TrustMarketVerifierPolicy` and `parse_policy`: schema check, required/unsupported claim lists, reputation-import weight cap, pinned market authority keys. |
| `src/claims.rs` | The nine claim id constants this crate verifies (eight `claim.trust_market.*` plus `claim.risk.comptroller_report_bound`) and the fixed `BLOCKED_MARKET_CLAIMS` disclosure list. |

## Verification sequence

1. Verify the transaction passport signature against the root (or, absent a
   root, the scoped) evidence graph bytes, and verify minimal passport
   artifact bindings - both delegated to `chio-transaction-passport`.
2. Parse the trust-market evidence graph and the verifier policy; reject a
   policy whose `required_claims` include a blocked market claim.
3. Intersect the bundle's `trusted_market_authority_keys` with the policy's
   pinned set (parsing already rejects an empty pinned set); fail if the
   bundle's set or the intersection is empty.
4. Resolve each of the ten evidence artifacts from the graph: match content
   digest, check the artifact's own `schema` field, verify its signature
   against the trusted authority keys, then deserialize it.
5. Run the per-artifact and cross-artifact validators in dependency order
   (discovery, reputation import, scorecard, selection, risk report, SLA,
   jurisdiction, collateral and guarantee), recording a claim id after each
   success.
6. Validate the policy's `unsupported_claims` disclosure and confirm every
   trust-market-scoped required claim was verified.
7. Assemble `TrustMarketVerifierReport`, binding the artifact id behind
   each section.

## Invariants and failure modes

- `verify_trust_market_context` returns `Err` on any failure; a returned
  `Ok(report)` always has `verdict == "verified"` - there is no partial or
  rejected verdict value.
- Every artifact, the evidence graph, and the policy deserialize with
  `#[serde(deny_unknown_fields)]`: an unexpected field is a parse failure,
  not a silent pass-through.
- Trusted market authority keys are never caller-supplied alone: signature
  checks use the intersection of `TrustMarketBundle::trusted_market_authority_keys`
  and the verifier policy's own pinned keys, so a bundle cannot
  self-authorize.
- Evidence graph node paths are validated as safe bundle-relative paths (no
  `..`, no absolute paths, no backslashes, no Windows drive prefixes) before
  any artifact lookup, closing path traversal into the caller's artifact
  map.
- An artifact is trusted only once three checks agree: the graph node's
  declared `sha256` matches the actual bytes, the artifact's own `schema`
  field matches the expected schema id for that role, and its
  `sig-ed25519:<key>:<sig>` signature verifies against a trusted authority
  key over the canonical JSON with `signature` removed.
- Collateral and guarantees are single-currency only (no cross-currency
  netting), collateral source is limited to `"bond"`, and guarantees are
  limited to `"bounded_sla_remedy"`; other values fail closed rather than
  degrading to a partial claim.
- A required claim is enforced only if it is trust-market-scoped
  (`claim.trust_market.*` or `claim.risk.comptroller_report_bound`); other
  required claims are left for other verifiers, so this crate never reports
  false coverage outside its domain.
- The verifier policy must disclose at least one `BLOCKED_MARKET_CLAIMS`
  entry as unsupported and must never require one; the list is a fixed
  compile-time constant, not policy-configurable.
- `TrustMarketVerifierSections::sla_remedy_ref` and `slash_authority_ref`
  are populated on the struct but marked `#[serde(skip)]`; they do not
  appear in the serialized report.

## Dependencies

`chio-core-types` supplies `PublicKey`/`Signature` and canonical-JSON
signing. `chio-transaction-passport` supplies `TransactionPassport`,
`TransactionPassportError` (this crate's sole error type), passport and
evidence-graph signature verification, and the evidence-graph and
verifier-policy schema id constants; the report's own `schema` field reuses
its `TRANSACTION_VERIFIER_REPORT_SCHEMA_ID`. `chio-risk-comptroller`
supplies `RiskComptrollerReport`, `RiskEvidenceRefKind`, and the risk-report
validators this crate delegates to. `chrono` parses and compares RFC3339
timestamps and windows; `serde`/`serde_json` deserialize artifacts, the
evidence graph, and the policy.
