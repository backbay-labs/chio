# chio-disclosure-lineage

Verifier for Chio selective-disclosure bundles. It checks that a disclosure
capsule, its privacy profile, its signed lineage subgraph, its leakage
ledger, and an optional crypto context report are internally consistent,
digest-bound, signature-verified, and compliant with the privacy profile's
policy, returning a `DisclosureLineageVerifierReport` or a
`DisclosureLineageError`. It lives in the trust layer (`crates/trust`): it
verifies evidence about a disclosure, it does not produce BBS proofs
(`chio-selective-disclosure`) or index the system-wide provenance graph
(`chio-lineage`).

## Responsibilities

- Define the disclosure-lineage artifact types and their schema tags:
  `DisclosureCapsule`, `DisclosureVerifierPrivacyProfile`,
  `SignedLineageSubgraph`, `DisclosureLeakageLedger`,
  `DisclosureCryptoContextReport`, `DisclosureLineageBundle`,
  `DisclosureLineageVerifierReport`.
- Recompute and check the lineage subgraph's frontier, checkpoint-inclusion,
  and subgraph digests, and verify its Ed25519 signature against a
  caller-supplied trusted key set.
- Verify a crypto context report's Ed25519 signature and its binding to the
  capsule (ref identity, verdict, claim whitelist, disclosed-field-set
  equality).
- Enforce the privacy profile's leakage budget and allow/forbid lists against
  the capsule's disclosed fields and hidden predicates, and hold the fixed
  catalog of supported hidden predicates (`SUPPORTED_HIDDEN_PREDICATES`).
- Enforce leakage-ledger completeness and score accounting: every disclosed
  field, hidden predicate, and required derived fact needs a matching,
  policy-allowed ledger entry, with entry scores summing to the declared
  total within the profile's maximum.
- Validate the lineage subgraph's graph closure (parent/depth/edge
  consistency, root-receipt shape) and an evidence-class floor every node
  must meet.

## Public API

- `verify_disclosure_lineage_bundle`, `verify_disclosure_lineage_bundle_with_trust` -
  verify a `DisclosureLineageBundle`, returning a
  `DisclosureLineageVerifierReport` or a `DisclosureLineageError`.
- `DisclosureLineageVerifierTrust` - two independent trusted-signer key sets,
  built with `with_trusted_lineage_signer_keys` and
  `with_trusted_crypto_context_report_signer_keys`.
- `sign_lineage_subgraph`, `compute_signed_lineage_subgraph_digest`,
  `sign_crypto_context_report`, `verify_crypto_context_report_signature`,
  `verify_crypto_context_report_signature_with_trust` - digest, sign, and
  verify the two signed artifact kinds.
- Artifact types: `DisclosureLineageBundle`, `DisclosureCapsule`,
  `DisclosureHiddenPredicate`, `DisclosureVerifierPrivacyProfile`,
  `DisclosureProfileLeakageBudget`, `DisclosureSensitivityClass`,
  `SignedLineageSubgraph`, `DisclosureSignedLineageNode`,
  `DisclosureSignedLineageEdge`, `DisclosureSignedLineageRedaction`,
  `DisclosureLeakageLedger`, `DisclosureLeakageLedgerEntry`,
  `DisclosureCryptoContextReport`, `DisclosureContextVerdict`,
  `DisclosureContextCheck`, `TransparencyState`,
  `DisclosureLineageVerifierReport`, `DisclosureLineageError`.
- Schema tags: `DISCLOSURE_CAPSULE_SCHEMA_V1`, `LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1`,
  `DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1`,
  `DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1`,
  `DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1`,
  `DISCLOSURE_LINEAGE_VERIFIER_REPORT_SCHEMA_V1`.

## Testing

`cargo test -p chio-disclosure-lineage`. The lib target sets `test = false`;
all coverage lives in `tests/disclosure_lineage.rs`, which is unaffected by
that setting.

## See also

- `chio-core-types` - canonical JSON, sha256 hashing, and the Ed25519
  `Keypair`/`PublicKey`/`Signature` types this crate signs and verifies with.
- `chio-selective-disclosure` - depends on this crate and re-exports its
  bundle types and verifier; produces the `DisclosureCryptoContextReport`
  this crate verifies by evaluating the profile's key-epoch, revocation,
  nonce, holder-binding, and transparency-state policy.
- `chio-lineage` - an unrelated provenance/lineage DAG indexer for
  observability (OTEL ingest, replay corpus, guard-version diffing); no
  shared code or types despite the similar name.
- `chio-proof-room` - verifies disclosure lineage bundles as part of its
  transaction-passport proof surface.
