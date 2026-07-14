# chio-proof-room architecture

## Overview

`chio-proof-room` is a standalone product binary and library, marked
`public_entrypoint = true` in its manifest metadata: a supported public entry
point distinct from the full `chio` CLI, built for the Docker quickstart. It
sits at an untrusted edge: it reads a bundle or fixture directory supplied by
the caller and never trusts a claimed verdict, recomputing every verifier
report from source artifacts through the domain-verifier crates listed under
Dependencies. Its verification and fixture machinery (around 8,800 lines) is
`pub(crate)`; the public surface is a handful of verification entry points
and the axum router/server constructors.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Schema/claim/env-var constants, `ProofRoomError`, manifest and fixture-catalog wire types, the embedded-fixture include, and per-domain `*_trust_from_env` / `*_keys_from_env` trust configuration (including the public-settlement independent-chain-head RPC fetch). |
| `src/main.rs` | CLI argument parsing; dispatches to `serve_proof_room` or `verify_proof_room_quickstart`. |
| `src/server.rs` | The axum `Router`: bundle/artifact/fixture routes, hand-rolled multipart upload verification, static UI serving, and `serve_proof_room` (bind, verify-before-serve, graceful shutdown). |
| `src/bundle_a.rs` | Core manifest verification: schema/hash checks, DSSE bundle-signature verification, negative-case replay, claim-to-artifact binding, first-run authority-evidence checks, and bundle-relative path safety. |
| `src/bundle_b.rs` | UI verifier-report cross-check, JSON Schema validation plumbing, bundle path resolution/percent-decoding, and negative-case mutation appliers (JSON-path edits, evidence-graph node rehash, manifest/DSSE refresh). |
| `src/receipt_coverage.rs` | Verifies the manifest's receipt-coverage matrix: required categories, terminal-status-to-category matching, kernel-signature verification per covered receipt. |
| `src/source_verifier.rs` | Recomputes the verifier report for a bare transaction passport on the manifest-bundle path: routes evidence-graph subsets to domain verifier crates by policy `required_claims`, merges family reports, attaches a runtime-proof-parity report. |
| `src/fixture_a.rs` | The fixture-catalog HTTP path: resolves `/proof-room-fixtures/{id}/{asset}`, defines `ProofRoomFixtureReportRoute` and the embedded/installed asset source, and routes each fixture's `verifier-report.json` to one domain verifier. |
| `src/fixture_b.rs` | Decodes typed domain-verifier bundles (commerce, disclosure lineage, swarm authority, public settlement, runtime) from an evidence graph and artifact map; shared by `source_verifier.rs` and `fixture_a.rs`. Also builds the `/proof-room-fixture-catalog.json` response. |
| `src/crypto_context.rs` | Recomputes a BBS selective-disclosure crypto-context report and cross-checks it against a claimed signed report. |
| `build.rs` (+ `../proof_fixture_build.rs`) | Embeds `fixtures/proof-room/first-run/single-call-authority` into the binary via `include_bytes!` at compile time; other catalog fixtures need `--fixture-root`. |

`fixture_a.rs` and `source_verifier.rs` are independent recomputation paths
that both route through `ProofRoomFixtureReportRoute` and share
`fixture_b.rs`'s artifact decoders: the fixture-catalog path resolves one
route per fixture, while the manifest-bundle path can merge several family
reports into one.

## Bundle verification

1. Read `manifest.json`, reject any non-regular file in the bundle tree, and
   validate the manifest against `bundle.schema.json`
   (`chio.proof-room.bundle.v1`, `hash_algorithm: sha256`).
2. Verify the detached DSSE bundle signature against trust roots declared in
   the bundle's own `artifacts/authority/trust-roots.json`, intersected with
   `CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS`.
3. Verify the `transaction_passport_ref` and `evidence_graph_ref` artifacts,
   and, for first-run bundles, the capability-proof / guard-report /
   trust-roots artifacts and their evidence-graph node bindings.
4. Recompute the source verifier report from the transaction passport
   (`source_verifier::verify_source_verifier_report`) and compare it to the
   manifest's claimed `verifier_report_ref` - the manifest's own report is
   never trusted directly.
5. Verify every claim is bundle-scoped or covered by the recomputed report,
   verify the receipt-coverage matrix, and (unless disabled) replay every
   negative case against a temp copy of the bundle, checking its expected
   failure code.
6. Verify the remaining manifest artifacts hash correctly and, if present,
   cross-check the UI-facing report against the recomputed verdict.

`serve_proof_room` runs this pipeline before binding a listener: an
unverified or tampered bundle is never served.

## Invariants and failure modes

- Fail closed: any schema, hash, signature, or claim mismatch rejects with a
  `proof-room.*` error code; the server refuses to serve until verification
  succeeds.
- Bundle-relative paths are validated and percent-decoded before resolution;
  canonicalized paths must stay under the bundle root, ruling out `..`,
  absolute paths, and symlink escapes.
- A DSSE bundle signature must be signed by a key both declared in the
  bundle's own trust-roots artifact and present in the env-pinned trusted
  signer set - a bundle cannot self-declare a new trusted signer.
- Negative cases must reproduce their exact `expected_failure_code`; an
  unexpectedly-passing negative case fails the whole verification.
- HTTP asset serving only exposes paths enumerated from a verified manifest
  (`proof_room_served_bundle_paths`) or the UI directory; everything else
  404s.
- The public-settlement independent-chain-head RPC path is the crate's only
  outbound network call; it runs through `chio-egress-contract`'s pinned-DNS
  resolver with redirects denied and a response-byte ceiling.
- Trust configuration (signer keys, chain policy) is read from `CHIO_*`
  environment variables at verification time; missing required configuration
  is a hard error, not a silent skip.

## Dependencies

Domain verifiers this crate orchestrates and recomputes reports from (each
owns its own fail-closed rules): `chio-transaction-passport` (root
passport/evidence-graph/claim-set and runtime-security verification),
`chio-swarm-authority`, `chio-runtime-proof-parity` (both validators -
`validate_runtime_proof_parity_report` and
`validate_runtime_proof_regeneration_artifacts`), `chio-web3`
(`settlement_proof`), `chio-commerce-order`, `chio-disclosure-lineage`,
`chio-selective-disclosure` (`bbs` feature), `chio-enterprise-export`,
`chio-risk-comptroller`, `chio-trust-market-context`,
`chio-agent-web-interop`, `chio-workflow-preflight` (fixture-catalog path
only).

Also: `chio-core-types` (`PublicKey`, `Signature`, canonical JSON,
`sha256_hex`); `chio-http-serve` (connection caps and graceful drain wrapped
around the axum router); `chio-egress-contract` (`reqwest-egress` feature,
pinned-DNS egress for the settlement RPC call). External: `axum` +
`tower-http` (router, static files), `tokio` (async runtime), `jsonschema`
(bundle/artifact schema validation), `reqwest` (RPC client), `serde` /
`serde_json`, `sha2` / `hex`, `thiserror`. No dependency aliasing:
`chio-core-types` imports as `chio_core_types`, matching its package name.
