# chio-transaction-passport architecture

## Overview

The crate is a verification library, not a runtime service: every entry point is a
pure function of caller-supplied bytes and caller-pinned public keys, with the wall
clock as the only ambient input (passport expiry). Its trust position is
downstream-authoritative: callers (`chio-control-plane`, `chio-proof-room`,
`chio-risk-comptroller`, and others) treat whatever this crate accepts as a verified
transaction, so every check fails closed rather than defaulting to trust.

The design centers on three ideas: evidence graphs are content-addressed (a node's id
is its own sha256 digest), identities are self-certifying (`did:chio:<64-hex>` or bare
hex *is* the Ed25519 public key), and verification comes in three increasingly strict
tiers plus an orthogonal runtime-security layer, so callers can choose how much they
re-derive versus trust from an already-signed claim set.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Facade. Every module is private; the crate's public surface is exactly its `pub use` list. |
| `src/types.rs` | `TransactionPassport`, `TransactionVerifierReport`, `TransactionClaimResult`, `TransactionOmissionPolicyEntry`, and the report's `verified`/`failed`/`with_*` builders. |
| `src/ids.rs` | Schema id constants for every artifact schema the crate or its callers reference. |
| `src/error.rs` | `TransactionPassportError`, the single error enum for every failure mode in the crate. |
| `src/validation.rs` | Shared primitives: sha256-hex shape, bundle-relative path safety (rejects absolute paths, `..`, backslashes, drive prefixes), non-empty field checks. |
| `src/minimal.rs` | Passport schema and signature verification, the root-graph verification path, and verifier-policy gate enforcement. |
| `src/evidence_graph.rs` | `TransactionEvidenceGraph` parsing and structural validation, plus the standalone "minimal governed action" cross-artifact binding and signature-chain verification. |
| `src/verifier_policy.rs` | `TransactionVerifierPolicy` shape validation and commerce-state to required-claim expansion (`effective_required_claims`). |
| `src/runtime_security.rs` | `verify_runtime_security_claims[_with_trust]`; orchestrates the runtime evidence-graph walk over leases and swarm artifacts. |
| `src/runtime_security/evidence.rs` | `RuntimeEvidenceGraph` parsing/validation and role/edge lookup helpers scoped to a given execution lease. |
| `src/runtime_security/artifacts.rs` | Typed structs and validators for every runtime artifact: execution lease, task graph, budget pool, join receipt, route-plan receipt, sandbox attestation, tool-server ack, trusted-time proof, terminal receipt, policy-activation receipt, attack-simulation and chaos-run reports. |
| `src/runtime_security/policy.rs` | Minimal `RuntimeVerifierPolicy` parse used only to read `required_claims`. |
| `src/runtime_security/claims.rs` | `claim.runtime.*` claim-id constants and `push_claim_once`. |

## Verification tiers

Every entry point takes caller-supplied bytes (passport, evidence graph, verifier
policy, and a `path -> bytes` artifact map) and returns a typed report or a
`TransactionPassportError`.

1. **Schema only** (`verify_minimal_passport_schema[_at]`) checks the passport's own
   shape: schema id, non-empty id/issuer, a well-formed signature, valid digests and
   safe paths for its three referenced artifacts, and its validity window. No
   artifact bytes are read.
2. **Root graph** (`verify_passport_root_and_claim_set_artifacts*`) additionally
   verifies the passport signature against pinned root keys, checks the
   evidence-graph and verifier-policy bytes hash to the digests the passport
   declares, enforces the verifier policy's gates, and validates the claim set's
   shape and required-claim status. Claims are trusted as the claim set states them,
   except `claim.risk.*` claims, which must also appear in the caller-supplied
   `externally_verified_claims`.
3. **Standalone minimal governed action**
   (`verify_standalone_minimal_passport_artifacts*`) restricts required claims to the
   six `claim.transaction.*` structural claims, then independently re-derives every
   binding: every evidence-graph node's digest must match caller-supplied bytes, and
   the capability proof, guard decision, receipt, and trust root must reference each
   other's ids and digests correctly and each carry a valid signature from a signer
   the trust root authorizes.
4. **Runtime security** (`verify_runtime_security_claims[_with_trust]`) runs tier 2,
   then walks a separate `RuntimeEvidenceGraph` to validate an execution lease and
   everything it references: sandbox attestation, tool-server acknowledgement,
   trusted-time proof, revocation-freshness proof, route-plan receipt, swarm task
   graph, budget pool, join receipt, and the terminal receipt that closes the lease.

## Invariants and failure modes

- Every check fails closed: malformed schema, missing or unknown fields
  (`deny_unknown_fields` on every wire struct), digest mismatches, expired validity
  windows, and untrusted signers all reject.
- Evidence-graph nodes are content-addressed (`id == sha256`), every edge must
  reference a declared node id, and the graph must be acyclic.
- Identities are self-certifying: `did:chio:<64-hex>` or a bare 64-hex string *is* the
  Ed25519 public key. Every signature chain must bottom out at a trust root whose
  signer key is in the caller-supplied pinned key list; an empty pinned-key list is
  rejected outright, never treated as "trust everything."
- Advisory evidence cannot authorize: an edge with an
  `Authorizes`/`Executes`/`Leases`/`Attenuates`/`Settles` predicate is rejected if
  either endpoint is an advisory-observation node or the edge itself is classed
  advisory.
- `claim.risk.*` claims cannot be self-attested by the claim set; the root-graph path
  additionally requires them in the caller's `externally_verified_claims`.
- A signed evidence graph and a caller-presented "scoped" (redacted) graph may
  differ: `verify_transaction_passport_signature_with_evidence_graph` accepts the
  scoped graph only if every one of its nodes and edges is also present in the signed
  graph, so redaction can remove entries but never alter or add them.
- Runtime execution leases: `max_invocations`, when present, must equal `1`;
  tool-server-ack nonces must be unique per lease across the whole bundle.
- Policy activation cannot widen in-flight authority: a policy-activation receipt
  with `narrowing_or_widening: "widening"` is rejected.
- Signature scope varies by artifact: most runtime artifacts (execution lease,
  route-plan receipt, sandbox attestation, tool-server ack, trusted-time proof,
  terminal receipt, policy-activation receipt, attack-simulation/chaos-run reports,
  revocation-freshness proof) sign a dedicated field-allowlist body under their own
  `*-signature.v1` schema id. Task graphs, join receipts, runtime trust roots, and the
  minimal-governed-action capability/guard-decision/receipt/trust-root artifacts
  instead sign their full canonical JSON with only `signature` removed.

## Dependencies

Internal: `chio-core-types` supplies `crypto::{Keypair, PublicKey, Signature}`
(Ed25519 sign/verify over canonical JSON) and `is_supported_signed_artifact_schema`,
the signed-artifact schema registry every evidence-graph node's schema is checked
against (except `advisory-observation` and `external-subject` nodes). External:
`chrono` for RFC 3339 timestamps and validity windows, `sha2`/`hex` for
content-addressed digests, `serde`/`serde_json` for wire parsing, `thiserror` for
`TransactionPassportError`. Dev-only: `chio-test-support` and `jsonschema` cross-check
fixtures against `spec/schemas/chio-transaction/v1/`.
