# T2.1 Hybrid PQ And Cross-Surface Conformance Proof Report

## Scope

This report captures the Lane F evidence added for TRJ4-200 through TRJ4-207
and TRJ4-T2.1.E.

## Claims

- `claim.signature.hybrid_pq`: capability tokens, federation handshakes, and
  receipt signing paths accept the `hybrid:<classical>:<pq>:<alg_set>` wire
  form with `algorithm: "hybrid"`.
- `claim.federation.conformance_tier`: federation handshakes bind
  `conformance_tier` into the signed challenge and `QuorumPolicy.min_tier`
  rejects peers below the configured floor.

## Evidence

- `spec/schemas/chio-wire/v1/capability/token.schema.json` accepts hybrid
  public keys, hybrid signatures, and the `hybrid` algorithm enum value.
- `crates/chio-federation/src/trust_establishment.rs` signs handshake
  envelopes through `SigningBackend` and pins the peer conformance tier.
- `crates/chio-federation/tests/trust_establishment.rs` covers Silver-tier
  admission, Bronze under Silver rejection, threshold derivation, invalid
  evidence rejection, and hybrid backend handshake under the `pq` feature.
- `crates/chio-core-types/tests/wire_protocol_schema.rs` validates a live
  hybrid capability token against the capability-token JSON schema under the
  `pq` feature.
- `crates/chio-conformance/tests/cross_surface.rs` validates the negative
  fixture family across MCP wrapped, hosted/native HTTP, and A2A/HTTP edge
  surfaces.

## Formal Inventory

- `theorem.signature.hybrid_soundness` remains proposed and now has schema-test
  evidence linked in the proof manifest.
- `theorem.federation.conformance_tier_gate` is proposed for the tier gate:
  any peer admitted through `KernelTrustExchange` under policy floor `T` has a
  signed `conformance_tier >= T`.
