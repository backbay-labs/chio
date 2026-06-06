# chio-federation Architecture

## Boundary

`chio-federation` owns Chio's cross-operator federation contracts for trust activation, quorum reporting, open admission, reputation clearing, treaty admission, bilateral invocation review, and gossip. The crate models how remote visibility and shared evidence can move between operators while runtime trust still remains local, explicit, and fail-closed.

## Internal Surfaces

The root module defines the activation, quorum, admission, reputation, and qualification data contracts plus their validators. Specialized modules own bilateral DSSE envelopes, treaty ladder intersections, revocation gossip, pheromone gossip, handshake-based trust establishment, metrics, and the default-off selective-disclosure projection.

## Module Map

- `lib.rs`: crate documentation, dependency aliases, public module declarations, and feature-gated module declarations.
- `artifacts.rs`: shared artifact references, trust scopes, delegation controls, and import controls.
- `activation.rs`: trust-activation exchange artifact, signed activation alias, and activation validation.
- `quorum.rs`: publisher observations, conflict evidence, anti-eclipse policy, quorum report, signed quorum alias, and quorum validation.
- `open_admission.rs`: federated stake requirements, open-admission policy artifact, signed policy alias, and admission validation.
- `reputation.rs`: reputation input references, sybil controls, clearing continuity, reputation clearing artifact, signed clearing alias, and clearing validation.
- `qualification.rs`: federation scenarios, qualification outcomes, qualification cases, matrix artifact, signed matrix alias, and matrix validation.
- `validation.rs`: shared internal non-empty, uniqueness, digest, money, and cross-contract validation helpers.
- `error.rs`: public federation contract error type.
- Existing modules `bilateral.rs`, `bilateral_dsse.rs`, `metrics.rs`, `pheromone_gossip.rs`, `revocation_gossip.rs`, `treaty.rs`, `trust_establishment.rs`, and feature-gated `selective_disclosure.rs` remain the owning modules for their specialized surfaces.
- `bilateral_dsse.rs`: DSSE constants, signature-slice and strict Chio bilateral invocation predicate types, statement/envelope builders, signing flows, and verification helpers.
- `bilateral_dsse/tests.rs`: DSSE encoding, signing, verification, predicate, and policy-summary regressions extracted from the inline module.
- `bilateral_verifier.rs`: public API root for partial local verifier and strict treaty-bound review exports.
- `bilateral_verifier/error.rs`: verifier error codes and bilateral DSSE error mapping.
- `bilateral_verifier/state.rs`: pinned peers, receipt stores, revocation oracle, lease registry, and governance receipt store.
- `bilateral_verifier/config.rs`: verifier configuration, action-class policy, and successful verifier output types.
- `bilateral_verifier/treaty.rs`: strict treaty-bound Chio bilateral DSSE review and treaty-reference reconciliation.
- `bilateral_verifier/cosign.rs`: strict Chio and signature-slice bilateral invocation verification flow.
- `bilateral_verifier/support.rs`: private canonical JSON, digest, hash-record, and verdict validation helpers.
- `bilateral_verifier/tests.rs`: verifier unit tests moved from the inline module.
- `tests.rs`: crate-local root-contract behavior tests.

## Trust Invariants

The security constraint is cross-operator boundary discipline. Federation artifacts must not create ambient runtime admission, stale trust activation, unbounded delegation, eclipse-prone quorum, or noncanonical live-money collateral before downstream kernels consume them.

## Verification Focus

Tests should cover admission freshness, signer authority, quorum threshold math, treaty-scope intersections, revocation gossip merge behavior, and collateral currency validation. Cross-crate tests should also prove that federation evidence remains advisory until a local trust activation or kernel admission path explicitly consumes it.

## Improvement Target

Planned improvement: require exact uppercase 3-letter currency codes for federated bond collateral so admission policies cannot canonicalize lowercase money identifiers after review. Keep the validation in this crate, not in downstream marketplace or settlement callers, because federation is the first boundary that knows whether collateral is being advertised as shared operator trust material.
