# chio-attest-buyer Architecture

## Boundary

`chio-attest-buyer` owns the public Chio buyer attestation boundary. It exposes Chio-native packet, review-package, lineage, continuation, and verification-report types so callers do not depend directly on the runtime-core verifier shapes.

## Internal Surfaces

The crate is a thin boundary adapter. It maps public Chio structs into the verifier backend, normalizes runtime-core error and check codes back into the `chio_attest_buyer` namespace, and delegates full proof replay to `chio-attest-buyer-core` when hydrated proof artifacts are available.

## Trust Invariants

The trust boundary is typed JSON construction. Public `*_from_json` functions must not return Chio-owned structs until schema ids, required identifiers, SHA-256 bindings, artifact paths, duplicate artifact keys, and byte counts have been checked. Verification still replays through the backend, but constructor validation prevents malformed packets or unsafe review packages from being handed to callers as trusted local shapes.

## Verification Focus

Tests should exercise malformed schema ids, missing artifact references, duplicate artifact keys, mismatched digests, and backend replay paths so public construction and verifier acceptance stay aligned.

Constructor validation and backend replay must agree on every rejection: a packet that fails the `*_from_json` checks must also fail verification, and a packet the backend rejects must never be reachable as a trusted local struct. Coverage holds that invariant across schema-id mismatches, byte-count drift, and missing or duplicated artifact bindings so the typed boundary cannot drift away from the verifier it fronts.
