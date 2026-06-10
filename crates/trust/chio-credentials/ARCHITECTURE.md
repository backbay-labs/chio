# chio-credentials Architecture

## Boundary

`chio-credentials` owns Chio's native reputation credential and Agent Passport artifacts. It issues canonically signed Ed25519 credentials, bundles them into unsigned passports, and projects them into OID4VCI, OID4VP, SD-JWT, JWT VC, lifecycle, and trust-tier surfaces.

## Internal Surfaces

The native passport structs are the source of truth. External projection modules may derive standards-native forms, but they must not widen the native schema or reinterpret unverified JSON as trusted passport state.

## Module Layout

Artifact types, passport construction, presentation challenge logic, policy evaluation, and projection code share crate-private helpers through one compilation unit. The native wire schema is the hardening surface, not the module boundary.

## Trust Invariants

Signed credentials and passport projections must preserve canonical bytes, issuer identity, subject identity, lifecycle state, trust tiers, and verifier challenge binding. External formats are projections, not independent sources of authority. Native passport, presentation, and verifier-policy documents reject unknown fields so malformed JSON fails at parse time before verification or canonical-signature logic sees it.

## Verification Focus

Tests should reject unknown native fields, projection-only fields in native documents, stale verifier challenges, mismatched issuer identities, and JSON that would serialize differently after validation.
