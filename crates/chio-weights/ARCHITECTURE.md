# chio-weights Architecture

## Boundary

`chio-weights` owns the signed model-card surface used to bind runtime-loaded model weights to allowed capability scopes, banned tools, training-data class, issuer identity, and cosign attestation metadata.

## Internal Surfaces

The crate is split into schema and canonical JSON handling in `card`, cosign bundle verification in `bundle`, stable typed error codes in `error`, and lineage-anchor projection in `lineage`. Kani harnesses live behind an explicit cfg and do not participate in production builds.

## Trust Invariants

The trust boundary is card acceptance. A successful public verifier result means the card bytes were canonical, the structure was valid, the cosign bundle verified against the exact bytes, the issuer matched the verified certificate identity, the card was live at verifier time, and any lineage anchor digest covered the canonical card bytes plus attestation metadata.

## Current Hardening

Current hardening: capability and banned-tool set entries now reject blank or surrounding-whitespace values in both deserialization and post-construction validation, so malformed scope identifiers cannot be signed into otherwise valid model cards.

## Verification Focus

Tests should cover canonical JSON stability, cosign byte binding, issuer identity matching, live-window rejection, lineage-anchor digest coverage, and capability or banned-tool normalization.
