# chio-data-guards-redactors-default Architecture

## Boundary

`chio-data-guards-redactors-default` owns the default implementation of `chio:guards/redact@0.1.0`. It performs bytewise regex redaction for common secrets, basic PII, credit-card candidates with Luhn validation, and bearer-token bodies before tee frames are persisted.

## Internal Surfaces

The crate is split into redaction class flags, pass manifests, vetted regex pattern constants, startup pattern validation, match collection, overlap resolution, span application, and Luhn filtering. `redact_payload` is the trust boundary: every selected class must either produce a stable manifest over original byte offsets or fail closed before callers persist the frame.

## Trust Invariants

The security constraint is whole-secret coverage. Pattern priority, overlap handling, replacement labels, manifest offsets, pass ids, and UTF-8 preservation must stay deterministic so downstream receipts can prove exactly what was removed from the original payload.

## Current Hardening

Current hardening: OpenAI-style `sk-...` and `sk-proj-...` keys are redacted as whole API keys before generic high-entropy matching can redact only the tail and leave the provider prefix in the output.

## Verification Focus

Tests should exercise overlap ordering, provider-specific key coverage, invalid regex startup failure, Luhn filtering, UTF-8 span preservation, and byte-offset manifest stability.
