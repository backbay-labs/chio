# chio-data-guards-redactors-default architecture

## Overview

The crate is a pure library: no I/O, no async runtime, no logging dependency.
It is the default, native-Rust implementation of the `redactor` world declared
in `wit/chio-guards-redact/world.wit` (package `chio:guards@0.1.0`) - its
public types (`RedactClass`, `RedactionMatch`, `RedactionManifest`,
`RedactedPayload`) mirror the WIT `redact-class` flags and
`redaction-match`/`redaction-manifest`/`redacted-payload` records
field-for-field, and `redact_payload` mirrors the WIT `redact-payload`
function. Its dependency set (`regex`, `serde`, `serde_json`, `thiserror`) is
deliberately narrow so the same source stays viable as a `wasm32-wasip2` guest
export, but no `crate-type = ["cdylib"]` is configured today: consumers link
it in-process as an ordinary `rlib`, not as a compiled WASM component.
`chio-tee`'s `Redactor` trait (`crates/trust/chio-tee/src/redact.rs`) is the
seam a wasmtime-hosted guest would plug into without call-site changes;
nothing implements that seam today besides this crate's `DefaultRedactor`.

## Module map

Single-file crate. `src/lib.rs` holds the WIT-mirrored public types, the
vetted regex pattern constants and their `LazyLock` statics, the startup
pattern validator, `redact_payload`/`redact`, and the match-collection,
overlap-resolution, span-application, and Luhn-filter internals.

## Redaction pass

1. `redact_payload` walks the enabled `RedactClass` flags in a fixed order:
   `secrets` (AWS key, JWT, Stripe secret, Stripe publishable, OpenAI key,
   high-entropy), then `bearer_tokens`, then `pii_basic` (email, US phone, US
   SSN, Luhn-checked credit card).
2. Each pattern runs `Regex::find_iter` over the raw bytes (`(?-u)`; bearer is
   case-insensitive `(?i-u)`). A candidate is dropped if it overlaps a span an
   earlier, higher-priority pattern already claimed (`overlaps`), so an
   OpenAI `sk-proj-...` key claims the whole key before the generic
   high-entropy pattern can match only its tail.
3. Credit-card candidates additionally pass `luhn_ok`; structurally
   card-shaped but Luhn-invalid digit runs are left untouched.
4. Accepted spans are recorded both as `(start, end, replacement_bytes)` for
   rewriting and as a `RedactionMatch` carrying the offset and length in the
   *original* payload's byte coordinates.
5. `apply_spans` sorts spans by start offset and rewrites the payload once,
   copying unmatched bytes through and splicing in each class's canonical
   replacement marker (`[REDACTED-EMAIL]`, `[REDACTED-API-KEY]`, etc.).
6. Matches are sorted by `(offset, length)` and returned in a
   `RedactionManifest` stamped with `PASS_ID` and the pass's elapsed time.

## Invariants and failure modes

- Fail-closed: an `Err(RedactError)` from `redact_payload` carries no bytes.
  Callers (the tee, `chio-log-redact`) must treat it as pass failure and
  refuse to persist or emit the payload; the crate has no path that returns
  partial or unredacted output alongside an error.
- `RedactError::Overflow` fires if a match offset or length does not fit
  `u32`, signalling a payload at or above 4 GiB that the caller should refuse.
- A pattern that fails to compile does not panic: `try_compile` returns `None`
  and the hot path silently skips that class. `validate_default_redactor_compiles`
  is the separate, opt-in hard-fail surface for callers that want to refuse
  startup instead of accepting the soft-skip.
- `default_pattern_inventory_matches_lazylocks` and
  `default_patterns_match_runtime_lazylock_sources` (tests) pin
  `DEFAULT_PATTERNS` and the runtime `LazyLock` statics to the same length and
  the same source strings per label, so the startup validator cannot silently
  drift from the hot path it is meant to validate.
- Manifest byte offsets are always in the original payload's coordinate space,
  never the redacted output's.
- Matched spans never split a UTF-8 codepoint: `\b`-anchored patterns fire
  only at ASCII word edges, which are always valid UTF-8 boundaries; two tests
  exercise multibyte input directly against this property.
- `pii_extended` and `custom` are accepted flag values, matching the WIT
  contract's requirement that a guest accept any flag combination without
  erroring, but both are no-ops in this implementation.
- `PASS_ID` is bumped whenever default coverage changes, so tenants can pin
  redactor behavior to an exact pass id from the manifest.

## Dependencies

No internal `chio-*` dependencies. External: `regex` (bytewise pattern
matching over `&[u8]`, not `&str`), `serde`/`serde_json` (wire-shape
(de)serialization for the WIT-mirrored types), `thiserror` (`RedactError`).
`tracing` is deliberately excluded to keep the crate viable as a
`wasm32-wasip2` guest export; `try_compile` writes pattern-compile failures to
stderr instead.

## Extension points

None. The crate exposes fixed functions and types, not a trait or registry;
the swap-in seam for an alternative (e.g. wasmtime-hosted) redactor is
`chio-tee`'s `Redactor` trait, one layer up.
