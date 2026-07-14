# chio-data-guards-redactors-default

Default implementation of the `chio:guards/redact@0.1.0` interface: regex-driven
redaction of secrets, basic PII, and bearer-token bodies from a byte payload.
Chio's tee runs it as the mandatory pass before a captured frame is buffered;
`chio-log-redact` runs it against text, display, and tracing log output. The
crate is nested under `crates/guards/chio-data-guards/` by path convention
only - it shares no code or dependency with the parent `chio-data-guards`
crate, which redacts query results through its own, unrelated regex path in
`QueryResultGuard`.

## Responsibilities

- Implement `redact_payload`: a byte payload plus `RedactClass` flags in, a
  `RedactedPayload` (redacted bytes plus manifest) or a fail-closed `Err` out.
- Own the vetted regex patterns for each class: AWS access keys, JWTs, Stripe
  live/test secret and publishable keys, OpenAI-style `sk-`/`sk-proj-` keys,
  generic high-entropy runs, email, US phone, US SSN, Luhn-validated
  credit-card numbers, and `Authorization: Bearer` bodies.
- Resolve overlapping matches first-registered-wins, and apply replacements
  without moving the manifest's byte offsets out of the original payload's
  coordinate space.
- Validate every vetted pattern compiles independently of the lazily
  initialized hot-path regexes, so a caller can refuse to start on a broken
  pattern instead of silently skipping a class.
- Stamp every manifest with a `PASS_ID` tenants can pin against.

## Public API

- `redact_payload(payload: &[u8], classes: RedactClass) -> Result<RedactedPayload, RedactError>` -
  primary entry point; mirrors the WIT `redact-payload` host call.
- `redact(payload: &[u8]) -> Result<Vec<u8>, RedactError>` - convenience
  wrapper over `RedactClass::default_full()` that drops the manifest.
- `validate_default_redactor_compiles() -> Result<(), Vec<String>>` -
  re-checks every vetted pattern at startup; returns the failing
  `(label, pattern)` descriptions.
- `RedactClass` - mirrors WIT `redact-class` flags (`secrets`, `pii_basic`,
  `pii_extended`, `bearer_tokens`, `custom`); `RedactClass::all()` and
  `RedactClass::default_full()` constructors. `pii_extended` and `custom` are
  accepted but are no-ops in this implementation.
- `RedactionMatch`, `RedactionManifest`, `RedactedPayload` - mirror WIT
  records `redaction-match`, `redaction-manifest`, `redacted-payload`.
- `RedactError::{Overflow, InvalidUtf8}` - fail-closed error variants.
- `PASS_ID` - `"redactors@1.5.0+default"`, stamped into every
  `RedactionManifest`.

## Usage

```rust
use chio_data_guards_redactors_default::{redact_payload, RedactClass};

let out = redact_payload(b"contact alice@example.com", RedactClass::default_full())?;
assert!(out.manifest.matches.iter().any(|m| m.class == "pii.email"));
```

## Testing

`cargo test -p chio-data-guards-redactors-default` runs the unit suite in
`src/lib.rs` plus the realistic-payload integration suite in
`tests/integration.rs`.

## See also

- `chio-tee` - `redact::DefaultRedactor` runs this crate's `redact_payload` as
  the mandatory fail-closed pass before a captured frame is buffered.
- `chio-log-redact` - runs this crate's `redact_payload` and
  `validate_default_redactor_compiles` against text, display, and tracing log
  output.
- `chio-data-guards` - the parent directory's crate; a separate package with
  its own independent redaction path (`QueryResultGuard`), not a dependency of
  this crate.
