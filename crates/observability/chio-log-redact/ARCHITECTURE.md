# chio-log-redact Architecture

## Boundary

`chio-log-redact` owns redaction at operator-facing tracing and telemetry
boundaries. It is not a guard evaluator, receipt redactor, SIEM exporter, or
kernel policy engine. Its job is to ensure payload-like log material is
redacted before it reaches a sink, and that redaction failure never falls back
to the original sensitive value.

The crate delegates byte-pattern coverage to
`chio-data-guards-redactors-default`; this crate owns the text/display/tracing
adapter surface around that redactor.

## Module Boundaries

- Raw text redaction turns UTF-8 strings into UTF-8 redacted strings under a
  selected `RedactClass` policy.
- Display redaction wraps arbitrary displayable values for log-site use through
  `redacted!(value)`.
- Tracing event capture records event targets and fields, redacts every value,
  and emits `RedactedEvent` objects to a sink.
- Sink implementations decide where already-redacted events go. They must not
  receive unredacted fallback values.

## Pain Points

- Policy selection is currently stored directly as `RedactClass` in the tracing
  layer, so validated setup and per-field redaction are not a distinct boundary.
- Text/display redaction and tracing visitor redaction duplicate the same
  placeholder-on-failure behavior.
- The only reusable policy object is the tracing layer itself, which makes it
  awkward for embedding code to validate redactor setup once and reuse the same
  policy across direct display wrappers and sink-facing event capture.

## Security And API Constraints

- Existing public APIs must remain compatible: `redact_text`,
  `redact_text_with_classes`, `RedactedValue`, `redacted!`,
  `RedactionLayer`, `MemoryRedactionSink`, and event structs stay available.
- `redacted!()` must never render the original value after a redaction error.
- `RedactionLayer` must redact event targets and every recorded field before
  handing an event to its sink.
- The default production class set remains `RedactClass::default_full()`.
- Startup validation must keep using `validate_default_redactor_compiles()` so
  invalid built-in patterns fail closed before deployment traffic is served.
- No ambient authority is introduced. The crate only transforms event data and
  delegates sink ownership to callers.

## Affected Dependents

Direct dependents include `chio-kernel` and `chio-siem`. They mostly use the
`redacted!` macro and should not need source changes. Any new reusable
redaction-policy handle must be additive and preserve the existing macro and
layer behavior.

## Planned Improvement

Introduce `LogRedactor`, a validated, reusable redaction policy handle. The
tracing layer will own a `LogRedactor` instead of raw classes, and direct
display wrappers can use the same handle when embedding code needs one
validated redaction policy across multiple log surfaces.

This is architectural because it separates lifecycle phases:
redactor setup -> display/text redaction -> tracing event capture -> sink
dispatch. The resulting boundary is reviewable and reusable without changing
the existing public API.
