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

## Security And API Constraints

- Public APIs are `redact_text`, `redact_text_with_classes`, `RedactedValue`,
  `redacted!`, `RedactionLayer`, `MemoryRedactionSink`, and the event structs.
- `redacted!()` must never render the original value after a redaction error.
- `RedactionLayer` must redact event targets and every recorded field before
  handing an event to its sink.
- The default production class set is `RedactClass::default_full()`.
- Startup validation uses `validate_default_redactor_compiles()` so invalid
  built-in patterns fail closed before deployment traffic is served.
- No ambient authority is introduced. The crate only transforms event data and
  delegates sink ownership to callers.

## Dependents

Direct dependents are `chio-kernel` and `chio-siem`, which use the `redacted!`
macro.
