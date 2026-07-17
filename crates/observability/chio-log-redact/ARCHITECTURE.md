# chio-log-redact architecture

## Overview

`chio-log-redact` is a pure adapter crate: no I/O, no kernel state,
`#![forbid(unsafe_code)]`. It sits at the operator-facing telemetry boundary,
between Chio log call sites that may carry sensitive text and the tracing
sinks that persist or display it. It is not a guard evaluator, policy engine,
or SIEM exporter; it delegates pattern matching to
`chio-data-guards-redactors-default`, a regex-driven redactor operating on
bytes, and builds two independent redaction paths on top of it: a macro for
individual log-site expressions, and a `tracing_subscriber::Layer` that
redacts every event as a backstop.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public re-exports, the `redacted!` macro, and the crate-level doc. |
| `src/engine.rs` | Text/`Display` redaction core: `LogRedactor`, `RedactedValue`, `LogRedactError`, and the free `redact_text`/`redact_text_with_classes` functions. |
| `src/layer.rs` | Tracing integration: `RedactionLayer<Sink>`, `RedactedEventSink`, `MemoryRedactionSink`, and the field-visiting `RedactingVisitor`. |

## Redaction paths

1. **Call site (`redacted!`)** - expands to `RedactedValue::new(value)`, which
   redacts the `Display` output under `RedactClass::default_full()`
   immediately and retains only the redacted string; the pre-redaction value
   is dropped after construction.
2. **Subscriber (`RedactionLayer`)** - `on_event` redacts the event's `target`
   and visits every field with `RedactingVisitor`, which redacts each value it
   records (`str`, `i64`, `u64`, `bool`, `bytes`, `debug`) before building a
   `RedactedEvent` and calling `Sink::record`. tracing-core's default `Visit`
   methods for `f64`, `i128`, `u128`, and `error` values delegate to
   `record_debug`, so no field type bypasses the override.

Both paths bottom out in `redact_text_with_classes`, which calls
`chio_data_guards_redactors_default::redact_payload` on the UTF-8 bytes and
re-validates the output is UTF-8.

## Invariants and failure modes

- Construction fails closed: `LogRedactor::new`/`with_classes` and
  `RedactionLayer::new`/`with_classes` call
  `validate_default_redactor_compiles()` and return
  `LogRedactError::DefaultRedactorInvalid` if the built-in patterns do not
  compile, before any event is redacted.
- The infallible paths never fall back to the original value on error:
  `RedactedValue`, `redact_display_or_placeholder`, and
  `RedactingVisitor::push_value` substitute the `[REDACTION-FAILED]`
  placeholder. Only the `Result`-returning primitives (`redact_text`,
  `redact_text_with_classes`, `LogRedactor::redact_text`, `redact_display`)
  surface `LogRedactError` to the caller instead.
- `redacted!` accepts exactly one expression; a `fmt, args` invocation is a
  `compile_error!`, so a call site cannot interpolate unredacted text into the
  macro's output.
- `RedactionLayer` redacts unconditionally, independent of `redacted!`: every
  event's target and every field are redacted whether or not the call site
  used the macro.
- The crate does not escape control characters. A value that survives
  redaction can still carry a raw `\n` or `\r`; a sink that writes one event
  per line must escape them itself to prevent log-line forgery (`chio-cli`
  does this before writing to stderr).
- `RedactClass` is not re-exported; selecting non-default classes requires a
  direct dependency on `chio-data-guards-redactors-default`.

## Dependencies

Internal: `chio-data-guards-redactors-default` supplies `RedactClass`,
`redact_payload`, and `validate_default_redactor_compiles`; no dependency
aliasing. External: `tracing` for event and field types, `tracing-subscriber`
(`registry` feature) for `Layer` and `LookupSpan`, `thiserror` for
`LogRedactError`.

## Extension points

`RedactedEventSink` is the trait a consumer implements to receive redacted
events, or a `Fn(RedactedEvent) + Send + Sync + 'static` closure via the
blanket impl. `MemoryRedactionSink` is the crate's only concrete sink and is
meant for tests and embedding probes; production consumers implement their
own (`chio-cli` writes one control-encoded line per event to stderr).

## Dependents

`chio-kernel` and `chio-siem` use the `redacted!` macro at log sites.
`chio-cli` installs `RedactionLayer` as the sole event-formatting layer on the
process tracing subscriber.
