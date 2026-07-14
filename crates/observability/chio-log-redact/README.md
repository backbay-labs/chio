# chio-log-redact

Tracing log-redaction primitives for Chio's operator-facing telemetry. Wraps
`chio-data-guards-redactors-default`'s regex-driven byte redactor in a text,
`Display`, and `tracing_subscriber::Layer` surface so payload-like log content
is redacted before it reaches a sink.

## Responsibilities

- Redact UTF-8 text and `Display` values under a selected `RedactClass` policy.
- Provide `redacted!(value)`, a macro that wraps exactly one payload expression
  for use at a log call site; formatting-style invocations are a compile error.
- Provide `RedactionLayer`, a `tracing_subscriber::Layer` that redacts an
  event's target and every field before handing a `RedactedEvent` to a sink,
  independently of whether the call site used `redacted!`.
- Fail closed: construction validates the default redactor patterns compile,
  and `RedactedValue` substitutes `[REDACTION-FAILED]` rather than ever
  rendering the pre-redaction value.

## Public API

- `redacted!(value)` - wrap one payload expression; returns a `RedactedValue`.
- `LogRedactor` - validated policy handle (`new`, `with_classes`, `classes`,
  `redact_text`, `redact_display`, `redact_display_or_placeholder`).
- `RedactedValue` - `Display` wrapper holding only the redacted string (`new`,
  `with_classes`, `with_redactor`, `as_str`).
- `redact_text`, `redact_text_with_classes` - free functions for one-off
  string redaction.
- `RedactionLayer<Sink>` - the tracing layer (`new`, `with_classes`,
  `with_redactor`, `redactor`).
- `RedactedEventSink` - trait a sink implements, or a `Fn(RedactedEvent)`
  closure via the blanket impl.
- `MemoryRedactionSink` - in-memory sink for tests and embedding probes.
- `RedactedEvent`, `RedactedField` - the event shape delivered to a sink.
- `LogRedactError` - `DefaultRedactorInvalid`, `RedactionFailed`.

Selecting non-default `RedactClass` values requires depending on
`chio-data-guards-redactors-default` directly; this crate does not re-export it.

## Usage

```rust
use chio_log_redact::{redacted, RedactionLayer};
use tracing_subscriber::prelude::*;

let redaction = RedactionLayer::new(|event: chio_log_redact::RedactedEvent| {
    eprintln!("{} {} {:?}", event.level, event.target, event.fields);
})?;
tracing_subscriber::registry().with(redaction).init();

tracing::warn!(payload = %redacted!(user_message), "dispatch failed");
```

## Testing

`cargo test -p chio-log-redact`

## See also

- `chio-data-guards-redactors-default` - the byte redactor this crate wraps.
- `chio-kernel` - uses `redacted!` at kernel log sites.
- `chio-siem` - wraps `redacted!` in its own operator-log redaction helper.
- `chio-cli` - installs `RedactionLayer` as the process tracing subscriber's
  event-formatting layer.
