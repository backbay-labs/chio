//! Log redaction primitives for Chio operator-facing telemetry.
//!
//! Use [`redacted!`] at any log site that may carry payload, body, prompt,
//! tool arguments, tool output, user message, or downstream response text.
//! Install [`RedactionLayer`] as the sink-facing tracing layer so every
//! observed event field is passed through the same default redaction tree.

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::{Arc, Mutex};

use chio_data_guards_redactors_default::{
    redact_payload, validate_default_redactor_compiles, RedactClass, RedactError,
};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

const REDACTION_FAILED_PLACEHOLDER: &str = "[REDACTION-FAILED]";

/// Failure modes for strict log redaction setup.
#[derive(Debug, thiserror::Error)]
pub enum LogRedactError {
    #[error("default redactor patterns failed to compile: {0}")]
    DefaultRedactorInvalid(String),
    #[error("log redaction failed: {0}")]
    RedactionFailed(String),
}

impl From<RedactError> for LogRedactError {
    fn from(error: RedactError) -> Self {
        Self::RedactionFailed(error.to_string())
    }
}

/// Redact a UTF-8 string with the default production redactor classes.
pub fn redact_text(value: &str) -> Result<String, LogRedactError> {
    redact_text_with_classes(value, RedactClass::default_full())
}

/// Redact a UTF-8 string with caller-selected classes.
pub fn redact_text_with_classes(
    value: &str,
    classes: RedactClass,
) -> Result<String, LogRedactError> {
    let redacted = redact_payload(value.as_bytes(), classes)?;
    String::from_utf8(redacted.bytes).map_err(|error| {
        LogRedactError::RedactionFailed(format!("redacted output was not utf-8: {error}"))
    })
}

/// Display wrapper that never falls back to the original value on failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactedValue {
    redacted: String,
}

impl RedactedValue {
    #[must_use]
    pub fn new(value: impl fmt::Display) -> Self {
        let original = value.to_string();
        let redacted =
            redact_text(&original).unwrap_or_else(|_| REDACTION_FAILED_PLACEHOLDER.to_string());
        Self { redacted }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.redacted
    }
}

impl fmt::Display for RedactedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.redacted)
    }
}

/// Redact one payload expression before it enters a log field.
///
/// This macro intentionally rejects formatting-style invocations. Build the
/// structured fields separately, then wrap each sensitive value with
/// `redacted!(value)`.
///
/// ```compile_fail
/// let payload = "Patient SSN 123-45-6789";
/// let _ = chio_log_redact::redacted!("payload {}", payload);
/// ```
#[macro_export]
macro_rules! redacted {
    ($value:expr $(,)?) => {
        $crate::RedactedValue::new($value)
    };
    ($fmt:literal, $($arg:tt)+) => {
        compile_error!(
            "redacted! accepts one payload expression; formatting inside redacted! is forbidden"
        )
    };
}

/// One redacted field captured from a tracing event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedField {
    pub name: String,
    pub value: String,
}

/// One redacted event emitted by [`RedactionLayer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedEvent {
    pub target: String,
    pub level: Level,
    pub fields: Vec<RedactedField>,
}

/// Sink for redacted tracing events.
pub trait RedactedEventSink: Send + Sync + 'static {
    fn record(&self, event: RedactedEvent);
}

impl<F> RedactedEventSink for F
where
    F: Fn(RedactedEvent) + Send + Sync + 'static,
{
    fn record(&self, event: RedactedEvent) {
        self(event);
    }
}

/// In-memory sink useful for smoke tests and embedding probes.
#[derive(Debug, Clone, Default)]
pub struct MemoryRedactionSink {
    events: Arc<Mutex<Vec<RedactedEvent>>>,
}

impl MemoryRedactionSink {
    #[must_use]
    pub fn events(&self) -> Vec<RedactedEvent> {
        match self.events.lock() {
            Ok(events) => events.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl RedactedEventSink for MemoryRedactionSink {
    fn record(&self, event: RedactedEvent) {
        match self.events.lock() {
            Ok(mut events) => events.push(event),
            Err(poisoned) => poisoned.into_inner().push(event),
        }
    }
}

/// Tracing layer that redacts every recorded event field before handing it to
/// a sink.
pub struct RedactionLayer<Sink> {
    sink: Sink,
    classes: RedactClass,
}

impl<Sink> RedactionLayer<Sink>
where
    Sink: RedactedEventSink,
{
    pub fn new(sink: Sink) -> Result<Self, LogRedactError> {
        Self::with_classes(sink, RedactClass::default_full())
    }

    pub fn with_classes(sink: Sink, classes: RedactClass) -> Result<Self, LogRedactError> {
        validate_default_redactor_compiles()
            .map_err(|failures| LogRedactError::DefaultRedactorInvalid(failures.join(", ")))?;
        Ok(Self { sink, classes })
    }
}

impl<S, Sink> Layer<S> for RedactionLayer<Sink>
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    Sink: RedactedEventSink,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = RedactingVisitor::new(self.classes);
        event.record(&mut visitor);
        self.sink.record(RedactedEvent {
            target: metadata.target().to_string(),
            level: *metadata.level(),
            fields: visitor.fields,
        });
    }
}

struct RedactingVisitor {
    classes: RedactClass,
    fields: Vec<RedactedField>,
}

impl RedactingVisitor {
    fn new(classes: RedactClass) -> Self {
        Self {
            classes,
            fields: Vec::new(),
        }
    }

    fn push_value(&mut self, field: &Field, value: String) {
        let redacted = redact_text_with_classes(&value, self.classes)
            .unwrap_or_else(|_| REDACTION_FAILED_PLACEHOLDER.to_string());
        self.fields.push(RedactedField {
            name: field.name().to_string(),
            value: redacted,
        });
    }
}

impl Visit for RedactingVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.push_value(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.push_value(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push_value(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push_value(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push_value(field, value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    #[test]
    fn redacted_macro_masks_phi() {
        let rendered = redacted!("Patient jane@example.com SSN 123-45-6789").to_string();
        assert!(rendered.contains("[REDACTED-EMAIL]"));
        assert!(rendered.contains("[REDACTED-SSN]"));
        assert!(!rendered.contains("jane@example.com"));
        assert!(!rendered.contains("123-45-6789"));
    }

    #[test]
    fn redaction_layer_records_only_redacted_fields() -> Result<(), String> {
        let sink = MemoryRedactionSink::default();
        let layer = RedactionLayer::new(sink.clone()).map_err(|error| error.to_string())?;
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                payload = "Patient jane@example.com SSN 123-45-6789",
                "dispatch failed"
            );
        });

        let events = sink.events();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        let payload = event
            .fields
            .iter()
            .find(|field| field.name == "payload")
            .ok_or_else(|| "missing payload field".to_string())?;
        assert!(payload.value.contains("[REDACTED-EMAIL]"));
        assert!(payload.value.contains("[REDACTED-SSN]"));
        assert!(!payload.value.contains("jane@example.com"));
        assert!(!payload.value.contains("123-45-6789"));
        Ok(())
    }
}
