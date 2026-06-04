use std::fmt;
use std::sync::{Arc, Mutex};

use chio_data_guards_redactors_default::RedactClass;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

use crate::{LogRedactError, LogRedactor};

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
    redactor: LogRedactor,
}

impl<Sink> RedactionLayer<Sink>
where
    Sink: RedactedEventSink,
{
    pub fn new(sink: Sink) -> Result<Self, LogRedactError> {
        Self::with_classes(sink, RedactClass::default_full())
    }

    pub fn with_classes(sink: Sink, classes: RedactClass) -> Result<Self, LogRedactError> {
        let redactor = LogRedactor::with_classes(classes)?;
        Ok(Self::with_redactor(sink, redactor))
    }

    #[must_use]
    pub fn with_redactor(sink: Sink, redactor: LogRedactor) -> Self {
        Self { sink, redactor }
    }

    #[must_use]
    pub fn redactor(&self) -> LogRedactor {
        self.redactor
    }
}

impl<S, Sink> Layer<S> for RedactionLayer<Sink>
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    Sink: RedactedEventSink,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = RedactingVisitor::new(self.redactor);
        event.record(&mut visitor);
        let target = self.redactor.redact_str_or_placeholder(metadata.target());
        self.sink.record(RedactedEvent {
            target,
            level: *metadata.level(),
            fields: visitor.fields,
        });
    }
}

struct RedactingVisitor {
    redactor: LogRedactor,
    fields: Vec<RedactedField>,
}

impl RedactingVisitor {
    fn new(redactor: LogRedactor) -> Self {
        Self {
            redactor,
            fields: Vec::new(),
        }
    }

    fn push_value(&mut self, field: &Field, value: String) {
        let redacted = self.redactor.redact_str_or_placeholder(&value);
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

    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        self.push_value(field, String::from_utf8_lossy(value).into_owned());
    }
}
