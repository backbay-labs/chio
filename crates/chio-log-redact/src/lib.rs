//! Log redaction primitives for Chio operator-facing telemetry.
//!
//! Use [`redacted!`] at any log site that may carry payload, body, prompt,
//! tool arguments, tool output, user message, or downstream response text.
//! Install [`RedactionLayer`] as the sink-facing tracing layer so every
//! observed event field is passed through the same default redaction tree.

#![forbid(unsafe_code)]

mod engine;
mod layer;

pub use engine::{
    redact_text, redact_text_with_classes, LogRedactError, LogRedactor, RedactedValue,
};
pub use layer::{
    MemoryRedactionSink, RedactedEvent, RedactedEventSink, RedactedField, RedactionLayer,
};

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

#[cfg(test)]
mod tests {
    use super::*;
    use chio_data_guards_redactors_default::RedactClass;
    use tracing_subscriber::prelude::*;

    fn secret_only_classes() -> RedactClass {
        RedactClass {
            secrets: true,
            pii_basic: false,
            pii_extended: false,
            bearer_tokens: false,
            custom: false,
        }
    }

    #[test]
    fn redacted_macro_masks_phi() {
        let rendered = redacted!("Patient jane@example.com SSN 123-45-6789").to_string();
        assert!(rendered.contains("[REDACTED-EMAIL]"));
        assert!(rendered.contains("[REDACTED-SSN]"));
        assert!(!rendered.contains("jane@example.com"));
        assert!(!rendered.contains("123-45-6789"));
    }

    #[test]
    fn log_redactor_reuses_validated_policy_for_text_and_display() -> Result<(), String> {
        let redactor =
            LogRedactor::with_classes(secret_only_classes()).map_err(|error| error.to_string())?;
        assert_eq!(redactor.classes(), secret_only_classes());

        let text = redactor
            .redact_text("contact jane@example.com with sk_live_abcdefghijklmnopqrstuvwx")
            .map_err(|error| error.to_string())?;
        assert!(text.contains("jane@example.com"));
        assert!(text.contains("[REDACTED-API-KEY]"));
        assert!(!text.contains("sk_live_abcdefghijklmnopqrstuvwx"));

        let rendered = RedactedValue::with_redactor(
            "contact jane@example.com with sk_live_abcdefghijklmnopqrstuvwx",
            &redactor,
        )
        .to_string();
        assert!(rendered.contains("jane@example.com"));
        assert!(rendered.contains("[REDACTED-API-KEY]"));
        assert!(!rendered.contains("sk_live_abcdefghijklmnopqrstuvwx"));
        Ok(())
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

    #[test]
    fn redaction_layer_redacts_utf8_byte_fields() -> Result<(), String> {
        let sink = MemoryRedactionSink::default();
        let layer = RedactionLayer::new(sink.clone()).map_err(|error| error.to_string())?;
        let subscriber = tracing_subscriber::registry().with(layer);
        let bytes = b"Patient jane@example.com SSN 123-45-6789";

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(payload = bytes.as_slice(), "dispatch failed");
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

    #[test]
    fn redaction_layer_redacts_event_target() -> Result<(), String> {
        let sink = MemoryRedactionSink::default();
        let layer = RedactionLayer::new(sink.clone()).map_err(|error| error.to_string())?;
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(target: "patient.jane@example.com", payload = "safe", "dispatch failed");
        });

        let events = sink.events();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert!(event.target.contains("[REDACTED-EMAIL]"));
        assert!(!event.target.contains("jane@example.com"));
        Ok(())
    }

    #[test]
    fn redaction_layer_uses_supplied_redactor_for_target_and_fields() -> Result<(), String> {
        let sink = MemoryRedactionSink::default();
        let redactor =
            LogRedactor::with_classes(secret_only_classes()).map_err(|error| error.to_string())?;
        let layer = RedactionLayer::with_redactor(sink.clone(), redactor);
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                target: "patient.jane@example.com",
                payload = "contact jane@example.com with sk_live_abcdefghijklmnopqrstuvwx",
                "dispatch failed"
            );
        });

        let events = sink.events();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert!(event.target.contains("jane@example.com"));
        assert!(!event.target.contains("[REDACTED-EMAIL]"));

        let payload = event
            .fields
            .iter()
            .find(|field| field.name == "payload")
            .ok_or_else(|| "missing payload field".to_string())?;
        assert!(payload.value.contains("jane@example.com"));
        assert!(payload.value.contains("[REDACTED-API-KEY]"));
        assert!(!payload.value.contains("sk_live_abcdefghijklmnopqrstuvwx"));
        Ok(())
    }
}
