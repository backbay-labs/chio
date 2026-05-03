//! CEF formatter for Chio receipt audit events.
//!
//! The M01 healthcare design-partner pilot ships CEF as the first text SIEM
//! format alongside the existing OCSF JSON mapper. This module formats one
//! CEF v0 event per receipt. Transport remains owned by existing webhook or
//! collector-specific exporters.

use crate::event::SiemEvent;
use crate::exporter::{ExportError, ExportFuture, Exporter};
use chio_core::receipt::Decision;

#[derive(Debug, Clone)]
pub struct CefExporterConfig {
    pub device_vendor: String,
    pub device_product: String,
    pub device_version: String,
}

impl Default for CefExporterConfig {
    fn default() -> Self {
        Self {
            device_vendor: "Backbay Industries".to_string(),
            device_product: "Chio".to_string(),
            device_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CefExporter {
    config: CefExporterConfig,
}

impl CefExporter {
    #[must_use]
    pub fn new(config: CefExporterConfig) -> Self {
        Self { config }
    }

    pub fn format_events(&self, events: &[SiemEvent]) -> Result<Vec<String>, ExportError> {
        events
            .iter()
            .map(|event| self.format_event(event))
            .collect()
    }

    pub fn format_event(&self, event: &SiemEvent) -> Result<String, ExportError> {
        let receipt = &event.receipt;
        let decision = decision_label(&receipt.decision);
        let signature_id = signature_id(&receipt.decision);
        let name = event_name(&receipt.decision);
        let severity = severity(&receipt.decision);
        let reason = reason_code(&receipt.decision);
        let tenant_id = receipt
            .tenant_id
            .as_deref()
            .or_else(|| metadata_str(receipt.metadata.as_ref(), "tenant_id"))
            .unwrap_or("single-tenant");
        let actor_subject =
            metadata_str(receipt.metadata.as_ref(), "actor_subject").unwrap_or("chio-agent");
        let redaction_status =
            metadata_str(receipt.metadata.as_ref(), "redaction_status").unwrap_or("unknown");
        let checkpoint_id = metadata_str(receipt.metadata.as_ref(), "checkpoint_id")
            .unwrap_or("checkpoint-pending");
        let rt_ms = receipt.timestamp.saturating_mul(1_000);

        let header = format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|",
            escape_header(&self.config.device_vendor),
            escape_header(&self.config.device_product),
            escape_header(&self.config.device_version),
            escape_header(signature_id),
            escape_header(name),
            severity
        );

        let extension = [
            ("rt", rt_ms.to_string()),
            ("msg", reason.to_string()),
            ("act", decision.to_string()),
            ("suser", actor_subject.to_string()),
            ("dvc", receipt.tool_server.clone()),
            ("dvchost", receipt.tool_name.clone()),
            ("cs1Label", "receipt_id".to_string()),
            ("cs1", receipt.id.clone()),
            ("cs2Label", "capability_id".to_string()),
            ("cs2", receipt.capability_id.clone()),
            ("cs3Label", "policy_hash".to_string()),
            ("cs3", receipt.policy_hash.clone()),
            ("cs4Label", "parameter_hash".to_string()),
            ("cs4", receipt.action.parameter_hash.clone()),
            ("cs5Label", "tenant_id".to_string()),
            ("cs5", tenant_id.to_string()),
            ("cs6Label", "redaction_status".to_string()),
            ("cs6", redaction_status.to_string()),
            ("flexString1Label", "checkpoint_id".to_string()),
            ("flexString1", checkpoint_id.to_string()),
        ]
        .into_iter()
        .map(|(key, value)| format!("{key}={}", escape_extension(&value)))
        .collect::<Vec<String>>()
        .join(" ");

        Ok(format!("{header}{extension}"))
    }
}

impl Exporter for CefExporter {
    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        Box::pin(async move {
            let formatted = self.format_events(events)?;
            Ok(formatted.len())
        })
    }

    fn name(&self) -> &str {
        "cef"
    }
}

fn metadata_str<'a>(metadata: Option<&'a serde_json::Value>, key: &str) -> Option<&'a str> {
    metadata
        .and_then(|value| value.get(key))
        .and_then(|value| value.as_str())
}

fn decision_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny { .. } => "deny",
        Decision::Cancelled { .. } => "cancelled",
        Decision::Incomplete { .. } => "incomplete",
    }
}

fn signature_id(decision: &Decision) -> &str {
    match decision {
        Decision::Allow => "chio.allow",
        Decision::Deny { guard, .. } => guard.as_str(),
        Decision::Cancelled { .. } => "chio.cancelled",
        Decision::Incomplete { .. } => "chio.incomplete",
    }
}

fn event_name(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "Chio allow",
        Decision::Deny { .. } => "Chio guard deny",
        Decision::Cancelled { .. } => "Chio cancelled",
        Decision::Incomplete { .. } => "Chio incomplete",
    }
}

fn reason_code(decision: &Decision) -> &str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny { reason, .. } => reason.as_str(),
        Decision::Cancelled { reason } => reason.as_str(),
        Decision::Incomplete { reason } => reason.as_str(),
    }
}

fn severity(decision: &Decision) -> u8 {
    match decision {
        Decision::Allow => 2,
        Decision::Deny { .. } => 8,
        Decision::Cancelled { .. } => 4,
        Decision::Incomplete { .. } => 5,
    }
}

fn escape_header(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => "\\\\".chars().collect::<Vec<char>>(),
            '|' => "\\|".chars().collect::<Vec<char>>(),
            '\n' | '\r' => " ".chars().collect::<Vec<char>>(),
            other => vec![other],
        })
        .collect()
}

fn escape_extension(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => "\\\\".chars().collect::<Vec<char>>(),
            '=' => "\\=".chars().collect::<Vec<char>>(),
            '\n' | '\r' => " ".chars().collect::<Vec<char>>(),
            other => vec![other],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_header_separator() {
        assert_eq!(escape_header("a|b"), "a\\|b");
    }

    #[test]
    fn escapes_extension_equals() {
        assert_eq!(escape_extension("a=b"), "a\\=b");
    }
}
