//! CEF formatter for Chio receipt audit events.
//!
//! CEF is the text SIEM format shipped alongside the OCSF JSON mapper.
//! This module formats one CEF v0 event per receipt. Transport remains
//! owned by existing webhook or collector-specific exporters.

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
            device_vendor: "Backbay Labs".to_string(),
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
        let decision = decision_label(event);
        let signature_id = signature_id(event);
        let name = event_name(event);
        let severity = severity(event);
        let reason = reason_code(event);
        let tenant_id = receipt.tenant_id.as_deref().unwrap_or("single-tenant");
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
            ("receiptKind", event.receipt_kind.clone()),
            ("boundaryClass", event.boundary_class.clone()),
            ("result", event.result.clone()),
            ("authorized", event.authorized.to_string()),
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

fn decision_label(event: &SiemEvent) -> &str {
    if !event.is_authorized() && matches!(&event.receipt.decision, Some(Decision::Allow)) {
        return event.receipt_kind.as_str();
    }
    match &event.receipt.decision {
        Some(Decision::Allow) => "allow",
        Some(Decision::Deny { .. }) => "deny",
        Some(Decision::Cancelled { .. }) => "cancelled",
        Some(Decision::Incomplete { .. }) => "incomplete",
        None => event.receipt_kind.as_str(),
    }
}

fn signature_id(event: &SiemEvent) -> &str {
    if !event.is_authorized() && matches!(&event.receipt.decision, Some(Decision::Allow)) {
        return match event.receipt_kind.as_str() {
            "trace_observation" => "chio.trace_observation",
            "advisory_evaluation" => "chio.advisory_evaluation",
            _ => "chio.observation",
        };
    }
    match &event.receipt.decision {
        Some(Decision::Allow) => "chio.allow",
        Some(Decision::Deny { guard, .. }) => guard.as_str(),
        Some(Decision::Cancelled { .. }) => "chio.cancelled",
        Some(Decision::Incomplete { .. }) => "chio.incomplete",
        None => match event.receipt_kind.as_str() {
            "trace_observation" => "chio.trace_observation",
            "advisory_evaluation" => "chio.advisory_evaluation",
            _ => "chio.observation",
        },
    }
}

fn event_name(event: &SiemEvent) -> &'static str {
    if !event.is_authorized() && matches!(&event.receipt.decision, Some(Decision::Allow)) {
        return match event.receipt_kind.as_str() {
            "trace_observation" => "Chio trace observation",
            "advisory_evaluation" => "Chio advisory evaluation",
            _ => "Chio observation",
        };
    }
    match &event.receipt.decision {
        Some(Decision::Allow) => "Chio allow",
        Some(Decision::Deny { .. }) => "Chio guard deny",
        Some(Decision::Cancelled { .. }) => "Chio cancelled",
        Some(Decision::Incomplete { .. }) => "Chio incomplete",
        None => match event.receipt_kind.as_str() {
            "trace_observation" => "Chio trace observation",
            "advisory_evaluation" => "Chio advisory evaluation",
            _ => "Chio observation",
        },
    }
}

fn reason_code(event: &SiemEvent) -> &str {
    if !event.is_authorized() && matches!(&event.receipt.decision, Some(Decision::Allow)) {
        return event.result.as_str();
    }
    match &event.receipt.decision {
        Some(Decision::Allow) => "allow",
        Some(Decision::Deny { reason, .. }) => reason.as_str(),
        Some(Decision::Cancelled { reason }) => reason.as_str(),
        Some(Decision::Incomplete { reason }) => reason.as_str(),
        None => event.result.as_str(),
    }
}

fn severity(event: &SiemEvent) -> u8 {
    if !event.is_authorized() && matches!(&event.receipt.decision, Some(Decision::Allow)) {
        return 3;
    }
    match &event.receipt.decision {
        Some(Decision::Allow) => 2,
        Some(Decision::Deny { .. }) => 8,
        Some(Decision::Cancelled { .. }) => 4,
        Some(Decision::Incomplete { .. }) => 5,
        None => 3,
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
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{
        ChioReceipt, ChioReceiptBody, Decision, ReceiptSemanticFields, ToolCallAction, TrustLevel,
    };
    use chio_test_support::prelude::*;

    #[test]
    fn escapes_header_separator() {
        assert_eq!(escape_header("a|b"), "a\\|b");
    }

    #[test]
    fn escapes_extension_equals() {
        assert_eq!(escape_extension("a=b"), "a\\=b");
    }

    #[test]
    fn trace_observation_allow_formats_as_trace_not_authorization_allow() {
        let event = SiemEvent::from_receipt(test_receipt_with_semantics(
            Decision::Allow,
            ReceiptSemanticFields::trace_detect_only(),
            TrustLevel::Verified,
        ));
        let cef = CefExporter::default()
            .format_event(&event)
            .test_expect("format trace CEF");

        assert!(cef.contains("receiptKind=trace_observation"));
        assert!(cef.contains("boundaryClass=detect_only"));
        assert!(cef.contains("authorized=false"));
        assert!(!cef.contains("act=allow"));
        assert!(!cef.contains("chio.allow"));
        assert!(!cef.contains("Chio allow"));
    }

    #[test]
    fn metadata_tenant_id_does_not_drive_authoritative_cef_tenant() {
        let mut receipt = test_receipt_with_semantics(
            Decision::Allow,
            ReceiptSemanticFields::mediated_prevent(),
            TrustLevel::Mediated,
        );
        receipt.metadata = Some(serde_json::json!({
            "tenant_id": "metadata-tenant"
        }));
        let event = SiemEvent::from_receipt(receipt);
        let cef = CefExporter::default()
            .format_event(&event)
            .test_expect("format CEF");

        assert!(cef.contains("cs5=single-tenant"));
        assert!(!cef.contains("metadata-tenant"));
    }

    fn test_receipt_with_semantics(
        decision: Decision,
        semantics: ReceiptSemanticFields,
        trust_level: TrustLevel,
    ) -> ChioReceipt {
        let kp = Keypair::generate();
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "path": "/etc/passwd"
        }))
        .test_expect("hash test receipt parameters");
        let decision = if semantics.receipt_kind == chio_core::ReceiptKind::MediatedDecision {
            Some(decision)
        } else {
            None
        };
        ChioReceipt::sign(
            ChioReceiptBody {
                id: "trace-cef-1".to_string(),
                timestamp: 1_712_345_678,
                capability_id: "cap-abc".to_string(),
                tool_server: "srv-files".to_string(),
                tool_name: "file_read".to_string(),
                action,
                decision,
                receipt_kind: semantics.receipt_kind,
                boundary_class: semantics.boundary_class,
                observation_outcome: semantics.observation_outcome,
                tool_origin: semantics.tool_origin,
                redaction_mode: semantics.redaction_mode,
                actor_chain: semantics.actor_chain,
                content_hash: "content-xyz".to_string(),
                policy_hash: "policy-xyz".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level,
                tenant_id: None,
                kernel_key: kp.public_key(),
            },
            &kp,
        )
        .test_expect("sign test receipt")
    }
}
