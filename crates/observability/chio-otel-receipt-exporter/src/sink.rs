use std::sync::Arc;

use chio_core::canonical::CanonicalBytes;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::ToolCallAction, kinds::BoundaryClass,
    kinds::ObservationOutcome, kinds::ReceiptKind, kinds::RedactionMode, kinds::ToolOrigin,
    kinds::TrustLevel,
};
use chio_core::{sha256_hex, Keypair};
use chio_kernel::otel::{
    ATTR_CHIO_AGENT_ID, ATTR_CHIO_KERNEL_ID, ATTR_CHIO_RECEIPT_ID, ATTR_CHIO_SERVER_ID,
    ATTR_GEN_AI_TOOL_NAME,
};
use chio_kernel::receipt_store::{ReceiptStore, ReceiptStoreError};
use uuid::Uuid;

use crate::denylist::strip_denied_attributes;
use crate::ingress::{attributes_to_map, OtlpGrpcTraceExport, OtlpSpan};

pub const RECEIPT_EXPORT_MAX_RESOURCE_SPANS: usize = 4_096;
pub const RECEIPT_EXPORT_MAX_SPANS: usize = 65_536;
pub const RECEIPT_EXPORT_MAX_ESTIMATED_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct ReceiptStoreSinkConfig {
    pub signing_keypair: Keypair,
    pub policy_hash: String,
    pub default_capability_id: String,
    pub default_tool_server: String,
    pub default_tool_name: String,
    pub tenant_id: Option<String>,
}

impl ReceiptStoreSinkConfig {
    pub fn new(signing_keypair: Keypair) -> Self {
        Self {
            signing_keypair,
            policy_hash: "otel-receipt-exporter".to_string(),
            default_capability_id: "otel-ingress".to_string(),
            default_tool_server: "otel-collector".to_string(),
            default_tool_name: "gen_ai.tool.call".to_string(),
            tenant_id: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReceiptStoreSinkSummary {
    pub accepted_spans: usize,
    pub appended_receipts: usize,
}

#[derive(Clone, Debug)]
pub struct CanonicalChioReceipt {
    receipt: ChioReceipt,
    canonical: Arc<CanonicalBytes>,
}

impl CanonicalChioReceipt {
    fn from_receipt(receipt: ChioReceipt) -> Result<Self, OTelReceiptExportError> {
        let canonical = Arc::new(
            CanonicalBytes::from_serializable(&receipt)
                .map_err(|error| OTelReceiptExportError::Canonical(error.to_string()))?,
        );
        Ok(Self { receipt, canonical })
    }

    #[must_use]
    pub fn receipt(&self) -> &ChioReceipt {
        &self.receipt
    }

    /// The signed receipt id (stable across retries once prepared).
    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt.id
    }

    #[must_use]
    pub fn canonical(&self) -> &Arc<CanonicalBytes> {
        &self.canonical
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    #[must_use]
    pub fn into_receipt(self) -> ChioReceipt {
        self.receipt
    }

    #[must_use]
    pub fn into_parts(self) -> (ChioReceipt, Arc<CanonicalBytes>) {
        (self.receipt, self.canonical)
    }
}

pub trait CanonicalReceiptSink: Send + Sync {
    fn append_chio_receipt_canonical(
        &self,
        receipt: CanonicalChioReceipt,
    ) -> Result<(), ReceiptStoreError>;
}

struct ReceiptStoreCanonicalAdapter {
    store: Arc<dyn ReceiptStore>,
}

impl ReceiptStoreCanonicalAdapter {
    fn new(store: Arc<dyn ReceiptStore>) -> Self {
        Self { store }
    }
}

impl CanonicalReceiptSink for ReceiptStoreCanonicalAdapter {
    fn append_chio_receipt_canonical(
        &self,
        receipt: CanonicalChioReceipt,
    ) -> Result<(), ReceiptStoreError> {
        self.store
            .append_chio_receipt_canonical(receipt.receipt(), receipt.canonical().as_ref())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OTelReceiptExportError {
    #[error("invalid OTLP span provenance: {0}")]
    InvalidSpan(String),
    #[error("failed to canonicalize OTLP span: {0}")]
    Canonical(String),
    #[error("failed to sign Chio receipt: {0}")]
    Sign(chio_core::error::Error),
    #[error("OTEL exporter queue error: {0}")]
    Queue(String),
    #[error("failed to append Chio receipt: {0}")]
    ReceiptStore(#[from] ReceiptStoreError),
}

impl OTelReceiptExportError {
    pub(crate) fn is_retryable_batch_error(&self) -> bool {
        matches!(
            self,
            Self::ReceiptStore(ReceiptStoreError::Pool(_)) | Self::Queue(_)
        )
    }
}

pub struct ReceiptStoreSink {
    sink: Arc<dyn CanonicalReceiptSink>,
    config: ReceiptStoreSinkConfig,
}

impl ReceiptStoreSink {
    pub fn new(store: Arc<dyn ReceiptStore>, config: ReceiptStoreSinkConfig) -> Self {
        Self::from_receipt_store(store, config)
    }

    pub fn from_receipt_store(
        store: Arc<dyn ReceiptStore>,
        config: ReceiptStoreSinkConfig,
    ) -> Self {
        Self::new_canonical(Arc::new(ReceiptStoreCanonicalAdapter::new(store)), config)
    }

    pub fn new_canonical(
        sink: Arc<dyn CanonicalReceiptSink>,
        config: ReceiptStoreSinkConfig,
    ) -> Self {
        Self { sink, config }
    }

    /// Generate the signed receipts for a batch once (pure, no store append).
    /// The caller caches the result so a retry never re-signs and never mints a
    /// fresh id for a span that was already prepared.
    pub fn prepare_receipts(
        &self,
        export: &OtlpGrpcTraceExport,
    ) -> Result<Vec<CanonicalChioReceipt>, OTelReceiptExportError> {
        validate_export_batch_limits(export)?;
        export
            .spans()
            .map(|span| self.canonical_receipt_for_span(span))
            .collect()
    }

    /// Append `receipts[*appended..]`, advancing `*appended` after each success.
    /// Returns Err on the first failed append (with `*appended` = how many
    /// succeeded), so the caller can resume at exactly that cursor with the
    /// SAME ids.
    pub fn append_from(
        &self,
        receipts: &[CanonicalChioReceipt],
        appended: &mut usize,
    ) -> Result<(), OTelReceiptExportError> {
        while *appended < receipts.len() {
            self.sink
                .append_chio_receipt_canonical(receipts[*appended].clone())?;
            *appended += 1;
        }
        Ok(())
    }

    pub fn export_traces(
        &self,
        export: &OtlpGrpcTraceExport,
    ) -> Result<ReceiptStoreSinkSummary, OTelReceiptExportError> {
        let receipts = self.prepare_receipts(export)?;
        let mut appended = 0usize;
        self.append_from(&receipts, &mut appended)?;
        Ok(ReceiptStoreSinkSummary {
            accepted_spans: appended,
            appended_receipts: appended,
        })
    }

    pub fn receipt_for_span(&self, span: &OtlpSpan) -> Result<ChioReceipt, OTelReceiptExportError> {
        Ok(self.canonical_receipt_for_span(span)?.into_receipt())
    }

    pub fn canonical_receipt_for_span(
        &self,
        span: &OtlpSpan,
    ) -> Result<CanonicalChioReceipt, OTelReceiptExportError> {
        validate_trace_id(&span.trace_id)?;
        validate_span_id(&span.span_id)?;
        let source_receipt_id = optional_source_receipt_id(span)?;

        let sanitized_attributes = strip_denied_attributes(&span.attributes);
        let sanitized_attribute_map = attributes_to_map(&sanitized_attributes);
        let source_attribute_map = span.attribute_map();
        let source_payload = serde_json::json!({
            "trace_id": span.trace_id,
            "span_id": span.span_id,
            "name": span.name,
            "attributes": source_attribute_map,
            "started_at_unix_nano": span.started_at_unix_nano,
            "ended_at_unix_nano": span.ended_at_unix_nano,
        });
        let canonical_span = CanonicalBytes::from_value(&source_payload)
            .map_err(|error| OTelReceiptExportError::Canonical(error.to_string()))?;
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "span_name": span.name,
            "attributes": sanitized_attribute_map,
        }))
        .map_err(OTelReceiptExportError::Sign)?;
        validate_span_verdict(span)?;
        let capability_id = optional_routing_attribute(span, "chio.capability.id")?
            .unwrap_or_else(|| self.config.default_capability_id.clone());
        let tool_server = optional_routing_attribute(span, ATTR_CHIO_SERVER_ID)?
            .unwrap_or_else(|| self.config.default_tool_server.clone());
        let tool_name = optional_routing_attribute(span, ATTR_GEN_AI_TOOL_NAME)?
            .unwrap_or_else(|| self.config.default_tool_name.clone());

        let body = ChioReceiptBody {
            id: next_receipt_id(),
            timestamp: timestamp_from_span(span),
            capability_id,
            tool_server,
            tool_name,
            action,
            decision: None,
            receipt_kind: ReceiptKind::TraceObservation,
            boundary_class: BoundaryClass::DetectOnly,
            observation_outcome: Some(ObservationOutcome::Observed),
            tool_origin: ToolOrigin::HostExecutedProviderReported,
            redaction_mode: RedactionMode::Summary,
            actor_chain: Vec::new(),
            content_hash: sha256_hex(canonical_span.as_bytes()),
            policy_hash: self.config.policy_hash.clone(),
            evidence: Vec::new(),
            metadata: Some(receipt_metadata(
                span,
                &sanitized_attributes,
                source_receipt_id,
            )),
            trust_level: TrustLevel::Verified,
            tenant_id: self.config.tenant_id.clone(),
            kernel_key: self.config.signing_keypair.public_key(),
            bbs_projection_version: None,
        };

        let receipt = ChioReceipt::sign(body, &self.config.signing_keypair)
            .map_err(OTelReceiptExportError::Sign)?;
        CanonicalChioReceipt::from_receipt(receipt)
    }
}

fn optional_source_receipt_id(span: &OtlpSpan) -> Result<Option<&str>, OTelReceiptExportError> {
    match span.attribute_value(ATTR_CHIO_RECEIPT_ID) {
        None => Ok(None),
        Some(serde_json::Value::String(value)) if is_chio_receipt_id(value) => {
            Ok(Some(value.as_str()))
        }
        Some(serde_json::Value::String(_)) => Err(OTelReceiptExportError::InvalidSpan(format!(
            "{ATTR_CHIO_RECEIPT_ID} must be a 64-character lowercase hex receipt id"
        ))),
        Some(value) => Err(OTelReceiptExportError::InvalidSpan(format!(
            "{ATTR_CHIO_RECEIPT_ID} must be a string, got {value}"
        ))),
    }
}

fn optional_routing_attribute(
    span: &OtlpSpan,
    key: &str,
) -> Result<Option<String>, OTelReceiptExportError> {
    match span.attribute_value(key) {
        None => Ok(None),
        Some(serde_json::Value::String(value)) if is_non_empty_unpadded(value) => {
            Ok(Some(value.clone()))
        }
        Some(serde_json::Value::String(_)) => Err(OTelReceiptExportError::InvalidSpan(format!(
            "{key} must be a non-empty unpadded string"
        ))),
        Some(value) => Err(OTelReceiptExportError::InvalidSpan(format!(
            "{key} must be a string, got {value}"
        ))),
    }
}

fn is_non_empty_unpadded(value: &str) -> bool {
    !value.is_empty() && value.trim() == value
}

fn is_chio_receipt_id(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|char| matches!(char, '0'..='9' | 'a'..='f'))
}

fn validate_export_batch_limits(
    export: &OtlpGrpcTraceExport,
) -> Result<(), OTelReceiptExportError> {
    let resource_spans = export.resource_spans.len();
    if resource_spans > RECEIPT_EXPORT_MAX_RESOURCE_SPANS {
        return Err(OTelReceiptExportError::Queue(format!(
            "OTLP export resource span group count {resource_spans} exceeds max {RECEIPT_EXPORT_MAX_RESOURCE_SPANS}"
        )));
    }

    let span_count = export.span_count();
    if span_count > RECEIPT_EXPORT_MAX_SPANS {
        return Err(OTelReceiptExportError::Queue(format!(
            "OTLP export span count {span_count} exceeds max {RECEIPT_EXPORT_MAX_SPANS}"
        )));
    }

    let estimated_bytes = export.estimated_bytes();
    if estimated_bytes > RECEIPT_EXPORT_MAX_ESTIMATED_BYTES {
        return Err(OTelReceiptExportError::Queue(format!(
            "OTLP export estimated byte size {estimated_bytes} exceeds max {RECEIPT_EXPORT_MAX_ESTIMATED_BYTES}"
        )));
    }

    Ok(())
}

fn receipt_metadata(
    span: &OtlpSpan,
    sanitized_attributes: &[crate::ingress::OtlpAttribute],
    source_receipt_id: Option<&str>,
) -> serde_json::Value {
    let mut metadata = serde_json::json!({
        "provenance": {
            "otel": {
                "trace_id": span.trace_id,
                "span_id": span.span_id
            }
        },
        "otel": {
            "schema": "otlp.grpc.trace.v1",
            "span_name": span.name,
            "kernel_id": span.attribute_string(ATTR_CHIO_KERNEL_ID),
            "agent_id": span.attribute_string(ATTR_CHIO_AGENT_ID),
            "source_verdict": span.attribute_string("chio.verdict"),
            "attributes": attributes_to_map(sanitized_attributes)
        }
    });

    if let Some(source_receipt_id) = source_receipt_id {
        if let Some(object) = metadata.as_object_mut() {
            object.insert(
                "correlation".to_string(),
                serde_json::json!({
                    "source_chio_receipt_id": source_receipt_id
                }),
            );
        }
    }

    metadata
}

fn validate_span_verdict(span: &OtlpSpan) -> Result<(), OTelReceiptExportError> {
    match span.attribute_value("chio.verdict") {
        None => Err(OTelReceiptExportError::InvalidSpan(
            "chio.verdict is required".to_string(),
        )),
        Some(serde_json::Value::String(verdict))
            if verdict == "allow" || verdict == "deny" || verdict == "incomplete" =>
        {
            let _ = observation_reason(span, verdict);
            Ok(())
        }
        Some(serde_json::Value::String(verdict)) => Err(OTelReceiptExportError::InvalidSpan(
            format!("chio.verdict must be allow, deny, or incomplete, got {verdict:?}"),
        )),
        Some(value) => Err(OTelReceiptExportError::InvalidSpan(format!(
            "chio.verdict must be a string, got {value}"
        ))),
    }
}

fn observation_reason(span: &OtlpSpan, verdict: &str) -> String {
    match verdict {
        "deny" => span
            .attribute_string("chio.deny.reason")
            .unwrap_or("otel span reported deny observation")
            .to_string(),
        "incomplete" => span
            .attribute_string("chio.incomplete.reason")
            .unwrap_or("otel span reported incomplete observation")
            .to_string(),
        _ => "otel span reported allow observation".to_string(),
    }
}

fn timestamp_from_span(span: &OtlpSpan) -> u64 {
    span.ended_at_unix_nano
        .or(span.started_at_unix_nano)
        .map(|nanos| nanos / 1_000_000_000)
        .unwrap_or(0)
}

fn next_receipt_id() -> String {
    format!("otel-{}", Uuid::now_v7())
}

fn validate_trace_id(value: &str) -> Result<(), OTelReceiptExportError> {
    if is_nonzero_lower_hex(value, 32) {
        Ok(())
    } else {
        Err(OTelReceiptExportError::InvalidSpan(format!(
            "trace_id must be 32 non-zero lowercase hex chars, got {value:?}"
        )))
    }
}

fn validate_span_id(value: &str) -> Result<(), OTelReceiptExportError> {
    if is_nonzero_lower_hex(value, 16) {
        Ok(())
    } else {
        Err(OTelReceiptExportError::InvalidSpan(format!(
            "span_id must be 16 non-zero lowercase hex chars, got {value:?}"
        )))
    }
}

fn is_nonzero_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value.chars().any(|char| char != '0')
        && value
            .chars()
            .all(|char| matches!(char, '0'..='9' | 'a'..='f'))
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct RecordingCanonicalSink {
        receipts: Mutex<Vec<CanonicalChioReceipt>>,
    }

    impl RecordingCanonicalSink {
        fn receipts(&self) -> Result<Vec<CanonicalChioReceipt>, ReceiptStoreError> {
            let guard = self
                .receipts
                .lock()
                .map_err(|_| ReceiptStoreError::Pool("receipt mutex poisoned".to_string()))?;
            Ok(guard.clone())
        }
    }

    impl CanonicalReceiptSink for RecordingCanonicalSink {
        fn append_chio_receipt_canonical(
            &self,
            receipt: CanonicalChioReceipt,
        ) -> Result<(), ReceiptStoreError> {
            let mut guard = self
                .receipts
                .lock()
                .map_err(|_| ReceiptStoreError::Pool("receipt mutex poisoned".to_string()))?;
            guard.push(receipt);
            Ok(())
        }
    }

    #[test]
    fn export_traces_passes_canonical_receipt_bytes_to_sink() -> Result<(), Box<dyn Error>> {
        let canonical_sink = Arc::new(RecordingCanonicalSink::default());
        let sink = ReceiptStoreSink::new_canonical(
            canonical_sink.clone(),
            ReceiptStoreSinkConfig::new(Keypair::generate()),
        );
        let span = OtlpSpan::new(
            "0123456789abcdef0123456789abcdef",
            "0123456789abcdef",
            "gen_ai.tool.call",
        )
        .with_attribute("chio.verdict", serde_json::json!("allow"));

        let summary = sink.export_traces(&OtlpGrpcTraceExport::from_spans(vec![span]))?;
        let receipts = canonical_sink.receipts()?;
        let receipt = receipts
            .first()
            .ok_or_else(|| std::io::Error::other("missing canonical receipt"))?;
        let expected = CanonicalBytes::from_serializable(receipt.receipt())?;

        assert_eq!(summary.appended_receipts, 1);
        assert_eq!(receipt.canonical_bytes(), expected.as_bytes());
        assert!(receipt.receipt().verify_signature()?);

        Ok(())
    }
}
