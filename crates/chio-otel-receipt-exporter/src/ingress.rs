use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::sink::{OTelReceiptExportError, ReceiptStoreSink, ReceiptStoreSinkSummary};

/// Synchronous OTLP gRPC trace ingress facade.
///
/// The network listener owns protobuf decoding. This facade receives the decoded
/// export request and commits it through the receipt-store sink.
pub struct OtlpGrpcIngress {
    sink: ReceiptStoreSink,
}

impl OtlpGrpcIngress {
    pub fn new(sink: ReceiptStoreSink) -> Self {
        Self { sink }
    }

    pub fn export(
        &self,
        request: &OtlpGrpcTraceExport,
    ) -> Result<ReceiptStoreSinkSummary, OTelReceiptExportError> {
        self.sink.export_traces(request)
    }
}

/// OTLP gRPC trace export payload after protobuf decoding.
///
/// Production ingress can decode `ExportTraceServiceRequest` into this stable
/// crate-local shape before sending spans to the receipt sink. Tests and offline
/// collectors can construct it directly.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OtlpGrpcTraceExport {
    #[serde(default)]
    pub resource_spans: Vec<OtlpResourceSpans>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OtlpResourceSpans {
    #[serde(default)]
    pub resource_attributes: Vec<OtlpAttribute>,
    #[serde(default)]
    pub spans: Vec<OtlpSpan>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OtlpSpan {
    pub trace_id: String,
    pub span_id: String,
    pub name: String,
    #[serde(default)]
    pub attributes: Vec<OtlpAttribute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_unix_nano: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at_unix_nano: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OtlpAttribute {
    pub key: String,
    pub value: serde_json::Value,
}

impl OtlpGrpcTraceExport {
    pub fn from_spans(spans: Vec<OtlpSpan>) -> Self {
        Self {
            resource_spans: vec![OtlpResourceSpans {
                resource_attributes: Vec::new(),
                spans,
            }],
        }
    }

    pub fn span_count(&self) -> usize {
        self.resource_spans
            .iter()
            .map(|resource| resource.spans.len())
            .sum()
    }

    pub fn spans(&self) -> impl Iterator<Item = &OtlpSpan> {
        self.resource_spans
            .iter()
            .flat_map(|resource| resource.spans.iter())
    }
}

impl OtlpResourceSpans {
    pub fn resource_attribute_map(&self) -> BTreeMap<String, serde_json::Value> {
        attributes_to_map(&self.resource_attributes)
    }
}

impl OtlpSpan {
    pub fn new(
        trace_id: impl Into<String>,
        span_id: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            span_id: span_id.into(),
            name: name.into(),
            attributes: Vec::new(),
            started_at_unix_nano: None,
            ended_at_unix_nano: None,
        }
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.attributes.push(OtlpAttribute {
            key: key.into(),
            value,
        });
        self
    }

    pub fn attribute_value(&self, key: &str) -> Option<&serde_json::Value> {
        self.attributes
            .iter()
            .find(|attribute| attribute.key == key)
            .map(|attribute| &attribute.value)
    }

    pub fn attribute_string(&self, key: &str) -> Option<&str> {
        self.attribute_value(key)
            .and_then(serde_json::Value::as_str)
    }

    pub fn attribute_map(&self) -> BTreeMap<String, serde_json::Value> {
        attributes_to_map(&self.attributes)
    }
}

pub(crate) fn attributes_to_map(
    attributes: &[OtlpAttribute],
) -> BTreeMap<String, serde_json::Value> {
    attributes
        .iter()
        .map(|attribute| (attribute.key.clone(), attribute.value.clone()))
        .collect()
}
