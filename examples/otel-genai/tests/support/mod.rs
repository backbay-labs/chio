use std::collections::BTreeMap;
use std::error::Error;
use std::sync::{Arc, Mutex};

use chio_core::crypto::Keypair;
use chio_core::receipt::{ChildRequestReceipt, ChioReceipt};
use chio_kernel::otel::{
    ATTR_CHIO_AGENT_ID, ATTR_CHIO_RECEIPT_ID, ATTR_CHIO_SERVER_ID, ATTR_GEN_AI_OPERATION_NAME,
    ATTR_GEN_AI_REQUEST_MODEL, ATTR_GEN_AI_SYSTEM, ATTR_GEN_AI_TOOL_CALL_ID, ATTR_GEN_AI_TOOL_NAME,
    ATTR_GEN_AI_USAGE_INPUT_TOKENS, ATTR_GEN_AI_USAGE_OUTPUT_TOKENS,
    GEN_AI_TOOL_CALL_OPERATION_NAME, GEN_AI_TOOL_CALL_SPAN_NAME,
};
use chio_kernel::receipt_store::{ReceiptStore, ReceiptStoreError};
use chio_otel_receipt_exporter::{
    OtlpGrpcIngress, OtlpGrpcTraceExport, OtlpSpan, ReceiptStoreSink, ReceiptStoreSinkConfig,
    ReceiptStoreSinkSummary,
};

pub const SOURCE_RECEIPT_ID: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
pub const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
pub const SPAN_ID: &str = "00f067aa0ba902b7";
pub const TOOL_NAME: &str = "customer_lookup";
pub const POLICY_HASH: &str = "policy-demo-otel";
pub const CAPABILITY_ID: &str = "cap-otel-demo";
pub const TOOL_SERVER: &str = "srv-openai-demo";
pub const TENANT_ID: &str = "tenant-demo";

#[derive(Default)]
pub struct MemoryReceiptStore {
    receipts: Mutex<Vec<ChioReceipt>>,
}

impl MemoryReceiptStore {
    fn receipts(&self) -> Result<Vec<ChioReceipt>, std::io::Error> {
        let guard = self
            .receipts
            .lock()
            .map_err(|_| std::io::Error::other("receipt mutex poisoned"))?;
        Ok(guard.clone())
    }
}

impl ReceiptStore for MemoryReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        let mut guard = self
            .receipts
            .lock()
            .map_err(|_| ReceiptStoreError::Pool("receipt mutex poisoned".to_string()))?;
        guard.push(receipt.clone());
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}

pub struct DemoExport {
    pub summary: ReceiptStoreSinkSummary,
    pub receipts: Vec<ChioReceipt>,
}

pub struct LookupIndexes {
    pub receipt_to_span: BTreeMap<String, String>,
    pub span_to_receipt: BTreeMap<String, String>,
}

pub fn export_demo_span() -> Result<DemoExport, Box<dyn Error>> {
    let store = Arc::new(MemoryReceiptStore::default());
    let ingress = OtlpGrpcIngress::new(demo_sink(store.clone()));
    let summary = ingress.export(&OtlpGrpcTraceExport::from_spans(vec![demo_span()]))?;

    Ok(DemoExport {
        summary,
        receipts: store.receipts()?,
    })
}

fn demo_sink(store: Arc<MemoryReceiptStore>) -> ReceiptStoreSink {
    ReceiptStoreSink::new(
        store,
        ReceiptStoreSinkConfig {
            signing_keypair: Keypair::generate(),
            policy_hash: POLICY_HASH.to_string(),
            default_capability_id: CAPABILITY_ID.to_string(),
            default_tool_server: TOOL_SERVER.to_string(),
            default_tool_name: TOOL_NAME.to_string(),
            tenant_id: Some(TENANT_ID.to_string()),
        },
    )
}

fn demo_span() -> OtlpSpan {
    OtlpSpan::new(TRACE_ID, SPAN_ID, GEN_AI_TOOL_CALL_SPAN_NAME)
        .with_attribute(ATTR_GEN_AI_SYSTEM, serde_json::json!("openai"))
        .with_attribute(
            ATTR_GEN_AI_OPERATION_NAME,
            serde_json::json!(GEN_AI_TOOL_CALL_OPERATION_NAME),
        )
        .with_attribute(ATTR_GEN_AI_REQUEST_MODEL, serde_json::json!("gpt-5"))
        .with_attribute(ATTR_GEN_AI_TOOL_CALL_ID, serde_json::json!("call-demo-1"))
        .with_attribute(ATTR_GEN_AI_TOOL_NAME, serde_json::json!(TOOL_NAME))
        .with_attribute(ATTR_GEN_AI_USAGE_INPUT_TOKENS, serde_json::json!(42))
        .with_attribute(ATTR_GEN_AI_USAGE_OUTPUT_TOKENS, serde_json::json!(7))
        .with_attribute(ATTR_CHIO_RECEIPT_ID, serde_json::json!(SOURCE_RECEIPT_ID))
        .with_attribute("chio.tenant.id", serde_json::json!(TENANT_ID))
        .with_attribute("chio.policy.ref", serde_json::json!(POLICY_HASH))
        .with_attribute("chio.verdict", serde_json::json!("allow"))
        .with_attribute("chio.tee.mode", serde_json::json!("shadow"))
        .with_attribute("chio.capability.id", serde_json::json!(CAPABILITY_ID))
        .with_attribute(ATTR_CHIO_SERVER_ID, serde_json::json!(TOOL_SERVER))
        .with_attribute(ATTR_CHIO_AGENT_ID, serde_json::json!("agent-demo"))
        .with_attribute(
            "redaction_pass_id",
            serde_json::json!("redactors@1.5.0+default"),
        )
        .with_attribute("redaction_elapsed_micros", serde_json::json!(12450_u64))
}

pub fn build_lookup_indexes(receipt: &ChioReceipt) -> Result<LookupIndexes, Box<dyn Error>> {
    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing receipt metadata"))?;
    let span_id = metadata["provenance"]["otel"]["span_id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("span id is not a string"))?
        .to_string();

    let mut receipt_to_span = BTreeMap::new();
    receipt_to_span.insert(receipt.id.clone(), span_id.clone());
    let mut span_to_receipt = BTreeMap::new();
    span_to_receipt.insert(span_id, receipt.id.clone());

    Ok(LookupIndexes {
        receipt_to_span,
        span_to_receipt,
    })
}
