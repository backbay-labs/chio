use std::collections::BTreeMap;
use std::error::Error;
use std::sync::{Arc, Mutex};

use chio_core::crypto::Keypair;
use chio_core::receipt::{ChildRequestReceipt, ChioReceipt};
use chio_kernel::receipt_store::{ReceiptStore, ReceiptStoreError};
use chio_otel_receipt_exporter::{
    OtlpGrpcIngress, OtlpGrpcTraceExport, OtlpSpan, ReceiptStoreSink, ReceiptStoreSinkConfig,
};

#[derive(Default)]
struct MemoryReceiptStore {
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

#[test]
#[ignore = "local demo gate: run with --ignored to validate receipt and span lookup"]
fn receipt_id_and_span_id_lookup_is_bidirectional() -> Result<(), Box<dyn Error>> {
    let receipt_id = "rcpt-otel-genai-0001";
    let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
    let span_id = "00f067aa0ba902b7";
    let store = Arc::new(MemoryReceiptStore::default());
    let sink = ReceiptStoreSink::new(
        store.clone(),
        ReceiptStoreSinkConfig {
            signing_keypair: Keypair::generate(),
            policy_hash: "policy-demo-otel".to_string(),
            default_capability_id: "cap-otel-demo".to_string(),
            default_tool_server: "srv-openai-demo".to_string(),
            default_tool_name: "customer_lookup".to_string(),
            tenant_id: Some("tenant-demo".to_string()),
        },
    );
    let span = OtlpSpan::new(trace_id, span_id, "gen_ai.tool.call")
        .with_attribute("gen_ai.system", serde_json::json!("openai"))
        .with_attribute("gen_ai.operation.name", serde_json::json!("tool.call"))
        .with_attribute("gen_ai.request.model", serde_json::json!("gpt-5"))
        .with_attribute("gen_ai.tool.call.id", serde_json::json!("call-demo-1"))
        .with_attribute("gen_ai.tool.name", serde_json::json!("customer_lookup"))
        .with_attribute("gen_ai.usage.input_tokens", serde_json::json!(42))
        .with_attribute("gen_ai.usage.output_tokens", serde_json::json!(7))
        .with_attribute("chio.receipt.id", serde_json::json!(receipt_id))
        .with_attribute("chio.tenant.id", serde_json::json!("tenant-demo"))
        .with_attribute("chio.policy.ref", serde_json::json!("policy-demo-otel"))
        .with_attribute("chio.verdict", serde_json::json!("allow"))
        .with_attribute("chio.tee.mode", serde_json::json!("shadow"))
        .with_attribute("chio.capability.id", serde_json::json!("cap-otel-demo"))
        .with_attribute("chio.server.id", serde_json::json!("srv-openai-demo"))
        .with_attribute("chio.agent.id", serde_json::json!("agent-demo"))
        .with_attribute(
            "redaction_pass_id",
            serde_json::json!("m06-redactors@1.4.0+default"),
        )
        .with_attribute("redaction_elapsed_micros", serde_json::json!(12450_u64));

    let ingress = OtlpGrpcIngress::new(sink);
    let summary = ingress.export(&OtlpGrpcTraceExport::from_spans(vec![span]))?;
    assert_eq!(summary.accepted_spans, 1);
    assert_eq!(summary.appended_receipts, 1);

    let receipts = store.receipts()?;
    let receipt = receipts
        .first()
        .ok_or_else(|| std::io::Error::other("missing exported receipt"))?;
    assert_eq!(receipt.id, receipt_id);
    assert_eq!(receipt.tool_server, "srv-openai-demo");
    assert_eq!(receipt.tool_name, "customer_lookup");
    assert!(receipt.verify_signature()?);

    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing receipt metadata"))?;
    assert_eq!(metadata["provenance"]["otel"]["trace_id"], trace_id);
    assert_eq!(metadata["provenance"]["otel"]["span_id"], span_id);
    assert_eq!(metadata["otel"]["attributes"]["gen_ai.system"], "openai");
    assert_eq!(
        metadata["otel"]["attributes"]["redaction_pass_id"],
        "m06-redactors@1.4.0+default"
    );
    assert!(metadata["otel"]["attributes"]
        .get("gen_ai.tool.call.id")
        .is_none());
    assert!(metadata["otel"]["attributes"]
        .get("chio.receipt.id")
        .is_none());

    let mut receipt_to_span = BTreeMap::new();
    receipt_to_span.insert(
        receipt.id.clone(),
        metadata["provenance"]["otel"]["span_id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("span id is not a string"))?
            .to_string(),
    );
    let mut span_to_receipt = BTreeMap::new();
    span_to_receipt.insert(
        metadata["provenance"]["otel"]["span_id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("span id is not a string"))?
            .to_string(),
        receipt.id.clone(),
    );

    assert_eq!(
        receipt_to_span.get(receipt_id).map(String::as_str),
        Some(span_id)
    );
    assert_eq!(
        span_to_receipt.get(span_id).map(String::as_str),
        Some(receipt_id)
    );

    Ok(())
}
