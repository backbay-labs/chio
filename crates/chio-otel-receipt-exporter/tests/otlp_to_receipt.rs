use std::error::Error;
use std::sync::{Arc, Mutex};

use chio_core::crypto::Keypair;
use chio_core::receipt::{ChildRequestReceipt, ChioReceipt, Decision};
use chio_kernel::otel::{
    ATTR_CHIO_AGENT_ID, ATTR_CHIO_RECEIPT_ID, ATTR_CHIO_SERVER_ID, ATTR_GEN_AI_TOOL_CALL_ID,
    ATTR_GEN_AI_TOOL_NAME,
};
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
fn otlp_trace_span_is_signed_and_appended_to_receipt_store() -> Result<(), Box<dyn Error>> {
    let store = Arc::new(MemoryReceiptStore::default());
    let sink = ReceiptStoreSink::new(
        store.clone(),
        ReceiptStoreSinkConfig {
            signing_keypair: Keypair::generate(),
            policy_hash: "policy-otel-test".to_string(),
            default_capability_id: "cap-default".to_string(),
            default_tool_server: "srv-default".to_string(),
            default_tool_name: "tool-default".to_string(),
            tenant_id: Some("tenant-authenticated".to_string()),
        },
    );
    let trace_id = "0123456789abcdef0123456789abcdef";
    let span_id = "0123456789abcdef";
    let span = OtlpSpan::new(trace_id, span_id, "gen_ai.tool.call")
        .with_attribute(ATTR_CHIO_RECEIPT_ID, serde_json::json!("rcpt-otel"))
        .with_attribute("chio.capability.id", serde_json::json!("cap-otel"))
        .with_attribute(ATTR_CHIO_SERVER_ID, serde_json::json!("srv-otel"))
        .with_attribute(ATTR_CHIO_AGENT_ID, serde_json::json!("agent-otel"))
        .with_attribute(ATTR_GEN_AI_TOOL_CALL_ID, serde_json::json!("call-otel"))
        .with_attribute(ATTR_GEN_AI_TOOL_NAME, serde_json::json!("search_web"))
        .with_attribute("chio.verdict", serde_json::json!("allow"))
        .with_attribute("gen_ai.system", serde_json::json!("openai"));

    let ingress = OtlpGrpcIngress::new(sink);
    let summary = ingress.export(&OtlpGrpcTraceExport::from_spans(vec![span]))?;
    let receipts = store.receipts()?;

    assert_eq!(summary.accepted_spans, 1);
    assert_eq!(summary.appended_receipts, 1);
    assert_eq!(receipts.len(), 1);

    let receipt = receipts
        .first()
        .ok_or_else(|| std::io::Error::other("missing appended receipt"))?;
    assert_ne!(receipt.id, "rcpt-otel");
    assert!(receipt.id.starts_with("otel-"));
    assert_eq!(receipt.capability_id, "cap-otel");
    assert_eq!(receipt.tool_server, "srv-otel");
    assert_eq!(receipt.tool_name, "search_web");
    assert_eq!(receipt.tenant_id.as_deref(), Some("tenant-authenticated"));
    assert!(receipt.verify_signature()?);

    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing receipt metadata"))?;
    assert_eq!(metadata["provenance"]["otel"]["trace_id"], trace_id);
    assert_eq!(metadata["provenance"]["otel"]["span_id"], span_id);
    assert_eq!(
        metadata["correlation"]["source_chio_receipt_id"],
        "rcpt-otel"
    );
    assert!(metadata["otel"]["attributes"]
        .get(ATTR_CHIO_RECEIPT_ID)
        .is_none());
    assert!(metadata["otel"]["attributes"]
        .get(ATTR_GEN_AI_TOOL_CALL_ID)
        .is_none());
    assert_eq!(metadata["otel"]["attributes"]["gen_ai.system"], "openai");

    Ok(())
}

#[test]
fn span_tenant_attribute_does_not_set_receipt_tenant() -> Result<(), Box<dyn Error>> {
    let store = Arc::new(MemoryReceiptStore::default());
    let sink = ReceiptStoreSink::new(
        store.clone(),
        ReceiptStoreSinkConfig::new(Keypair::generate()),
    );
    let span = OtlpSpan::new(
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef",
        "gen_ai.tool.call",
    )
    .with_attribute("chio.verdict", serde_json::json!("allow"))
    .with_attribute("chio.tenant.id", serde_json::json!("spoofed-tenant"));

    let summary = sink.export_traces(&OtlpGrpcTraceExport::from_spans(vec![span]))?;
    let receipts = store.receipts()?;

    assert_eq!(summary.appended_receipts, 1);
    assert_eq!(
        receipts
            .first()
            .and_then(|receipt| receipt.tenant_id.as_deref()),
        None
    );

    Ok(())
}

#[test]
fn invalid_span_prevents_partial_batch_append() -> Result<(), Box<dyn Error>> {
    let store = Arc::new(MemoryReceiptStore::default());
    let sink = ReceiptStoreSink::new(
        store.clone(),
        ReceiptStoreSinkConfig::new(Keypair::generate()),
    );
    let valid = OtlpSpan::new(
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef",
        "gen_ai.tool.call",
    )
    .with_attribute("chio.verdict", serde_json::json!("allow"));
    let invalid = OtlpSpan::new(
        "00000000000000000000000000000000",
        "0123456789abcdef",
        "gen_ai.tool.call",
    )
    .with_attribute("chio.verdict", serde_json::json!("allow"));

    let error = match sink.export_traces(&OtlpGrpcTraceExport::from_spans(vec![valid, invalid])) {
        Ok(_) => {
            return Err(std::io::Error::other("invalid batch unexpectedly exported").into());
        }
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("trace_id"),
        "unexpected error: {error}"
    );
    assert!(store.receipts()?.is_empty());

    Ok(())
}

#[test]
fn missing_verdict_prevents_receipt_append() -> Result<(), Box<dyn Error>> {
    let store = Arc::new(MemoryReceiptStore::default());
    let sink = ReceiptStoreSink::new(
        store.clone(),
        ReceiptStoreSinkConfig::new(Keypair::generate()),
    );
    let span = OtlpSpan::new(
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef",
        "gen_ai.tool.call",
    );

    let error = match sink.export_traces(&OtlpGrpcTraceExport::from_spans(vec![span])) {
        Ok(_) => {
            return Err(std::io::Error::other("missing verdict unexpectedly exported").into());
        }
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("chio.verdict"),
        "unexpected error: {error}"
    );
    assert!(store.receipts()?.is_empty());

    Ok(())
}

#[test]
fn unknown_or_malformed_verdict_prevents_receipt_append() -> Result<(), Box<dyn Error>> {
    for (name, verdict) in [
        ("unknown", serde_json::json!("blocked")),
        ("uppercase", serde_json::json!("DENY")),
        ("non-string", serde_json::json!(false)),
    ] {
        let store = Arc::new(MemoryReceiptStore::default());
        let sink = ReceiptStoreSink::new(
            store.clone(),
            ReceiptStoreSinkConfig::new(Keypair::generate()),
        );
        let span = OtlpSpan::new(
            "0123456789abcdef0123456789abcdef",
            "0123456789abcdef",
            "gen_ai.tool.call",
        )
        .with_attribute("chio.verdict", verdict);

        let error = match sink.export_traces(&OtlpGrpcTraceExport::from_spans(vec![span])) {
            Ok(_) => {
                return Err(
                    std::io::Error::other(format!("{name} verdict unexpectedly exported")).into(),
                );
            }
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("chio.verdict"),
            "unexpected error for {name}: {error}"
        );
        assert!(store.receipts()?.is_empty());
    }

    Ok(())
}

#[test]
fn explicit_allow_verdict_maps_to_allow_decision() -> Result<(), Box<dyn Error>> {
    let store = Arc::new(MemoryReceiptStore::default());
    let sink = ReceiptStoreSink::new(
        store.clone(),
        ReceiptStoreSinkConfig::new(Keypair::generate()),
    );
    let span = OtlpSpan::new(
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef",
        "gen_ai.tool.call",
    )
    .with_attribute("chio.verdict", serde_json::json!("allow"));

    sink.export_traces(&OtlpGrpcTraceExport::from_spans(vec![span]))?;
    let receipts = store.receipts()?;
    assert!(matches!(
        receipts.first().map(|receipt| &receipt.decision),
        Some(Decision::Allow)
    ));

    Ok(())
}

#[test]
fn invalid_otel_ids_fail_before_receipt_append() -> Result<(), Box<dyn Error>> {
    let store = Arc::new(MemoryReceiptStore::default());
    let sink = ReceiptStoreSink::new(
        store.clone(),
        ReceiptStoreSinkConfig::new(Keypair::generate()),
    );
    let span = OtlpSpan::new(
        "0123456789ABCDEF0123456789ABCDEF",
        "0123456789abcdef",
        "gen_ai.tool.call",
    );

    let error = match sink.export_traces(&OtlpGrpcTraceExport::from_spans(vec![span])) {
        Ok(_) => {
            return Err(std::io::Error::other("invalid span unexpectedly exported").into());
        }
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("trace_id"),
        "unexpected error: {error}"
    );
    assert!(store.receipts()?.is_empty());

    Ok(())
}
