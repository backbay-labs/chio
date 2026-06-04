use std::error::Error;
use std::sync::{Arc, Mutex};

use chio_core::crypto::Keypair;
use chio_core::receipt::{ChildRequestReceipt, ChioReceipt};
use chio_kernel::otel::{
    ATTR_CHIO_AGENT_ID, ATTR_CHIO_RECEIPT_ID, ATTR_CHIO_SERVER_ID, ATTR_GEN_AI_TOOL_CALL_ID,
    ATTR_GEN_AI_TOOL_NAME,
};
use chio_kernel::receipt_store::{ReceiptStore, ReceiptStoreError};
use chio_otel_receipt_exporter::{
    OTelReceiptExportError, OtlpGrpcIngress, OtlpGrpcTraceExport, OtlpSpan, ReceiptStoreSink,
    ReceiptStoreSinkConfig, RECEIPT_EXPORT_MAX_SPANS,
};

const SOURCE_RECEIPT_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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
        .with_attribute(ATTR_CHIO_RECEIPT_ID, serde_json::json!(SOURCE_RECEIPT_ID))
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
    assert_eq!(receipt.id.len(), 64);
    assert!(receipt.id.chars().all(|value| value.is_ascii_hexdigit()));
    assert_eq!(receipt.capability_id, "cap-otel");
    assert_eq!(receipt.tool_server, "srv-otel");
    assert_eq!(receipt.tool_name, "search_web");
    assert_eq!(receipt.tenant_id.as_deref(), Some("tenant-authenticated"));
    assert!(receipt.verify_signature()?);
    assert!(!receipt.is_allowed());

    let semantics = receipt.semantic_fields();
    assert_eq!(semantics.receipt_kind.as_str(), "trace_observation");
    assert_eq!(semantics.boundary_class.as_str(), "detect_only");

    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing receipt metadata"))?;
    assert_eq!(metadata["provenance"]["otel"]["trace_id"], trace_id);
    assert_eq!(metadata["provenance"]["otel"]["span_id"], span_id);
    assert_eq!(
        metadata["correlation"]["source_chio_receipt_id"],
        SOURCE_RECEIPT_ID
    );
    assert!(metadata["otel"]["attributes"]
        .get(ATTR_CHIO_RECEIPT_ID)
        .is_none());
    assert!(metadata["otel"]["attributes"]
        .get(ATTR_GEN_AI_TOOL_CALL_ID)
        .is_none());
    assert_eq!(metadata["otel"]["attributes"]["gen_ai.system"], "openai");
    assert_eq!(metadata["otel"]["source_verdict"], "allow");

    Ok(())
}

#[test]
fn malformed_correlation_receipt_id_prevents_receipt_append() -> Result<(), Box<dyn Error>> {
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
    .with_attribute(ATTR_CHIO_RECEIPT_ID, serde_json::json!("not-a-receipt-id"));

    let error = match sink.export_traces(&OtlpGrpcTraceExport::from_spans(vec![span])) {
        Ok(_) => {
            return Err(std::io::Error::other(
                "malformed receipt correlation unexpectedly exported",
            )
            .into());
        }
        Err(error) => error,
    };

    assert!(matches!(error, OTelReceiptExportError::InvalidSpan(_)));
    assert!(
        error.to_string().contains(ATTR_CHIO_RECEIPT_ID),
        "unexpected error: {error}"
    );
    assert!(store.receipts()?.is_empty());

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
    let metadata = receipts
        .first()
        .and_then(|receipt| receipt.metadata.as_ref())
        .ok_or_else(|| std::io::Error::other("missing receipt metadata"))?;
    assert!(metadata["otel"]["attributes"]
        .get("chio.tenant.id")
        .is_none());

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
fn export_traces_rejects_span_count_over_cap_before_processing() -> Result<(), Box<dyn Error>> {
    let store = Arc::new(MemoryReceiptStore::default());
    let sink = ReceiptStoreSink::new(
        store.clone(),
        ReceiptStoreSinkConfig::new(Keypair::generate()),
    );
    let invalid = OtlpSpan::new("not-a-trace-id", "0123456789abcdef", "gen_ai.tool.call")
        .with_attribute("chio.verdict", serde_json::json!("allow"));
    let over_cap_span_count = RECEIPT_EXPORT_MAX_SPANS + 1;

    let error = match sink.export_traces(&OtlpGrpcTraceExport::from_spans(vec![
        invalid;
        over_cap_span_count
    ])) {
        Ok(_) => return Err(std::io::Error::other("oversized batch was accepted").into()),
        Err(error) => error,
    };

    assert!(matches!(error, OTelReceiptExportError::Queue(_)));
    assert!(
        error.to_string().contains("span count"),
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
fn explicit_allow_verdict_maps_to_trace_observation() -> Result<(), Box<dyn Error>> {
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
    let receipt = receipts
        .first()
        .ok_or_else(|| std::io::Error::other("missing appended receipt"))?;
    assert!(receipt.decision.is_none());
    let semantics = receipt.semantic_fields();
    assert_eq!(semantics.receipt_kind.as_str(), "trace_observation");
    assert_eq!(semantics.boundary_class.as_str(), "detect_only");
    assert!(!receipt.is_allowed());

    Ok(())
}

#[test]
fn explicit_deny_and_incomplete_verdicts_map_to_trace_observations() -> Result<(), Box<dyn Error>> {
    for verdict in ["deny", "incomplete"] {
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
        .with_attribute("chio.verdict", serde_json::json!(verdict));

        sink.export_traces(&OtlpGrpcTraceExport::from_spans(vec![span]))?;
        let receipts = store.receipts()?;
        let receipt = receipts
            .first()
            .ok_or_else(|| std::io::Error::other("missing appended receipt"))?;
        assert!(receipt.decision.is_none());
        let semantics = receipt.semantic_fields();
        assert_eq!(semantics.receipt_kind.as_str(), "trace_observation");
        assert_eq!(semantics.boundary_class.as_str(), "detect_only");
        assert!(!receipt.is_allowed());
        assert_eq!(
            receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("otel"))
                .and_then(|otel| otel.get("source_verdict"))
                .and_then(serde_json::Value::as_str),
            Some(verdict)
        );
    }

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

#[test]
fn malformed_routing_attributes_prevent_receipt_append() -> Result<(), Box<dyn Error>> {
    for (key, value) in [
        ("chio.capability.id", serde_json::json!(" cap-otel")),
        (ATTR_CHIO_SERVER_ID, serde_json::json!("")),
        (ATTR_GEN_AI_TOOL_NAME, serde_json::json!(false)),
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
        .with_attribute("chio.verdict", serde_json::json!("allow"))
        .with_attribute(key, value);

        let error = match sink.export_traces(&OtlpGrpcTraceExport::from_spans(vec![span])) {
            Ok(_) => {
                return Err(std::io::Error::other(format!("{key} unexpectedly exported")).into());
            }
            Err(error) => error,
        };

        assert!(matches!(error, OTelReceiptExportError::InvalidSpan(_)));
        assert!(
            error.to_string().contains(key),
            "unexpected error for {key}: {error}"
        );
        assert!(store.receipts()?.is_empty());
    }

    Ok(())
}
