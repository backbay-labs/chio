//! A partial OTEL batch retry never mints a duplicate signed receipt; ids are
//! stable across attempts and per-span accounting reconciles.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use chio_core::crypto::Keypair;
use chio_otel_receipt_exporter::ingress::{OtlpGrpcIngress, OtlpGrpcTraceExport, OtlpSpan};
use chio_otel_receipt_exporter::sink::{
    CanonicalChioReceipt, CanonicalReceiptSink, ReceiptStoreSink, ReceiptStoreSinkConfig,
};
use proptest::prelude::*;

/// A sink that logs every appended receipt id and fails once (retryable) after
/// `fail_after` successful appends, then accepts everything.
struct FlakySink {
    appended_ids: Mutex<Vec<String>>,
    ok_count: AtomicUsize,
    fail_after: usize,
    armed: std::sync::atomic::AtomicBool,
}

impl CanonicalReceiptSink for FlakySink {
    fn append_chio_receipt_canonical(
        &self,
        receipt: CanonicalChioReceipt,
    ) -> Result<(), chio_kernel::receipt_store::ReceiptStoreError> {
        let so_far = self.ok_count.load(Ordering::SeqCst);
        if so_far == self.fail_after && self.armed.swap(false, Ordering::SeqCst) {
            // One retryable failure (Pool) at the boundary.
            return Err(chio_kernel::receipt_store::ReceiptStoreError::Pool(
                "commit actor saturated".to_string(),
            ));
        }
        self.ok_count.fetch_add(1, Ordering::SeqCst);
        self.appended_ids
            .lock()
            .expect("test lock")
            .push(receipt.receipt_id().to_string());
        Ok(())
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]
    #[test]
    fn otel_partial_retry_never_duplicates(n in 1usize..12, k in 0usize..12) {
        let k = k % n; // fail boundary within the batch
        let sink = std::sync::Arc::new(FlakySink {
            appended_ids: Mutex::new(Vec::new()),
            ok_count: AtomicUsize::new(0),
            fail_after: k,
            armed: std::sync::atomic::AtomicBool::new(true),
        });
        let store_sink = ReceiptStoreSink::new_canonical(
            std::sync::Arc::clone(&sink) as std::sync::Arc<dyn CanonicalReceiptSink>,
            test_config(),
        );
        let ingress = OtlpGrpcIngress::new(store_sink);
        let export = build_span_batch(n);

        // First attempt enqueues + drains, appends k, then hits the retryable
        // failure; the batch (and its resume cursor) is retained in the queue.
        let first = ingress.export(&export);
        prop_assert!(first.is_err(), "expected a retryable failure after k appends");

        // Retry: drain resumes the retained batch at cursor k with the SAME ids
        // and completes (never re-enqueues, never re-signs from span 0).
        let second = ingress.drain();
        prop_assert!(second.is_ok(), "retry completes: {second:?}");

        let ids = sink.appended_ids.lock().expect("test lock").clone();
        let mut distinct = ids.clone();
        distinct.sort();
        distinct.dedup();
        // Exactly n appends, all distinct (no re-mint of the first k with fresh
        // otel-<uuid> ids on retry).
        prop_assert_eq!(ids.len(), n, "no duplicate appends: {:?}", ids);
        prop_assert_eq!(distinct.len(), n, "ids stable and unique: {:?}", ids);
    }
}

fn test_config() -> ReceiptStoreSinkConfig {
    ReceiptStoreSinkConfig {
        signing_keypair: Keypair::generate(),
        policy_hash: "policy-otel-retry".to_string(),
        default_capability_id: "cap-default".to_string(),
        default_tool_server: "srv-default".to_string(),
        default_tool_name: "tool-default".to_string(),
        tenant_id: None,
    }
}

fn build_span_batch(n: usize) -> OtlpGrpcTraceExport {
    let trace_id = "0123456789abcdef0123456789abcdef";
    let spans = (0..n)
        .map(|index| {
            // span_id must be 16 non-zero lowercase hex chars; offset by 1.
            let span_id = format!("{:016x}", index + 1);
            OtlpSpan::new(trace_id, span_id, "gen_ai.tool.call")
                .with_attribute("chio.verdict", serde_json::json!("allow"))
        })
        .collect();
    OtlpGrpcTraceExport::from_spans(spans)
}
