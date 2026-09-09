use super::*;

#[derive(Clone, Default)]
pub(super) struct AdmissionReceiptProjectionStore {
    receipts: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, ChioReceipt>>>,
    successful_appends: std::sync::Arc<AtomicU64>,
    fail_next_append: std::sync::Arc<AtomicBool>,
    batch_lookups: std::sync::Arc<AtomicU64>,
    point_lookups: std::sync::Arc<AtomicU64>,
}

impl AdmissionReceiptProjectionStore {
    pub(super) fn fail_next_append(&self) {
        self.fail_next_append.store(true, Ordering::SeqCst);
    }

    pub(super) fn receipt(&self) -> Option<ChioReceipt> {
        self.receipts
            .lock()
            .expect("admission receipt projection lock")
            .values()
            .next()
            .cloned()
    }

    pub(super) fn successful_appends(&self) -> u64 {
        self.successful_appends.load(Ordering::SeqCst)
    }
}

impl ReceiptStore for AdmissionReceiptProjectionStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        if self.fail_next_append.swap(false, Ordering::SeqCst) {
            return Err(ReceiptStoreError::Conflict(
                "injected admission receipt projection failure".to_owned(),
            ));
        }
        let mut stored = self.receipts.lock().map_err(|_| {
            ReceiptStoreError::Conflict("admission receipt projection lock poisoned".to_owned())
        })?;
        if let Some(existing) = stored.get(&receipt.id) {
            let existing = chio_core::canonical::canonical_json_bytes(existing)
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
            let projected = chio_core::canonical::canonical_json_bytes(receipt)
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
            return (existing == projected).then_some(()).ok_or_else(|| {
                ReceiptStoreError::Conflict("admission receipt projection id conflicts".to_owned())
            });
        }
        stored.insert(receipt.id.clone(), receipt.clone());
        self.successful_appends.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn durable_sink_id(&self) -> Option<&str> {
        Some("receipt-sink:admission-projection-test")
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        self.point_lookups.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .receipts
            .lock()
            .map_err(|_| {
                ReceiptStoreError::Conflict("admission receipt projection lock poisoned".to_owned())
            })?
            .get(receipt_id)
            .cloned())
    }

    fn load_chio_receipts(
        &self,
        receipt_ids: &[&str],
    ) -> Result<Vec<Option<ChioReceipt>>, ReceiptStoreError> {
        self.batch_lookups.fetch_add(1, Ordering::SeqCst);
        let stored = self.receipts.lock().map_err(|_| {
            ReceiptStoreError::Conflict("admission receipt projection lock poisoned".to_owned())
        })?;
        Ok(receipt_ids
            .iter()
            .map(|id| stored.get(*id).cloned())
            .collect())
    }

    fn append_child_receipt(
        &self,
        _receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported(
            "test child receipt persistence".to_owned(),
        ))
    }
}

#[test]
fn existing_admission_projections_use_verified_batch_without_point_reads_or_appends() {
    let (mut kernel, request, _store, invocations) =
        durable_admission_fixture("durable-batch-existing-projection");
    let completed = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("complete tool call");
    let projection = AdmissionReceiptProjectionStore::default();
    projection
        .append_chio_receipt(&completed.receipt)
        .expect("seed existing projection");
    kernel
        .set_receipt_store(Box::new(projection.clone()))
        .expect("install projection store");
    assert_eq!(
        kernel
            .reconcile_durable_admission_receipt_projections()
            .expect("reconcile existing"),
        1
    );
    assert_eq!(projection.batch_lookups.load(Ordering::SeqCst), 1);
    assert_eq!(projection.point_lookups.load(Ordering::SeqCst), 0);
    assert_eq!(projection.successful_appends(), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    projection
        .receipts
        .lock()
        .expect("projection lock")
        .get_mut(&completed.receipt.id)
        .expect("projected receipt")
        .tool_name = "forged".to_owned();
    let error = kernel
        .reconcile_durable_admission_receipt_projections()
        .expect_err("reject changed projection");
    assert!(error
        .to_string()
        .contains("conflicts with the canonical admission receipt"));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}
