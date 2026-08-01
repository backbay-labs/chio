use super::*;

#[derive(Clone, Default)]
pub(super) struct AdmissionReceiptProjectionStore {
    receipt: std::sync::Arc<std::sync::Mutex<Option<ChioReceipt>>>,
    successful_appends: std::sync::Arc<AtomicU64>,
    fail_next_append: std::sync::Arc<AtomicBool>,
}

impl AdmissionReceiptProjectionStore {
    pub(super) fn fail_next_append(&self) {
        self.fail_next_append.store(true, Ordering::SeqCst);
    }

    pub(super) fn receipt(&self) -> Option<ChioReceipt> {
        self.receipt
            .lock()
            .expect("admission receipt projection lock")
            .clone()
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
        let mut stored = self.receipt.lock().map_err(|_| {
            ReceiptStoreError::Conflict("admission receipt projection lock poisoned".to_owned())
        })?;
        if let Some(existing) = stored.as_ref() {
            let existing = chio_core::canonical::canonical_json_bytes(existing)
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
            let projected = chio_core::canonical::canonical_json_bytes(receipt)
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
            return (existing == projected).then_some(()).ok_or_else(|| {
                ReceiptStoreError::Conflict("admission receipt projection id conflicts".to_owned())
            });
        }
        *stored = Some(receipt.clone());
        self.successful_appends.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Ok(self
            .receipt
            .lock()
            .map_err(|_| {
                ReceiptStoreError::Conflict("admission receipt projection lock poisoned".to_owned())
            })?
            .as_ref()
            .filter(|receipt| receipt.id == receipt_id)
            .cloned())
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
