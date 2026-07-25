/// A receipt store whose supervised commit writer has died. Appends would still
/// nominally succeed, but the writer flag reports serving-closed, so the kernel
/// pre-dispatch gate must fail closed before any tool executes.
struct DeadWriterReceiptStore;

impl ReceiptStore for DeadWriterReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn writer_serving_closed(&self) -> bool {
        true
    }
}

/// A receipt store whose supervised commit writer is serving-closed AND whose
/// appends now fail, modelling a real poisoned-head or dead-writer store rather
/// than one that still silently accepts writes. The pre-dispatch gate must deny
/// before any tool executes, and the fail-closed deny it builds must not be
/// masked into an error by attempting to persist itself through the same closed
/// writer.
struct RejectingDeadWriterReceiptStore;

impl ReceiptStore for RejectingDeadWriterReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Pool(
            "receipt append rejected by a serving-closed commit writer".to_string(),
        ))
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Pool(
            "child receipt append rejected by a serving-closed commit writer".to_string(),
        ))
    }

    fn writer_serving_closed(&self) -> bool {
        true
    }
}

/// A commit writer that is always serving closed and, once armed, fails every
/// capability-lineage write like a poisoned writer. It records whether the
/// lineage write was attempted so a test can prove the pre-dispatch gate denies
/// BEFORE any writer-backed metadata write runs. Arming is deferred so capability
/// issuance during test setup (which also records lineage) still succeeds.
struct SnapshotTrackingDeadWriterStore {
    snapshot_attempted: std::sync::Arc<AtomicBool>,
    fail_snapshots: std::sync::Arc<AtomicBool>,
}

impl ReceiptStore for SnapshotTrackingDeadWriterStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn writer_serving_closed(&self) -> bool {
        true
    }

    fn record_capability_snapshot(
        &self,
        _token: &CapabilityToken,
        _parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        if self.fail_snapshots.load(Ordering::SeqCst) {
            self.snapshot_attempted.store(true, Ordering::SeqCst);
            return Err(ReceiptStoreError::Pool(
                "capability lineage write rejected by a dead receipt writer".to_string(),
            ));
        }
        Ok(())
    }
}
