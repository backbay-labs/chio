use super::client::build_client;
use super::errors::{into_receipt_store_error, into_revocation_store_error};
use super::*;

/// Worker threads a remote receipt store keeps for blocking control-plane
/// writes. Receipt writes are serialized by the kernel-wide receipt write lock,
/// so one worker covers the common case; the extra worker lets a capability
/// snapshot proceed alongside an in-flight append without either failing closed
/// under a healthy control plane.
const REMOTE_WRITER_WORKERS: usize = 2;

/// Writes that may queue behind busy workers before submissions fail closed.
/// Together with the worker count this caps how many blocking writes can be
/// outstanding against a stalled control plane, so the parked-thread count never
/// grows per write.
const REMOTE_WRITER_QUEUE_DEPTH: usize = 2;

pub fn build_remote_receipt_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn ReceiptStore>, CliError> {
    Ok(Box::new(RemoteReceiptStore {
        client: build_client(control_url, control_token)?,
        writer: BoundedReceiptWriter::new(REMOTE_WRITER_WORKERS, REMOTE_WRITER_QUEUE_DEPTH),
    }))
}

/// A fixed-size pool of persistent worker threads that runs blocking
/// control-plane writes under a wall-clock budget.
///
/// The control client carries only a coarse network-level request timeout, not
/// the operator's per-eval receipt budget, so a stalled control plane keeps a
/// blocking write parked until that coarse timeout fires, far past the hot
/// path's budget. Running each write on a fresh detached thread would let
/// sustained traffic against a stalled endpoint accumulate one parked thread per
/// write and eventually exhaust process threads. This pool caps the number of
/// concurrently parked writes at a fixed worker count: once every worker is
/// parked and the small queue is full, further submissions fail closed at the
/// budget instead of spawning more threads. A worker frees when its write
/// finishes or the client's own network timeout fires, then picks up the next
/// queued write. A write that outlives the caller's budget still completes with
/// its result discarded, since the caller has already failed closed.
pub(crate) struct BoundedReceiptWriter {
    submit: std::sync::mpsc::SyncSender<WriteJob>,
}

type WriteJob = Box<dyn FnOnce() + Send + 'static>;

impl BoundedReceiptWriter {
    pub(crate) fn new(workers: usize, queue_depth: usize) -> Self {
        let (submit, receive) = std::sync::mpsc::sync_channel::<WriteJob>(queue_depth);
        let receive = std::sync::Arc::new(std::sync::Mutex::new(receive));
        for _ in 0..workers.max(1) {
            let receive = std::sync::Arc::clone(&receive);
            std::thread::spawn(move || Self::run_worker(&receive));
        }
        Self { submit }
    }

    fn run_worker(receive: &std::sync::Mutex<std::sync::mpsc::Receiver<WriteJob>>) {
        loop {
            // Hold the lock only to dequeue, never while running the job, so a
            // worker parked on a stalled write does not block its peers from
            // dequeuing the next one.
            let job = {
                let guard = receive
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.recv()
            };
            match job {
                Ok(job) => job(),
                // Every submitter has dropped: the store is gone, so exit.
                Err(_) => break,
            }
        }
    }

    /// Run `write` under `budget`, returning its result or a fail-closed
    /// `Timeout`. Fails closed immediately when every worker is parked on a
    /// stalled write and the queue is full, so a stalled control plane can never
    /// grow the pool past its fixed worker count.
    pub(crate) fn run_within_budget<F, T>(
        &self,
        budget: std::time::Duration,
        operation: &str,
        write: F,
    ) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce() -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        let timeout_error = || ReceiptStoreError::Timeout {
            operation: operation.to_string(),
            timeout_ms: u64::try_from(budget.as_millis()).unwrap_or(u64::MAX),
        };
        let (done, result) = std::sync::mpsc::sync_channel::<Result<T, ReceiptStoreError>>(1);
        let job: WriteJob = Box::new(move || {
            // The caller may have already failed closed and dropped `result`; the
            // send then fails and the completed write is simply discarded.
            let _ = done.send(write());
        });
        if self.submit.try_send(job).is_err() {
            return Err(timeout_error());
        }
        match result.recv_timeout(budget) {
            Ok(outcome) => outcome,
            Err(_) => Err(timeout_error()),
        }
    }
}

pub fn build_remote_revocation_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn RevocationStore>, CliError> {
    Ok(Box::new(RemoteRevocationStore {
        client: build_client(control_url, control_token)?,
    }))
}

impl RevocationStore for RemoteRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        self.client
            .list_revocations(&RevocationQuery {
                capability_id: Some(capability_id.to_string()),
                limit: Some(1),
            })
            .and_then(|response| {
                response.revoked.ok_or_else(|| {
                    CliError::cli_other_error(format!(
                        "trust-control revocation response omitted revoked status for {capability_id}"
                    ))
                })
            })
            .map_err(into_revocation_store_error)
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        self.client
            .revoke_capability(capability_id)
            .map(|response| response.newly_revoked)
            .map_err(into_revocation_store_error)
    }

    fn is_ephemeral(&self) -> bool {
        false
    }
}

impl ReceiptStore for RemoteReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.client
            .append_tool_receipt(receipt)
            .map_err(into_receipt_store_error)
    }

    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        self.client
            .append_child_receipt(receipt)
            .map_err(into_receipt_store_error)
    }

    /// Bounded tool-receipt append for the mediation hot path. The base trait
    /// default drops the budget and blocks on the control client's own timeout,
    /// so this override enforces the operator-configured append budget over the
    /// remote round trip, failing closed on expiry.
    fn append_chio_receipt_with_timeout(
        &self,
        receipt: &ChioReceipt,
        budget: std::time::Duration,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        let client = self.client.clone();
        let receipt = receipt.clone();
        self.writer
            .run_within_budget(budget, "remote tool receipt append", move || {
                client
                    .append_tool_receipt(&receipt)
                    .map_err(into_receipt_store_error)?;
                Ok(None)
            })
    }

    /// Bounded child-receipt append (same budget rationale as
    /// [`Self::append_chio_receipt_with_timeout`]) for nested-flow drains.
    fn append_child_receipt_with_timeout(
        &self,
        receipt: &ChildRequestReceipt,
        budget: std::time::Duration,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        let client = self.client.clone();
        let receipt = receipt.clone();
        self.writer
            .run_within_budget(budget, "remote child receipt append", move || {
                client
                    .append_child_receipt(&receipt)
                    .map_err(into_receipt_store_error)?;
                Ok(None)
            })
    }

    /// Point-load a tool receipt by id over the control-plane remote protocol so
    /// a store-authoritative `--control-url` deployment resolves a parent receipt
    /// that the kernel's bounded in-memory mirror has evicted, rather than
    /// falsely denying a governed call-chain continuation. The query is bounded
    /// to a single row.
    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        let response = self
            .client
            .list_tool_receipts(&ToolReceiptQuery {
                receipt_id: Some(receipt_id.to_string()),
                limit: Some(1),
                ..ToolReceiptQuery::default()
            })
            .map_err(into_receipt_store_error)?;
        match response.receipts.into_iter().next() {
            Some(value) => {
                let receipt: ChioReceipt = serde_json::from_value(value)?;
                // Verify the returned id matches the REQUESTED id before accepting
                // the hit. A rolling-upgrade or non-conforming control-plane that
                // ignores the `receiptId` filter can return an unrelated receipt as
                // the first row. `has_local_receipt_id` treats any `Some(_)` as
                // "the requested parent exists", so an unverified hit would let a
                // governed parent-receipt existence check pass on the WRONG receipt
                // after the mirror evicts the real one. A mismatch is treated as a
                // miss (fail-closed): the caller then denies the dependent claim
                // rather than trusting a substituted receipt.
                if receipt.id != receipt_id {
                    return Ok(None);
                }
                Ok(Some(receipt))
            }
            None => Ok(None),
        }
    }

    /// Point-load a child receipt by id over the control-plane remote protocol
    /// (same bounded-mirror-eviction rationale as [`Self::load_chio_receipt`]).
    fn load_child_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChildRequestReceipt>, ReceiptStoreError> {
        let response = self
            .client
            .list_child_receipts(&ChildReceiptQuery {
                receipt_id: Some(receipt_id.to_string()),
                limit: Some(1),
                ..ChildReceiptQuery::default()
            })
            .map_err(into_receipt_store_error)?;
        match response.receipts.into_iter().next() {
            Some(value) => {
                let receipt: ChildRequestReceipt = serde_json::from_value(value)?;
                // Same returned-id-must-match-requested-id check as
                // [`Self::load_chio_receipt`]: a non-conforming control-plane that
                // ignores the filter cannot substitute a different child receipt
                // for a governed existence check. A mismatch is a fail-closed miss.
                if receipt.id != receipt_id {
                    return Ok(None);
                }
                Ok(Some(receipt))
            }
            None => Ok(None),
        }
    }

    fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        self.client
            .record_capability_snapshot(token, parent_capability_id)
            .map_err(into_receipt_store_error)
    }

    /// Bounded pre-dispatch capability snapshot. The base trait default drops the
    /// budget and blocks on the control client's own network timeout, so a
    /// stalled control plane would pin the pre-dispatch receipt write lock past
    /// the append budget. This override runs the snapshot through the same
    /// bounded writer pool as the append overrides, failing closed at the budget.
    fn record_capability_snapshot_with_timeout(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
        budget: std::time::Duration,
    ) -> Result<(), ReceiptStoreError> {
        let client = self.client.clone();
        let token = token.clone();
        let parent_capability_id = parent_capability_id.map(str::to_string);
        self.writer
            .run_within_budget(budget, "remote capability snapshot", move || {
                client
                    .record_capability_snapshot(&token, parent_capability_id.as_deref())
                    .map_err(into_receipt_store_error)
            })
    }

    fn resolve_credit_bond(
        &self,
        bond_id: &str,
    ) -> Result<Option<chio_kernel::CreditBondRow>, ReceiptStoreError> {
        self.client
            .list_credit_bonds(&CreditBondListQuery {
                bond_id: Some(bond_id.to_string()),
                facility_id: None,
                capability_id: None,
                agent_subject: None,
                tool_server: None,
                tool_name: None,
                disposition: None,
                lifecycle_state: None,
                limit: Some(1),
            })
            .map(|report| report.bonds.into_iter().next())
            .map_err(into_receipt_store_error)
    }
}
