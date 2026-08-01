use chio_core::receipt::body::ChioReceipt;

/// An event emitted from a completed kernel state transition that contributes
/// to an implementation trace.
#[derive(Debug, Clone)]
pub enum RuntimeTraceEvent {
    /// The revocation store accepted a revoke operation.
    RevocationCommitted {
        source_sequence: u64,
        capability_id: String,
        newly_revoked: bool,
        delegation_depth_limit: u32,
    },
    /// The tool-call path completed its revocation admission check.
    RevocationAdmission {
        source_sequence: u64,
        request_id: String,
        capability_id: String,
        revocation_subject_ids: Vec<String>,
        revoked_capability_id: Option<String>,
        delegation_depth: u32,
        delegation_depth_limit: u32,
        admitted: bool,
    },
    /// A signed receipt was appended to durable storage, when configured, and
    /// to the kernel's local receipt log.
    ReceiptAppended {
        source_sequence: u64,
        receipt: Box<ChioReceipt>,
    },
}

/// Optional observer for implementation-trace evidence.
///
/// Observation cannot change the mediated decision. Implementations must keep
/// their own error state and refuse evidence finalization after any recording
/// error. Callbacks are synchronous for each emitter. Concurrent emitters may
/// deliver callbacks out of causal order, so consumers must order them by the
/// kernel-assigned source sequence.
pub trait RuntimeTraceObserver: Send + Sync {
    fn observe(&self, event: RuntimeTraceEvent);
}
