use chio_core::receipt::body::ChioReceipt;

/// An event emitted from a completed kernel state transition that contributes
/// to an implementation trace.
#[derive(Debug, Clone)]
pub enum RuntimeTraceEvent {
    /// The revocation store accepted a revoke operation.
    RevocationCommitted {
        capability_id: String,
        newly_revoked: bool,
        delegation_depth_limit: u32,
    },
    /// The tool-call path completed its revocation admission check.
    RevocationAdmission {
        request_id: String,
        capability_id: String,
        delegation_depth: u32,
        delegation_depth_limit: u32,
        admitted: bool,
    },
    /// A signed receipt was appended to durable storage, when configured, and
    /// to the kernel's local receipt log.
    ReceiptAppended { receipt: Box<ChioReceipt> },
}

/// Optional observer for implementation-trace evidence.
///
/// Observation cannot change the mediated decision. Implementations must keep
/// their own error state and refuse evidence finalization after any recording
/// error. Callbacks are synchronous so their order matches the kernel event
/// order visible at this boundary.
pub trait RuntimeTraceObserver: Send + Sync {
    fn observe(&self, event: RuntimeTraceEvent);
}
