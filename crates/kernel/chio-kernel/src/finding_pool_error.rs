//! Finding-pool ledger error vocabulary.
//!
//! Lives outside the gated pool module so integration seams keep one
//! signature whether or not the `finding-market` feature is compiled in.

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FindingPoolLedgerError {
    #[error("finding pool debit conflicts with a prior purchase id")]
    ReplayConflict,
    #[error("finding pool signed amount is exhausted")]
    AmountExceeded,
    #[error("finding pool allocation is not live for a new debit")]
    AllocationNotLive,
    #[error("finding pool id is already bound to another signed allocation")]
    PoolBindingConflict,
    #[error("finding pool allocation is bound to another qualified ledger domain")]
    LedgerDomainMismatch,
    #[error("finding pool ledger domain is already served by another durable store")]
    LedgerDomainInUse,
    #[error("finding pool ledger is bound to another external store identity")]
    LedgerStoreBindingMismatch,
    #[error("finding pool external store identity is invalid")]
    InvalidLedgerStoreIdentity,
    #[error("finding pool ledger is bound to another durable receipt sink")]
    ReceiptSinkMismatch,
    #[error("finding pool durable receipt sink identity is invalid")]
    InvalidReceiptSink,
    #[error("finding pool receipt retention archive is not rollback-qualified")]
    UnqualifiedRetentionArchive,
    #[error("finding pool ledger is bound to another mutation receipt authority")]
    ReceiptAuthorityMismatch,
    #[error("finding pool receipt authority and sink configuration did not bind atomically")]
    ReceiptConfigurationMismatch,
    #[error("finding pool mutation receipt authority is invalid")]
    InvalidReceiptAuthority,
    #[error("finding pool allocation authority is invalid")]
    InvalidAllocationAuthority,
    #[error("finding pool purchase has no durable reservation")]
    ReservationMissing,
    #[error("finding pool reservation conflicts with its recorded terminal")]
    TerminalConflict,
    #[error("finding pool reservation expired before durable admission claimed it")]
    ClaimDeadlineElapsed,
    #[error("finding pool dispatch requires durable admission coverage")]
    DurableAdmissionRequired,
    #[error("finding pool ledger is already configured for this kernel")]
    AlreadyConfigured,
    #[error("finding pool ledger cannot be configured after durable startup reconciliation")]
    StartupAlreadyReconciled,
    #[error("finding pool mutation receipt authority is not configured")]
    ReceiptAuthorityMissing,
    #[error("finding pool mutation receipt authority is already configured for this kernel")]
    ReceiptAuthorityAlreadyConfigured,
    #[error("finding pool mutation receipts require a durable ordinary receipt store")]
    DurableReceiptStoreMissing,
    #[error("finding pool ledger storage failed: {0}")]
    Storage(String),
    #[error("finding pool mutation receipt failed: {0}")]
    Receipt(String),
    #[error("finding pool mutation receipt outbox flush lock is poisoned")]
    MutationReceiptFlushPoisoned,
}
