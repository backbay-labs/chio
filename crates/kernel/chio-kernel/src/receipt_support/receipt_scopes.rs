use std::cell::RefCell;
use std::collections::VecDeque;

use chio_appraisal::VerifiedRuntimeAttestationRecord;
use chio_core::capability::governance::GovernedUpstreamCallChainProof;
use chio_core::receipt::metadata::GuardEvidence;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GovernedCallChainReceiptEvidence {
    pub(crate) local_parent_request_id: Option<String>,
    pub(crate) local_parent_receipt_id: Option<String>,
    pub(crate) capability_delegator_subject: Option<String>,
    pub(crate) capability_origin_subject: Option<String>,
    pub(crate) upstream_proof: Option<GovernedUpstreamCallChainProof>,
    pub(crate) continuation_token_id: Option<String>,
    pub(crate) session_anchor_id: Option<String>,
}

thread_local! {
    static GOVERNED_CALL_CHAIN_RECEIPT_EVIDENCE: RefCell<Option<GovernedCallChainReceiptEvidence>> =
        const { RefCell::new(None) };
    static GOVERNED_RUNTIME_ATTESTATION_RECORD: RefCell<Option<VerifiedRuntimeAttestationRecord>> =
        const { RefCell::new(None) };
    static PRE_INVOCATION_GUARD_EVIDENCE: RefCell<Vec<GuardEvidence>> =
        const { RefCell::new(Vec::new()) };
    static POST_INVOCATION_GUARD_EVIDENCE: RefCell<Vec<GuardEvidence>> =
        const { RefCell::new(Vec::new()) };
    static FIXED_RUNTIME_UNIX_SECS: RefCell<Option<u64>> = const { RefCell::new(None) };
    static FIXED_RUNTIME_RECEIPT_IDS: RefCell<Option<FixedRuntimeReceiptIds>> =
        const { RefCell::new(None) };
}

struct FixedRuntimeReceiptIds {
    ids: VecDeque<String>,
    counter: u64,
}

pub struct FixedRuntimeScope {
    previous_unix_secs: Option<u64>,
    previous_receipt_ids: Option<FixedRuntimeReceiptIds>,
}

impl Drop for FixedRuntimeScope {
    fn drop(&mut self) {
        let previous_unix_secs = self.previous_unix_secs.take();
        FIXED_RUNTIME_UNIX_SECS.with(|slot| {
            *slot.borrow_mut() = previous_unix_secs;
        });
        let previous_receipt_ids = self.previous_receipt_ids.take();
        FIXED_RUNTIME_RECEIPT_IDS.with(|slot| {
            *slot.borrow_mut() = previous_receipt_ids;
        });
    }
}

pub fn scope_fixed_runtime_for_current_thread(
    now_unix_secs: u64,
    receipt_ids: impl IntoIterator<Item = String>,
) -> FixedRuntimeScope {
    let previous_unix_secs = FIXED_RUNTIME_UNIX_SECS.with(|slot| slot.replace(Some(now_unix_secs)));
    let previous_receipt_ids = FIXED_RUNTIME_RECEIPT_IDS.with(|slot| {
        slot.replace(Some(FixedRuntimeReceiptIds {
            ids: receipt_ids.into_iter().collect(),
            counter: 0,
        }))
    });
    FixedRuntimeScope {
        previous_unix_secs,
        previous_receipt_ids,
    }
}

pub fn fixed_runtime_unix_secs_for_current_thread() -> Option<u64> {
    FIXED_RUNTIME_UNIX_SECS.with(|slot| *slot.borrow())
}

pub(crate) struct ScopedGovernedCallChainReceiptEvidence {
    previous: Option<GovernedCallChainReceiptEvidence>,
}

impl Drop for ScopedGovernedCallChainReceiptEvidence {
    fn drop(&mut self) {
        let previous = self.previous.take();
        GOVERNED_CALL_CHAIN_RECEIPT_EVIDENCE.with(|slot| {
            slot.replace(previous);
        });
    }
}

pub(crate) fn scope_governed_call_chain_receipt_evidence(
    evidence: Option<GovernedCallChainReceiptEvidence>,
) -> ScopedGovernedCallChainReceiptEvidence {
    let previous = GOVERNED_CALL_CHAIN_RECEIPT_EVIDENCE.with(|slot| slot.replace(evidence));
    ScopedGovernedCallChainReceiptEvidence { previous }
}

pub(super) fn current_governed_call_chain_receipt_evidence(
) -> Option<GovernedCallChainReceiptEvidence> {
    GOVERNED_CALL_CHAIN_RECEIPT_EVIDENCE.with(|slot| slot.borrow().clone())
}

pub(crate) struct ScopedGovernedRuntimeAttestationRecord {
    previous: Option<VerifiedRuntimeAttestationRecord>,
}

impl Drop for ScopedGovernedRuntimeAttestationRecord {
    fn drop(&mut self) {
        let previous = self.previous.take();
        GOVERNED_RUNTIME_ATTESTATION_RECORD.with(|slot| {
            slot.replace(previous);
        });
    }
}

pub(crate) fn scope_governed_runtime_attestation_receipt_record(
    record: Option<VerifiedRuntimeAttestationRecord>,
) -> ScopedGovernedRuntimeAttestationRecord {
    let previous = GOVERNED_RUNTIME_ATTESTATION_RECORD.with(|slot| slot.replace(record));
    ScopedGovernedRuntimeAttestationRecord { previous }
}

pub(super) fn current_governed_runtime_attestation_record(
) -> Option<VerifiedRuntimeAttestationRecord> {
    GOVERNED_RUNTIME_ATTESTATION_RECORD.with(|slot| slot.borrow().clone())
}

pub(crate) struct ScopedPreInvocationGuardEvidence {
    previous: Vec<GuardEvidence>,
}

impl Drop for ScopedPreInvocationGuardEvidence {
    fn drop(&mut self) {
        let previous = core::mem::take(&mut self.previous);
        PRE_INVOCATION_GUARD_EVIDENCE.with(|slot| {
            slot.replace(previous);
        });
    }
}

pub(crate) fn scope_pre_invocation_guard_evidence(
    evidence: Vec<GuardEvidence>,
) -> ScopedPreInvocationGuardEvidence {
    let previous = PRE_INVOCATION_GUARD_EVIDENCE.with(|slot| slot.replace(evidence));
    ScopedPreInvocationGuardEvidence { previous }
}

pub(crate) fn current_pre_invocation_guard_evidence() -> Vec<GuardEvidence> {
    PRE_INVOCATION_GUARD_EVIDENCE.with(|slot| slot.borrow().clone())
}

pub(crate) struct ScopedPostInvocationGuardEvidence {
    previous: Vec<GuardEvidence>,
}

impl Drop for ScopedPostInvocationGuardEvidence {
    fn drop(&mut self) {
        let previous = core::mem::take(&mut self.previous);
        POST_INVOCATION_GUARD_EVIDENCE.with(|slot| {
            slot.replace(previous);
        });
    }
}

pub(crate) fn scope_post_invocation_guard_evidence(
    evidence: Vec<GuardEvidence>,
) -> ScopedPostInvocationGuardEvidence {
    let previous = POST_INVOCATION_GUARD_EVIDENCE.with(|slot| slot.replace(evidence));
    ScopedPostInvocationGuardEvidence { previous }
}

pub(crate) fn current_post_invocation_guard_evidence() -> Vec<GuardEvidence> {
    POST_INVOCATION_GUARD_EVIDENCE.with(|slot| slot.borrow().clone())
}

pub(super) fn next_fixed_runtime_receipt_id(prefix: &str) -> Option<String> {
    FIXED_RUNTIME_RECEIPT_IDS.with(|slot| {
        let mut fixed = slot.borrow_mut();
        let fixed = fixed.as_mut()?;
        if let Some(id) = fixed.ids.pop_front() {
            return Some(id);
        }
        let id = format!("{prefix}-fixed-runtime-{}", fixed.counter);
        fixed.counter = fixed.counter.saturating_add(1);
        Some(id)
    })
}
