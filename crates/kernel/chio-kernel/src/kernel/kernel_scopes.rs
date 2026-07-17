use chio_appraisal::VerifiedRuntimeAttestationRecord;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use dashmap::DashMap;

use crate::receipt_support::GovernedCallChainReceiptEvidence;
use crate::{SessionAuthContext, VerifiedFederationTreatyMaterial};

const TERMINAL_RECEIPT_NOT_ATTEMPTED: u8 = 0;
const TERMINAL_RECEIPT_APPEND_ATTEMPTED: u8 = 1;
const TERMINAL_RECEIPT_COMMITTED: u8 = 2;

thread_local! {
    static RECEIPT_TENANT_ID_SCOPE: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
    static RECEIPT_FEDERATION_ADMISSION_SCOPE:
        std::cell::RefCell<Option<ReceiptFederationAdmission>> =
        const { std::cell::RefCell::new(None) };
}

#[derive(Clone, Default)]
pub(crate) struct EvaluationReceiptContext {
    pub(crate) tenant_id: Option<String>,
    pub(crate) federation_admission: Option<ReceiptFederationAdmission>,
    pub(crate) governed_call_chain: Option<GovernedCallChainReceiptEvidence>,
    pub(crate) runtime_attestation: Option<VerifiedRuntimeAttestationRecord>,
    pub(crate) verified_treaty_material: Option<VerifiedFederationTreatyMaterial>,
    pub(crate) terminal_receipt_persistence_state: Arc<AtomicU8>,
}

/// Guard returned by [`scope_receipt_tenant_id`]. Restores the previously
/// active tenant scope when dropped.
#[cfg(test)]
pub(crate) struct ScopedReceiptTenantId {
    previous: Option<String>,
}

#[cfg(test)]
impl Drop for ScopedReceiptTenantId {
    fn drop(&mut self) {
        let previous = self.previous.take();
        RECEIPT_TENANT_ID_SCOPE.with(|slot| {
            *slot.borrow_mut() = previous;
        });
    }
}

/// Install `tenant_id` as the active scope for this thread until the
/// returned guard is dropped. Passing `None` explicitly clears the scope
/// (so a child evaluate that lacks a session cannot inherit a parent's
/// tenant tag by accident).
#[cfg(test)]
pub(crate) fn scope_receipt_tenant_id(tenant_id: Option<String>) -> ScopedReceiptTenantId {
    let previous = RECEIPT_TENANT_ID_SCOPE.with(|slot| slot.replace(tenant_id));
    ScopedReceiptTenantId { previous }
}

/// Read the tenant_id currently in scope on this thread.
pub(crate) fn current_scoped_receipt_tenant_id() -> Option<String> {
    RECEIPT_TENANT_ID_SCOPE.with(|slot| slot.borrow().clone())
}

/// Request-keyed tenant registration, dropped when the evaluation future
/// finishes. The map stores the RESOLVED tenant for the request, including a
/// known-none entry for tenantless requests: an entry that merely disappeared
/// would fall back to the thread-local scope, and on a worker that resumes
/// this evaluation while a sibling task's scope guard is still alive that
/// fallback would leak the sibling's tenant into this request's receipts.
pub(crate) struct ScopedKernelReceiptTenantId {
    pub(super) request_id: String,
    pub(super) tenant_ids: Arc<DashMap<String, Option<String>>>,
    pub(super) previous: Option<Option<String>>,
}

impl Drop for ScopedKernelReceiptTenantId {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            self.tenant_ids.insert(self.request_id.clone(), previous);
        } else {
            self.tenant_ids.remove(&self.request_id);
        }
    }
}

impl EvaluationReceiptContext {
    pub(crate) fn new(tenant_id: Option<String>) -> Self {
        Self {
            tenant_id,
            ..Self::default()
        }
    }

    pub(crate) fn set_federation_admission(&mut self, admission: ReceiptFederationAdmission) {
        self.federation_admission = Some(admission);
    }

    pub(crate) fn set_governed_evidence(
        &mut self,
        call_chain: Option<GovernedCallChainReceiptEvidence>,
        runtime_attestation: Option<VerifiedRuntimeAttestationRecord>,
    ) {
        self.governed_call_chain = call_chain;
        self.runtime_attestation = runtime_attestation;
    }

    pub(crate) fn set_verified_treaty_material(
        &mut self,
        material: VerifiedFederationTreatyMaterial,
    ) {
        self.verified_treaty_material = Some(material);
    }

    /// Create an equivalent receipt context with an independent persistence
    /// latch for an additional signed audit record. A tool evaluation still
    /// has exactly one terminal response receipt, but cleanup can discover
    /// multiple distinct faults that each require durable evidence.
    pub(crate) fn additional_audit_receipt_context(&self) -> Self {
        let mut context = self.clone();
        context.terminal_receipt_persistence_state =
            Arc::new(AtomicU8::new(TERMINAL_RECEIPT_NOT_ATTEMPTED));
        context
    }

    pub(crate) fn begin_terminal_receipt_append(&self) -> bool {
        self.terminal_receipt_persistence_state
            .compare_exchange(
                TERMINAL_RECEIPT_NOT_ATTEMPTED,
                TERMINAL_RECEIPT_APPEND_ATTEMPTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub(crate) fn mark_terminal_receipt_committed(&self) {
        self.terminal_receipt_persistence_state
            .store(TERMINAL_RECEIPT_COMMITTED, Ordering::Release);
    }

    pub(crate) fn terminal_receipt_append_started(&self) -> bool {
        self.terminal_receipt_persistence_state
            .load(Ordering::Acquire)
            != TERMINAL_RECEIPT_NOT_ATTEMPTED
    }

    pub(crate) fn terminal_receipt_committed(&self) -> bool {
        self.terminal_receipt_persistence_state
            .load(Ordering::Acquire)
            == TERMINAL_RECEIPT_COMMITTED
    }
}

/// Request-keyed dispatch-intent registration, dropped when the evaluation
/// future finishes. Restores any previously registered handle (nested
/// evaluations under one request id keep their outer binding).
pub(crate) struct ScopedKernelDispatchIntent {
    pub(super) request_id: String,
    pub(super) intents: Arc<DashMap<String, crate::receipt_store::DispatchIntentHandle>>,
    pub(super) previous: Option<crate::receipt_store::DispatchIntentHandle>,
}

impl Drop for ScopedKernelDispatchIntent {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            self.intents.insert(self.request_id.clone(), previous);
        } else {
            self.intents.remove(&self.request_id);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReceiptFederationAdmission {
    pub remote_kernel_id: Option<String>,
    pub peer: Option<chio_federation::trust_establishment::FederationPeer>,
}

pub(crate) fn current_scoped_receipt_federation_admission() -> Option<ReceiptFederationAdmission> {
    RECEIPT_FEDERATION_ADMISSION_SCOPE.with(|slot| slot.borrow().clone())
}

pub(crate) struct ScopedKernelReceiptFederationAdmission {
    pub(super) request_id: String,
    pub(super) admissions: Arc<DashMap<String, ReceiptFederationAdmission>>,
    pub(super) previous: Option<ReceiptFederationAdmission>,
}

impl Drop for ScopedKernelReceiptFederationAdmission {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            self.admissions.insert(self.request_id.clone(), previous);
        } else {
            self.admissions.remove(&self.request_id);
        }
    }
}

/// Extract tenant_id from a session's authenticated auth context.
///
/// Preference order:
///   1. OAuth bearer `enterprise_identity.tenant_id` (the richer SSO
///      claim, preferred because IdP integrations that surface full
///      EnterpriseIdentityContext use this path).
///   2. OAuth bearer `federated_claims.tenant_id` (the minimal OIDC
///      claim set; populated when the IdP only emits `tid`).
///
/// Anonymous sessions and static-bearer sessions return `None`.
pub(crate) fn extract_tenant_id_from_auth_context(
    auth_context: &SessionAuthContext,
) -> Option<String> {
    if let chio_core::session::SessionAuthMethod::OAuthBearer {
        enterprise_identity,
        federated_claims,
        ..
    } = &auth_context.method
    {
        if let Some(identity) = enterprise_identity.as_ref() {
            if let Some(id) = identity.tenant_id.as_ref() {
                return Some(id.clone());
            }
        }
        if let Some(id) = federated_claims.tenant_id.as_ref() {
            return Some(id.clone());
        }
    }
    None
}
