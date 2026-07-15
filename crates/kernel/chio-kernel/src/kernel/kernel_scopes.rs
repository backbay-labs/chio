use std::sync::Arc;

use dashmap::DashMap;

use crate::SessionAuthContext;

thread_local! {
    static RECEIPT_TENANT_ID_SCOPE: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
    static RECEIPT_FEDERATION_ADMISSION_SCOPE:
        std::cell::RefCell<Option<ReceiptFederationAdmission>> =
        const { std::cell::RefCell::new(None) };
}

/// Guard returned by [`scope_receipt_tenant_id`]. Restores the previously
/// active tenant scope when dropped.
pub(crate) struct ScopedReceiptTenantId {
    previous: Option<String>,
}

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

#[derive(Debug, Clone)]
pub(crate) struct ReceiptFederationAdmission {
    pub remote_kernel_id: Option<String>,
    pub peer: Option<chio_federation::trust_establishment::FederationPeer>,
}

/// Guard returned by [`scope_receipt_federation_admission`]. Restores the
/// previously active admission snapshot when dropped.
pub(crate) struct ScopedReceiptFederationAdmission {
    previous: Option<ReceiptFederationAdmission>,
}

impl Drop for ScopedReceiptFederationAdmission {
    fn drop(&mut self) {
        let previous = self.previous.take();
        RECEIPT_FEDERATION_ADMISSION_SCOPE.with(|slot| {
            *slot.borrow_mut() = previous;
        });
    }
}

/// Install the receipt-version and peer-key decision made at admission time.
/// Persistence and federation cosigning must use this snapshot rather than
/// re-resolving freshness after the tool has already produced side effects.
pub(crate) fn scope_receipt_federation_admission(
    admission: Option<ReceiptFederationAdmission>,
) -> ScopedReceiptFederationAdmission {
    let previous = RECEIPT_FEDERATION_ADMISSION_SCOPE.with(|slot| slot.replace(admission));
    ScopedReceiptFederationAdmission { previous }
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
