use chio_appraisal::VerifiedRuntimeAttestationRecord;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use crate::receipt_support::GovernedCallChainReceiptEvidence;
use crate::{SessionAuthContext, VerifiedFederationTreatyMaterial};

const TERMINAL_RECEIPT_NOT_ATTEMPTED: u8 = 0;
const TERMINAL_RECEIPT_APPEND_ATTEMPTED: u8 = 1;
const TERMINAL_RECEIPT_COMMITTED: u8 = 2;

#[derive(Clone, Default)]
pub(crate) struct EvaluationReceiptContext {
    pub(crate) tenant_id: Option<String>,
    pub(crate) federation_admission: Option<ReceiptFederationAdmission>,
    pub(crate) governed_call_chain: Option<GovernedCallChainReceiptEvidence>,
    pub(crate) runtime_attestation: Option<VerifiedRuntimeAttestationRecord>,
    pub(crate) verified_treaty_material: Option<VerifiedFederationTreatyMaterial>,
    pub(crate) terminal_receipt_persistence_state: Arc<AtomicU8>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReceiptFederationAdmission {
    pub remote_kernel_id: Option<String>,
    pub peer: Option<chio_federation::trust_establishment::FederationPeer>,
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
