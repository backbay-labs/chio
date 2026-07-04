use std::path::{Path, PathBuf};

use chio_core::capability::{
    runtime_attestation::RuntimeAttestationEvidence, scope::ChioScope, token::CapabilityToken,
};
use chio_core::crypto::PublicKey;
use chio_kernel::{CapabilityAuthority, KernelError};
use chio_store_sqlite::SqliteReceiptStore;

use crate::policy::{ReputationIssuancePolicy, RuntimeAssuranceIssuancePolicy};

use super::attestation::verify_runtime_attestation_for_issuance;
use super::reputation::enforce_reputation_policy;
use super::scope::enforce_runtime_assurance_policy;
use super::util::unix_now;

pub fn wrap_capability_authority(
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<RuntimeAssuranceIssuancePolicy>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
) -> Box<dyn CapabilityAuthority> {
    Box::new(PolicyBackedCapabilityAuthority {
        inner,
        issuance_policy,
        runtime_assurance_policy,
        receipt_db_path: receipt_db_path.map(Path::to_path_buf),
        budget_db_path: budget_db_path.map(Path::to_path_buf),
    })
}

struct PolicyBackedCapabilityAuthority {
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<RuntimeAssuranceIssuancePolicy>,
    receipt_db_path: Option<PathBuf>,
    budget_db_path: Option<PathBuf>,
}

impl CapabilityAuthority for PolicyBackedCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.inner.authority_public_key()
    }

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        self.inner.trusted_public_keys()
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        self.issue_capability_with_attestation(subject, scope, ttl_seconds, None)
    }

    fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, KernelError> {
        let mut scope = scope;
        let now = unix_now();
        let verified_runtime_attestation = verify_runtime_attestation_for_issuance(
            runtime_attestation.as_ref(),
            self.runtime_assurance_policy.as_ref(),
            now,
        )?;

        if let Some(policy) = &self.issuance_policy {
            // Reputation integrity validation requires a trust set of kernel
            // signing keys. The inner authority (the local kernel) is the
            // canonical signer of issuance-context receipts, and its trusted
            // peers (federation/cross-kernel) extend that set. Without these,
            // an empty trust set would silently filter every receipt as
            // unsigned (see chio-reputation::receipt_integrity_valid).
            let mut trusted_keys: Vec<String> = self
                .inner
                .trusted_public_keys()
                .into_iter()
                .map(|key| key.to_hex())
                .collect();
            trusted_keys.push(self.inner.authority_public_key().to_hex());
            enforce_reputation_policy(
                subject,
                &scope,
                ttl_seconds,
                policy,
                self.receipt_db_path.as_deref(),
                self.budget_db_path.as_deref(),
                &trusted_keys,
            )?;
        }

        if let Some(policy) = &self.runtime_assurance_policy {
            scope = enforce_runtime_assurance_policy(
                &scope,
                ttl_seconds,
                policy,
                verified_runtime_attestation.as_ref(),
            )?;
        }

        let capability = self.inner.issue_capability(subject, scope, ttl_seconds)?;

        if let Some(path) = self.receipt_db_path.as_deref() {
            let store = SqliteReceiptStore::open(path)
                .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
            store
                .record_capability_snapshot(&capability, None)
                .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
        }

        Ok(capability)
    }
}
