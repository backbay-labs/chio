use async_trait::async_trait;
use chio_finding_market_port::{
    HostedApiKeyLifecyclePort, HostedApiKeyRecord, HostedAuthPort, HostedCapabilityAdmission,
    HostedCapabilityAdmissionOutcome, HostedMarketPortError, HostedPortWriteOutcome,
    HostedPrincipal, HostedTenantId, HOSTED_API_KEY_ISSUED_EVENT_KIND,
    HOSTED_API_KEY_REVOKED_EVENT_KIND,
};

use crate::{HostedJobWriteOutcome, HostedMarketStoreError, PostgresFindingMarketStore};

#[async_trait]
impl HostedAuthPort for PostgresFindingMarketStore {
    async fn principal_by_capability_key(
        &self,
        tenant: &HostedTenantId,
        public_key_hex: &str,
        now: u64,
    ) -> Result<Option<HostedPrincipal>, HostedMarketPortError> {
        self.get_principal_by_capability_key(tenant, public_key_hex, now)
            .await
            .map_err(map_error)
    }

    async fn principal(
        &self,
        tenant: &HostedTenantId,
        principal_id: &str,
    ) -> Result<Option<HostedPrincipal>, HostedMarketPortError> {
        self.get_principal(tenant, principal_id)
            .await
            .map_err(map_error)
    }

    async fn active_api_key(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        now: u64,
    ) -> Result<Option<HostedApiKeyRecord>, HostedMarketPortError> {
        self.get_active_api_key(tenant, key_id, now)
            .await
            .map_err(map_error)
    }

    async fn consume_capability_dpop_admission(
        &self,
        tenant: &HostedTenantId,
        admission: &HostedCapabilityAdmission<'_>,
    ) -> Result<HostedCapabilityAdmissionOutcome, HostedMarketPortError> {
        PostgresFindingMarketStore::consume_capability_dpop_admission(
            self,
            tenant,
            admission.capability_id,
            admission.nonce_sha256,
            admission.request_sha256,
            admission.valid_through,
            admission.max_invocations,
            admission.expires_at,
            admission.now,
            admission.tenant_nonce_capacity,
        )
        .await
        .map_err(map_error)
    }
}

#[async_trait]
impl HostedApiKeyLifecyclePort for PostgresFindingMarketStore {
    async fn issue_with_event(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        principal_id: &str,
        verifier_sha256: &str,
        allowed_actions: &std::collections::BTreeSet<String>,
        active_from: u64,
        expires_at: u64,
        rotated_from_key_id: Option<&str>,
        event_id: &str,
        artifact_json: &[u8],
        now: u64,
    ) -> Result<HostedPortWriteOutcome, HostedMarketPortError> {
        self.put_api_key_with_security_event(
            tenant,
            key_id,
            principal_id,
            verifier_sha256,
            allowed_actions,
            active_from,
            expires_at,
            rotated_from_key_id,
            event_id,
            HOSTED_API_KEY_ISSUED_EVENT_KIND,
            artifact_json,
            now,
        )
        .await
        .map(write_outcome)
        .map_err(map_error)
    }

    async fn revoke_with_event(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        revoked_at: u64,
        event_id: &str,
        artifact_json: &[u8],
    ) -> Result<HostedPortWriteOutcome, HostedMarketPortError> {
        self.revoke_api_key_with_security_event(
            tenant,
            key_id,
            revoked_at,
            event_id,
            HOSTED_API_KEY_REVOKED_EVENT_KIND,
            artifact_json,
        )
        .await
        .map(write_outcome)
        .map_err(map_error)
    }
}

const fn write_outcome(outcome: HostedJobWriteOutcome) -> HostedPortWriteOutcome {
    match outcome {
        HostedJobWriteOutcome::Inserted => HostedPortWriteOutcome::Inserted,
        HostedJobWriteOutcome::ExactReplay => HostedPortWriteOutcome::ExactReplay,
    }
}

const fn map_error(error: HostedMarketStoreError) -> HostedMarketPortError {
    match error {
        HostedMarketStoreError::Configuration
        | HostedMarketStoreError::MigrationDrift
        | HostedMarketStoreError::Unavailable => HostedMarketPortError::Unavailable,
        HostedMarketStoreError::Tenant => HostedMarketPortError::Tenant,
        HostedMarketStoreError::TenantNotFound => HostedMarketPortError::TenantNotFound,
        HostedMarketStoreError::TenantDisabled => HostedMarketPortError::TenantDisabled,
        HostedMarketStoreError::Invalid(_) => HostedMarketPortError::Invalid,
        HostedMarketStoreError::Conflict => HostedMarketPortError::Conflict,
        HostedMarketStoreError::Capacity => HostedMarketPortError::Capacity,
        HostedMarketStoreError::NotFound => HostedMarketPortError::NotFound,
        HostedMarketStoreError::LeaseLost => HostedMarketPortError::LeaseLost,
        HostedMarketStoreError::DigestMismatch | HostedMarketStoreError::Decode(_) => {
            HostedMarketPortError::Integrity
        }
        HostedMarketStoreError::RetentionHeld => HostedMarketPortError::RetentionHeld,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_specific_failures_are_not_exposed_through_ports() {
        assert_eq!(
            map_error(HostedMarketStoreError::MigrationDrift),
            HostedMarketPortError::Unavailable
        );
        assert_eq!(
            map_error(HostedMarketStoreError::DigestMismatch),
            HostedMarketPortError::Integrity
        );
    }
}
