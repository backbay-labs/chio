use std::collections::BTreeSet;

use chio_core_types::canonical_json_bytes;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;

use super::*;

const MAX_PRINCIPAL_ID_BYTES: usize = 256;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_CAPABILITY_ID_BYTES: usize = 256;
const MAX_EVENT_ID_BYTES: usize = 256;
const MAX_EVENT_KIND_BYTES: usize = 96;
const MAX_ALLOWED_ACTIONS: usize = 64;
const MAX_SECURITY_EVENT_BYTES: usize = 1024 * 1024;
const MAX_AUTH_CAPACITY: u64 = 10_000_000;
const DPOP_SWEEP_INTERVAL_SECS: i64 = 3_600;
/// How many request admissions a tenant may retain per live-proof slot.
///
/// A binding outlives the proof that recorded it by the ratio of the
/// capability lifetime to the proof lifetime, so a tenant legitimately
/// holds more bindings than live proofs. This is the headroom for that,
/// and it bounds what a credential holder can retain by rotating
/// idempotency keys as its proof slots expire.
const RETAINED_BINDINGS_PER_NONCE_SLOT: i64 = 64;

pub const HOSTED_PRINCIPAL_LIFECYCLE_SCHEMA: &str = "chio.finding.hosted-principal-lifecycle.v1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostedPrincipalLifecycleOperation {
    Provision,
    Disable,
    RoleChange,
    KeyRotation,
    EmergencyRevoke,
}

impl HostedPrincipalLifecycleOperation {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Provision => "provision",
            Self::Disable => "disable",
            Self::RoleChange => "role_change",
            Self::KeyRotation => "key_rotation",
            Self::EmergencyRevoke => "emergency_revoke",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, HostedMarketStoreError> {
        match value {
            "provision" => Ok(Self::Provision),
            "disable" => Ok(Self::Disable),
            "role_change" => Ok(Self::RoleChange),
            "key_rotation" => Ok(Self::KeyRotation),
            "emergency_revoke" => Ok(Self::EmergencyRevoke),
            _ => Err(HostedMarketStoreError::Decode(
                "principal lifecycle operation label",
            )),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedPrincipalLifecycleBody {
    pub schema: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub operation: HostedPrincipalLifecycleOperation,
    pub role: HostedPrincipalRole,
    pub capability_public_key_hex: Option<String>,
    pub overlap_expires_at: Option<u64>,
    pub previous_event_sha256: Option<String>,
    pub created_at: u64,
}

pub type SignedHostedPrincipalLifecycleEvent = SignedExportEnvelope<HostedPrincipalLifecycleBody>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedSecurityEventOutcome {
    Inserted,
    ExactReplay,
}

impl PostgresFindingMarketStore {
    pub async fn apply_principal_lifecycle(
        &self,
        tenant: &HostedTenantId,
        expected_signer: &PublicKey,
        event: &SignedHostedPrincipalLifecycleEvent,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        let body = &event.body;
        let envelope = validate_principal_lifecycle_event(tenant, expected_signer, event)?;
        let event_sha256 = sha256_hex(&envelope);
        let mut transaction = self.begin_tenant(tenant).await?;
        let outcome: i16 = sqlx::query_scalar(
            r#"SELECT chio_finding_market_apply_principal_event(
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
            )"#,
        )
        .bind(tenant.as_str())
        .bind(event_sha256)
        .bind(&body.principal_id)
        .bind(body.operation.as_str())
        .bind(body.role.as_str())
        .bind(body.capability_public_key_hex.as_deref())
        .bind(
            body.overlap_expires_at
                .map(|value| checked_i64(value, "principal key overlap"))
                .transpose()?,
        )
        .bind(body.previous_event_sha256.as_deref())
        .bind(event.signer_key.to_hex())
        .bind(envelope)
        .bind(checked_i64(body.created_at, "principal lifecycle time")?)
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let outcome = match outcome {
            0 => HostedJobWriteOutcome::Inserted,
            1 => HostedJobWriteOutcome::ExactReplay,
            2 => return Err(HostedMarketStoreError::Conflict),
            _ => return Err(HostedMarketStoreError::Unavailable),
        };
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    pub async fn get_principal(
        &self,
        tenant: &HostedTenantId,
        principal_id: &str,
    ) -> Result<Option<HostedPrincipal>, HostedMarketStoreError> {
        validate_identifier(principal_id, MAX_PRINCIPAL_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("principal_id"))?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT principal_id, role, capability_public_key_hex, enabled, created_at, updated_at FROM chio_finding_market_principals WHERE tenant_id = $1 AND principal_id = $2",
        )
        .bind(tenant.as_str())
        .bind(principal_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
        row.map(|row| principal_from_row(tenant, &row)).transpose()
    }

    pub async fn get_principal_by_capability_key(
        &self,
        tenant: &HostedTenantId,
        public_key_hex: &str,
        now: u64,
    ) -> Result<Option<HostedPrincipal>, HostedMarketStoreError> {
        let parsed = chio_core_types::PublicKey::from_hex(public_key_hex)
            .map_err(|_| HostedMarketStoreError::Invalid("capability_public_key"))?;
        if parsed.is_weak_ed25519() {
            return Err(HostedMarketStoreError::Invalid("capability_public_key"));
        }
        let normalized = parsed.to_hex();
        let now = checked_i64(now, "principal lookup time")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            r#"SELECT principal_id, role, capability_public_key_hex, enabled,
                      created_at, updated_at
               FROM chio_finding_market_principals AS principal
               WHERE tenant_id = $1 AND (
                   capability_public_key_hex = $2
                   OR EXISTS (
                       SELECT 1
                       FROM chio_finding_market_principal_key_overlaps AS overlap
                       WHERE overlap.tenant_id = principal.tenant_id
                         AND overlap.principal_id = principal.principal_id
                         AND overlap.capability_public_key_hex = $2
                         AND overlap.valid_through >= $3
                   )
               )"#,
        )
        .bind(tenant.as_str())
        .bind(normalized)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
        row.map(|row| principal_from_row(tenant, &row)).transpose()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_api_key(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        principal_id: &str,
        verifier_sha256: &str,
        allowed_actions: &BTreeSet<String>,
        active_from: u64,
        expires_at: u64,
        rotated_from_key_id: Option<&str>,
        now: u64,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_api_key_issue(
            key_id,
            principal_id,
            verifier_sha256,
            allowed_actions,
            active_from,
            expires_at,
            rotated_from_key_id,
        )?;
        let active_from = checked_i64(active_from, "api_key active_from")?;
        let expires_at = checked_i64(expires_at, "api_key expires_at")?;
        let now = checked_i64(now, "api_key now")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let outcome = put_api_key_tx(
            &mut transaction,
            tenant,
            key_id,
            principal_id,
            verifier_sha256,
            allowed_actions,
            active_from,
            expires_at,
            rotated_from_key_id,
            now,
        )
        .await?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    pub async fn get_active_api_key(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        now: u64,
    ) -> Result<Option<HostedApiKeyRecord>, HostedMarketStoreError> {
        validate_identifier(key_id, MAX_KEY_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("key_id"))?;
        let now_i64 = checked_i64(now, "api_key now")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT key_id, principal_id, verifier_sha256, allowed_actions, active_from, expires_at, revoked_at, rotated_from_key_id, created_at FROM chio_finding_market_api_keys WHERE tenant_id = $1 AND key_id = $2 AND active_from <= $3 AND expires_at > $3 AND revoked_at IS NULL",
        )
        .bind(tenant.as_str())
        .bind(key_id)
        .bind(now_i64)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
        row.map(|row| api_key_from_row(tenant, &row)).transpose()
    }

    pub async fn revoke_api_key(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        revoked_at: u64,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_identifier(key_id, MAX_KEY_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("key_id"))?;
        let revoked_at = checked_i64(revoked_at, "api_key revoked_at")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let outcome = revoke_api_key_tx(&mut transaction, tenant, key_id, revoked_at).await?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn consume_capability_dpop_admission(
        &self,
        tenant: &HostedTenantId,
        capability_id: &str,
        nonce_sha256: &str,
        request_sha256: Option<&str>,
        valid_through: u64,
        max_invocations: u32,
        expires_at: u64,
        now: u64,
        tenant_nonce_capacity: u64,
    ) -> Result<HostedCapabilityAdmissionOutcome, HostedMarketStoreError> {
        validate_identifier(capability_id, MAX_CAPABILITY_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("capability_id"))?;
        validate_digest(nonce_sha256, "nonce_sha256")?;
        if let Some(request_sha256) = request_sha256 {
            validate_digest(request_sha256, "request_sha256")?;
        }
        if valid_through <= now
            || max_invocations == 0
            || expires_at <= now
            || !(1..=MAX_AUTH_CAPACITY).contains(&tenant_nonce_capacity)
        {
            return Err(HostedMarketStoreError::Invalid("capability_dpop_admission"));
        }
        let valid_through = checked_i64(valid_through, "dpop valid_through")?;
        let max_invocations = i64::from(max_invocations);
        let expires_at = checked_i64(expires_at, "capability expires_at")?;
        let now = checked_i64(now, "capability dpop now")?;
        let capacity = checked_i64(tenant_nonce_capacity, "dpop capacity")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        if resumes_admitted_request(&mut transaction, tenant, capability_id, request_sha256, now)
            .await?
        {
            transaction.commit().await.map_err(unavailable)?;
            return Ok(HostedCapabilityAdmissionOutcome::RetriedSameRequest);
        }
        let replayed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM chio_finding_market_dpop_nonces WHERE tenant_id = $1 AND capability_id = $2 AND nonce_sha256 = $3 AND valid_through > $4)",
        )
        .bind(tenant.as_str())
        .bind(capability_id)
        .bind(nonce_sha256)
        .bind(now)
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        if replayed {
            transaction.commit().await.map_err(unavailable)?;
            return Ok(HostedCapabilityAdmissionOutcome::Replay);
        }
        // A replica running the previous release serializes its capacity
        // decision on this tenant-keyed advisory lock and accounts for the
        // nonce only afterwards, so trigger-maintained visibility alone
        // would not exclude it: it could decide against a stale count while
        // this transaction admits into the last slot. Taking the same lock
        // here restores mutual exclusion across both releases and adds no
        // contention class of its own, since admissions already serialize
        // on the admission-state row below.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1))")
            .bind(tenant.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        // The admission-state row is the per-tenant serialization point:
        // its lock covers the live-nonce counter, the sweep decision, and
        // the nonce insert below. Expired-credential sweeps run only under
        // capacity pressure or on the sweep cadence, so the ordinary
        // admission path stays O(1) in the number of live nonces.
        sqlx::query(
            "INSERT INTO chio_finding_market_dpop_admission_state (tenant_id, live_nonces, last_swept_at) VALUES ($1, 0, 0) ON CONFLICT (tenant_id) DO NOTHING",
        )
        .bind(tenant.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let state = sqlx::query(
            "SELECT live_nonces, last_swept_at, live_request_bindings FROM chio_finding_market_dpop_admission_state WHERE tenant_id = $1 FOR UPDATE",
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let mut live_nonces: i64 = state.try_get(0).map_err(unavailable)?;
        let last_swept_at: i64 = state.try_get(1).map_err(unavailable)?;
        let mut live_bindings: i64 = state.try_get(2).map_err(unavailable)?;
        let binding_capacity = capacity.saturating_mul(RETAINED_BINDINGS_PER_NONCE_SLOT);
        // The probe before the locks can miss an admission of this same
        // request that was still in flight, and a fresh proof carries a
        // nonce the replay probe does not recognize either. This row is the
        // tenant's serialization point, so no other admission can record one
        // between here and this transaction's end: a single check covers the
        // capacity, budget, and nonce decisions below, and concurrent
        // retries of one request spend one invocation rather than several.
        if resumes_admitted_request(&mut transaction, tenant, capability_id, request_sha256, now)
            .await?
        {
            transaction.commit().await.map_err(unavailable)?;
            return Ok(HostedCapabilityAdmissionOutcome::RetriedSameRequest);
        }
        if live_nonces >= capacity
            || live_bindings >= binding_capacity
            || now.saturating_sub(last_swept_at) >= DPOP_SWEEP_INTERVAL_SECS
        {
            let live = sweep_expired_dpop_state(&mut transaction, tenant, now).await?;
            live_nonces = live.nonces;
            live_bindings = live.request_bindings;
        }
        if live_nonces >= capacity {
            transaction.commit().await.map_err(unavailable)?;
            return Err(HostedMarketStoreError::Capacity);
        }
        // This admission would retain a binding of its own: a retry of one
        // already recorded resumed above. Refusing here rather than evicting
        // keeps every recorded request recoverable for as long as the
        // capability that admitted it lives.
        if request_sha256.is_some() && live_bindings >= binding_capacity {
            transaction.commit().await.map_err(unavailable)?;
            return Err(HostedMarketStoreError::Capacity);
        }
        let row = sqlx::query(
            "SELECT used_count, max_invocations, expires_at FROM chio_finding_market_capability_uses WHERE tenant_id = $1 AND capability_id = $2 FOR UPDATE",
        )
        .bind(tenant.as_str())
        .bind(capability_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let live_row = match row {
            Some(row) => {
                let stored_expiry: i64 = row.try_get(2).map_err(unavailable)?;
                if stored_expiry <= now {
                    sqlx::query(
                        "DELETE FROM chio_finding_market_capability_uses WHERE tenant_id = $1 AND capability_id = $2",
                    )
                    .bind(tenant.as_str())
                    .bind(capability_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(unavailable)?;
                    None
                } else {
                    Some(row)
                }
            }
            None => None,
        };
        if let Some(row) = live_row {
            let used: i64 = row.try_get(0).map_err(unavailable)?;
            let stored_max: i64 = row.try_get(1).map_err(unavailable)?;
            let stored_expiry: i64 = row.try_get(2).map_err(unavailable)?;
            if stored_max != max_invocations || stored_expiry != expires_at {
                return Err(HostedMarketStoreError::Conflict);
            }
            if used >= max_invocations {
                transaction.commit().await.map_err(unavailable)?;
                return Ok(HostedCapabilityAdmissionOutcome::BudgetExceeded);
            }
            sqlx::query(
                "UPDATE chio_finding_market_capability_uses SET used_count = used_count + 1, updated_at = $3 WHERE tenant_id = $1 AND capability_id = $2",
            )
            .bind(tenant.as_str())
            .bind(capability_id)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        } else {
            sqlx::query(
                "INSERT INTO chio_finding_market_capability_uses (tenant_id, capability_id, used_count, max_invocations, expires_at, updated_at) VALUES ($1, $2, 1, $3, $4, $5)",
            )
            .bind(tenant.as_str())
            .bind(capability_id)
            .bind(max_invocations)
            .bind(expires_at)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        }
        // Replace an expired row carrying this exact nonce. The live-nonce
        // counter is trigger-maintained, so the delete and the insert below
        // net out on their own.
        sqlx::query(
            "DELETE FROM chio_finding_market_dpop_nonces WHERE tenant_id = $1 AND capability_id = $2 AND nonce_sha256 = $3 AND valid_through <= $4",
        )
        .bind(tenant.as_str())
        .bind(capability_id)
        .bind(nonce_sha256)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let inserted = sqlx::query(
            "INSERT INTO chio_finding_market_dpop_nonces (tenant_id, capability_id, nonce_sha256, valid_through, created_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(tenant.as_str())
        .bind(capability_id)
        .bind(nonce_sha256)
        .bind(valid_through)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?
        .rows_affected();
        if inserted != 1 {
            // This nonce was already live even though the probe before the
            // locks did not observe it, so the proof is a replay. A retry of
            // a request this capability already admitted returned above, so
            // rolling back here cannot lose one.
            transaction.rollback().await.map_err(unavailable)?;
            return Ok(HostedCapabilityAdmissionOutcome::Replay);
        }
        if let Some(request_sha256) = request_sha256 {
            // The capability admitted this request. The record outlives the
            // proof so an interrupted mutation can be retried with a fresh
            // one without spending another invocation.
            // An expired record for this same request can still hold the
            // key, since the sweep that removes it runs on capacity pressure
            // or its own cadence. The resume probe above ignores an expired
            // record, so leaving its expiry in place would deny the retry
            // this admission is recording itself for.
            sqlx::query(
                "DELETE FROM chio_finding_market_capability_request_admissions WHERE tenant_id = $1 AND capability_id = $2 AND request_sha256 = $3 AND expires_at <= $4",
            )
            .bind(tenant.as_str())
            .bind(capability_id)
            .bind(request_sha256)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
            sqlx::query(
                "INSERT INTO chio_finding_market_capability_request_admissions (tenant_id, capability_id, request_sha256, admitted_at, expires_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            )
            .bind(tenant.as_str())
            .bind(capability_id)
            .bind(request_sha256)
            .bind(now)
            .bind(expires_at)
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        }
        transaction.commit().await.map_err(unavailable)?;
        Ok(HostedCapabilityAdmissionOutcome::Admitted)
    }

    pub async fn append_security_event(
        &self,
        tenant: &HostedTenantId,
        event_id: &str,
        event_kind: &str,
        artifact_json: &[u8],
        now: u64,
    ) -> Result<HostedSecurityEventOutcome, HostedMarketStoreError> {
        validate_security_event(event_id, event_kind, artifact_json)?;
        let digest = sha256_hex(artifact_json);
        let now = checked_i64(now, "security_event now")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let outcome = append_security_event_tx(
            &mut transaction,
            tenant,
            event_id,
            event_kind,
            artifact_json,
            &digest,
            now,
        )
        .await?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    /// Atomically install an API key and its signed lifecycle event.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_api_key_with_security_event(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        principal_id: &str,
        verifier_sha256: &str,
        allowed_actions: &BTreeSet<String>,
        active_from: u64,
        expires_at: u64,
        rotated_from_key_id: Option<&str>,
        event_id: &str,
        event_kind: &str,
        artifact_json: &[u8],
        now: u64,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_api_key_issue(
            key_id,
            principal_id,
            verifier_sha256,
            allowed_actions,
            active_from,
            expires_at,
            rotated_from_key_id,
        )?;
        validate_security_event(event_id, event_kind, artifact_json)?;
        let active_from = checked_i64(active_from, "api_key active_from")?;
        let expires_at = checked_i64(expires_at, "api_key expires_at")?;
        let now = checked_i64(now, "api_key now")?;
        let digest = sha256_hex(artifact_json);
        let mut transaction = self.begin_tenant(tenant).await?;
        let key_outcome = put_api_key_tx(
            &mut transaction,
            tenant,
            key_id,
            principal_id,
            verifier_sha256,
            allowed_actions,
            active_from,
            expires_at,
            rotated_from_key_id,
            now,
        )
        .await?;
        let event_outcome = append_security_event_tx(
            &mut transaction,
            tenant,
            event_id,
            event_kind,
            artifact_json,
            &digest,
            now,
        )
        .await?;
        if matches!(key_outcome, HostedJobWriteOutcome::ExactReplay)
            != matches!(event_outcome, HostedSecurityEventOutcome::ExactReplay)
        {
            return Err(HostedMarketStoreError::Conflict);
        }
        transaction.commit().await.map_err(unavailable)?;
        Ok(key_outcome)
    }

    /// Atomically revoke an API key and append its signed lifecycle event.
    pub async fn revoke_api_key_with_security_event(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        revoked_at: u64,
        event_id: &str,
        event_kind: &str,
        artifact_json: &[u8],
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_identifier(key_id, MAX_KEY_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("key_id"))?;
        validate_security_event(event_id, event_kind, artifact_json)?;
        let revoked_at = checked_i64(revoked_at, "api_key revoked_at")?;
        let digest = sha256_hex(artifact_json);
        let mut transaction = self.begin_tenant(tenant).await?;
        let key_outcome = revoke_api_key_tx(&mut transaction, tenant, key_id, revoked_at).await?;
        let event_outcome = append_security_event_tx(
            &mut transaction,
            tenant,
            event_id,
            event_kind,
            artifact_json,
            &digest,
            revoked_at,
        )
        .await?;
        if matches!(key_outcome, HostedJobWriteOutcome::ExactReplay)
            != matches!(event_outcome, HostedSecurityEventOutcome::ExactReplay)
        {
            return Err(HostedMarketStoreError::Conflict);
        }
        transaction.commit().await.map_err(unavailable)?;
        Ok(key_outcome)
    }
}

pub(crate) fn validate_principal_lifecycle_event(
    tenant: &HostedTenantId,
    expected_signer: &PublicKey,
    event: &SignedHostedPrincipalLifecycleEvent,
) -> Result<Vec<u8>, HostedMarketStoreError> {
    let body = &event.body;
    if body.schema != HOSTED_PRINCIPAL_LIFECYCLE_SCHEMA
        || body.tenant_id != tenant.as_str()
        || event.signer_key != *expected_signer
        || expected_signer.is_weak_ed25519()
        || !matches!(event.verify_signature(), Ok(true))
        || body.created_at == 0
    {
        return Err(HostedMarketStoreError::Invalid("principal lifecycle"));
    }
    validate_identifier(&body.principal_id, MAX_PRINCIPAL_ID_BYTES)
        .map_err(|_| HostedMarketStoreError::Invalid("principal_id"))?;
    if let Some(key) = body.capability_public_key_hex.as_deref() {
        let parsed = chio_core_types::PublicKey::from_hex(key)
            .map_err(|_| HostedMarketStoreError::Invalid("capability_public_key"))?;
        if parsed.is_weak_ed25519() || parsed.to_hex() != key {
            return Err(HostedMarketStoreError::Invalid("capability_public_key"));
        }
    }
    if let Some(previous) = body.previous_event_sha256.as_deref() {
        validate_digest(previous, "principal lifecycle predecessor")?;
    }
    match body.operation {
        HostedPrincipalLifecycleOperation::Provision
            if body.previous_event_sha256.is_some() || body.overlap_expires_at.is_some() =>
        {
            return Err(HostedMarketStoreError::Invalid("principal lifecycle"));
        }
        HostedPrincipalLifecycleOperation::KeyRotation => {
            let overlap = body
                .overlap_expires_at
                .ok_or(HostedMarketStoreError::Invalid("principal key overlap"))?;
            if body.previous_event_sha256.is_none()
                || body.capability_public_key_hex.is_none()
                || overlap <= body.created_at
                || overlap > body.created_at.saturating_add(86_400)
            {
                return Err(HostedMarketStoreError::Invalid("principal key overlap"));
            }
        }
        HostedPrincipalLifecycleOperation::Disable
        | HostedPrincipalLifecycleOperation::RoleChange
        | HostedPrincipalLifecycleOperation::EmergencyRevoke
            if body.previous_event_sha256.is_none() || body.overlap_expires_at.is_some() =>
        {
            return Err(HostedMarketStoreError::Invalid("principal lifecycle"));
        }
        _ => {}
    }
    let envelope = canonical_json_bytes(event)
        .map_err(|_| HostedMarketStoreError::Invalid("principal lifecycle"))?;
    if envelope.is_empty() || envelope.len() > MAX_SECURITY_EVENT_BYTES {
        return Err(HostedMarketStoreError::Invalid("principal lifecycle"));
    }
    Ok(envelope)
}

#[allow(clippy::too_many_arguments)]
async fn put_api_key_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &HostedTenantId,
    key_id: &str,
    principal_id: &str,
    verifier_sha256: &str,
    allowed_actions: &BTreeSet<String>,
    active_from: i64,
    expires_at: i64,
    rotated_from_key_id: Option<&str>,
    now: i64,
) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
    let principal_enabled = sqlx::query_scalar::<_, bool>(
        "SELECT enabled FROM chio_finding_market_principals WHERE tenant_id = $1 AND principal_id = $2",
    )
    .bind(tenant.as_str())
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(unavailable)?
    .ok_or(HostedMarketStoreError::NotFound)?;
    if !principal_enabled {
        return Err(HostedMarketStoreError::TenantDisabled);
    }
    let existing = sqlx::query(
        "SELECT principal_id, verifier_sha256, allowed_actions, active_from, expires_at, rotated_from_key_id FROM chio_finding_market_api_keys WHERE tenant_id = $1 AND key_id = $2 FOR UPDATE",
    )
    .bind(tenant.as_str())
    .bind(key_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(unavailable)?;
    if let Some(row) = existing {
        let same = row.try_get::<String, _>(0).map_err(unavailable)? == principal_id
            && row.try_get::<String, _>(1).map_err(unavailable)? == verifier_sha256
            && row.try_get::<Vec<String>, _>(2).map_err(unavailable)?
                == allowed_actions.iter().cloned().collect::<Vec<_>>()
            && row.try_get::<i64, _>(3).map_err(unavailable)? == active_from
            && row.try_get::<i64, _>(4).map_err(unavailable)? == expires_at
            && row
                .try_get::<Option<String>, _>(5)
                .map_err(unavailable)?
                .as_deref()
                == rotated_from_key_id;
        return if same {
            Ok(HostedJobWriteOutcome::ExactReplay)
        } else {
            Err(HostedMarketStoreError::Conflict)
        };
    }
    sqlx::query(
        "INSERT INTO chio_finding_market_api_keys (tenant_id, key_id, principal_id, verifier_sha256, allowed_actions, active_from, expires_at, rotated_from_key_id, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(tenant.as_str())
    .bind(key_id)
    .bind(principal_id)
    .bind(verifier_sha256)
    .bind(allowed_actions.iter().cloned().collect::<Vec<_>>())
    .bind(active_from)
    .bind(expires_at)
    .bind(rotated_from_key_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    Ok(HostedJobWriteOutcome::Inserted)
}

async fn revoke_api_key_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &HostedTenantId,
    key_id: &str,
    revoked_at: i64,
) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
    let row = sqlx::query(
        "SELECT active_from, revoked_at FROM chio_finding_market_api_keys WHERE tenant_id = $1 AND key_id = $2 FOR UPDATE",
    )
    .bind(tenant.as_str())
    .bind(key_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(unavailable)?
    .ok_or(HostedMarketStoreError::NotFound)?;
    let active_from: i64 = row.try_get(0).map_err(unavailable)?;
    let existing: Option<i64> = row.try_get(1).map_err(unavailable)?;
    if revoked_at < active_from {
        return Err(HostedMarketStoreError::Invalid("api_key revoked_at"));
    }
    if let Some(existing) = existing {
        return if existing == revoked_at {
            Ok(HostedJobWriteOutcome::ExactReplay)
        } else {
            Err(HostedMarketStoreError::Conflict)
        };
    }
    sqlx::query(
        "UPDATE chio_finding_market_api_keys SET revoked_at = $3 WHERE tenant_id = $1 AND key_id = $2 AND revoked_at IS NULL",
    )
    .bind(tenant.as_str())
    .bind(key_id)
    .bind(revoked_at)
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    Ok(HostedJobWriteOutcome::Inserted)
}

#[allow(clippy::too_many_arguments)]
async fn append_security_event_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &HostedTenantId,
    event_id: &str,
    event_kind: &str,
    artifact_json: &[u8],
    artifact_sha256: &str,
    now: i64,
) -> Result<HostedSecurityEventOutcome, HostedMarketStoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 5))")
        .bind(auth_lock_key("security-event", tenant.as_str(), event_id))
        .execute(&mut **transaction)
        .await
        .map_err(unavailable)?;
    let existing = sqlx::query(
        "SELECT event_kind, artifact_sha256, artifact_json FROM chio_finding_market_security_events WHERE tenant_id = $1 AND event_id = $2",
    )
    .bind(tenant.as_str())
    .bind(event_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(unavailable)?;
    if let Some(row) = existing {
        let same = row.try_get::<String, _>(0).map_err(unavailable)? == event_kind
            && row.try_get::<String, _>(1).map_err(unavailable)? == artifact_sha256
            && row.try_get::<Vec<u8>, _>(2).map_err(unavailable)? == artifact_json;
        return if same {
            Ok(HostedSecurityEventOutcome::ExactReplay)
        } else {
            Err(HostedMarketStoreError::Conflict)
        };
    }
    sqlx::query(
        "INSERT INTO chio_finding_market_security_events (tenant_id, event_id, event_kind, artifact_sha256, artifact_json, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(tenant.as_str())
    .bind(event_id)
    .bind(event_kind)
    .bind(artifact_sha256)
    .bind(artifact_json)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    Ok(HostedSecurityEventOutcome::Inserted)
}

fn auth_lock_key(domain: &str, tenant_id: &str, identifier: &str) -> String {
    format!(
        "chio.finding.hosted.auth-lock.v1:{domain}:{}:{tenant_id}:{}:{identifier}",
        tenant_id.len(),
        identifier.len()
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_api_key_issue(
    key_id: &str,
    principal_id: &str,
    verifier_sha256: &str,
    allowed_actions: &BTreeSet<String>,
    active_from: u64,
    expires_at: u64,
    rotated_from_key_id: Option<&str>,
) -> Result<(), HostedMarketStoreError> {
    validate_identifier(key_id, MAX_KEY_ID_BYTES)
        .map_err(|_| HostedMarketStoreError::Invalid("key_id"))?;
    validate_identifier(principal_id, MAX_PRINCIPAL_ID_BYTES)
        .map_err(|_| HostedMarketStoreError::Invalid("principal_id"))?;
    validate_digest(verifier_sha256, "api_key_verifier")?;
    validate_allowed_actions(allowed_actions)?;
    if let Some(previous) = rotated_from_key_id {
        validate_identifier(previous, MAX_KEY_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("rotated_from_key_id"))?;
        if previous == key_id {
            return Err(HostedMarketStoreError::Invalid("rotated_from_key_id"));
        }
    }
    if expires_at <= active_from {
        return Err(HostedMarketStoreError::Invalid("api_key_window"));
    }
    Ok(())
}

fn validate_security_event(
    event_id: &str,
    event_kind: &str,
    artifact_json: &[u8],
) -> Result<(), HostedMarketStoreError> {
    validate_identifier(event_id, MAX_EVENT_ID_BYTES)
        .map_err(|_| HostedMarketStoreError::Invalid("event_id"))?;
    validate_identifier(event_kind, MAX_EVENT_KIND_BYTES)
        .map_err(|_| HostedMarketStoreError::Invalid("event_kind"))?;
    validate_canonical_json(artifact_json, "security_event")?;
    if artifact_json.len() > MAX_SECURITY_EVENT_BYTES {
        return Err(HostedMarketStoreError::Invalid("security_event"));
    }
    Ok(())
}

fn principal_from_row(
    tenant: &HostedTenantId,
    row: &sqlx::postgres::PgRow,
) -> Result<HostedPrincipal, HostedMarketStoreError> {
    let principal_id: String = row.try_get(0).map_err(unavailable)?;
    validate_identifier(&principal_id, MAX_PRINCIPAL_ID_BYTES)
        .map_err(|()| HostedMarketStoreError::DigestMismatch)?;
    let role = row
        .try_get::<String, _>(1)
        .map_err(unavailable)?
        .parse::<HostedPrincipalRole>()
        .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    let capability_public_key_hex: Option<String> = row.try_get(2).map_err(unavailable)?;
    if let Some(key) = capability_public_key_hex.as_deref() {
        let parsed = chio_core_types::PublicKey::from_hex(key)
            .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
        if parsed.is_weak_ed25519() {
            return Err(HostedMarketStoreError::DigestMismatch);
        }
    }
    Ok(HostedPrincipal {
        tenant_id: tenant.clone(),
        principal_id,
        role,
        capability_public_key_hex,
        enabled: row.try_get(3).map_err(unavailable)?,
        created_at: stored_u64(row.try_get(4).map_err(unavailable)?)?,
        updated_at: stored_u64(row.try_get(5).map_err(unavailable)?)?,
    })
}

fn api_key_from_row(
    tenant: &HostedTenantId,
    row: &sqlx::postgres::PgRow,
) -> Result<HostedApiKeyRecord, HostedMarketStoreError> {
    let key_id: String = row.try_get(0).map_err(unavailable)?;
    let principal_id: String = row.try_get(1).map_err(unavailable)?;
    let verifier_sha256: String = row.try_get(2).map_err(unavailable)?;
    validate_identifier(&key_id, MAX_KEY_ID_BYTES)
        .map_err(|()| HostedMarketStoreError::DigestMismatch)?;
    validate_identifier(&principal_id, MAX_PRINCIPAL_ID_BYTES)
        .map_err(|()| HostedMarketStoreError::DigestMismatch)?;
    validate_digest(&verifier_sha256, "durable api key verifier")
        .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    let allowed_actions: BTreeSet<String> = row
        .try_get::<Vec<String>, _>(3)
        .map_err(unavailable)?
        .into_iter()
        .collect();
    validate_allowed_actions(&allowed_actions)
        .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    let rotated_from_key_id: Option<String> = row.try_get(7).map_err(unavailable)?;
    if let Some(previous) = rotated_from_key_id.as_deref() {
        validate_identifier(previous, MAX_KEY_ID_BYTES)
            .map_err(|()| HostedMarketStoreError::DigestMismatch)?;
    }
    Ok(HostedApiKeyRecord {
        tenant_id: tenant.clone(),
        key_id,
        principal_id,
        verifier_sha256,
        allowed_actions,
        active_from: stored_u64(row.try_get(4).map_err(unavailable)?)?,
        expires_at: stored_u64(row.try_get(5).map_err(unavailable)?)?,
        revoked_at: row
            .try_get::<Option<i64>, _>(6)
            .map_err(unavailable)?
            .map(stored_u64)
            .transpose()?,
        rotated_from_key_id,
        created_at: stored_u64(row.try_get(8).map_err(unavailable)?)?,
    })
}

/// Whether this capability already admitted this exact request.
///
/// Only a request carrying an idempotency key is recorded, so a read proof
/// can never resume. The record outlives the proof that created it, which
/// is what lets a mutation cut short after admission be retried once its
/// original proof has expired.
async fn resumes_admitted_request(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &HostedTenantId,
    capability_id: &str,
    request_sha256: Option<&str>,
    now: i64,
) -> Result<bool, HostedMarketStoreError> {
    let Some(request_sha256) = request_sha256 else {
        return Ok(false);
    };
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chio_finding_market_capability_request_admissions WHERE tenant_id = $1 AND capability_id = $2 AND request_sha256 = $3 AND expires_at > $4)",
    )
    .bind(tenant.as_str())
    .bind(capability_id)
    .bind(request_sha256)
    .bind(now)
    .fetch_one(&mut **transaction)
    .await
    .map_err(unavailable)
}

/// What one tenant still holds after its expired state was reclaimed.
struct LiveAdmissionState {
    nonces: i64,
    request_bindings: i64,
}

/// Delete one tenant's expired nonces, request admissions and capability
/// uses, then resync both counters from an exact count. Callers hold the
/// admission-state row lock, so neither can drift while the sweep runs.
async fn sweep_expired_dpop_state(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &HostedTenantId,
    now: i64,
) -> Result<LiveAdmissionState, HostedMarketStoreError> {
    sqlx::query(
        "DELETE FROM chio_finding_market_dpop_nonces WHERE tenant_id = $1 AND valid_through <= $2",
    )
    .bind(tenant.as_str())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    sqlx::query(
        "DELETE FROM chio_finding_market_capability_request_admissions WHERE tenant_id = $1 AND expires_at <= $2",
    )
    .bind(tenant.as_str())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    sqlx::query(
        "DELETE FROM chio_finding_market_capability_uses WHERE tenant_id = $1 AND expires_at <= $2",
    )
    .bind(tenant.as_str())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    let nonces: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chio_finding_market_dpop_nonces WHERE tenant_id = $1",
    )
    .bind(tenant.as_str())
    .fetch_one(&mut **transaction)
    .await
    .map_err(unavailable)?;
    let request_bindings: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chio_finding_market_capability_request_admissions WHERE tenant_id = $1",
    )
    .bind(tenant.as_str())
    .fetch_one(&mut **transaction)
    .await
    .map_err(unavailable)?;
    sqlx::query(
        "UPDATE chio_finding_market_dpop_admission_state SET live_nonces = $2, live_request_bindings = $3, last_swept_at = $4 WHERE tenant_id = $1",
    )
    .bind(tenant.as_str())
    .bind(nonces)
    .bind(request_bindings)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    Ok(LiveAdmissionState {
        nonces,
        request_bindings,
    })
}

fn validate_allowed_actions(
    allowed_actions: &BTreeSet<String>,
) -> Result<(), HostedMarketStoreError> {
    if allowed_actions.is_empty() || allowed_actions.len() > MAX_ALLOWED_ACTIONS {
        return Err(HostedMarketStoreError::Invalid("allowed_actions"));
    }
    for action in allowed_actions {
        validate_identifier(action, MAX_EVENT_KIND_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("allowed_actions"))?;
    }
    Ok(())
}
