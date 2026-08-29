use chio_core_types::{canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};
use sqlx::Row as _;

use super::{
    checked_i64, stored_u64, unavailable, validate_canonical_json, validate_digest,
    validate_identifier, verify_payload, HostedJobWriteOutcome, HostedMarketStoreError,
    HostedTenantId, PostgresFindingMarketStore,
};

const MAX_AGGREGATE_ID_BYTES: usize = 256;
const MAX_EVENT_ID_BYTES: usize = 256;
const MAX_EVENT_KIND_BYTES: usize = 96;
const MAX_AGGREGATE_HISTORY: u32 = 10_000;
const EVENT_DIGEST_DOMAIN: &str = "chio.finding.hosted.aggregate-event.v1";

/// Closed set of durable cognition-market aggregate families.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum HostedAggregateKind {
    Finding,
    Listing,
    Admission,
    Purchase,
    PurchaseTerminal,
    FailedDelivery,
    Challenge,
    ChallengeOutcome,
    Liability,
    Appeal,
    Penalty,
    Enforcement,
    Settlement,
    StatusEpoch,
    AuditRound,
}

impl HostedAggregateKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::Listing => "listing",
            Self::Admission => "admission",
            Self::Purchase => "purchase",
            Self::PurchaseTerminal => "purchase_terminal",
            Self::FailedDelivery => "failed_delivery",
            Self::Challenge => "challenge",
            Self::ChallengeOutcome => "challenge_outcome",
            Self::Liability => "liability",
            Self::Appeal => "appeal",
            Self::Penalty => "penalty",
            Self::Enforcement => "enforcement",
            Self::Settlement => "settlement",
            Self::StatusEpoch => "status_epoch",
            Self::AuditRound => "audit_round",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, HostedMarketStoreError> {
        match value {
            "finding" => Ok(Self::Finding),
            "listing" => Ok(Self::Listing),
            "admission" => Ok(Self::Admission),
            "purchase" => Ok(Self::Purchase),
            "purchase_terminal" => Ok(Self::PurchaseTerminal),
            "failed_delivery" => Ok(Self::FailedDelivery),
            "challenge" => Ok(Self::Challenge),
            "challenge_outcome" => Ok(Self::ChallengeOutcome),
            "liability" => Ok(Self::Liability),
            "appeal" => Ok(Self::Appeal),
            "penalty" => Ok(Self::Penalty),
            "enforcement" => Ok(Self::Enforcement),
            "settlement" => Ok(Self::Settlement),
            "status_epoch" => Ok(Self::StatusEpoch),
            "audit_round" => Ok(Self::AuditRound),
            _ => Err(HostedMarketStoreError::DigestMismatch),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedAggregateEvent {
    pub tenant_id: HostedTenantId,
    pub aggregate_kind: HostedAggregateKind,
    pub aggregate_id: String,
    pub revision: u64,
    pub event_id: String,
    pub event_kind: String,
    pub previous_event_sha256: Option<String>,
    pub payload_sha256: String,
    pub payload_json: Vec<u8>,
    pub event_sha256: String,
    pub committed_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedAggregateHead {
    pub tenant_id: HostedTenantId,
    pub aggregate_kind: HostedAggregateKind,
    pub aggregate_id: String,
    pub revision: u64,
    pub event_sha256: String,
    pub updated_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AggregateEventDigest<'a> {
    domain: &'static str,
    tenant_id: &'a str,
    aggregate_kind: &'a str,
    aggregate_id: &'a str,
    revision: u64,
    event_id: &'a str,
    event_kind: &'a str,
    previous_event_sha256: Option<&'a str>,
    payload_sha256: &'a str,
    committed_at: u64,
}

impl PostgresFindingMarketStore {
    /// Append exactly one canonical event under an optimistic head fence.
    ///
    /// `expected_revision` and `expected_event_sha256` must describe the
    /// current head. A new aggregate uses revision zero and no digest. Event
    /// identifiers are tenant-global idempotency keys and replay only when all
    /// immutable event bytes and bindings match exactly.
    #[allow(clippy::too_many_arguments)]
    pub async fn append_aggregate_event(
        &self,
        tenant: &HostedTenantId,
        aggregate_kind: HostedAggregateKind,
        aggregate_id: &str,
        event_id: &str,
        event_kind: &str,
        expected_revision: u64,
        expected_event_sha256: Option<&str>,
        payload_json: &[u8],
        committed_at: u64,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_identifier(aggregate_id, MAX_AGGREGATE_ID_BYTES)
            .map_err(|()| HostedMarketStoreError::Invalid("aggregate_id"))?;
        validate_identifier(event_id, MAX_EVENT_ID_BYTES)
            .map_err(|()| HostedMarketStoreError::Invalid("event_id"))?;
        validate_identifier(event_kind, MAX_EVENT_KIND_BYTES)
            .map_err(|()| HostedMarketStoreError::Invalid("event_kind"))?;
        validate_canonical_json(payload_json, "aggregate payload")?;
        if expected_revision == 0 {
            if expected_event_sha256.is_some() {
                return Err(HostedMarketStoreError::Invalid("expected aggregate head"));
            }
        } else {
            validate_digest(
                expected_event_sha256
                    .ok_or(HostedMarketStoreError::Invalid("expected aggregate head"))?,
                "expected aggregate head",
            )?;
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(HostedMarketStoreError::Invalid("aggregate revision"))?;
        if revision > u64::from(MAX_AGGREGATE_HISTORY) {
            return Err(HostedMarketStoreError::Capacity);
        }
        let committed_at_i64 = checked_i64(committed_at, "aggregate commit time")?;
        let payload_sha256 = sha256_hex(payload_json);
        let event_sha256 = aggregate_event_digest(
            tenant,
            aggregate_kind,
            aggregate_id,
            revision,
            event_id,
            event_kind,
            expected_event_sha256,
            &payload_sha256,
            committed_at,
        )?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let outcome: i16 = sqlx::query_scalar(
            r#"SELECT chio_finding_market_append_aggregate_event(
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
            )"#,
        )
        .bind(tenant.as_str())
        .bind(aggregate_kind.label())
        .bind(aggregate_id)
        .bind(
            i64::try_from(expected_revision)
                .map_err(|_| HostedMarketStoreError::Invalid("expected aggregate revision"))?,
        )
        .bind(expected_event_sha256)
        .bind(event_id)
        .bind(event_kind)
        .bind(&payload_sha256)
        .bind(payload_json)
        .bind(&event_sha256)
        .bind(committed_at_i64)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
        let outcome = match outcome {
            0 => HostedJobWriteOutcome::Inserted,
            1 => HostedJobWriteOutcome::ExactReplay,
            2 => return Err(HostedMarketStoreError::Conflict),
            _ => return Err(HostedMarketStoreError::Unavailable),
        };
        transaction
            .commit()
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        Ok(outcome)
    }

    pub async fn aggregate_head(
        &self,
        tenant: &HostedTenantId,
        aggregate_kind: HostedAggregateKind,
        aggregate_id: &str,
    ) -> Result<Option<HostedAggregateHead>, HostedMarketStoreError> {
        validate_identifier(aggregate_id, MAX_AGGREGATE_ID_BYTES)
            .map_err(|()| HostedMarketStoreError::Invalid("aggregate_id"))?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            r#"SELECT tenant_id, aggregate_kind, aggregate_id, revision,
                      event_sha256, updated_at
               FROM chio_finding_market_aggregate_heads
               WHERE tenant_id = $1 AND aggregate_kind = $2 AND aggregate_id = $3"#,
        )
        .bind(tenant.as_str())
        .bind(aggregate_kind.label())
        .bind(aggregate_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        row.map(|row| aggregate_head_from_row(tenant, &row))
            .transpose()
    }

    pub async fn aggregate_history(
        &self,
        tenant: &HostedTenantId,
        aggregate_kind: HostedAggregateKind,
        aggregate_id: &str,
        limit: u32,
    ) -> Result<Vec<HostedAggregateEvent>, HostedMarketStoreError> {
        validate_identifier(aggregate_id, MAX_AGGREGATE_ID_BYTES)
            .map_err(|()| HostedMarketStoreError::Invalid("aggregate_id"))?;
        if limit == 0 || limit > MAX_AGGREGATE_HISTORY {
            return Err(HostedMarketStoreError::Invalid("aggregate history limit"));
        }
        let mut transaction = self.begin_tenant_snapshot(tenant).await?;
        let head = sqlx::query(
            r#"SELECT revision, event_sha256
               FROM chio_finding_market_aggregate_heads
               WHERE tenant_id = $1 AND aggregate_kind = $2 AND aggregate_id = $3"#,
        )
        .bind(tenant.as_str())
        .bind(aggregate_kind.label())
        .bind(aggregate_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
        let Some(head) = head else {
            transaction
                .commit()
                .await
                .map_err(|_| HostedMarketStoreError::Unavailable)?;
            return Ok(Vec::new());
        };
        let head_revision = stored_u64(head.try_get(0).map_err(unavailable)?)?;
        let head_digest: String = head.try_get(1).map_err(unavailable)?;
        validate_digest(&head_digest, "durable aggregate head")
            .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
        if head_revision > u64::from(limit) {
            return Err(HostedMarketStoreError::Capacity);
        }
        let rows = sqlx::query(
            r#"SELECT tenant_id, aggregate_kind, aggregate_id, revision,
                      event_id, event_kind, previous_event_sha256, payload_sha256,
                      payload_json, event_sha256, committed_at
               FROM chio_finding_market_aggregate_events
               WHERE tenant_id = $1 AND aggregate_kind = $2 AND aggregate_id = $3
               ORDER BY revision ASC LIMIT $4"#,
        )
        .bind(tenant.as_str())
        .bind(aggregate_kind.label())
        .bind(aggregate_id)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        let events = rows
            .iter()
            .map(|row| aggregate_event_from_row(tenant, row))
            .collect::<Result<Vec<_>, _>>()?;
        verify_aggregate_history(&events, head_revision, &head_digest)?;
        Ok(events)
    }
}

#[allow(clippy::too_many_arguments)]
fn aggregate_event_digest(
    tenant: &HostedTenantId,
    aggregate_kind: HostedAggregateKind,
    aggregate_id: &str,
    revision: u64,
    event_id: &str,
    event_kind: &str,
    previous_event_sha256: Option<&str>,
    payload_sha256: &str,
    committed_at: u64,
) -> Result<String, HostedMarketStoreError> {
    canonical_json_bytes(&AggregateEventDigest {
        domain: EVENT_DIGEST_DOMAIN,
        tenant_id: tenant.as_str(),
        aggregate_kind: aggregate_kind.label(),
        aggregate_id,
        revision,
        event_id,
        event_kind,
        previous_event_sha256,
        payload_sha256,
        committed_at,
    })
    .map(|bytes| sha256_hex(&bytes))
    .map_err(|_| HostedMarketStoreError::Invalid("aggregate event digest"))
}

#[allow(clippy::too_many_arguments)]
fn aggregate_head_from_row(
    tenant: &HostedTenantId,
    row: &sqlx::postgres::PgRow,
) -> Result<HostedAggregateHead, HostedMarketStoreError> {
    let stored_tenant: String = row.try_get(0).map_err(unavailable)?;
    let aggregate_kind =
        HostedAggregateKind::parse(&row.try_get::<String, _>(1).map_err(unavailable)?)?;
    let aggregate_id: String = row.try_get(2).map_err(unavailable)?;
    let event_sha256: String = row.try_get(4).map_err(unavailable)?;
    if stored_tenant != tenant.as_str() {
        return Err(HostedMarketStoreError::Tenant);
    }
    validate_identifier(&aggregate_id, MAX_AGGREGATE_ID_BYTES)
        .map_err(|()| HostedMarketStoreError::DigestMismatch)?;
    validate_digest(&event_sha256, "durable aggregate head")
        .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    Ok(HostedAggregateHead {
        tenant_id: tenant.clone(),
        aggregate_kind,
        aggregate_id,
        revision: stored_u64(row.try_get(3).map_err(unavailable)?)?,
        event_sha256,
        updated_at: stored_u64(row.try_get(5).map_err(unavailable)?)?,
    })
}

fn aggregate_event_from_row(
    tenant: &HostedTenantId,
    row: &sqlx::postgres::PgRow,
) -> Result<HostedAggregateEvent, HostedMarketStoreError> {
    let stored_tenant: String = row.try_get(0).map_err(unavailable)?;
    let aggregate_kind =
        HostedAggregateKind::parse(&row.try_get::<String, _>(1).map_err(unavailable)?)?;
    let aggregate_id: String = row.try_get(2).map_err(unavailable)?;
    let revision = stored_u64(row.try_get(3).map_err(unavailable)?)?;
    let event_id: String = row.try_get(4).map_err(unavailable)?;
    let event_kind: String = row.try_get(5).map_err(unavailable)?;
    let previous_event_sha256: Option<String> = row.try_get(6).map_err(unavailable)?;
    let payload_sha256: String = row.try_get(7).map_err(unavailable)?;
    let payload_json: Vec<u8> = row.try_get(8).map_err(unavailable)?;
    let event_sha256: String = row.try_get(9).map_err(unavailable)?;
    let committed_at = stored_u64(row.try_get(10).map_err(unavailable)?)?;
    if stored_tenant != tenant.as_str() {
        return Err(HostedMarketStoreError::Tenant);
    }
    validate_identifier(&aggregate_id, MAX_AGGREGATE_ID_BYTES)
        .and_then(|()| validate_identifier(&event_id, MAX_EVENT_ID_BYTES))
        .and_then(|()| validate_identifier(&event_kind, MAX_EVENT_KIND_BYTES))
        .map_err(|()| HostedMarketStoreError::DigestMismatch)?;
    verify_payload(&payload_sha256, &payload_json)?;
    validate_digest(&event_sha256, "durable aggregate event")
        .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    if let Some(previous) = previous_event_sha256.as_deref() {
        validate_digest(previous, "durable aggregate predecessor")
            .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    }
    let expected_digest = aggregate_event_digest(
        tenant,
        aggregate_kind,
        &aggregate_id,
        revision,
        &event_id,
        &event_kind,
        previous_event_sha256.as_deref(),
        &payload_sha256,
        committed_at,
    )?;
    if expected_digest != event_sha256 {
        return Err(HostedMarketStoreError::DigestMismatch);
    }
    Ok(HostedAggregateEvent {
        tenant_id: tenant.clone(),
        aggregate_kind,
        aggregate_id,
        revision,
        event_id,
        event_kind,
        previous_event_sha256,
        payload_sha256,
        payload_json,
        event_sha256,
        committed_at,
    })
}

fn verify_aggregate_history(
    events: &[HostedAggregateEvent],
    head_revision: u64,
    head_digest: &str,
) -> Result<(), HostedMarketStoreError> {
    if u64::try_from(events.len()) != Ok(head_revision)
        || events.last().map(|event| event.event_sha256.as_str()) != Some(head_digest)
    {
        return Err(HostedMarketStoreError::DigestMismatch);
    }
    for (index, event) in events.iter().enumerate() {
        let revision = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(HostedMarketStoreError::DigestMismatch)?;
        let expected_previous = index
            .checked_sub(1)
            .and_then(|previous| events.get(previous))
            .map(|previous| previous.event_sha256.as_str());
        if event.revision != revision || event.previous_event_sha256.as_deref() != expected_previous
        {
            return Err(HostedMarketStoreError::DigestMismatch);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_kinds_have_a_closed_round_trip() {
        for kind in [
            HostedAggregateKind::Finding,
            HostedAggregateKind::Listing,
            HostedAggregateKind::Purchase,
            HostedAggregateKind::Challenge,
            HostedAggregateKind::Appeal,
            HostedAggregateKind::Enforcement,
            HostedAggregateKind::Settlement,
            HostedAggregateKind::StatusEpoch,
        ] {
            assert!(matches!(
                HostedAggregateKind::parse(kind.label()),
                Ok(parsed) if parsed == kind
            ));
        }
        assert!(HostedAggregateKind::parse("custom").is_err());
    }

    #[test]
    fn aggregate_event_digest_binds_tenant_revision_and_predecessor() {
        let tenant = HostedTenantId::new("tenant:a").unwrap_or_else(|error| panic!("{error}"));
        let digest = |revision, predecessor: Option<&str>| {
            aggregate_event_digest(
                &tenant,
                HostedAggregateKind::Challenge,
                "challenge:1",
                revision,
                "event:1",
                "challenge.submitted",
                predecessor,
                &"a".repeat(64),
                1_700_000_000,
            )
        };
        assert_ne!(digest(1, None).ok(), digest(2, None).ok());
        assert_ne!(digest(2, Some(&"b".repeat(64))).ok(), digest(2, None).ok());
    }

    #[test]
    fn aggregate_history_rejects_a_gap_or_broken_link() {
        let tenant = HostedTenantId::new("tenant:a").unwrap_or_else(|error| panic!("{error}"));
        let event = |revision, previous_event_sha256| HostedAggregateEvent {
            tenant_id: tenant.clone(),
            aggregate_kind: HostedAggregateKind::Challenge,
            aggregate_id: "challenge:1".to_owned(),
            revision,
            event_id: format!("event:{revision}"),
            event_kind: "challenge.transition".to_owned(),
            previous_event_sha256,
            payload_sha256: "a".repeat(64),
            payload_json: br#"{"state":"submitted"}"#.to_vec(),
            event_sha256: format!("{revision:064x}"),
            committed_at: 1_700_000_000,
        };
        let first = event(1, None);
        let second = event(2, Some(first.event_sha256.clone()));
        assert!(verify_aggregate_history(
            &[first.clone(), second.clone()],
            2,
            &second.event_sha256,
        )
        .is_ok());
        assert!(
            verify_aggregate_history(std::slice::from_ref(&first), 2, &second.event_sha256)
                .is_err()
        );
        assert!(verify_aggregate_history(
            &[first.clone(), event(3, Some(first.event_sha256))],
            2,
            &second.event_sha256,
        )
        .is_err());
        let malformed = event(1, Some("f".repeat(64)));
        assert!(verify_aggregate_history(
            std::slice::from_ref(&malformed),
            1,
            &malformed.event_sha256,
        )
        .is_err());
    }
}
