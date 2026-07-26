use super::*;
use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{PublicKey, Signature};
use chio_core::sha256_hex;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

const BUDGET_ANCHOR_GENESIS_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BudgetSnapshotAnchorCommitment {
    pub schema: String,
    pub commit_sequence: u64,
    pub previous_chain_digest: String,
    pub chain_digest: String,
    pub anchor_set_digest: String,
    pub leader_url: String,
    pub election_term: u64,
    pub committed_at: u64,
    pub signer_public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedBudgetSnapshotAnchorCommitment {
    pub body: BudgetSnapshotAnchorCommitment,
    pub signature: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BudgetSnapshotAnchorProvenance {
    pub schema: String,
    pub chain: Vec<SignedBudgetSnapshotAnchorCommitment>,
    pub cluster_authenticator: String,
}

#[derive(Serialize)]
struct AnchorSetDigestBody<'a> {
    schema: &'static str,
    anchors: Vec<AnchorDigestRecord<'a>>,
}

#[derive(Serialize)]
struct AnchorDigestRecord<'a> {
    capability_id: &'a str,
    grant_index: u32,
    invocation_count: u32,
    updated_at: i64,
    seq: u64,
    total_cost_exposed: u64,
    total_cost_realized_spend: u64,
}

#[derive(Serialize)]
struct AnchorChainDigestBody<'a> {
    schema: &'static str,
    commit_sequence: u64,
    previous_chain_digest: &'a str,
    anchor_set_digest: &'a str,
    leader_url: &'a str,
    election_term: u64,
    committed_at: u64,
    signer_public_key: &'a str,
}

#[derive(Serialize)]
struct AnchorAuthenticatorBody<'a> {
    scheme: &'static str,
    chain: &'a [SignedBudgetSnapshotAnchorCommitment],
}

pub fn budget_snapshot_anchor_set_digest(
    anchors: &[BudgetUsageRecord],
) -> Result<String, BudgetStoreError> {
    let mut canonical_anchors = anchors.to_vec();
    canonical_anchors.sort_by(|left, right| {
        (&left.capability_id, left.grant_index).cmp(&(&right.capability_id, right.grant_index))
    });
    let anchors = canonical_anchors
        .iter()
        .map(|anchor| AnchorDigestRecord {
            capability_id: &anchor.capability_id,
            grant_index: anchor.grant_index,
            invocation_count: anchor.invocation_count,
            updated_at: anchor.updated_at,
            seq: anchor.seq,
            total_cost_exposed: anchor.total_cost_exposed,
            total_cost_realized_spend: anchor.total_cost_realized_spend,
        })
        .collect();
    let bytes = canonical_json_bytes(&AnchorSetDigestBody {
        schema: "chio.budget-snapshot-anchor-set.v1",
        anchors,
    })
    .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn budget_snapshot_anchor_chain_digest(
    body: &BudgetSnapshotAnchorCommitment,
) -> Result<String, BudgetStoreError> {
    let bytes = canonical_json_bytes(&AnchorChainDigestBody {
        schema: "chio.budget-snapshot-anchor-chain.v1",
        commit_sequence: body.commit_sequence,
        previous_chain_digest: &body.previous_chain_digest,
        anchor_set_digest: &body.anchor_set_digest,
        leader_url: &body.leader_url,
        election_term: body.election_term,
        committed_at: body.committed_at,
        signer_public_key: &body.signer_public_key,
    })
    .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn budget_snapshot_anchor_authenticator(
    service_token: &str,
    chain: &[SignedBudgetSnapshotAnchorCommitment],
) -> Result<String, BudgetStoreError> {
    let bytes = canonical_json_bytes(&AnchorAuthenticatorBody {
        scheme: "chio.cluster-budget-anchor-auth.v1",
        chain,
    })
    .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
    let mut authenticator = Hmac::<Sha256>::new_from_slice(service_token.as_bytes())
        .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
    authenticator.update(&bytes);
    Ok(hex::encode(authenticator.finalize().into_bytes()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetStoreSnapshot {
    pub usages: Vec<BudgetUsageRecord>,
    pub usage_history_anchors: Vec<BudgetUsageRecord>,
    pub mutation_events: Vec<BudgetMutationRecord>,
    pub abandoned_seq_ranges: Vec<(u64, u64)>,
    pub covered_head: u64,
    pub origin_ack_heads: Vec<(String, u64)>,
}

struct BudgetImportBatch<'a> {
    usages: &'a [BudgetUsageRecord],
    events: &'a [BudgetMutationRecord],
    anchors: &'a [BudgetUsageRecord],
    abandoned_seq_ranges: &'a [(u64, u64)],
    covered_head: Option<u64>,
    origin_ack_heads: Option<&'a [(String, u64)]>,
    allow_verified_anchor_install: bool,
}

impl SqliteBudgetStore {
    pub fn budget_import_floor(&self, authority_id: &str) -> Result<u64, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let floor: i64 = transaction
            .query_row(
                "SELECT floor_seq FROM budget_import_floors WHERE authority_id = ?1",
                rusqlite::params![authority_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        transaction.rollback()?;
        Ok(floor.max(0) as u64)
    }

    pub fn record_budget_import_floors(
        &self,
        events: &[BudgetMutationRecord],
    ) -> Result<(), BudgetStoreError> {
        self.require_standalone_mutation("budget import floor")?;
        use std::collections::BTreeMap;
        let mut min_by_origin: BTreeMap<&str, u64> = BTreeMap::new();
        for event in events {
            let Some(authority) = event.authority.as_ref() else {
                continue;
            };
            let entry = min_by_origin
                .entry(authority.authority_id.as_str())
                .or_insert(event.event_seq);
            *entry = (*entry).min(event.event_seq);
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        for (origin, min_seq) in min_by_origin {
            let floor = min_seq.saturating_sub(1);
            transaction.execute(
                "INSERT INTO budget_import_floors (authority_id, floor_seq) VALUES (?1, ?2) \
                 ON CONFLICT(authority_id) DO UPDATE SET floor_seq = MAX(floor_seq, excluded.floor_seq)",
                rusqlite::params![origin, budget_u64_to_sqlite(floor, "floor_seq")?],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn upsert_usage(&self, record: &BudgetUsageRecord) -> Result<(), BudgetStoreError> {
        self.require_standalone_mutation("budget usage upsert")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::reconcile_imported_usages(&transaction, std::slice::from_ref(record), &[])?;
        transaction.commit()?;
        Ok(())
    }

    pub fn import_snapshot_records(
        &self,
        usages: &[BudgetUsageRecord],
        events: &[BudgetMutationRecord],
    ) -> Result<(), BudgetStoreError> {
        self.import_records(
            &BudgetImportBatch {
                usages,
                events,
                anchors: &[],
                abandoned_seq_ranges: &[],
                covered_head: None,
                origin_ack_heads: None,
                allow_verified_anchor_install: false,
            },
            "budget snapshot import",
        )
    }

    pub fn import_snapshot_records_with_anchors(
        &self,
        usages: &[BudgetUsageRecord],
        events: &[BudgetMutationRecord],
        anchors: &[BudgetUsageRecord],
        abandoned_seq_ranges: &[(u64, u64)],
        covered_head: u64,
    ) -> Result<(), BudgetStoreError> {
        self.import_records(
            &BudgetImportBatch {
                usages,
                events,
                anchors,
                abandoned_seq_ranges,
                covered_head: Some(covered_head),
                origin_ack_heads: None,
                allow_verified_anchor_install: false,
            },
            "budget snapshot import",
        )
    }

    pub fn import_budget_snapshot(
        &self,
        snapshot: &BudgetStoreSnapshot,
    ) -> Result<(), BudgetStoreError> {
        const OPERATION: &str = "budget snapshot import";
        self.require_standalone_mutation(OPERATION)?;

        let validated = Self::validate_budget_snapshot_in_isolation(snapshot)?;
        let batch = BudgetImportBatch {
            usages: &validated.usages,
            events: &validated.mutation_events,
            anchors: &validated.usage_history_anchors,
            abandoned_seq_ranges: &validated.abandoned_seq_ranges,
            covered_head: Some(validated.covered_head),
            origin_ack_heads: Some(&validated.origin_ack_heads),
            allow_verified_anchor_install: false,
        };
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::validate_exact_snapshot_usage_anchors(&transaction, batch.anchors)?;
        Self::validate_local_snapshot_subset(&transaction, &validated)?;
        Self::apply_import_batch(&transaction, &batch)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn import_budget_snapshot_with_anchor_provenance(
        &self,
        snapshot: &BudgetStoreSnapshot,
        provenance: &BudgetSnapshotAnchorProvenance,
        expected_leader_url: &str,
        expected_election_term: u64,
        cluster_service_token: &str,
    ) -> Result<(), BudgetStoreError> {
        const OPERATION: &str = "verified budget snapshot import";
        self.require_standalone_mutation(OPERATION)?;
        let head = verify_budget_snapshot_anchor_provenance(
            snapshot,
            provenance,
            expected_leader_url,
            expected_election_term,
            cluster_service_token,
        )?;
        let validated = Self::validate_budget_snapshot_in_isolation(snapshot)?;
        let batch = BudgetImportBatch {
            usages: &validated.usages,
            events: &validated.mutation_events,
            anchors: &validated.usage_history_anchors,
            abandoned_seq_ranges: &validated.abandoned_seq_ranges,
            covered_head: Some(validated.covered_head),
            origin_ack_heads: Some(&validated.origin_ack_heads),
            allow_verified_anchor_install: true,
        };
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        verify_local_anchor_provenance_continuity(&transaction, provenance)?;
        Self::validate_local_snapshot_subset(&transaction, &validated)?;
        Self::apply_import_batch(&transaction, &batch)?;
        let local = Self::snapshot_usage_history_anchors(&transaction)?;
        if local != validated.usage_history_anchors {
            return Err(BudgetStoreError::Invariant(
                "verified budget snapshot history anchor set is not exact".to_string(),
            ));
        }
        transaction.execute(
            r#"
            INSERT INTO budget_snapshot_anchor_provenance (
                leader_url, commit_sequence, chain_digest, anchor_set_digest,
                election_term, signer_public_key, committed_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(leader_url) DO UPDATE SET
                commit_sequence = excluded.commit_sequence,
                chain_digest = excluded.chain_digest,
                anchor_set_digest = excluded.anchor_set_digest,
                election_term = excluded.election_term,
                signer_public_key = excluded.signer_public_key,
                committed_at = excluded.committed_at
            "#,
            params![
                &head.leader_url,
                budget_u64_to_sqlite(head.commit_sequence, "anchor_commit_sequence")?,
                &head.chain_digest,
                &head.anchor_set_digest,
                budget_u64_to_sqlite(head.election_term, "anchor_election_term")?,
                &head.signer_public_key,
                budget_u64_to_sqlite(head.committed_at, "anchor_committed_at")?,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn import_delta_records(
        &self,
        usages: &[BudgetUsageRecord],
        events: &[BudgetMutationRecord],
    ) -> Result<(), BudgetStoreError> {
        self.import_records(
            &BudgetImportBatch {
                usages,
                events,
                anchors: &[],
                abandoned_seq_ranges: &[],
                covered_head: None,
                origin_ack_heads: None,
                allow_verified_anchor_install: false,
            },
            "budget delta import",
        )
    }

    fn import_records(
        &self,
        batch: &BudgetImportBatch<'_>,
        operation: &str,
    ) -> Result<(), BudgetStoreError> {
        self.require_standalone_mutation(operation)?;
        Self::validate_import_batch_order(batch.events)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::apply_import_batch(&transaction, batch)?;
        transaction.commit()?;
        Ok(())
    }

    fn apply_import_batch(
        transaction: &rusqlite::Transaction<'_>,
        batch: &BudgetImportBatch<'_>,
    ) -> Result<(), BudgetStoreError> {
        Self::install_snapshot_usage_anchors(
            transaction,
            batch.anchors,
            batch.allow_verified_anchor_install,
        )?;
        for event in batch.events {
            Self::import_mutation_record_in_transaction(transaction, event)?;
        }
        Self::reconcile_imported_usages(transaction, batch.usages, batch.events)?;
        Self::insert_abandoned_event_seq_ranges(transaction, batch.abandoned_seq_ranges)?;
        if let Some(claimed_head) = batch.covered_head {
            let exact_head = Self::contiguous_snapshot_head_from(transaction, 0)?;
            if claimed_head != exact_head {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget snapshot claimed covered head {claimed_head}, but imported records prove {exact_head}"
                )));
            }
            let exact_origin_heads = Self::origin_ack_heads_at(transaction, exact_head)?;
            if let Some(claimed_origin_heads) = batch.origin_ack_heads {
                if claimed_origin_heads != exact_origin_heads {
                    return Err(BudgetStoreError::Invariant(
                        "budget snapshot origin acknowledgement heads are not proved by the retained mutation prefix"
                            .to_string(),
                    ));
                }
            }
            Self::install_snapshot_coverage(transaction, exact_head, &exact_origin_heads)?;
        }
        Ok(())
    }

    fn validate_budget_snapshot_in_isolation(
        snapshot: &BudgetStoreSnapshot,
    ) -> Result<BudgetStoreSnapshot, BudgetStoreError> {
        let validator = Self::open(":memory:")?;
        Self::seed_snapshot_validation_anchors(&validator, &snapshot.usage_history_anchors)?;
        validator.import_records(
            &BudgetImportBatch {
                usages: &snapshot.usages,
                events: &snapshot.mutation_events,
                anchors: &snapshot.usage_history_anchors,
                abandoned_seq_ranges: &snapshot.abandoned_seq_ranges,
                covered_head: Some(snapshot.covered_head),
                origin_ack_heads: Some(&snapshot.origin_ack_heads),
                allow_verified_anchor_install: false,
            },
            "budget snapshot validation",
        )?;
        let validated = validator.export_budget_snapshot()?;
        Self::validate_staged_snapshot_matches_payload(snapshot, &validated)?;
        Ok(validated)
    }

    fn validate_staged_snapshot_matches_payload(
        payload: &BudgetStoreSnapshot,
        staged: &BudgetStoreSnapshot,
    ) -> Result<(), BudgetStoreError> {
        let mut payload_usages = payload.usages.clone();
        payload_usages.sort_by(|left, right| {
            (&left.capability_id, left.grant_index).cmp(&(&right.capability_id, right.grant_index))
        });
        if payload_usages != staged.usages {
            return Err(BudgetStoreError::Invariant(
                "budget snapshot does not carry its complete final usage projection".to_string(),
            ));
        }

        let same_event_history = payload.mutation_events.len() == staged.mutation_events.len()
            && payload
                .mutation_events
                .iter()
                .zip(&staged.mutation_events)
                .all(|(payload, staged)| {
                    payload.event_id == staged.event_id && payload.event_seq == staged.event_seq
                });
        let same_abandoned_history =
            payload.abandoned_seq_ranges.iter().all(|&(start, end)| {
                snapshot_ranges_cover(&staged.abandoned_seq_ranges, start, end)
            }) && staged.abandoned_seq_ranges.iter().all(|&(start, end)| {
                snapshot_ranges_cover(&payload.abandoned_seq_ranges, start, end)
            });
        if !same_event_history || !same_abandoned_history {
            return Err(BudgetStoreError::Invariant(
                "budget snapshot validation changed the supplied durable history".to_string(),
            ));
        }
        Ok(())
    }

    fn seed_snapshot_validation_anchors(
        validator: &Self,
        anchors: &[BudgetUsageRecord],
    ) -> Result<(), BudgetStoreError> {
        let mut connection = validator.connection()?;
        let transaction = validator.begin_write(&mut connection)?;
        transaction.execute(
            "INSERT OR IGNORE INTO budget_usage_anchor_migration_gate(singleton) VALUES (1)",
            [],
        )?;
        for anchor in anchors {
            Self::upsert_usage_in_transaction(&transaction, anchor)?;
            transaction.execute(
                r#"
                INSERT INTO budget_usage_history_anchors (
                    capability_id, grant_index, invocation_count, updated_at, seq,
                    total_cost_exposed, total_cost_realized_spend,
                    anchored_schema_version
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 6)
                "#,
                params![
                    &anchor.capability_id,
                    i64::from(anchor.grant_index),
                    i64::from(anchor.invocation_count),
                    anchor.updated_at,
                    budget_u64_to_sqlite(anchor.seq, "anchor_seq")?,
                    budget_u64_to_sqlite(anchor.total_cost_exposed, "anchor_total_cost_exposed")?,
                    budget_u64_to_sqlite(
                        anchor.total_cost_realized_spend,
                        "anchor_total_cost_realized_spend"
                    )?,
                ],
            )?;
        }
        transaction.execute("DELETE FROM budget_usage_anchor_migration_gate", [])?;
        transaction.commit()?;
        Ok(())
    }

    fn validate_exact_snapshot_usage_anchors(
        transaction: &rusqlite::Transaction<'_>,
        anchors: &[BudgetUsageRecord],
    ) -> Result<(), BudgetStoreError> {
        Self::install_snapshot_usage_anchors(transaction, anchors, false)?;
        let local = Self::snapshot_usage_history_anchors(transaction)?;
        let mut incoming = anchors.to_vec();
        incoming.sort_by(|left, right| {
            (&left.capability_id, left.grant_index).cmp(&(&right.capability_id, right.grant_index))
        });
        if local != incoming {
            return Err(BudgetStoreError::Invariant(
                "budget snapshot history anchor set differs from immutable local migration anchors"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_local_snapshot_subset(
        transaction: &rusqlite::Transaction<'_>,
        snapshot: &BudgetStoreSnapshot,
    ) -> Result<(), BudgetStoreError> {
        let incoming_events = snapshot
            .mutation_events
            .iter()
            .map(|event| (event.event_id.as_str(), event))
            .collect::<std::collections::BTreeMap<_, _>>();
        for local in Self::snapshot_mutation_events(transaction)? {
            if incoming_events.get(local.event_id.as_str()).copied() != Some(&local) {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget snapshot does not retain identical local event `{}`",
                    local.event_id
                )));
            }
        }

        for (start, end) in Self::snapshot_abandoned_seq_ranges(transaction)? {
            if !snapshot_ranges_cover(&snapshot.abandoned_seq_ranges, start, end) {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget snapshot does not retain local abandoned sequence range {start}..={end}"
                )));
            }
        }

        for usage in Self::snapshot_usages(transaction)? {
            if !snapshot_proves_usage(snapshot, &usage) {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget snapshot does not prove local usage `{}` grant {} at sequence {}",
                    usage.capability_id, usage.grant_index, usage.seq
                )));
            }
        }
        Ok(())
    }

    fn install_snapshot_coverage(
        transaction: &rusqlite::Transaction<'_>,
        covered_head: u64,
        origin_ack_heads: &[(String, u64)],
    ) -> Result<(), BudgetStoreError> {
        let covered_head = budget_u64_to_sqlite(covered_head, "covered_head")?;
        transaction.execute(
            "UPDATE budget_snapshot_coverage SET covered_head = ?1 WHERE singleton = 1",
            params![covered_head],
        )?;
        transaction.execute(
            "UPDATE budget_ack_head_watermark SET head_seq = ?1 WHERE singleton = 1",
            params![covered_head],
        )?;
        transaction.execute("DELETE FROM budget_origin_ack_heads", [])?;
        for (authority_id, head_seq) in origin_ack_heads {
            transaction.execute(
                "INSERT INTO budget_origin_ack_heads (authority_id, head_seq) VALUES (?1, ?2)",
                params![
                    authority_id,
                    budget_u64_to_sqlite(*head_seq, "origin_ack_head")?
                ],
            )?;
        }
        raise_budget_replication_seq_floor(transaction, covered_head as u64)?;
        Ok(())
    }

    fn origin_ack_heads_at(
        connection: &Connection,
        covered_head: u64,
    ) -> Result<Vec<(String, u64)>, BudgetStoreError> {
        let mut statement = connection.prepare(
            r#"
            SELECT authority_id, MAX(event_seq)
            FROM budget_mutation_events
            WHERE authority_id IS NOT NULL AND event_seq <= ?1
            GROUP BY authority_id
            ORDER BY authority_id
            "#,
        )?;
        let rows = statement
            .query_map(
                params![budget_u64_to_sqlite(covered_head, "covered_head")?],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        budget_u64_from_row(row, 1, "origin_ack_head")?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn export_budget_snapshot(&self) -> Result<BudgetStoreSnapshot, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let usages = Self::snapshot_usages(&transaction)?;
        let usage_history_anchors = Self::snapshot_usage_history_anchors(&transaction)?;
        let mutation_events = Self::snapshot_mutation_events(&transaction)?;
        let abandoned_seq_ranges = Self::snapshot_abandoned_seq_ranges(&transaction)?;
        let covered_head = Self::contiguous_snapshot_head_in(&transaction)?;
        let origin_ack_heads = Self::origin_ack_heads_at(&transaction, covered_head)?;
        transaction.rollback()?;
        Ok(BudgetStoreSnapshot {
            usages,
            usage_history_anchors,
            mutation_events,
            abandoned_seq_ranges,
            covered_head,
            origin_ack_heads,
        })
    }

    fn snapshot_usages(
        connection: &Connection,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let mut statement = connection.prepare(
            r#"
            SELECT capability_id, grant_index, invocation_count, updated_at, seq,
                   total_cost_exposed, total_cost_realized_spend
            FROM capability_grant_budgets
            ORDER BY capability_id, grant_index
            "#,
        )?;
        let rows = statement
            .query_map([], record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn snapshot_usage_history_anchors(
        connection: &Connection,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let mut statement = connection.prepare(
            r#"
            SELECT capability_id, grant_index, invocation_count, updated_at, seq,
                   total_cost_exposed, total_cost_realized_spend
            FROM budget_usage_history_anchors
            ORDER BY capability_id, grant_index
            "#,
        )?;
        let rows = statement
            .query_map([], record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn snapshot_mutation_events(
        transaction: &rusqlite::Transaction<'_>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        let event_ids = {
            let mut statement = transaction
                .prepare("SELECT event_id FROM budget_mutation_events ORDER BY event_seq")?;
            let event_ids = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            event_ids
        };
        event_ids
            .iter()
            .map(|event_id| {
                Self::load_projected_mutation_event(transaction, event_id)?.ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "budget mutation event `{event_id}` disappeared during snapshot export"
                    ))
                })
            })
            .collect()
    }

    fn snapshot_abandoned_seq_ranges(
        connection: &Connection,
    ) -> Result<Vec<(u64, u64)>, BudgetStoreError> {
        let mut statement = connection.prepare(
            r#"
            SELECT MIN(seq), MAX(seq)
            FROM (
                SELECT seq, seq - ROW_NUMBER() OVER (ORDER BY seq) AS island
                FROM budget_abandoned_event_seqs
            )
            GROUP BY island
            ORDER BY MIN(seq)
            "#,
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    budget_u64_from_row(row, 0, "abandoned_range_start")?,
                    budget_u64_from_row(row, 1, "abandoned_range_end")?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn budget_snapshot_covered_head(&self) -> Result<u64, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let head = Self::contiguous_snapshot_head_in(&transaction)?;
        transaction.rollback()?;
        Ok(head)
    }

    pub(super) fn contiguous_snapshot_head_in(
        connection: &Connection,
    ) -> Result<u64, BudgetStoreError> {
        Self::contiguous_snapshot_head_from(connection, 0)
    }

    pub(super) fn rebuild_snapshot_proof_caches(
        connection: &mut Connection,
    ) -> Result<(), BudgetStoreError> {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let covered_head = Self::contiguous_snapshot_head_from(&transaction, 0)?;
        let origin_ack_heads = Self::origin_ack_heads_at(&transaction, covered_head)?;
        Self::install_snapshot_coverage(&transaction, covered_head, &origin_ack_heads)?;
        transaction.commit()?;
        Ok(())
    }

    fn contiguous_snapshot_head_from(
        connection: &Connection,
        floor: u64,
    ) -> Result<u64, BudgetStoreError> {
        let floor_sqlite = budget_u64_to_sqlite(floor, "snapshot_covered_head")?;
        let next_slot = floor_sqlite.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("budget snapshot head overflowed i64".to_string())
        })?;
        let next_slot_filled: bool = connection.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM budget_mutation_events WHERE event_seq = ?1
                UNION ALL
                SELECT 1 FROM budget_abandoned_event_seqs WHERE seq = ?1
            )
            "#,
            params![next_slot],
            |row| row.get::<_, i64>(0).map(|value| value != 0),
        )?;
        if !next_slot_filled {
            return Ok(floor);
        }
        let head: i64 = connection.query_row(
            r#"
            WITH filled AS (
                SELECT event_seq AS seq
                FROM budget_mutation_events
                WHERE event_seq IS NOT NULL AND event_seq > ?1
                UNION
                SELECT seq
                FROM budget_abandoned_event_seqs
                WHERE seq > ?1
            ),
            run AS (
                SELECT seq, seq - ROW_NUMBER() OVER (ORDER BY seq) AS island
                FROM filled
            )
            SELECT COALESCE(MAX(seq), ?1)
            FROM run
            WHERE island = ?1
            "#,
            params![floor_sqlite],
            |row| row.get(0),
        )?;
        u64::try_from(head).map_err(|_| {
            BudgetStoreError::Invariant("budget snapshot head has a negative sequence".to_string())
        })
    }

    pub fn list_usage_history_anchors(&self) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let anchors = {
            let mut statement = transaction.prepare(
                r#"
                SELECT capability_id, grant_index, invocation_count, updated_at, seq,
                       total_cost_exposed, total_cost_realized_spend
                FROM budget_usage_history_anchors
                ORDER BY capability_id, grant_index
                "#,
            )?;
            let rows = statement
                .query_map([], record_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        transaction.rollback()?;
        Ok(anchors)
    }
}

fn snapshot_ranges_cover(ranges: &[(u64, u64)], start: u64, end: u64) -> bool {
    let mut next = start;
    for &(range_start, range_end) in ranges {
        if range_end < next {
            continue;
        }
        if range_start > next {
            return false;
        }
        if range_end >= end {
            return true;
        }
        let Some(after_range) = range_end.checked_add(1) else {
            return true;
        };
        next = after_range;
    }
    false
}

fn snapshot_proves_usage(snapshot: &BudgetStoreSnapshot, usage: &BudgetUsageRecord) -> bool {
    snapshot
        .usage_history_anchors
        .iter()
        .any(|anchor| anchor == usage)
        || snapshot.mutation_events.iter().any(|event| {
            event.capability_id == usage.capability_id
                && event.grant_index == usage.grant_index
                && event.event_seq == usage.seq
                && event.usage_seq == Some(event.event_seq)
                && event.recorded_at == usage.updated_at
                && event.invocation_count_after == usage.invocation_count
                && event.total_cost_exposed_after == usage.total_cost_exposed
                && event.total_cost_realized_spend_after == usage.total_cost_realized_spend
        })
}

fn verify_budget_snapshot_anchor_provenance<'a>(
    snapshot: &BudgetStoreSnapshot,
    provenance: &'a BudgetSnapshotAnchorProvenance,
    expected_leader_url: &str,
    expected_election_term: u64,
    cluster_service_token: &str,
) -> Result<&'a BudgetSnapshotAnchorCommitment, BudgetStoreError> {
    if expected_leader_url.is_empty()
        || expected_election_term == 0
        || cluster_service_token.is_empty()
        || provenance.chain.is_empty()
        || provenance.schema != "chio.budget-snapshot-anchor-provenance.v1"
    {
        return Err(BudgetStoreError::Invariant(
            "budget snapshot anchor provenance trust context is incomplete".to_string(),
        ));
    }
    let expected_authenticator =
        budget_snapshot_anchor_authenticator(cluster_service_token, &provenance.chain)?;
    if !bool::from(
        provenance
            .cluster_authenticator
            .as_bytes()
            .ct_eq(expected_authenticator.as_bytes()),
    ) {
        return Err(BudgetStoreError::Invariant(
            "budget snapshot anchor provenance cluster authentication failed".to_string(),
        ));
    }
    let expected_anchor_digest =
        budget_snapshot_anchor_set_digest(&snapshot.usage_history_anchors)?;
    let mut previous_digest = BUDGET_ANCHOR_GENESIS_DIGEST;
    for (index, signed) in provenance.chain.iter().enumerate() {
        let expected_sequence = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "budget snapshot anchor provenance sequence overflowed".to_string(),
                )
            })?;
        let body = &signed.body;
        if body.schema != "chio.budget-snapshot-anchor-commitment.v1"
            || body.commit_sequence != expected_sequence
            || body.previous_chain_digest != previous_digest
            || body.election_term == 0
            || body.leader_url.is_empty()
            || body.signer_public_key.is_empty()
            || budget_snapshot_anchor_chain_digest(body)? != body.chain_digest
        {
            return Err(BudgetStoreError::Invariant(
                "budget snapshot anchor provenance chain is invalid".to_string(),
            ));
        }
        let signer = PublicKey::from_hex(&body.signer_public_key)
            .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        if !signer
            .verify_canonical(body, &signed.signature)
            .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?
        {
            return Err(BudgetStoreError::Invariant(
                "budget snapshot anchor provenance signature is invalid".to_string(),
            ));
        }
        previous_digest = &body.chain_digest;
    }
    let head = provenance.chain.last().ok_or_else(|| {
        BudgetStoreError::Invariant("budget snapshot anchor provenance is empty".to_string())
    })?;
    if head.body.leader_url != expected_leader_url
        || head.body.election_term != expected_election_term
        || head.body.anchor_set_digest != expected_anchor_digest
    {
        return Err(BudgetStoreError::Invariant(
            "budget snapshot anchor provenance is not bound to the elected leader, term, and exact anchor set"
                .to_string(),
        ));
    }
    Ok(&head.body)
}

fn verify_local_anchor_provenance_continuity(
    transaction: &rusqlite::Transaction<'_>,
    provenance: &BudgetSnapshotAnchorProvenance,
) -> Result<(), BudgetStoreError> {
    let head = provenance.chain.last().ok_or_else(|| {
        BudgetStoreError::Invariant("budget snapshot anchor provenance is empty".to_string())
    })?;
    let local = transaction
        .query_row(
            r#"
            SELECT commit_sequence, chain_digest
            FROM budget_snapshot_anchor_provenance
            WHERE leader_url = ?1
            "#,
            params![&head.body.leader_url],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((local_sequence, local_digest)) = local else {
        return Ok(());
    };
    let local_sequence = local_sequence.max(0) as u64;
    let index = usize::try_from(local_sequence.saturating_sub(1)).map_err(|_| {
        BudgetStoreError::Invariant(
            "persisted budget snapshot anchor provenance sequence is invalid".to_string(),
        )
    })?;
    let committed = provenance.chain.get(index).ok_or_else(|| {
        BudgetStoreError::Invariant(
            "budget snapshot anchor provenance rewinds the persisted leader chain".to_string(),
        )
    })?;
    if committed.body.commit_sequence != local_sequence
        || committed.body.chain_digest != local_digest
    {
        return Err(BudgetStoreError::Invariant(
            "budget snapshot anchor provenance forks the persisted leader chain".to_string(),
        ));
    }
    Ok(())
}
