// Shared evidence reference report query.

use super::*;

impl SqliteReceiptStore {
    pub fn query_shared_evidence_report(
        &self,
        query: &SharedEvidenceQuery,
    ) -> Result<SharedEvidenceReferenceReport, ReceiptStoreError> {
        require_admin_receipt_read_context(query.read_context.as_ref(), "shared evidence report")?;
        let limit = query.limit_or_default();
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();
        let issuer = query.issuer.as_deref();
        let partner = query.partner.as_deref();

        let rows = self
            .connection()?
            .prepare(
                r#"
                SELECT r.receipt_id, r.timestamp, r.capability_id, r.decision_kind
                FROM chio_tool_receipts r
                LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
                WHERE (?1 IS NULL OR r.capability_id = ?1)
                  AND (?2 IS NULL OR r.tool_server = ?2)
                  AND (?3 IS NULL OR r.tool_name = ?3)
                  AND (?4 IS NULL OR r.timestamp >= ?4)
                  AND (?5 IS NULL OR r.timestamp <= ?5)
                  AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
                ORDER BY r.seq ASC
                "#,
            )?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let mut share_cache = BTreeMap::<String, Option<FederatedEvidenceShareSummary>>::new();
        let mut references = BTreeMap::<(String, String), SharedEvidenceReferenceRow>::new();
        let mut matched_local_receipts = BTreeSet::<String>::new();

        for (receipt_id, timestamp, local_capability_id, decision) in rows {
            let chain = self.get_combined_delegation_chain(&local_capability_id)?;
            if chain.is_empty() {
                continue;
            }

            let mut matched_this_receipt = false;
            for (index, snapshot) in chain.iter().enumerate() {
                let share = match share_cache.get(&snapshot.capability_id) {
                    Some(cached) => cached.clone(),
                    None => {
                        let loaded = self
                            .get_federated_share_for_capability(&snapshot.capability_id)?
                            .map(|(share, _)| share);
                        share_cache.insert(snapshot.capability_id.clone(), loaded.clone());
                        loaded
                    }
                };
                let Some(share) = share else {
                    continue;
                };
                if issuer.is_some_and(|expected| share.issuer != expected) {
                    continue;
                }
                if partner.is_some_and(|expected| share.partner != expected) {
                    continue;
                }

                let local_anchor_capability_id =
                    chain.iter().skip(index + 1).find_map(|candidate| {
                        match share_cache.get(&candidate.capability_id) {
                            Some(Some(_)) => None,
                            Some(None) => Some(candidate.capability_id.clone()),
                            None => {
                                let loaded = self
                                    .get_federated_share_for_capability(&candidate.capability_id)
                                    .ok()
                                    .and_then(|value| value.map(|(share, _)| share));
                                share_cache.insert(candidate.capability_id.clone(), loaded.clone());
                                if loaded.is_some() {
                                    None
                                } else {
                                    Some(candidate.capability_id.clone())
                                }
                            }
                        }
                    });

                let key = (share.share_id.clone(), snapshot.capability_id.clone());
                let entry = references
                    .entry(key)
                    .or_insert_with(|| SharedEvidenceReferenceRow {
                        share: share.clone(),
                        capability_id: snapshot.capability_id.clone(),
                        subject_key: snapshot.subject_key.clone(),
                        issuer_key: snapshot.issuer_key.clone(),
                        delegation_depth: snapshot.delegation_depth,
                        parent_capability_id: snapshot.parent_capability_id.clone(),
                        local_anchor_capability_id: local_anchor_capability_id.clone(),
                        matched_local_receipts: 0,
                        allow_count: 0,
                        deny_count: 0,
                        cancelled_count: 0,
                        incomplete_count: 0,
                        first_seen: Some(timestamp),
                        last_seen: Some(timestamp),
                    });

                entry.local_anchor_capability_id = entry
                    .local_anchor_capability_id
                    .clone()
                    .or(local_anchor_capability_id);
                entry.matched_local_receipts = entry.matched_local_receipts.saturating_add(1);
                entry.first_seen = Some(
                    entry
                        .first_seen
                        .map_or(timestamp, |value| value.min(timestamp)),
                );
                entry.last_seen = Some(
                    entry
                        .last_seen
                        .map_or(timestamp, |value| value.max(timestamp)),
                );
                match decision.as_str() {
                    "allow" => entry.allow_count = entry.allow_count.saturating_add(1),
                    "deny" => entry.deny_count = entry.deny_count.saturating_add(1),
                    "cancelled" => entry.cancelled_count = entry.cancelled_count.saturating_add(1),
                    _ => entry.incomplete_count = entry.incomplete_count.saturating_add(1),
                }
                matched_this_receipt = true;
            }

            if matched_this_receipt {
                matched_local_receipts.insert(receipt_id);
            }
        }

        let mut returned_references = references.into_values().collect::<Vec<_>>();
        returned_references.sort_by(|left, right| {
            right
                .matched_local_receipts
                .cmp(&left.matched_local_receipts)
                .then_with(|| right.last_seen.cmp(&left.last_seen))
                .then_with(|| right.share.imported_at.cmp(&left.share.imported_at))
                .then_with(|| left.share.share_id.cmp(&right.share.share_id))
                .then_with(|| left.capability_id.cmp(&right.capability_id))
        });

        let mut distinct_shares = BTreeMap::<String, FederatedEvidenceShareSummary>::new();
        let mut distinct_remote_subjects = BTreeSet::<String>::new();
        for reference in &returned_references {
            distinct_shares
                .entry(reference.share.share_id.clone())
                .or_insert_with(|| reference.share.clone());
            distinct_remote_subjects.insert(reference.subject_key.clone());
        }

        let matching_references = returned_references.len() as u64;
        let truncated = returned_references.len() > limit;
        if truncated {
            returned_references.truncate(limit);
        }

        Ok(SharedEvidenceReferenceReport {
            summary: SharedEvidenceReferenceSummary {
                matching_shares: distinct_shares.len() as u64,
                matching_references,
                matching_local_receipts: matched_local_receipts.len() as u64,
                remote_tool_receipts: distinct_shares
                    .values()
                    .map(|share| share.tool_receipts)
                    .sum(),
                remote_lineage_records: distinct_shares
                    .values()
                    .map(|share| share.capability_lineage)
                    .sum(),
                distinct_remote_subjects: distinct_remote_subjects.len() as u64,
                proof_required_shares: distinct_shares
                    .values()
                    .filter(|share| share.require_proofs)
                    .count() as u64,
                truncated,
            },
            references: returned_references,
        })
    }
}
