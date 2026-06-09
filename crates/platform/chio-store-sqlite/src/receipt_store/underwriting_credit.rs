use super::*;

impl SqliteReceiptStore {
    pub fn record_underwriting_decision(
        &mut self,
        decision: &SignedUnderwritingDecision,
    ) -> Result<(), ReceiptStoreError> {
        if !decision
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "underwriting decision signature verification failed".to_string(),
            ));
        }

        let artifact = &decision.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT decision_id FROM underwriting_decisions WHERE decision_id = ?1",
                params![artifact.decision_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "underwriting decision `{}` already exists",
                artifact.decision_id
            )));
        }

        if let Some(supersedes_decision_id) = artifact.supersedes_decision_id.as_deref() {
            let state = tx
                .query_row(
                    "SELECT lifecycle_state, superseded_by_decision_id
                     FROM underwriting_decisions
                     WHERE decision_id = ?1",
                    params![supersedes_decision_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .optional()?
                .ok_or_else(|| {
                    ReceiptStoreError::NotFound(format!(
                        "superseded underwriting decision `{supersedes_decision_id}` not found"
                    ))
                })?;
            if state.0
                != underwriting_lifecycle_state_label(UnderwritingDecisionLifecycleState::Active)
                || state.1.is_some()
            {
                return Err(ReceiptStoreError::Conflict(format!(
                    "underwriting decision `{supersedes_decision_id}` is not active"
                )));
            }
        }

        let premium_units = artifact
            .premium
            .quoted_amount
            .as_ref()
            .map(|amount| amount.units as i64);
        tx.execute(
            "INSERT INTO underwriting_decisions (
                decision_id, issued_at, capability_id, subject_key, tool_server, tool_name,
                outcome, lifecycle_state, review_state, risk_class, supersedes_decision_id,
                superseded_by_decision_id, premium_units, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, ?12, ?13, ?14, ?15)",
            params![
                artifact.decision_id,
                artifact.issued_at as i64,
                artifact.evaluation.input.filters.capability_id.as_deref(),
                artifact.evaluation.input.filters.agent_subject.as_deref(),
                artifact.evaluation.input.filters.tool_server.as_deref(),
                artifact.evaluation.input.filters.tool_name.as_deref(),
                underwriting_decision_outcome_label(artifact.evaluation.outcome),
                underwriting_lifecycle_state_label(artifact.lifecycle_state),
                underwriting_review_state_label(artifact.review_state),
                underwriting_risk_class_label(artifact.evaluation.risk_class),
                artifact.supersedes_decision_id.as_deref(),
                premium_units,
                serde_json::to_string(decision)?,
                decision.signer_key.to_hex(),
                decision.signature.to_hex(),
            ],
        )?;

        if let Some(supersedes_decision_id) = artifact.supersedes_decision_id.as_deref() {
            tx.execute(
                "UPDATE underwriting_decisions
                 SET lifecycle_state = ?1, superseded_by_decision_id = ?2
                 WHERE decision_id = ?3",
                params![
                    underwriting_lifecycle_state_label(
                        UnderwritingDecisionLifecycleState::Superseded,
                    ),
                    artifact.decision_id,
                    supersedes_decision_id,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn create_underwriting_appeal(
        &mut self,
        request: &UnderwritingAppealCreateRequest,
    ) -> Result<UnderwritingAppealRecord, ReceiptStoreError> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let exists = tx
            .query_row(
                "SELECT decision_id FROM underwriting_decisions WHERE decision_id = ?1",
                params![request.decision_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(ReceiptStoreError::NotFound(format!(
                "underwriting decision `{}` not found",
                request.decision_id
            )));
        }
        let open_appeal = tx
            .query_row(
                "SELECT appeal_id FROM underwriting_appeals
                 WHERE decision_id = ?1 AND status = ?2",
                params![
                    request.decision_id,
                    underwriting_appeal_status_label(UnderwritingAppealStatus::Open)
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(appeal_id) = open_appeal {
            return Err(ReceiptStoreError::Conflict(format!(
                "underwriting decision `{}` already has open appeal `{appeal_id}`",
                request.decision_id
            )));
        }

        let created_at = unix_now();
        let appeal_id = format!(
            "uwa-{}",
            chio_core::sha256_hex(
                &canonical_json_bytes(&(
                    &request.decision_id,
                    &request.requested_by,
                    &request.reason,
                    &request.note,
                    created_at,
                ))
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
            )
        );
        let record = UnderwritingAppealRecord {
            schema: chio_kernel::UNDERWRITING_APPEAL_SCHEMA.to_string(),
            appeal_id: appeal_id.clone(),
            decision_id: request.decision_id.clone(),
            requested_by: request.requested_by.clone(),
            reason: request.reason.clone(),
            status: UnderwritingAppealStatus::Open,
            created_at,
            updated_at: created_at,
            note: request.note.clone(),
            resolved_by: None,
            replacement_decision_id: None,
        };
        tx.execute(
            "INSERT INTO underwriting_appeals (
                appeal_id, decision_id, requested_by, reason, status, note,
                created_at, updated_at, resolved_by, replacement_decision_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL)",
            params![
                record.appeal_id,
                record.decision_id,
                record.requested_by,
                record.reason,
                underwriting_appeal_status_label(record.status),
                record.note.as_deref(),
                record.created_at as i64,
                record.updated_at as i64,
            ],
        )?;
        tx.commit()?;
        Ok(record)
    }

    pub fn resolve_underwriting_appeal(
        &mut self,
        request: &UnderwritingAppealResolveRequest,
    ) -> Result<UnderwritingAppealRecord, ReceiptStoreError> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut record = query_underwriting_appeal(&tx, &request.appeal_id)?.ok_or_else(|| {
            ReceiptStoreError::NotFound(format!(
                "underwriting appeal `{}` not found",
                request.appeal_id
            ))
        })?;
        if record.status != UnderwritingAppealStatus::Open {
            return Err(ReceiptStoreError::Conflict(format!(
                "underwriting appeal `{}` is already resolved",
                request.appeal_id
            )));
        }

        if let Some(replacement_decision_id) = request.replacement_decision_id.as_deref() {
            if request.resolution != UnderwritingAppealResolution::Accepted {
                return Err(ReceiptStoreError::Conflict(
                    "replacement underwriting decision may only be linked when an appeal is accepted"
                        .to_string(),
                ));
            }
            let replacement = tx
                .query_row(
                    "SELECT supersedes_decision_id FROM underwriting_decisions WHERE decision_id = ?1",
                    params![replacement_decision_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
                .ok_or_else(|| {
                    ReceiptStoreError::NotFound(format!(
                        "replacement underwriting decision `{replacement_decision_id}` not found"
                    ))
                })?;
            if replacement.as_deref() != Some(record.decision_id.as_str()) {
                return Err(ReceiptStoreError::Conflict(format!(
                    "replacement underwriting decision `{replacement_decision_id}` does not supersede `{}`",
                    record.decision_id
                )));
            }
        }

        record.status = match request.resolution {
            UnderwritingAppealResolution::Accepted => UnderwritingAppealStatus::Accepted,
            UnderwritingAppealResolution::Rejected => UnderwritingAppealStatus::Rejected,
        };
        record.updated_at = unix_now();
        record.note = request.note.clone().or(record.note);
        record.resolved_by = Some(request.resolved_by.clone());
        record.replacement_decision_id = request.replacement_decision_id.clone();

        tx.execute(
            "UPDATE underwriting_appeals
             SET status = ?1, note = ?2, updated_at = ?3, resolved_by = ?4,
                 replacement_decision_id = ?5
             WHERE appeal_id = ?6",
            params![
                underwriting_appeal_status_label(record.status),
                record.note.as_deref(),
                record.updated_at as i64,
                record.resolved_by.as_deref(),
                record.replacement_decision_id.as_deref(),
                record.appeal_id,
            ],
        )?;
        tx.commit()?;
        Ok(record)
    }

    pub fn query_underwriting_decisions(
        &self,
        query: &UnderwritingDecisionQuery,
    ) -> Result<UnderwritingDecisionListReport, ReceiptStoreError> {
        let normalized = query.normalized();
        let appeals = self.load_underwriting_appeals_by_decision()?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT raw_json, lifecycle_state
             FROM underwriting_decisions
             ORDER BY issued_at DESC, decision_id DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut matching_decisions = 0_u64;
        let mut active_decisions = 0_u64;
        let mut superseded_decisions = 0_u64;
        let mut open_appeals = 0_u64;
        let mut accepted_appeals = 0_u64;
        let mut rejected_appeals = 0_u64;
        let mut total_quoted_premium_units = 0_u64;
        let mut total_quoted_premium_currency = None;
        let mut quoted_premium_totals_by_currency = BTreeMap::<String, u64>::new();
        let mut decisions = Vec::new();

        for row in rows {
            let (raw_json, lifecycle_state_raw) = row?;
            let decision: SignedUnderwritingDecision = serde_json::from_str(&raw_json)?;
            let lifecycle_state =
                parse_underwriting_lifecycle_state(&lifecycle_state_raw).map_err(|error| {
                    ReceiptStoreError::Conflict(format!(
                        "invalid underwriting decision lifecycle state `{lifecycle_state_raw}`: {error}"
                    ))
                })?;
            let decision_appeals = appeals
                .get(decision.body.decision_id.as_str())
                .cloned()
                .unwrap_or_default();
            let latest_appeal = decision_appeals.iter().max_by(|left, right| {
                left.updated_at
                    .cmp(&right.updated_at)
                    .then(left.appeal_id.cmp(&right.appeal_id))
            });
            if !underwriting_decision_matches_query(
                &decision,
                lifecycle_state,
                latest_appeal.map(|appeal| appeal.status),
                &normalized,
            ) {
                continue;
            }

            matching_decisions += 1;
            match lifecycle_state {
                UnderwritingDecisionLifecycleState::Active => active_decisions += 1,
                UnderwritingDecisionLifecycleState::Superseded => superseded_decisions += 1,
            }
            for appeal in &decision_appeals {
                match appeal.status {
                    UnderwritingAppealStatus::Open => open_appeals += 1,
                    UnderwritingAppealStatus::Accepted => accepted_appeals += 1,
                    UnderwritingAppealStatus::Rejected => rejected_appeals += 1,
                }
            }
            if let Some(quoted_amount) = decision.body.premium.quoted_amount.as_ref() {
                let total = quoted_premium_totals_by_currency
                    .entry(quoted_amount.currency.clone())
                    .or_insert(0);
                *total = total.saturating_add(quoted_amount.units);
            }

            if decisions.len() < normalized.limit_or_default() {
                let open_appeal_count = decision_appeals
                    .iter()
                    .filter(|appeal| appeal.status == UnderwritingAppealStatus::Open)
                    .count() as u64;
                decisions.push(UnderwritingDecisionRow {
                    decision,
                    lifecycle_state,
                    open_appeal_count,
                    latest_appeal_id: latest_appeal.map(|appeal| appeal.appeal_id.clone()),
                    latest_appeal_status: latest_appeal.map(|appeal| appeal.status),
                });
            }
        }

        if quoted_premium_totals_by_currency.len() == 1 {
            if let Some((currency, units)) = quoted_premium_totals_by_currency
                .iter()
                .next()
                .map(|(currency, units)| (currency.clone(), *units))
            {
                total_quoted_premium_units = units;
                total_quoted_premium_currency = Some(currency);
            }
        }

        Ok(UnderwritingDecisionListReport {
            generated_at: unix_now(),
            filters: normalized,
            summary: UnderwritingDecisionSummary {
                matching_decisions,
                returned_decisions: decisions.len() as u64,
                active_decisions,
                superseded_decisions,
                open_appeals,
                accepted_appeals,
                rejected_appeals,
                total_quoted_premium_units,
                total_quoted_premium_currency,
                quoted_premium_totals_by_currency,
            },
            decisions,
        })
    }

    pub fn record_credit_facility(
        &mut self,
        facility: &SignedCreditFacility,
    ) -> Result<(), ReceiptStoreError> {
        if !facility
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "credit facility signature verification failed".to_string(),
            ));
        }

        let artifact = &facility.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT facility_id FROM credit_facilities WHERE facility_id = ?1",
                params![artifact.facility_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "credit facility `{}` already exists",
                artifact.facility_id
            )));
        }

        if let Some(supersedes_facility_id) = artifact.supersedes_facility_id.as_deref() {
            let state = tx
                .query_row(
                    "SELECT lifecycle_state, superseded_by_facility_id, expires_at
                     FROM credit_facilities
                     WHERE facility_id = ?1",
                    params![supersedes_facility_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    ReceiptStoreError::NotFound(format!(
                        "superseded credit facility `{supersedes_facility_id}` not found"
                    ))
                })?;
            if state.0
                != credit_facility_lifecycle_state_label(CreditFacilityLifecycleState::Active)
                || state.1.is_some()
                || state.2.max(0) as u64 <= unix_now()
            {
                return Err(ReceiptStoreError::Conflict(format!(
                    "credit facility `{supersedes_facility_id}` is not active"
                )));
            }
        }

        tx.execute(
            "INSERT INTO credit_facilities (
                facility_id, issued_at, expires_at, capability_id, subject_key, tool_server,
                tool_name, disposition, lifecycle_state, supersedes_facility_id,
                superseded_by_facility_id, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11, ?12, ?13)",
            params![
                artifact.facility_id,
                artifact.issued_at as i64,
                artifact.expires_at as i64,
                artifact.report.filters.capability_id.as_deref(),
                artifact.report.filters.agent_subject.as_deref(),
                artifact.report.filters.tool_server.as_deref(),
                artifact.report.filters.tool_name.as_deref(),
                credit_facility_disposition_label(artifact.report.disposition),
                credit_facility_lifecycle_state_label(artifact.lifecycle_state),
                artifact.supersedes_facility_id.as_deref(),
                serde_json::to_string(facility)?,
                facility.signer_key.to_hex(),
                facility.signature.to_hex(),
            ],
        )?;

        if let Some(supersedes_facility_id) = artifact.supersedes_facility_id.as_deref() {
            tx.execute(
                "UPDATE credit_facilities
                 SET lifecycle_state = ?1, superseded_by_facility_id = ?2
                 WHERE facility_id = ?3",
                params![
                    credit_facility_lifecycle_state_label(
                        CreditFacilityLifecycleState::Superseded,
                    ),
                    artifact.facility_id,
                    supersedes_facility_id,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn query_credit_facilities(
        &self,
        query: &CreditFacilityListQuery,
    ) -> Result<CreditFacilityListReport, ReceiptStoreError> {
        let normalized = query.normalized();
        let now = unix_now();
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT raw_json, lifecycle_state, superseded_by_facility_id
             FROM credit_facilities
             ORDER BY issued_at DESC, facility_id DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;

        let mut matching_facilities = 0_u64;
        let mut active_facilities = 0_u64;
        let mut superseded_facilities = 0_u64;
        let mut denied_facilities = 0_u64;
        let mut expired_facilities = 0_u64;
        let mut granted_facilities = 0_u64;
        let mut manual_review_facilities = 0_u64;
        let mut facilities = Vec::new();

        for row in rows {
            let (raw_json, lifecycle_state_raw, superseded_by_facility_id) = row?;
            let facility: SignedCreditFacility = serde_json::from_str(&raw_json)?;
            let persisted_lifecycle = parse_credit_facility_lifecycle_state(&lifecycle_state_raw)
                .map_err(|error| {
                ReceiptStoreError::Conflict(format!(
                    "invalid credit facility lifecycle state `{lifecycle_state_raw}`: {error}"
                ))
            })?;
            let lifecycle_state =
                effective_credit_facility_lifecycle_state(&facility, persisted_lifecycle, now);
            if !credit_facility_matches_query(&facility, lifecycle_state, &normalized) {
                continue;
            }

            matching_facilities += 1;
            match lifecycle_state {
                CreditFacilityLifecycleState::Active => active_facilities += 1,
                CreditFacilityLifecycleState::Superseded => superseded_facilities += 1,
                CreditFacilityLifecycleState::Denied => denied_facilities += 1,
                CreditFacilityLifecycleState::Expired => expired_facilities += 1,
            }
            match facility.body.report.disposition {
                CreditFacilityDisposition::Grant => granted_facilities += 1,
                CreditFacilityDisposition::ManualReview => manual_review_facilities += 1,
                CreditFacilityDisposition::Deny => {}
            }

            if facilities.len() < normalized.limit_or_default() {
                facilities.push(CreditFacilityRow {
                    facility,
                    lifecycle_state,
                    superseded_by_facility_id,
                });
            }
        }

        Ok(CreditFacilityListReport {
            schema: CREDIT_FACILITY_LIST_REPORT_SCHEMA.to_string(),
            generated_at: unix_now(),
            query: normalized,
            summary: CreditFacilityListSummary {
                matching_facilities,
                returned_facilities: facilities.len() as u64,
                active_facilities,
                superseded_facilities,
                denied_facilities,
                expired_facilities,
                granted_facilities,
                manual_review_facilities,
            },
            facilities,
        })
    }

    pub fn record_credit_bond(&mut self, bond: &SignedCreditBond) -> Result<(), ReceiptStoreError> {
        if !bond
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "credit bond signature verification failed".to_string(),
            ));
        }

        let artifact = &bond.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT bond_id FROM credit_bonds WHERE bond_id = ?1",
                params![artifact.bond_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "credit bond `{}` already exists",
                artifact.bond_id
            )));
        }

        if let Some(supersedes_bond_id) = artifact.supersedes_bond_id.as_deref() {
            let state = tx
                .query_row(
                    "SELECT lifecycle_state, superseded_by_bond_id, expires_at
                     FROM credit_bonds
                     WHERE bond_id = ?1",
                    params![supersedes_bond_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    ReceiptStoreError::NotFound(format!(
                        "superseded credit bond `{supersedes_bond_id}` not found"
                    ))
                })?;
            if state.0 != credit_bond_lifecycle_state_label(CreditBondLifecycleState::Active)
                || state.1.is_some()
                || state.2.max(0) as u64 <= unix_now()
            {
                return Err(ReceiptStoreError::Conflict(format!(
                    "credit bond `{supersedes_bond_id}` is not active"
                )));
            }
        }

        tx.execute(
            "INSERT INTO credit_bonds (
                bond_id, issued_at, expires_at, facility_id, capability_id, subject_key,
                tool_server, tool_name, disposition, lifecycle_state, supersedes_bond_id,
                superseded_by_bond_id, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, ?12, ?13, ?14)",
            params![
                artifact.bond_id,
                artifact.issued_at as i64,
                artifact.expires_at as i64,
                artifact.report.latest_facility_id.as_deref(),
                artifact.report.filters.capability_id.as_deref(),
                artifact.report.filters.agent_subject.as_deref(),
                artifact.report.filters.tool_server.as_deref(),
                artifact.report.filters.tool_name.as_deref(),
                credit_bond_disposition_label(artifact.report.disposition),
                credit_bond_lifecycle_state_label(artifact.lifecycle_state),
                artifact.supersedes_bond_id.as_deref(),
                serde_json::to_string(bond)?,
                bond.signer_key.to_hex(),
                bond.signature.to_hex(),
            ],
        )?;

        if let Some(supersedes_bond_id) = artifact.supersedes_bond_id.as_deref() {
            tx.execute(
                "UPDATE credit_bonds
                 SET lifecycle_state = ?1, superseded_by_bond_id = ?2
                 WHERE bond_id = ?3",
                params![
                    credit_bond_lifecycle_state_label(CreditBondLifecycleState::Superseded),
                    artifact.bond_id,
                    supersedes_bond_id,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn query_credit_bonds(
        &self,
        query: &CreditBondListQuery,
    ) -> Result<CreditBondListReport, ReceiptStoreError> {
        let normalized = query.normalized();
        let now = unix_now();
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT raw_json, lifecycle_state, superseded_by_bond_id
             FROM credit_bonds
             ORDER BY issued_at DESC, bond_id DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;

        let mut matching_bonds = 0_u64;
        let mut active_bonds = 0_u64;
        let mut superseded_bonds = 0_u64;
        let mut released_bonds = 0_u64;
        let mut impaired_bonds = 0_u64;
        let mut expired_bonds = 0_u64;
        let mut locked_bonds = 0_u64;
        let mut held_bonds = 0_u64;
        let mut bonds = Vec::new();

        for row in rows {
            let (raw_json, lifecycle_state_raw, superseded_by_bond_id) = row?;
            let bond: SignedCreditBond = serde_json::from_str(&raw_json)?;
            let persisted_lifecycle = parse_credit_bond_lifecycle_state(&lifecycle_state_raw)
                .map_err(|error| {
                    ReceiptStoreError::Conflict(format!(
                        "invalid credit bond lifecycle state `{lifecycle_state_raw}`: {error}"
                    ))
                })?;
            let lifecycle_state =
                effective_credit_bond_lifecycle_state(&bond, persisted_lifecycle, now);
            if !credit_bond_matches_query(&bond, lifecycle_state, &normalized) {
                continue;
            }

            matching_bonds += 1;
            match lifecycle_state {
                CreditBondLifecycleState::Active => active_bonds += 1,
                CreditBondLifecycleState::Superseded => superseded_bonds += 1,
                CreditBondLifecycleState::Released => released_bonds += 1,
                CreditBondLifecycleState::Impaired => impaired_bonds += 1,
                CreditBondLifecycleState::Expired => expired_bonds += 1,
            }
            match bond.body.report.disposition {
                CreditBondDisposition::Lock => locked_bonds += 1,
                CreditBondDisposition::Hold => held_bonds += 1,
                CreditBondDisposition::Release | CreditBondDisposition::Impair => {}
            }

            if bonds.len() < normalized.limit_or_default() {
                bonds.push(CreditBondRow {
                    bond,
                    lifecycle_state,
                    superseded_by_bond_id,
                });
            }
        }

        Ok(CreditBondListReport {
            schema: CREDIT_BOND_LIST_REPORT_SCHEMA.to_string(),
            generated_at: unix_now(),
            query: normalized,
            summary: CreditBondListSummary {
                matching_bonds,
                returned_bonds: bonds.len() as u64,
                active_bonds,
                superseded_bonds,
                released_bonds,
                impaired_bonds,
                expired_bonds,
                locked_bonds,
                held_bonds,
            },
            bonds,
        })
    }

    pub fn record_credit_loss_lifecycle(
        &mut self,
        event: &SignedCreditLossLifecycle,
    ) -> Result<(), ReceiptStoreError> {
        if !event
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "credit loss lifecycle signature verification failed".to_string(),
            ));
        }

        let artifact = &event.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT event_id FROM credit_loss_lifecycle WHERE event_id = ?1",
                params![artifact.event_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "credit loss lifecycle `{}` already exists",
                artifact.event_id
            )));
        }

        let bond_exists = tx
            .query_row(
                "SELECT bond_id FROM credit_bonds WHERE bond_id = ?1",
                params![artifact.bond_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if bond_exists.is_none() {
            return Err(ReceiptStoreError::NotFound(format!(
                "credit bond `{}` not found",
                artifact.bond_id
            )));
        }

        tx.execute(
            "INSERT INTO credit_loss_lifecycle (
                event_id, issued_at, bond_id, facility_id, capability_id, subject_key,
                tool_server, tool_name, event_kind, projected_bond_lifecycle_state,
                raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                artifact.event_id,
                artifact.issued_at as i64,
                artifact.bond_id,
                artifact.report.summary.facility_id.as_deref(),
                artifact.report.summary.capability_id.as_deref(),
                artifact.report.summary.agent_subject.as_deref(),
                artifact.report.summary.tool_server.as_deref(),
                artifact.report.summary.tool_name.as_deref(),
                credit_loss_lifecycle_event_kind_label(artifact.event_kind),
                credit_bond_lifecycle_state_label(artifact.projected_bond_lifecycle_state),
                serde_json::to_string(event)?,
                event.signer_key.to_hex(),
                event.signature.to_hex(),
            ],
        )?;

        tx.execute(
            "UPDATE credit_bonds
             SET lifecycle_state = ?1
             WHERE bond_id = ?2",
            params![
                credit_bond_lifecycle_state_label(artifact.projected_bond_lifecycle_state),
                artifact.bond_id,
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn query_credit_loss_lifecycle(
        &self,
        query: &CreditLossLifecycleListQuery,
    ) -> Result<CreditLossLifecycleListReport, ReceiptStoreError> {
        let normalized = query.normalized();
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT raw_json
             FROM credit_loss_lifecycle
             ORDER BY issued_at DESC, event_id DESC",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;

        let mut matching_events = 0_u64;
        let mut delinquency_events = 0_u64;
        let mut recovery_events = 0_u64;
        let mut reserve_release_events = 0_u64;
        let mut reserve_slash_events = 0_u64;
        let mut write_off_events = 0_u64;
        let mut events = Vec::new();

        for row in rows {
            let raw_json = row?;
            let event: SignedCreditLossLifecycle = serde_json::from_str(&raw_json)?;
            let body = &event.body;
            let summary = &body.report.summary;
            if normalized
                .event_id
                .as_deref()
                .is_some_and(|value| value != body.event_id)
            {
                continue;
            }
            if normalized
                .bond_id
                .as_deref()
                .is_some_and(|value| value != body.bond_id)
            {
                continue;
            }
            if normalized
                .facility_id
                .as_deref()
                .is_some_and(|value| summary.facility_id.as_deref() != Some(value))
            {
                continue;
            }
            if normalized
                .capability_id
                .as_deref()
                .is_some_and(|value| summary.capability_id.as_deref() != Some(value))
            {
                continue;
            }
            if normalized
                .agent_subject
                .as_deref()
                .is_some_and(|value| summary.agent_subject.as_deref() != Some(value))
            {
                continue;
            }
            if normalized
                .tool_server
                .as_deref()
                .is_some_and(|value| summary.tool_server.as_deref() != Some(value))
            {
                continue;
            }
            if normalized
                .tool_name
                .as_deref()
                .is_some_and(|value| summary.tool_name.as_deref() != Some(value))
            {
                continue;
            }
            if normalized
                .event_kind
                .is_some_and(|value| value != body.event_kind)
            {
                continue;
            }

            matching_events = matching_events.saturating_add(1);
            match body.event_kind {
                CreditLossLifecycleEventKind::Delinquency => {
                    delinquency_events = delinquency_events.saturating_add(1);
                }
                CreditLossLifecycleEventKind::Recovery => {
                    recovery_events = recovery_events.saturating_add(1);
                }
                CreditLossLifecycleEventKind::ReserveRelease => {
                    reserve_release_events = reserve_release_events.saturating_add(1);
                }
                CreditLossLifecycleEventKind::ReserveSlash => {
                    reserve_slash_events = reserve_slash_events.saturating_add(1);
                }
                CreditLossLifecycleEventKind::WriteOff => {
                    write_off_events = write_off_events.saturating_add(1);
                }
            }

            if events.len() < normalized.limit_or_default() {
                events.push(CreditLossLifecycleRow { event });
            }
        }

        Ok(CreditLossLifecycleListReport {
            schema: CREDIT_LOSS_LIFECYCLE_LIST_REPORT_SCHEMA.to_string(),
            generated_at: unix_now(),
            query: normalized,
            summary: CreditLossLifecycleListSummary {
                matching_events,
                returned_events: events.len() as u64,
                delinquency_events,
                recovery_events,
                reserve_release_events,
                reserve_slash_events,
                write_off_events,
            },
            events,
        })
    }
}
