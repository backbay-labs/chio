use super::*;

impl SqliteReceiptStore {
    pub fn record_liability_claim_package(
        &mut self,
        claim: &SignedLiabilityClaimPackage,
    ) -> Result<(), ReceiptStoreError> {
        if !claim
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability claim package signature verification failed".to_string(),
            ));
        }
        claim.body.validate().map_err(ReceiptStoreError::Conflict)?;

        let artifact = &claim.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT claim_id FROM liability_claim_packages WHERE claim_id = ?1",
                params![artifact.claim_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability claim package `{}` already exists",
                artifact.claim_id
            )));
        }

        let stored_bound_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_bound_coverages
                 WHERE bound_coverage_id = ?1",
                params![artifact.bound_coverage.body.bound_coverage_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability bound coverage `{}` not found",
                    artifact.bound_coverage.body.bound_coverage_id
                ))
            })?;
        let stored_bound: SignedLiabilityBoundCoverage =
            serde_json::from_str(&stored_bound_raw_json)?;
        if stored_bound.body != artifact.bound_coverage.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim package bound_coverage does not match the persisted bound coverage"
                    .to_string(),
            ));
        }

        let stored_bond_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM credit_bonds
                 WHERE bond_id = ?1",
                params![artifact.bond.body.bond_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "credit bond `{}` not found",
                    artifact.bond.body.bond_id
                ))
            })?;
        let stored_bond: SignedCreditBond = serde_json::from_str(&stored_bond_raw_json)?;
        if stored_bond.body != artifact.bond.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim package bond does not match the persisted credit bond".to_string(),
            ));
        }

        let stored_loss_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM credit_loss_lifecycle
                 WHERE event_id = ?1",
                params![artifact.loss_event.body.event_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "credit loss lifecycle event `{}` not found",
                    artifact.loss_event.body.event_id
                ))
            })?;
        let stored_loss: SignedCreditLossLifecycle = serde_json::from_str(&stored_loss_raw_json)?;
        if stored_loss.body != artifact.loss_event.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim package loss_event does not match the persisted credit loss lifecycle event"
                    .to_string(),
            ));
        }

        for receipt_id in &artifact.receipt_ids {
            let exists = tx
                .query_row(
                    "SELECT 1 FROM chio_tool_receipts WHERE receipt_id = ?1",
                    params![receipt_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if exists.is_none() {
                return Err(ReceiptStoreError::NotFound(format!(
                    "receipt {receipt_id} does not exist"
                )));
            }
        }

        tx.execute(
            "INSERT INTO liability_claim_packages (
                claim_id, issued_at, provider_id, policy_number, jurisdiction, subject_key,
                claim_event_at, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                artifact.claim_id,
                artifact.issued_at as i64,
                artifact
                    .bound_coverage
                    .body
                    .placement
                    .body
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .provider_policy
                    .provider_id,
                artifact.bound_coverage.body.policy_number,
                artifact
                    .bound_coverage
                    .body
                    .placement
                    .body
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .provider_policy
                    .jurisdiction,
                artifact
                    .bound_coverage
                    .body
                    .placement
                    .body
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .risk_package
                    .body
                    .subject_key,
                artifact.claim_event_at as i64,
                serde_json::to_string(claim)?,
                claim.signer_key.to_hex(),
                claim.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_claim_response(
        &mut self,
        response: &SignedLiabilityClaimResponse,
    ) -> Result<(), ReceiptStoreError> {
        if !response
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability claim response signature verification failed".to_string(),
            ));
        }
        response
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &response.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT claim_response_id
                 FROM liability_claim_responses
                 WHERE claim_response_id = ?1",
                params![artifact.claim_response_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability claim response `{}` already exists",
                artifact.claim_response_id
            )));
        }

        let stored_claim_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_claim_packages
                 WHERE claim_id = ?1",
                params![artifact.claim.body.claim_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability claim package `{}` not found",
                    artifact.claim.body.claim_id
                ))
            })?;
        let stored_claim: SignedLiabilityClaimPackage =
            serde_json::from_str(&stored_claim_raw_json)?;
        if stored_claim.body != artifact.claim.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim response claim does not match the persisted claim package"
                    .to_string(),
            ));
        }

        tx.execute(
            "INSERT INTO liability_claim_responses (
                claim_response_id, issued_at, claim_id, provider_id, disposition,
                raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                artifact.claim_response_id,
                artifact.issued_at as i64,
                artifact.claim.body.claim_id,
                artifact
                    .claim
                    .body
                    .bound_coverage
                    .body
                    .placement
                    .body
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .provider_policy
                    .provider_id,
                serde_json::to_string(&artifact.disposition)?,
                serde_json::to_string(response)?,
                response.signer_key.to_hex(),
                response.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_claim_dispute(
        &mut self,
        dispute: &SignedLiabilityClaimDispute,
    ) -> Result<(), ReceiptStoreError> {
        if !dispute
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability claim dispute signature verification failed".to_string(),
            ));
        }
        dispute
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &dispute.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT dispute_id FROM liability_claim_disputes WHERE dispute_id = ?1",
                params![artifact.dispute_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability claim dispute `{}` already exists",
                artifact.dispute_id
            )));
        }

        let stored_response_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_claim_responses
                 WHERE claim_response_id = ?1",
                params![artifact.provider_response.body.claim_response_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability claim response `{}` not found",
                    artifact.provider_response.body.claim_response_id
                ))
            })?;
        let stored_response: SignedLiabilityClaimResponse =
            serde_json::from_str(&stored_response_raw_json)?;
        if stored_response.body != artifact.provider_response.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim dispute provider_response does not match the persisted claim response"
                    .to_string(),
            ));
        }

        tx.execute(
            "INSERT INTO liability_claim_disputes (
                dispute_id, issued_at, claim_id, claim_response_id, provider_id,
                raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                artifact.dispute_id,
                artifact.issued_at as i64,
                artifact.provider_response.body.claim.body.claim_id,
                artifact.provider_response.body.claim_response_id,
                artifact
                    .provider_response
                    .body
                    .claim
                    .body
                    .bound_coverage
                    .body
                    .placement
                    .body
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .provider_policy
                    .provider_id,
                serde_json::to_string(dispute)?,
                dispute.signer_key.to_hex(),
                dispute.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_claim_adjudication(
        &mut self,
        adjudication: &SignedLiabilityClaimAdjudication,
    ) -> Result<(), ReceiptStoreError> {
        if !adjudication
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability claim adjudication signature verification failed".to_string(),
            ));
        }
        adjudication
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &adjudication.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT adjudication_id
                 FROM liability_claim_adjudications
                 WHERE adjudication_id = ?1",
                params![artifact.adjudication_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability claim adjudication `{}` already exists",
                artifact.adjudication_id
            )));
        }

        let stored_dispute_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_claim_disputes
                 WHERE dispute_id = ?1",
                params![artifact.dispute.body.dispute_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability claim dispute `{}` not found",
                    artifact.dispute.body.dispute_id
                ))
            })?;
        let stored_dispute: SignedLiabilityClaimDispute =
            serde_json::from_str(&stored_dispute_raw_json)?;
        if stored_dispute.body != artifact.dispute.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim adjudication dispute does not match the persisted claim dispute"
                    .to_string(),
            ));
        }

        tx.execute(
            "INSERT INTO liability_claim_adjudications (
                adjudication_id, issued_at, claim_id, dispute_id, outcome,
                raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                artifact.adjudication_id,
                artifact.issued_at as i64,
                artifact
                    .dispute
                    .body
                    .provider_response
                    .body
                    .claim
                    .body
                    .claim_id,
                artifact.dispute.body.dispute_id,
                serde_json::to_string(&artifact.outcome)?,
                serde_json::to_string(adjudication)?,
                adjudication.signer_key.to_hex(),
                adjudication.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_claim_payout_instruction(
        &mut self,
        payout_instruction: &SignedLiabilityClaimPayoutInstruction,
    ) -> Result<(), ReceiptStoreError> {
        if !payout_instruction
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability claim payout instruction signature verification failed".to_string(),
            ));
        }
        payout_instruction
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &payout_instruction.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT payout_instruction_id
                 FROM liability_claim_payout_instructions
                 WHERE payout_instruction_id = ?1",
                params![artifact.payout_instruction_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability claim payout instruction `{}` already exists",
                artifact.payout_instruction_id
            )));
        }

        let stored_adjudication_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_claim_adjudications
                 WHERE adjudication_id = ?1",
                params![artifact.adjudication.body.adjudication_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability claim adjudication `{}` not found",
                    artifact.adjudication.body.adjudication_id
                ))
            })?;
        let stored_adjudication: SignedLiabilityClaimAdjudication =
            serde_json::from_str(&stored_adjudication_raw_json)?;
        if stored_adjudication.body != artifact.adjudication.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim payout instruction adjudication does not match the persisted adjudication"
                    .to_string(),
            ));
        }

        let claim_id = artifact
            .adjudication
            .body
            .dispute
            .body
            .provider_response
            .body
            .claim
            .body
            .claim_id
            .clone();

        tx.execute(
            "INSERT INTO liability_claim_payout_instructions (
                payout_instruction_id, issued_at, claim_id, adjudication_id,
                payout_amount_units, payout_amount_currency,
                raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                artifact.payout_instruction_id,
                artifact.issued_at as i64,
                claim_id,
                artifact.adjudication.body.adjudication_id,
                artifact.payout_amount.units as i64,
                artifact.payout_amount.currency,
                serde_json::to_string(payout_instruction)?,
                payout_instruction.signer_key.to_hex(),
                payout_instruction.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_claim_payout_receipt(
        &mut self,
        payout_receipt: &SignedLiabilityClaimPayoutReceipt,
    ) -> Result<(), ReceiptStoreError> {
        if !payout_receipt
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability claim payout receipt signature verification failed".to_string(),
            ));
        }
        payout_receipt
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &payout_receipt.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT payout_receipt_id
                 FROM liability_claim_payout_receipts
                 WHERE payout_receipt_id = ?1",
                params![artifact.payout_receipt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability claim payout receipt `{}` already exists",
                artifact.payout_receipt_id
            )));
        }

        let stored_instruction_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_claim_payout_instructions
                 WHERE payout_instruction_id = ?1",
                params![artifact.payout_instruction.body.payout_instruction_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability claim payout instruction `{}` not found",
                    artifact.payout_instruction.body.payout_instruction_id
                ))
            })?;
        let stored_instruction: SignedLiabilityClaimPayoutInstruction =
            serde_json::from_str(&stored_instruction_raw_json)?;
        if stored_instruction.body != artifact.payout_instruction.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim payout receipt payout_instruction does not match the persisted payout instruction"
                    .to_string(),
            ));
        }

        let claim_id = artifact
            .payout_instruction
            .body
            .adjudication
            .body
            .dispute
            .body
            .provider_response
            .body
            .claim
            .body
            .claim_id
            .clone();

        tx.execute(
            "INSERT INTO liability_claim_payout_receipts (
                payout_receipt_id, issued_at, claim_id, payout_instruction_id,
                reconciliation_state, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                artifact.payout_receipt_id,
                artifact.issued_at as i64,
                claim_id,
                artifact.payout_instruction.body.payout_instruction_id,
                serde_json::to_string(&artifact.reconciliation_state)?,
                serde_json::to_string(payout_receipt)?,
                payout_receipt.signer_key.to_hex(),
                payout_receipt.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_claim_settlement_instruction(
        &mut self,
        settlement_instruction: &SignedLiabilityClaimSettlementInstruction,
    ) -> Result<(), ReceiptStoreError> {
        if !settlement_instruction
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability claim settlement instruction signature verification failed".to_string(),
            ));
        }
        settlement_instruction
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &settlement_instruction.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT settlement_instruction_id
                 FROM liability_claim_settlement_instructions
                 WHERE settlement_instruction_id = ?1",
                params![artifact.settlement_instruction_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability claim settlement instruction `{}` already exists",
                artifact.settlement_instruction_id
            )));
        }

        let stored_payout_receipt_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_claim_payout_receipts
                 WHERE payout_receipt_id = ?1",
                params![artifact.payout_receipt.body.payout_receipt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability claim payout receipt `{}` not found",
                    artifact.payout_receipt.body.payout_receipt_id
                ))
            })?;
        let stored_payout_receipt: SignedLiabilityClaimPayoutReceipt =
            serde_json::from_str(&stored_payout_receipt_raw_json)?;
        if stored_payout_receipt.body != artifact.payout_receipt.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim settlement instruction payout_receipt does not match the persisted payout receipt"
                    .to_string(),
            ));
        }

        let claim_id = artifact
            .payout_receipt
            .body
            .payout_instruction
            .body
            .adjudication
            .body
            .dispute
            .body
            .provider_response
            .body
            .claim
            .body
            .claim_id
            .clone();

        tx.execute(
            "INSERT INTO liability_claim_settlement_instructions (
                settlement_instruction_id, issued_at, claim_id, payout_receipt_id,
                settlement_kind, payer_role, payer_id, payee_role, payee_id,
                settlement_amount_units, settlement_amount_currency,
                raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                artifact.settlement_instruction_id,
                artifact.issued_at as i64,
                claim_id,
                artifact.payout_receipt.body.payout_receipt_id,
                serde_json::to_string(&artifact.settlement_kind)?,
                serde_json::to_string(&artifact.topology.payer.role)?,
                artifact.topology.payer.party_id,
                serde_json::to_string(&artifact.topology.payee.role)?,
                artifact.topology.payee.party_id,
                artifact.settlement_amount.units as i64,
                artifact.settlement_amount.currency,
                serde_json::to_string(settlement_instruction)?,
                settlement_instruction.signer_key.to_hex(),
                settlement_instruction.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_claim_settlement_receipt(
        &mut self,
        settlement_receipt: &SignedLiabilityClaimSettlementReceipt,
    ) -> Result<(), ReceiptStoreError> {
        if !settlement_receipt
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability claim settlement receipt signature verification failed".to_string(),
            ));
        }
        settlement_receipt
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &settlement_receipt.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT settlement_receipt_id
                 FROM liability_claim_settlement_receipts
                 WHERE settlement_receipt_id = ?1",
                params![artifact.settlement_receipt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability claim settlement receipt `{}` already exists",
                artifact.settlement_receipt_id
            )));
        }

        let stored_instruction_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_claim_settlement_instructions
                 WHERE settlement_instruction_id = ?1",
                params![
                    artifact
                        .settlement_instruction
                        .body
                        .settlement_instruction_id
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability claim settlement instruction `{}` not found",
                    artifact
                        .settlement_instruction
                        .body
                        .settlement_instruction_id
                ))
            })?;
        let stored_instruction: SignedLiabilityClaimSettlementInstruction =
            serde_json::from_str(&stored_instruction_raw_json)?;
        if stored_instruction.body != artifact.settlement_instruction.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim settlement receipt settlement_instruction does not match the persisted settlement instruction"
                    .to_string(),
            ));
        }

        let claim_id = artifact
            .settlement_instruction
            .body
            .payout_receipt
            .body
            .payout_instruction
            .body
            .adjudication
            .body
            .dispute
            .body
            .provider_response
            .body
            .claim
            .body
            .claim_id
            .clone();

        tx.execute(
            "INSERT INTO liability_claim_settlement_receipts (
                settlement_receipt_id, issued_at, claim_id, settlement_instruction_id,
                reconciliation_state, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                artifact.settlement_receipt_id,
                artifact.issued_at as i64,
                claim_id,
                artifact
                    .settlement_instruction
                    .body
                    .settlement_instruction_id,
                serde_json::to_string(&artifact.reconciliation_state)?,
                serde_json::to_string(settlement_receipt)?,
                settlement_receipt.signer_key.to_hex(),
                settlement_receipt.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn query_liability_claim_workflows(
        &self,
        query: &LiabilityClaimWorkflowQuery,
    ) -> Result<LiabilityClaimWorkflowReport, ReceiptStoreError> {
        let normalized = query.normalized();
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT raw_json
             FROM liability_claim_packages
             ORDER BY issued_at DESC, claim_id DESC",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;

        let mut matching_claims = 0_u64;
        let mut provider_responses = 0_u64;
        let mut accepted_responses = 0_u64;
        let mut denied_responses = 0_u64;
        let mut disputes = 0_u64;
        let mut adjudications = 0_u64;
        let mut payout_instructions = 0_u64;
        let mut payout_receipts = 0_u64;
        let mut matched_payout_receipts = 0_u64;
        let mut mismatched_payout_receipts = 0_u64;
        let mut settlement_instructions = 0_u64;
        let mut settlement_receipts = 0_u64;
        let mut matched_settlement_receipts = 0_u64;
        let mut mismatched_settlement_receipts = 0_u64;
        let mut counterparty_mismatch_settlement_receipts = 0_u64;
        let mut claims = Vec::new();

        for row in rows {
            let raw_json = row?;
            let claim: SignedLiabilityClaimPackage = serde_json::from_str(&raw_json)?;
            if !liability_claim_workflow_matches_query(&claim, &normalized) {
                continue;
            }
            matching_claims += 1;

            let provider_response = self
                .connection()?
                .query_row(
                    "SELECT raw_json
                     FROM liability_claim_responses
                     WHERE claim_id = ?1
                     ORDER BY issued_at DESC, claim_response_id DESC
                     LIMIT 1",
                    params![claim.body.claim_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str::<SignedLiabilityClaimResponse>(&raw_json))
                .transpose()?;
            if let Some(response) = provider_response.as_ref() {
                provider_responses += 1;
                match response.body.disposition {
                    LiabilityClaimResponseDisposition::Accepted => accepted_responses += 1,
                    LiabilityClaimResponseDisposition::Denied => denied_responses += 1,
                    LiabilityClaimResponseDisposition::Acknowledged => {}
                }
            }

            let dispute = self
                .connection()?
                .query_row(
                    "SELECT raw_json
                     FROM liability_claim_disputes
                     WHERE claim_id = ?1
                     ORDER BY issued_at DESC, dispute_id DESC
                     LIMIT 1",
                    params![claim.body.claim_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str::<SignedLiabilityClaimDispute>(&raw_json))
                .transpose()?;
            if dispute.is_some() {
                disputes += 1;
            }

            let adjudication = self
                .connection()?
                .query_row(
                    "SELECT raw_json
                     FROM liability_claim_adjudications
                     WHERE claim_id = ?1
                     ORDER BY issued_at DESC, adjudication_id DESC
                     LIMIT 1",
                    params![claim.body.claim_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str::<SignedLiabilityClaimAdjudication>(&raw_json))
                .transpose()?;
            if adjudication.is_some() {
                adjudications += 1;
            }

            let payout_instruction = self
                .connection()?
                .query_row(
                    "SELECT raw_json
                     FROM liability_claim_payout_instructions
                     WHERE claim_id = ?1
                     ORDER BY issued_at DESC, payout_instruction_id DESC
                     LIMIT 1",
                    params![claim.body.claim_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| {
                    serde_json::from_str::<SignedLiabilityClaimPayoutInstruction>(&raw_json)
                })
                .transpose()?;
            if payout_instruction.is_some() {
                payout_instructions += 1;
            }

            let payout_receipt = self
                .connection()?
                .query_row(
                    "SELECT raw_json
                     FROM liability_claim_payout_receipts
                     WHERE claim_id = ?1
                     ORDER BY issued_at DESC, payout_receipt_id DESC
                     LIMIT 1",
                    params![claim.body.claim_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| {
                    serde_json::from_str::<SignedLiabilityClaimPayoutReceipt>(&raw_json)
                })
                .transpose()?;
            if let Some(receipt) = payout_receipt.as_ref() {
                payout_receipts += 1;
                match receipt.body.reconciliation_state {
                    LiabilityClaimPayoutReconciliationState::Matched => {
                        matched_payout_receipts += 1;
                    }
                    LiabilityClaimPayoutReconciliationState::AmountMismatch => {
                        mismatched_payout_receipts += 1;
                    }
                }
            }

            let settlement_instruction = self
                .connection()?
                .query_row(
                    "SELECT raw_json
                     FROM liability_claim_settlement_instructions
                     WHERE claim_id = ?1
                     ORDER BY issued_at DESC, settlement_instruction_id DESC
                     LIMIT 1",
                    params![claim.body.claim_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| {
                    serde_json::from_str::<SignedLiabilityClaimSettlementInstruction>(&raw_json)
                })
                .transpose()?;
            if settlement_instruction.is_some() {
                settlement_instructions += 1;
            }

            let settlement_receipt = self
                .connection()?
                .query_row(
                    "SELECT raw_json
                     FROM liability_claim_settlement_receipts
                     WHERE claim_id = ?1
                     ORDER BY issued_at DESC, settlement_receipt_id DESC
                     LIMIT 1",
                    params![claim.body.claim_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| {
                    serde_json::from_str::<SignedLiabilityClaimSettlementReceipt>(&raw_json)
                })
                .transpose()?;
            if let Some(receipt) = settlement_receipt.as_ref() {
                settlement_receipts += 1;
                match receipt.body.reconciliation_state {
                    LiabilityClaimSettlementReconciliationState::Matched => {
                        matched_settlement_receipts += 1;
                    }
                    LiabilityClaimSettlementReconciliationState::AmountMismatch => {
                        mismatched_settlement_receipts += 1;
                    }
                    LiabilityClaimSettlementReconciliationState::CounterpartyMismatch => {
                        counterparty_mismatch_settlement_receipts += 1;
                    }
                }
            }

            if claims.len() < normalized.limit_or_default() {
                claims.push(LiabilityClaimWorkflowRow {
                    claim,
                    provider_response,
                    dispute,
                    adjudication,
                    payout_instruction,
                    payout_receipt,
                    settlement_instruction,
                    settlement_receipt,
                });
            }
        }

        Ok(LiabilityClaimWorkflowReport {
            schema: LIABILITY_CLAIM_WORKFLOW_REPORT_SCHEMA.to_string(),
            generated_at: unix_now(),
            query: normalized,
            summary: LiabilityClaimWorkflowSummary {
                matching_claims,
                returned_claims: claims.len() as u64,
                provider_responses,
                accepted_responses,
                denied_responses,
                disputes,
                adjudications,
                payout_instructions,
                payout_receipts,
                matched_payout_receipts,
                mismatched_payout_receipts,
                settlement_instructions,
                settlement_receipts,
                matched_settlement_receipts,
                mismatched_settlement_receipts,
                counterparty_mismatch_settlement_receipts,
            },
            claims,
        })
    }
}
