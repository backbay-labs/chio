use super::*;

impl SqliteFindingMarketStore {
    /// Register one live collateral allocation from a collateral-authority
    /// backing envelope. `accepted_at` is the venue trusted time of
    /// acceptance. The raw envelope bytes must parse to exactly the
    /// supplied backing body; pinned-authority signature verification
    /// is the caller's boundary. Exclusivity: at most one live allocation
    /// per (seller, finding, listing), and an allocation id registers
    /// exactly once whatever its state, so an already-encumbered or reused
    /// allocation rejects.
    pub fn register_allocation(
        &self,
        backing_envelope_json: &str,
        backing: &FindingBondBacking,
        accepted_at: u64,
    ) -> Result<(), FindingMarketStoreError> {
        match self.register_allocation_idempotent(backing_envelope_json, backing, accepted_at)? {
            FindingAllocationRegistrationOutcome::Registered { .. } => Ok(()),
            FindingAllocationRegistrationOutcome::ExactReplay { .. } => {
                Err(FindingMarketStoreError::Conflict(
                    "collateral allocation id was already registered".to_owned(),
                ))
            }
        }
    }

    /// Register collateral and classify an identical retry in the same
    /// immediate transaction that enforces allocation exclusivity.
    pub fn register_allocation_idempotent(
        &self,
        backing_envelope_json: &str,
        backing: &FindingBondBacking,
        accepted_at: u64,
    ) -> Result<FindingAllocationRegistrationOutcome, FindingMarketStoreError> {
        backing
            .validate()
            .map_err(|error| invariant(format!("bond backing rejected: {error}")))?;
        if backing_envelope_json.is_empty() || backing_envelope_json.len() > MAX_ENVELOPE_BYTES {
            return Err(invariant("backing envelope byte length is out of bounds"));
        }
        let parsed: SignedFindingBondBacking = serde_json::from_str(backing_envelope_json)
            .map_err(|error| invariant(format!("backing envelope bytes are invalid: {error}")))?;
        if parsed.body != *backing {
            return Err(invariant(
                "backing envelope bytes do not carry the supplied backing body",
            ));
        }
        let backing_envelope_sha256 = sha256_hex(backing_envelope_json.as_bytes());
        let seller_hex = backing.seller.to_hex();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let existing: Option<(String, String, i64)> = transaction
            .query_row(
                r#"
                SELECT backing_envelope_sha256, backing_envelope_json, accepted_at
                FROM collateral_allocations WHERE allocation_id = ?1
                "#,
                [backing.allocation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some((stored_sha256, stored_json, stored_accepted_at)) = existing {
            verify_stored_digest(
                stored_json.as_bytes(),
                &stored_sha256,
                "collateral backing envelope",
            )?;
            if stored_sha256 == backing_envelope_sha256 && stored_json == backing_envelope_json {
                return Ok(FindingAllocationRegistrationOutcome::ExactReplay {
                    accepted_at: stored_u64(stored_accepted_at, "accepted_at")?,
                });
            }
            return Err(FindingMarketStoreError::Conflict(
                "collateral allocation id is bound to different backing".to_owned(),
            ));
        }
        if accepted_at < backing.issued_at || accepted_at >= backing.expires_at {
            return Err(FindingMarketStoreError::Conflict(
                "backing allocation is not live at acceptance time".to_owned(),
            ));
        }
        let live_for_listing: i64 = transaction
            .query_row(
                r#"
                SELECT COUNT(*) FROM collateral_allocations
                WHERE seller_hex = ?1 AND finding_id = ?2 AND listing_id = ?3
                  AND state = 'live'
                "#,
                params![&seller_hex, &backing.finding_id, &backing.listing_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if live_for_listing != 0 {
            return Err(FindingMarketStoreError::Conflict(
                "a live collateral allocation already backs this finding listing".to_owned(),
            ));
        }
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO collateral_allocations (
                    allocation_id, seller_hex, finding_id, listing_id,
                    backing_envelope_sha256, backing_envelope_json, currency,
                    locked_units, maximum_sale_exposure_units, expires_at,
                    accepted_at, state
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'live')
                "#,
                params![
                    &backing.allocation_id,
                    &seller_hex,
                    &backing.finding_id,
                    &backing.listing_id,
                    &backing_envelope_sha256,
                    backing_envelope_json,
                    &backing.locked_amount.currency,
                    sqlite_i64(backing.locked_amount.units, "locked_units")?,
                    sqlite_i64(
                        backing.maximum_sale_exposure.units,
                        "maximum_sale_exposure_units"
                    )?,
                    sqlite_i64(backing.expires_at, "expires_at")?,
                    sqlite_i64(accepted_at, "accepted_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("allocation insert did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingAllocationRegistrationOutcome::Registered { accepted_at })
    }
}
