use super::*;

impl AdmissionOperationStore for SqliteAdmissionOperationStore {
    fn begin(
        &self,
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError> {
        if operation.binding().participant_requirements().channel {
            return Err(invariant(
                "channel operations require the atomic channel prepared begin",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(fence))?;
        let encoded =
            match begin_prepared_operation_tx(&transaction, operation, fence, trusted_now_unix_ms)?
            {
                PreparedAdmissionBeginTxResult::Created { encoded } => encoded,
                PreparedAdmissionBeginTxResult::ExactReplay {
                    operation,
                    terminal_replay,
                } => {
                    transaction.commit().map_err(sqlite_error)?;
                    return Ok(AdmissionBeginResult::ExactReplay {
                        operation: *operation,
                        terminal_replay,
                    });
                }
                PreparedAdmissionBeginTxResult::Conflict {
                    existing_operation_id,
                } => {
                    transaction.commit().map_err(sqlite_error)?;
                    return Ok(AdmissionBeginResult::Conflict {
                        existing_operation_id,
                    });
                }
            };
        append_operation_commit(
            &transaction,
            operation,
            &encoded,
            None,
            "begin",
            &self.serving_owner,
            trusted_now_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(AdmissionBeginResult::Created(operation.clone()))
    }

    fn load_by_operation_id(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let operation =
            load_by_operation_id_tx(&transaction, operation_id)?.map(|row| row.operation);
        transaction.commit().map_err(sqlite_error)?;
        Ok(operation)
    }

    fn load_by_replay_key(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let operation = load_by_replay_key_tx(&transaction, replay_key)?.map(|row| row.operation);
        transaction.commit().map_err(sqlite_error)?;
        Ok(operation)
    }

    fn compare_and_swap(
        &self,
        command: &AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        let fence = command.recovery_lease().store_fence();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, command.operation_id())?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        ensure_no_reserved_terminal_stage(&transaction, command.operation_id())?;
        qualify_generic_channel_command(&transaction, &stored.operation, command)?;
        if trusted_now_unix_ms < stored.updated_at_unix_ms {
            return Err(invariant("trusted operation time regressed"));
        }
        verify_stored_recovery_claim(
            &transaction,
            &self.serving_owner,
            &stored,
            command.recovery_lease().untrusted_claim(),
            trusted_now_unix_ms,
            fence,
        )?;

        let result = stored
            .operation
            .apply_command(command, trusted_now_unix_ms)?;
        let AdmissionCommandResult::Applied(updated) = result else {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(result);
        };
        let encoded = encode_operation(&updated)?;
        let changed = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET operation_json = ?1, state = ?2, terminal = ?3,
                    coordinator_lease_epoch = ?4, version = ?5,
                    updated_at_unix_ms = ?6
                WHERE operation_id = ?7 AND version = ?8
                "#,
                params![
                    encoded,
                    state_name(updated.state()),
                    i64::from(updated.state().is_terminal()),
                    sqlite_i64(updated.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                    sqlite_i64(updated.version(), "version")?,
                    sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                    updated.binding().operation_id().as_str(),
                    sqlite_i64(stored.operation.version(), "expected_version")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        append_operation_commit(
            &transaction,
            &updated,
            &encoded,
            stored.recovery_claim.as_ref(),
            "compare_and_swap",
            &self.serving_owner,
            trusted_now_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(AdmissionCommandResult::Applied(updated))
    }

    fn claim_recovery_untrusted(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        claimant_id: &AdmissionIdentifier,
        trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        fence: &StoreMutationFence,
    ) -> Result<UntrustedAdmissionRecoveryClaim, AdmissionOperationStoreError> {
        validate_trusted_time(trusted_now_unix_ms, "trusted_now_unix_ms")?;
        validate_trusted_time(expires_at_unix_ms, "expires_at_unix_ms")?;
        if expected_version == 0 {
            return Err(AdmissionOperationError::ZeroVersionOrEpoch.into());
        }
        if trusted_now_unix_ms >= expires_at_unix_ms {
            return Err(AdmissionOperationError::LeaseExpired.into());
        }
        if expires_at_unix_ms - trusted_now_unix_ms > MAX_RECOVERY_LEASE_DURATION_MS {
            return Err(invariant("recovery lease exceeds its maximum duration"));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if stored.operation.state().is_terminal() {
            return Err(invariant("terminal operation cannot be recovery-claimed"));
        }
        if trusted_now_unix_ms < stored.updated_at_unix_ms {
            return Err(invariant("trusted operation time regressed"));
        }
        if stored.operation.version() != expected_version {
            return Err(AdmissionOperationError::StaleVersion {
                expected: expected_version,
                actual: stored.operation.version(),
            }
            .into());
        }
        if crate::economic_state_cache::has_reserved_terminal_stage(
            &transaction,
            operation_id.as_str(),
        )
        .map_err(map_economic_cache_error)?
        {
            if let Some(active) = stored.recovery_claim.as_ref().filter(|active| {
                active.expires_at_unix_ms() > trusted_now_unix_ms
                    && active.store_fence() == fence
                    && active.claimant_id() == claimant_id
                    && active.claimed_version() == expected_version
            }) {
                let active = active.clone();
                transaction.commit().map_err(sqlite_error)?;
                return Ok(active);
            }
            return Err(AdmissionOperationStoreError::Fenced);
        }

        let coordinator_lease_id = coordinator_lease_id_for_epoch(
            &transaction,
            &self.serving_owner,
            stored.operation.coordinator_lease_epoch(),
        )?;
        let claim = UntrustedAdmissionRecoveryClaim::new(
            operation_id.clone(),
            claimant_id.clone(),
            coordinator_lease_id,
            stored.operation.coordinator_lease_epoch(),
            expected_version,
            expires_at_unix_ms,
            fence.clone(),
        )?;
        if let Some(active) = stored
            .recovery_claim
            .as_ref()
            .filter(|active| active.expires_at_unix_ms() > trusted_now_unix_ms)
        {
            if active.store_fence() == fence {
                let same_claimant = active.claimant_id() == claimant_id
                    && active.coordinator_lease_id() == claim.coordinator_lease_id()
                    && active.coordinator_lease_epoch() == claim.coordinator_lease_epoch();
                if same_claimant && active.claimed_version() == expected_version {
                    let active = active.clone();
                    transaction.commit().map_err(sqlite_error)?;
                    return Ok(active);
                }
                if !same_claimant || active.claimed_version() >= expected_version {
                    return Err(AdmissionOperationStoreError::Fenced);
                }
            }
        }

        let changed = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET recovery_claimant_id = ?1,
                    recovery_coordinator_lease_id = ?2,
                    recovery_coordinator_lease_epoch = ?3,
                    recovery_claimed_version = ?4,
                    recovery_expires_at_unix_ms = ?5,
                    recovery_store_uuid = ?6,
                    recovery_store_lease_id = ?7,
                    recovery_store_owner_epoch = ?8,
                    updated_at_unix_ms = ?9
                WHERE operation_id = ?10 AND version = ?4 AND terminal = 0
                "#,
                params![
                    claimant_id.as_str(),
                    claim.coordinator_lease_id().as_str(),
                    sqlite_i64(claim.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                    sqlite_i64(expected_version, "claimed_version")?,
                    sqlite_i64(expires_at_unix_ms, "expires_at_unix_ms")?,
                    &fence.store_uuid,
                    &fence.lease_id,
                    sqlite_i64(fence.owner_epoch, "store_owner_epoch")?,
                    sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                    operation_id.as_str(),
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        let encoded = encode_operation(&stored.operation)?;
        append_operation_commit(
            &transaction,
            &stored.operation,
            &encoded,
            Some(&claim),
            "recovery_claim",
            &self.serving_owner,
            trusted_now_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(claim)
    }

    fn revalidate_recovery_claim(
        &self,
        operation: &AdmissionOperationV1,
        claim: &UntrustedAdmissionRecoveryClaim,
        trusted_now_unix_ms: u64,
        current_store_fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(current_store_fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, claim.operation_id())?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if stored.operation != *operation {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        verify_stored_recovery_claim(
            &transaction,
            &self.serving_owner,
            &stored,
            claim,
            trusted_now_unix_ms,
            current_store_fence,
        )?;
        transaction.commit().map_err(sqlite_error)
    }

    fn list_recoverable(
        &self,
        not_after_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<AdmissionOperationV1>, AdmissionOperationStoreError> {
        if limit > MAX_RECOVERY_BATCH {
            return Err(invariant("recovery batch limit exceeds 256"));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT operation_id, request_namespace_digest, request_id,
                       operation_json, state, terminal, coordinator_lease_epoch,
                       version, created_at_unix_ms, updated_at_unix_ms,
                       recovery_claimant_id, recovery_coordinator_lease_id,
                       recovery_coordinator_lease_epoch, recovery_claimed_version,
                       recovery_expires_at_unix_ms, recovery_store_uuid,
                       recovery_store_lease_id, recovery_store_owner_epoch
                FROM admission_operations
                WHERE terminal = 0
                  AND state <> 'approval_required'
                  AND (recovery_expires_at_unix_ms IS NULL
                       OR recovery_expires_at_unix_ms <= ?1
                       OR recovery_store_uuid <> ?2
                       OR recovery_store_lease_id <> ?3
                       OR recovery_store_owner_epoch <> ?4)
                ORDER BY updated_at_unix_ms, operation_id
                LIMIT ?5
                "#,
            )
            .map_err(sqlite_error)?;
        let mut rows = statement
            .query(params![
                sqlite_i64(not_after_unix_ms, "not_after_unix_ms")?,
                &self.serving_owner.fence.store_uuid,
                &self.serving_owner.fence.lease_id,
                sqlite_i64(self.serving_owner.fence.owner_epoch, "store_owner_epoch")?,
                i64::try_from(limit).map_err(|_| invariant("recovery limit overflow"))?,
            ])
            .map_err(sqlite_error)?;
        let mut operations = Vec::with_capacity(limit);
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let stored = decode_row(read_raw_row(row).map_err(sqlite_error)?)?;
            verify_latest_commit(&transaction, &stored)?;
            operations.push(stored.operation);
        }
        drop(rows);
        drop(statement);
        transaction.commit().map_err(sqlite_error)?;
        Ok(operations)
    }

    fn load_terminal_replay(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionTerminalReplay>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let replay = load_by_replay_key_tx(&transaction, replay_key)?
            .and_then(|stored| stored.operation.terminal_replay().cloned());
        transaction.commit().map_err(sqlite_error)?;
        Ok(replay)
    }
}
