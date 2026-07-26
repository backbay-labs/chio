use super::*;

impl SqliteAdmissionOperationStore {
    pub(crate) fn reserve_threshold_approval_and_commit_admission(
        &self,
        command: &AdmissionOperationCommand,
        reservation: &chio_kernel::ThresholdApprovalReplayReservationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        if command.next_state() != Some(AdmissionOperationState::ApprovalReserved) {
            return Err(invariant(
                "threshold approval reservation must advance to approval_reserved",
            ));
        }
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

        let proposal = reservation.proposal();
        let verified_set = reservation.verified_set();
        if proposal.body.request_id != updated.binding().request_id().as_str() {
            return Err(invariant(
                "threshold approval proposal request does not match its admission operation",
            ));
        }
        let proposal_hash = proposal
            .artifact_digest()
            .map_err(|error| invariant(error.to_string()))?;
        let approval_set_hash = verified_set
            .approval_set_hash()
            .map_err(|error| invariant(error.to_string()))?;
        let attachment_matches = command.attachments().iter().any(|attachment| {
            matches!(
                attachment,
                AdmissionAttachment::ThresholdProposalHash(digest)
                    if digest.as_str() == proposal_hash
            )
        }) && command.attachments().iter().any(|attachment| {
            matches!(
                attachment,
                AdmissionAttachment::ApprovalSetHash(digest)
                    if digest.as_str() == approval_set_hash
            )
        });
        if !attachment_matches {
            return Err(invariant(
                "threshold approval replay reservation does not match operation attachments",
            ));
        }
        if trusted_now_unix_ms / 1_000 >= proposal.body.proposal_deadline {
            return Err(invariant(
                "threshold approval proposal expired before durable reservation",
            ));
        }

        let proposal_json = canonical_json_bytes(proposal)
            .map_err(|error| invariant(format!("threshold proposal encoding failed: {error}")))?;
        transaction
            .execute(
                r#"
                INSERT INTO threshold_approval_proposals (
                    proposal_id, operation_id, request_id, governed_intent_hash,
                    subject_fingerprint, authorizing_capability_digest, policy_hash,
                    threshold, eligible_set_digest, proposal_created_at,
                    proposal_deadline, proposal_hash, approval_set_hash, proposal_json,
                    state, reserved_at_unix_ms, updated_at_unix_ms
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                    ?14, 'reserved', ?15, ?15
                )
                "#,
                params![
                    &proposal.body.proposal_id,
                    command.operation_id().as_str(),
                    &proposal.body.request_id,
                    &proposal.body.governed_intent_hash,
                    proposal.body.subject.to_hex(),
                    &proposal.body.authorizing_capability_digest,
                    &proposal.body.policy_hash,
                    i64::from(proposal.body.threshold),
                    &proposal.body.eligible_set_digest,
                    sqlite_i64(proposal.body.proposal_created_at, "proposal_created_at")?,
                    sqlite_i64(proposal.body.proposal_deadline, "proposal_deadline")?,
                    proposal_hash,
                    approval_set_hash,
                    proposal_json,
                    sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                ],
            )
            .map_err(replay_conflict)?;
        for token in reservation.tokens() {
            let token_digest = token
                .artifact_digest()
                .map_err(|error| invariant(error.to_string()))?;
            let token_json = canonical_json_bytes(token).map_err(|error| {
                invariant(format!("threshold approval token encoding failed: {error}"))
            })?;
            transaction
                .execute(
                    r#"
                    INSERT INTO threshold_approval_tokens (
                        token_id, proposal_id, approver_fingerprint,
                        canonical_token_digest, token_json
                    ) VALUES (?1, ?2, ?3, ?4, ?5)
                    "#,
                    params![
                        &token.id,
                        &proposal.body.proposal_id,
                        token.approver.to_hex(),
                        token_digest,
                        token_json,
                    ],
                )
                .map_err(replay_conflict)?;
        }

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
}

fn replay_conflict(error: rusqlite::Error) -> AdmissionOperationStoreError {
    if matches!(
        &error,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::ConstraintViolation,
                ..
            },
            _
        )
    ) {
        AdmissionOperationStoreError::Invariant(format!(
            "threshold approval replay reservation conflicts with a durable tombstone: {error}"
        ))
    } else {
        sqlite_error(error)
    }
}
