use super::*;

impl ChioKernel {
    pub(super) fn reconcile_finding_pool_terminal_claims(&self) -> Result<usize, KernelError> {
        const PAGE_LIMIT: usize = 256;

        let Some(ledger) = self.finding_pool_ledger() else {
            return Ok(0);
        };
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let mut after_operation_id: Option<String> = None;
        let mut reconciled = 0_usize;
        loop {
            let operation_ids = ledger
                .list_claimed_admission_operations(after_operation_id.as_deref(), PAGE_LIMIT)
                .map_err(|error| {
                    KernelError::DurableAdmission(format!(
                        "finding pool claimed-operation scan failed: {error}"
                    ))
                })?;
            if operation_ids.len() > PAGE_LIMIT {
                return Err(KernelError::DurableAdmission(
                    "finding pool ledger exceeded the claimed-operation page limit".to_owned(),
                ));
            }
            if operation_ids.is_empty() {
                break;
            }
            for operation_id in operation_ids {
                if after_operation_id
                    .as_deref()
                    .is_some_and(|after| operation_id.as_str() <= after)
                {
                    return Err(KernelError::DurableAdmission(
                        "finding pool claimed-operation page did not advance".to_owned(),
                    ));
                }
                let persisted_operation_id =
                    crate::admission_operation::AdmissionOperationId::from_persisted(
                        operation_id.clone(),
                    )?;
                let operation = runtime
                    .store
                    .load_by_operation_id(&persisted_operation_id)
                    .map_err(durable_store_error)?
                    .ok_or_else(|| {
                        KernelError::DurableAdmission(
                            "finding pool claim references a missing admission operation"
                                .to_owned(),
                        )
                    })?;
                if operation.state() == AdmissionOperationState::NotAcceptedAfterDispatchCommit {
                    self.release_finding_pool_claim_after_verified_no_effect(
                        &operation_id,
                        trusted_now_unix_ms,
                    )
                    .map_err(|error| {
                        KernelError::DurableAdmission(format!(
                            "terminal finding pool claim reconciliation failed: {error}"
                        ))
                    })?;
                    reconciled = reconciled.checked_add(1).ok_or_else(|| {
                        KernelError::DurableAdmission(
                            "finding pool reconciliation count overflow".to_owned(),
                        )
                    })?;
                }
                after_operation_id = Some(operation_id);
            }
        }
        Ok(reconciled)
    }
}
