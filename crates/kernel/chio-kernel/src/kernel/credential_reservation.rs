use super::*;
use chio_log_redact::redacted;

fn run_credential_store_operation<T>(
    reservation_id: &str,
    operation_name: &'static str,
    operation: impl FnOnce() -> Result<T, KernelError>,
) -> Result<T, KernelError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!(
                reservation_id,
                operation = operation_name,
                "dispatch credential store operation panicked; denying fail-closed"
            );
            Err(KernelError::Internal(format!(
                "dispatch credential {operation_name} panicked; denying fail-closed"
            )))
        }
    }
}

pub(crate) struct DispatchCredentialReservation<'a> {
    kernel: &'a ChioKernel,
    reservation_id: String,
    dpop_key: Option<(String, String)>,
    execution_nonce_id: Option<String>,
    legacy_execution_nonce: Option<(String, i64, String)>,
    execution_nonce_present: bool,
    approval_key: Option<(String, String, String)>,
    credentials_present: bool,
    rollback_on_drop: bool,
    retain_on_drop: bool,
}

impl DispatchCredentialReservation<'_> {
    /// Retain replay markers if the evaluation future is dropped after the
    /// dispatch future starts polling. At that point a tool side effect may
    /// already have committed.
    pub(crate) fn retain_if_dropped(
        &mut self,
    ) -> Result<PaymentCredentialDisposition, KernelError> {
        // Keep owned reservations reversible until dispatch starts. Once the
        // server is polled, neither a dropped future nor a server-controlled
        // URL-elicitation result can prove that no side effect occurred. Drop
        // therefore promotes the governed approval marker and leaves owned
        // nonce reservations in their fail-closed state.
        self.rollback_on_drop = false;
        self.retain_on_drop = true;
        // A legacy execution nonce store has no owned reservation state. Its
        // marker must be consumed before entering the effect boundary and
        // cannot participate in pre-effect rollback.
        self.reserve_legacy_execution_nonce_at_effect_boundary()?;
        Ok(self.retention_disposition())
    }

    /// Retain replay markers after an external authorization has already been
    /// acknowledged. At this point retrying could duplicate a payment hold or
    /// minted authority, so the governed approval marker must be promoted
    /// before the evaluation can continue.
    pub(crate) fn retain_after_external_authorization(
        &mut self,
    ) -> Result<PaymentCredentialDisposition, KernelError> {
        self.rollback_on_drop = false;
        self.retain_on_drop = true;
        self.reserve_legacy_execution_nonce_at_effect_boundary()?;
        self.commit_approval_marker()?;
        Ok(self.retention_disposition())
    }

    pub(crate) fn requires_post_reservation_revalidation(&self) -> bool {
        self.credentials_present
    }

    pub(crate) fn has_payment_authorization_credential(&self) -> bool {
        self.execution_nonce_present || self.approval_key.is_some()
    }

    pub(crate) fn commit(&mut self) -> Result<PaymentCredentialDisposition, KernelError> {
        // Clear rollback before the first fallible retention operation. On an
        // uncertain failure, keeping every owned marker is the safe direction.
        self.rollback_on_drop = false;
        self.retain_on_drop = false;
        self.reserve_legacy_execution_nonce_at_effect_boundary()?;
        self.commit_approval_marker()?;
        Ok(self.retention_disposition())
    }

    /// Consume a nonce held by a legacy store immediately before the first
    /// external effect. Legacy stores cannot conditionally roll back a marker,
    /// so consuming earlier would burn a valid nonce when later admission
    /// checks deny the request.
    pub(crate) fn reserve_legacy_execution_nonce_at_effect_boundary(
        &mut self,
    ) -> Result<(), KernelError> {
        let Some((nonce_id, nonce_expires_at, capability_id)) = self.legacy_execution_nonce.take()
        else {
            return Ok(());
        };
        let store = self
            .kernel
            .execution_nonce_store
            .as_deref()
            .ok_or_else(|| {
                KernelError::Internal(
                    "execution nonce store disappeared before dispatch".to_string(),
                )
            })?;
        match run_credential_store_operation(
            &self.reservation_id,
            "legacy execution nonce reservation",
            || {
                let _ = capability_id;
                store.reserve_until(&nonce_id, nonce_expires_at)
            },
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err(KernelError::Internal(
                "execution nonce has already been consumed".to_string(),
            )),
            Err(error) => Err(KernelError::Internal(format!(
                "legacy execution nonce reservation failed; consumption outcome unknown: {error}"
            ))),
        }
    }

    fn retention_disposition(&self) -> PaymentCredentialDisposition {
        if self.credentials_present {
            PaymentCredentialDisposition::RetainedAfterAuthorization
        } else {
            PaymentCredentialDisposition::NonePresent
        }
    }

    fn commit_approval_marker(&mut self) -> Result<(), KernelError> {
        let Some((subject_id, request_id, intent_hash)) = self.approval_key.as_ref() else {
            return Ok(());
        };
        let result = match self.kernel.approval_replay_store.as_deref() {
            Some(store) => run_credential_store_operation(
                &self.reservation_id,
                "governed approval reservation commit",
                || {
                    store.commit_dispatch_reservation(
                        subject_id,
                        request_id,
                        intent_hash,
                        &self.reservation_id,
                    )
                },
            ),
            None => Err(KernelError::GovernedTransactionDenied(
                "approval replay store disappeared during dispatch commit; marker retained fail-closed"
                    .to_string(),
            )),
        };
        match result {
            Ok(true) => {
                self.approval_key = None;
                Ok(())
            }
            Ok(false) => Err(KernelError::GovernedTransactionDenied(
                "governed approval reservation ownership was not confirmed during commit; marker retention outcome unknown"
                    .to_string(),
            )),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn rollback_before_dispatch(mut self) -> Result<(), KernelError> {
        self.rollback_on_drop = false;
        self.retain_on_drop = false;
        self.rollback_entries()
    }

    fn rollback_entries(&mut self) -> Result<(), KernelError> {
        let mut failures = Vec::new();

        // A pending legacy nonce has not been consumed yet. Once consumed it
        // is intentionally absent here because the legacy API has no owned
        // rollback operation.
        self.legacy_execution_nonce = None;

        if let Some((subject_id, request_id, intent_hash)) = self.approval_key.take() {
            let result = match self.kernel.approval_replay_store.as_deref() {
                Some(store) => run_credential_store_operation(
                    &self.reservation_id,
                    "governed approval reservation rollback",
                    || {
                        store.rollback_dispatch_reservation(
                            &subject_id,
                            &request_id,
                            &intent_hash,
                            &self.reservation_id,
                        )
                    },
                ),
                None => Err(KernelError::GovernedTransactionDenied(
                    "approval replay store disappeared during dispatch rollback".to_string(),
                )),
            };
            match result {
                Ok(true) => {}
                Ok(false) => failures.push(
                    "governed approval dispatch reservation was not owned during rollback"
                        .to_string(),
                ),
                Err(error) => failures.push(error.to_string()),
            }
        }

        if let Some(nonce_id) = self.execution_nonce_id.take() {
            let result = match self.kernel.execution_nonce_store.as_deref() {
                Some(store) => run_credential_store_operation(
                    &self.reservation_id,
                    "execution nonce reservation rollback",
                    || store.rollback_dispatch_reservation(&nonce_id, &self.reservation_id),
                ),
                None => Err(KernelError::Internal(
                    "execution nonce store disappeared during dispatch rollback".to_string(),
                )),
            };
            match result {
                Ok(true) => {}
                Ok(false) => failures.push(
                    "execution nonce dispatch reservation was not owned during rollback"
                        .to_string(),
                ),
                Err(error) => failures.push(error.to_string()),
            }
        }

        if let Some((nonce, capability_id)) = self.dpop_key.take() {
            let result = match self.kernel.dpop_nonce_store.as_ref() {
                Some(store) => run_credential_store_operation(
                    &self.reservation_id,
                    "DPoP nonce reservation rollback",
                    || {
                        store.rollback_dispatch_reservation(
                            &nonce,
                            &capability_id,
                            &self.reservation_id,
                        )
                    },
                ),
                None => Err(KernelError::DpopVerificationFailed(
                    "DPoP nonce store disappeared during dispatch rollback".to_string(),
                )),
            };
            match result {
                Ok(true) => {}
                Ok(false) => failures
                    .push("DPoP dispatch reservation was not owned during rollback".to_string()),
                Err(error) => failures.push(error.to_string()),
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(KernelError::Internal(format!(
                "dispatch credential rollback failed: {}",
                failures.join("; ")
            )))
        }
    }
}

impl Drop for DispatchCredentialReservation<'_> {
    fn drop(&mut self) {
        if self.retain_on_drop {
            if let Err(error) = self.reserve_legacy_execution_nonce_at_effect_boundary() {
                tracing::warn!(
                    reason = %redacted!(&error),
                    "legacy dispatch credential retention failed while dropping an evaluation"
                );
            }
            if let Err(error) = self.commit_approval_marker() {
                tracing::warn!(
                    reason = %redacted!(&error),
                    "governed dispatch credential retention failed while dropping an evaluation"
                );
            }
            return;
        }
        if !self.rollback_on_drop {
            return;
        }
        if let Err(error) = self.rollback_entries() {
            tracing::warn!(
                reason = %redacted!(&error),
                "dispatch credential rollback failed while dropping an evaluation"
            );
        }
    }
}

impl ChioKernel {
    pub(crate) fn reserve_dispatch_credentials(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        dpop_required: bool,
        now: u64,
    ) -> Result<DispatchCredentialReservation<'_>, KernelError> {
        self.reserve_credentials(request, cap, dpop_required, now, true, false)
    }

    /// Reserve the credentials presented to a reserve-for-caller authorization.
    ///
    /// No execution nonce exists yet on this preflight. DPoP and governed
    /// approval credentials are nevertheless authorizing this request to mint
    /// one, so they use the same owned commit/rollback lifecycle as normal
    /// dispatch credentials. This prevents concurrent authorization replays
    /// without burning a credential when later admission revalidation denies.
    pub(crate) fn reserve_caller_authorization_credentials(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        dpop_required: bool,
        now: u64,
        require_governed_approval: bool,
    ) -> Result<DispatchCredentialReservation<'_>, KernelError> {
        self.reserve_credentials(
            request,
            cap,
            dpop_required,
            now,
            false,
            require_governed_approval,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn reserve_credentials(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        dpop_required: bool,
        now: u64,
        reserve_execution_nonce: bool,
        require_governed_approval: bool,
    ) -> Result<DispatchCredentialReservation<'_>, KernelError> {
        let dpop_proof = if dpop_required {
            let proof = request.dpop_proof.as_ref().ok_or_else(|| {
                KernelError::DpopVerificationFailed(
                    "grant requires DPoP proof but none was provided".to_string(),
                )
            })?;
            self.verify_dpop_for_permission_preview(
                proof,
                cap,
                &request.server_id,
                &request.tool_name,
                &request.arguments,
            )?;
            Some(proof)
        } else {
            None
        };

        let execution_nonce = if reserve_execution_nonce {
            self.validate_execution_nonce_non_consuming(request, cap, now)?
        } else {
            None
        };
        let approval_intent_hash =
            self.validate_governed_approval_for_dispatch_non_consuming(request, cap, now)?;
        if require_governed_approval && approval_intent_hash.is_none() {
            return Err(KernelError::GovernedTransactionDenied(
                "strict reserve-for-caller payment authorization requires a governed approval token"
                    .to_string(),
            ));
        }
        if approval_intent_hash.is_some() && self.approval_replay_store.is_none() {
            return Err(KernelError::GovernedTransactionDenied(
                "approval replay store not configured; denying as fail-closed".to_string(),
            ));
        }

        let mut reservation = DispatchCredentialReservation {
            kernel: self,
            reservation_id: uuid::Uuid::now_v7().as_hyphenated().to_string(),
            dpop_key: None,
            execution_nonce_id: None,
            legacy_execution_nonce: None,
            execution_nonce_present: execution_nonce.is_some(),
            approval_key: None,
            credentials_present: dpop_proof.is_some()
                || execution_nonce.is_some()
                || approval_intent_hash.is_some(),
            rollback_on_drop: true,
            retain_on_drop: false,
        };

        let result = (|| {
            if let Some(proof) = dpop_proof {
                let store = self.dpop_nonce_store.as_ref().ok_or_else(|| {
                    KernelError::DpopVerificationFailed(
                        "kernel DPoP nonce store not configured".to_string(),
                    )
                })?;
                let config = self.dpop_config.as_ref().ok_or_else(|| {
                    KernelError::DpopVerificationFailed(
                        "kernel DPoP configuration not installed".to_string(),
                    )
                })?;
                reservation.dpop_key =
                    Some((proof.body.nonce.clone(), proof.body.capability_id.clone()));
                let valid_through = proof.body.issued_at.saturating_add(config.proof_ttl_secs);
                match run_credential_store_operation(
                    &reservation.reservation_id,
                    "DPoP nonce reservation",
                    || {
                        store.reserve_for_dispatch_through(
                            &proof.body.nonce,
                            &proof.body.capability_id,
                            valid_through,
                            &reservation.reservation_id,
                        )
                    },
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        reservation.dpop_key = None;
                        return Err(KernelError::DpopVerificationFailed(
                            "nonce replayed: this nonce has already been used during the proof validity window"
                                .to_string(),
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }

            if let Some(presented) = execution_nonce {
                let store = self.execution_nonce_store.as_deref().ok_or_else(|| {
                    KernelError::Internal("execution nonce store is not installed".to_string())
                })?;
                if store.supports_dispatch_reservations() {
                    reservation.execution_nonce_id = Some(presented.nonce.nonce_id.clone());
                    match run_credential_store_operation(
                        &reservation.reservation_id,
                        "execution nonce reservation",
                        || {
                            store.reserve_for_dispatch(
                                &presented.nonce.nonce_id,
                                presented.nonce.expires_at,
                                &reservation.reservation_id,
                            )
                        },
                    ) {
                        Ok(true) => {}
                        Ok(false) => {
                            reservation.execution_nonce_id = None;
                            return Err(KernelError::Internal(
                                "execution nonce has already been consumed".to_string(),
                            ));
                        }
                        Err(error) => return Err(error),
                    }
                } else {
                    reservation.legacy_execution_nonce = Some((
                        presented.nonce.nonce_id.clone(),
                        presented.nonce.expires_at,
                        presented.nonce.bound_to.capability_id.clone(),
                    ));
                }
            }

            if let (Some(approval_token), Some(intent_hash)) = (
                request.approval_token.as_ref(),
                approval_intent_hash.as_ref(),
            ) {
                let store = self.approval_replay_store.as_deref().ok_or_else(|| {
                    KernelError::GovernedTransactionDenied(
                        "approval replay store not configured; denying as fail-closed".to_string(),
                    )
                })?;
                reservation.approval_key = Some((
                    approval_token.subject.to_hex(),
                    approval_token.request_id.clone(),
                    intent_hash.to_string(),
                ));
                match run_credential_store_operation(
                    &reservation.reservation_id,
                    "governed approval reservation",
                    || {
                        store.reserve_for_dispatch(
                            &approval_token.subject.to_hex(),
                            &approval_token.request_id,
                            intent_hash,
                            approval_token.expires_at,
                            &reservation.reservation_id,
                        )
                    },
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        reservation.approval_key = None;
                        return Err(KernelError::GovernedTransactionDenied(
                            "approval token has already been consumed (replay detected)"
                                .to_string(),
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })();

        match result {
            Ok(()) => Ok(reservation),
            Err(error) => match reservation.rollback_before_dispatch() {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(KernelError::Internal(format!(
                    "dispatch credential reservation failed: {error}; {rollback_error}"
                ))),
            },
        }
    }

    pub(crate) fn validate_execution_nonce_non_consuming<'a>(
        &self,
        request: &'a ToolCallRequest,
        cap: &CapabilityToken,
        now: u64,
    ) -> Result<Option<&'a crate::execution_nonce::SignedExecutionNonce>, KernelError> {
        let presented = request.execution_nonce.as_ref();
        if !self.execution_nonce_required() && presented.is_none() {
            return Ok(None);
        }
        let presented = presented.ok_or_else(|| {
            KernelError::Internal(
                "execution nonce required but not presented on tool call".to_string(),
            )
        })?;
        let _store = self.execution_nonce_store.as_deref().ok_or_else(|| {
            KernelError::Internal("execution nonce store is not installed".to_string())
        })?;
        let parameter_hash = ToolCallAction::from_parameters(request.arguments.clone())
            .map_err(|error| {
                KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {error}"))
            })?
            .parameter_hash;
        let expected = crate::execution_nonce::NonceBinding {
            subject_id: cap.subject.to_hex(),
            capability_id: cap.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            request_id: request.request_id.clone(),
            parameter_hash,
        };
        crate::execution_nonce::validate_execution_nonce(
            presented,
            &self.config.keypair.public_key(),
            &expected,
            i64::try_from(now).unwrap_or(i64::MAX),
        )
        .map_err(|error| KernelError::Internal(error.to_string()))?;
        Ok(Some(presented))
    }
}
