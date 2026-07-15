use super::evaluation_helpers::PreDispatchCleanupDeny;
use super::*;

impl ChioKernel {
    pub(super) async fn evaluate_tool_call_async_with_session_context(
        &self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
        extra_metadata: Option<serde_json::Value>,
        session_id: Option<&SessionId>,
    ) -> Result<ToolCallResponse, KernelError> {
        let receipt_context =
            EvaluationReceiptContext::new(self.resolve_tenant_id_for_session(session_id));
        self.evaluate_tool_call_async_core(
            request,
            session_filesystem_roots,
            extra_metadata,
            session_id,
            receipt_context,
        )
        .await
    }

    async fn evaluate_tool_call_async_core(
        &self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
        extra_metadata: Option<serde_json::Value>,
        session_id: Option<&SessionId>,
        mut receipt_context: EvaluationReceiptContext,
    ) -> Result<ToolCallResponse, KernelError> {
        let runtime_admission_input_metadata = extra_metadata;
        let sanitized_metadata =
            sanitize_external_receipt_metadata(runtime_admission_input_metadata.clone());
        let safe_external_metadata = strip_external_receipt_provenance(sanitized_metadata.clone());
        let now_unix_ms = current_unix_timestamp_ms();
        let now = now_unix_ms / 1000;

        // Emergency kill switch: every evaluate path checks the flag
        // before receipt negotiation, capability validation, guard evaluation,
        // or budget mutation so a stopped kernel cannot be coerced into doing
        // any work or peer lookup.
        if self.is_emergency_stopped() {
            warn!(
                request_id = %request.request_id,
                "emergency stop active -- denying evaluate_tool_call"
            );
            return self.build_emergency_stop_deny_response_with_metadata(
                request,
                &receipt_context,
                EMERGENCY_STOP_DENY_REASON,
                now,
                None,
                safe_external_metadata.clone(),
            );
        }

        // Receipt-version negotiation is a TRUST-BOUNDARY admission check
        // that must run BEFORE any dispatch path. The admission snapshot is
        // scoped for every receipt builder below so persistence and federation cosign
        // use the peer/version/key material admitted before side effects.
        // PROTOCOL.md section 6 normative MUST.
        let receipt_admission = match self
            .kernel_receipt_admission_for_remote(request.federated_origin_kernel_id.as_deref(), now)
        {
            Ok(admission) => admission,
            Err(error) => {
                let msg = error.to_string();
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&msg),
                    "receipt federation admission failed pre-dispatch"
                );
                return self.build_negotiation_failclosed_deny_response_with_metadata(
                    request,
                    &receipt_context,
                    &msg,
                    now,
                    None,
                    safe_external_metadata.clone(),
                );
            }
        };
        receipt_context.set_federation_admission(receipt_admission.clone());

        let extra_metadata = match normalize_external_receipt_metadata(sanitized_metadata) {
            Ok(metadata) => metadata,
            Err(error) => {
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&error),
                    "receipt metadata rejected before dispatch"
                );
                return self.build_deny_response_with_metadata(
                    request,
                    &receipt_context,
                    "receipt provenance metadata rejected",
                    now,
                    None,
                    safe_external_metadata,
                );
            }
        };

        self.validate_web3_evidence_prerequisites()?;

        debug!(
            request_id = %request.request_id,
            tool = %request.tool_name,
            server = %request.server_id,
            "evaluating tool call"
        );

        let cap = &request.capability;

        // Signature is verified first (no budget mutation); the actual
        // `admit_capability_budget` call is deferred until all
        // subsequent checks (time, revocation, delegation-admission,
        // subject, scope, guards) have passed. Otherwise a denied call
        // would still consume the parent's share, starving later valid
        // siblings.
        if let Err(reason) = self.verify_capability_full_pre_admit(
            cap,
            request.federated_origin_kernel_id.as_deref(),
            now,
        ) {
            let msg = format!("capability verification failed: {reason}");
            warn!(request_id = %request.request_id, msg = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &receipt_context,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(e) = check_time_bounds(cap, now) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &receipt_context,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(e) = self.check_tool_call_revocation_admission(request) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &receipt_context,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(e) = self.validate_delegation_admission(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &receipt_context,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(e) = check_subject_binding(cap, &request.agent_id) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &receipt_context,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        let matching_grants = match resolve_required_matching_grants(
            cap,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        ) {
            Ok(grants) => grants,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
                return self.build_deny_response_with_metadata(
                    request,
                    &receipt_context,
                    &msg,
                    now,
                    None,
                    extra_metadata.clone(),
                );
            }
        };

        // DPoP enforcement before budget charge: if any matching grant requires
        // DPoP, verify the proof now so an attacker cannot drain the budget with
        // a valid capability token but missing or invalid DPoP proof.
        let dpop_required = matching_grants
            .iter()
            .any(|m| m.grant.dpop_required == Some(true));
        if dpop_required {
            let verification = request.dpop_proof.as_ref().map_or_else(
                || {
                    Err(KernelError::DpopVerificationFailed(
                        "grant requires DPoP proof but none was provided".to_string(),
                    ))
                },
                |proof| {
                    self.verify_dpop_for_permission_preview(
                        proof,
                        cap,
                        &request.server_id,
                        &request.tool_name,
                        &request.arguments,
                    )
                },
            );
            let admitted = chio_kernel_core::dpop_verification_admits(
                dpop_required,
                request.dpop_proof.is_some(),
                verification.is_ok(),
            );
            if !admitted {
                let msg = match verification {
                    Ok(()) => "DPoP admission rejected a verified proof".to_string(),
                    Err(error) => error.to_string(),
                };
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "DPoP verification failed");
                return self.build_deny_response_with_metadata(
                    request,
                    &receipt_context,
                    &msg,
                    now,
                    None,
                    extra_metadata.clone(),
                );
            }
        }

        if let Err(e) = self.ensure_registered_tool_target(request) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool target not registered");
            return self.build_deny_response_with_metadata(
                request,
                &receipt_context,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(error) = self.record_observed_capability_snapshot(cap) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "failed to persist capability lineage");
            return self.build_deny_response_with_metadata(
                request,
                &receipt_context,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(error) = self.ensure_federated_receipt_persistence_ready(
            request.federated_origin_kernel_id.as_deref(),
        ) {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "federated receipt persistence unavailable pre-dispatch"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request,
                &receipt_context,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }
        if let Err(error) = self.ensure_receipt_persistence_ready() {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "receipt persistence unavailable pre-dispatch"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request,
                &receipt_context,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        let (matched_grant_index, budget_mutation) = match self.check_and_increment_budget(
            request,
            cap,
            &matching_grants,
        ) {
            Ok(result) => result,
            Err(e) => {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
                // For monetary budget exhaustion, build a denial receipt with financial metadata.
                return self.build_monetary_deny_response_with_metadata(
                    ReceiptResponseContext {
                        request,
                        evaluation_context: &receipt_context,
                        timestamp: now,
                        matched_grant_index: None,
                        extra_metadata: self.merge_budget_receipt_metadata(
                            extra_metadata.clone(),
                            self.budget_backend_receipt_metadata()?,
                        ),
                    },
                    &msg,
                    &matching_grants,
                    cap,
                );
            }
        };

        let matched_grant = matching_grants
            .iter()
            .find(|matching| matching.index == matched_grant_index)
            .map(|matching| matching.grant)
            .ok_or_else(|| {
                KernelError::Internal(format!(
                    "matched grant index {matched_grant_index} missing from candidate set"
                ))
            })?;

        let validated_governed_admission = match self.validate_governed_transaction(
            request,
            cap,
            matched_grant,
            budget_mutation.charge_result(),
            None,
            now,
        ) {
            Ok(validated_governed_admission) => validated_governed_admission,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "governed transaction denied");
                let cleanup = self.cleanup_pre_admission_budget_state(
                    request,
                    cap,
                    &budget_mutation,
                    extra_metadata.clone(),
                    None,
                );
                if let (Some(charge), Some(reverse)) =
                    (budget_mutation.charge_result(), cleanup.reverse.as_ref())
                {
                    return self.build_pre_execution_monetary_deny_response_with_metadata(
                        request,
                        &receipt_context,
                        &msg,
                        now,
                        charge,
                        reverse.committed_cost_units_after,
                        cap,
                        self.merge_budget_receipt_metadata(
                            cleanup.metadata,
                            self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ),
                        ),
                    );
                }
                return self.build_deny_response_with_metadata(
                    request,
                    &receipt_context,
                    &msg,
                    now,
                    Some(matched_grant_index),
                    cleanup.metadata,
                );
            }
        };
        receipt_context.set_governed_evidence(
            self.governed_call_chain_receipt_evidence(
                request,
                cap,
                None,
                validated_governed_admission
                    .as_ref()
                    .and_then(|admission| admission.call_chain_proof.clone()),
            ),
            validated_governed_admission
                .as_ref()
                .and_then(|admission| admission.verified_runtime_attestation.clone()),
        );

        let pre_invocation_guard_evidence = match self.run_guards(
            request,
            &cap.scope,
            session_filesystem_roots,
            Some(matched_grant_index),
        ) {
            Ok(evidence) => evidence,
            Err(e) => {
                let msg = e.error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "guard denied");
                let cleanup = self.cleanup_pre_admission_budget_state(
                    request,
                    cap,
                    &budget_mutation,
                    extra_metadata.clone(),
                    None,
                );
                if let (Some(charge), Some(reverse)) =
                    (budget_mutation.charge_result(), cleanup.reverse.as_ref())
                {
                    return self.with_pre_invocation_guard_evidence(&e.evidence, || {
                        self.build_pre_execution_monetary_deny_response_with_metadata(
                            request,
                            &receipt_context,
                            &msg,
                            now,
                            charge,
                            reverse.committed_cost_units_after,
                            cap,
                            self.merge_budget_receipt_metadata(
                                cleanup.metadata,
                                self.budget_execution_receipt_metadata(
                                    charge,
                                    Some(("reversed", reverse)),
                                ),
                            ),
                        )
                    });
                }
                return self.with_pre_invocation_guard_evidence(&e.evidence, || {
                    self.build_deny_response_with_metadata(
                        request,
                        &receipt_context,
                        &msg,
                        now,
                        Some(matched_grant_index),
                        cleanup.metadata,
                    )
                });
            }
        };

        let runtime_admission = self.run_runtime_admission_hook(
            request,
            runtime_admission_input_metadata.as_ref(),
            now,
            now_unix_ms,
            Some(matched_grant_index),
        );
        let runtime_admission_metadata = runtime_admission.metadata.clone();
        let verified_treaty_material = runtime_admission.verified_treaty_material.clone();
        let runtime_admission_receipt_metadata = match validate_runtime_admission_receipt_metadata(
            runtime_admission_metadata.as_ref(),
        ) {
            Ok(metadata) => metadata,
            Err(error) => {
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&error),
                    "runtime admission metadata rejected before dispatch"
                );
                let cleanup_metadata = runtime_admission
                    .allowed
                    .then(|| runtime_admission_metadata.clone())
                    .flatten();
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                            request,
                            evaluation_context: &receipt_context,
                            reason: "runtime admission metadata rejected",
                            timestamp: now,
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: None,
                            receipt_metadata: extra_metadata.clone(),
                            runtime_admission_metadata: cleanup_metadata,
                            budget_lease_acquired: false,
                        })
                    },
                );
            }
        };
        let receipt_metadata = merge_metadata_objects(
            merge_metadata_objects(extra_metadata.clone(), runtime_admission_receipt_metadata),
            verified_treaty_material
                .as_ref()
                .map(VerifiedFederationTreatyMaterial::receipt_metadata),
        );
        if !runtime_admission.allowed {
            let msg = runtime_admission
                .reason
                .unwrap_or_else(|| "runtime admission denied".to_string());
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "runtime admission denied");
            let cleanup = self.cleanup_pre_admission_budget_state(
                request,
                cap,
                &budget_mutation,
                receipt_metadata.clone(),
                None,
            );
            if let (Some(charge), Some(reverse)) =
                (budget_mutation.charge_result(), cleanup.reverse.as_ref())
            {
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_runtime_admission_pre_execution_monetary_deny_response_with_metadata(
                request,
                &receipt_context,
                        &msg,
                        now,
                        charge,
                        reverse.committed_cost_units_after,
                        cap,
                        self.merge_budget_receipt_metadata(
                            cleanup.metadata,
                            self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ),
                        ),
                    )
                    },
                );
            }
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_runtime_admission_deny_response_with_metadata(
                    request,
                    &receipt_context,
                    &msg,
                    now,
                    Some(matched_grant_index),
                    cleanup.metadata,
                )
            });
        }

        if request.federated_origin_kernel_id.is_some() && verified_treaty_material.is_none() {
            let msg = "verified federation treaty material missing";
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    evaluation_context: &receipt_context,
                    reason: msg,
                    timestamp: now,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: None,
                    receipt_metadata: receipt_metadata.clone(),
                    runtime_admission_metadata: runtime_admission_metadata.clone(),
                    budget_lease_acquired: false,
                })
            });
        }
        if let Some(material) = verified_treaty_material {
            receipt_context.set_verified_treaty_material(material);
        }

        // Capture whether THIS evaluation acquired a sibling-sum child-budget
        // holder lease. Every successful `admit_capability_budget` against a
        // parent takes one lease (fresh insert OR idempotent re-admit); a later
        // pre-dispatch cleanup releases exactly this evaluation's lease. The
        // reference-counted release frees the shared edge only when the last
        // holder releases, so an overlapping evaluation that still holds it
        // keeps its share and an oversubscribing sibling stays denied.
        let budget_lease_acquired = match self.admit_capability_budget(cap) {
            Ok(lease_acquired) => lease_acquired,
            Err(reason) => {
                let msg = format!("sibling-sum budget admission failed: {reason}");
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                            request,
                            evaluation_context: &receipt_context,
                            reason: &msg,
                            timestamp: now,
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: None,
                            receipt_metadata: receipt_metadata.clone(),
                            runtime_admission_metadata: runtime_admission_metadata.clone(),
                            // Admission failed: this evaluation acquired no
                            // lease, so there is nothing for cleanup to release.
                            budget_lease_acquired: false,
                        })
                    },
                );
            }
        };

        if self.execution_nonce_preflight_required(request) {
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_execution_nonce_preflight_allow_response_after_cleanup(
                    request,
                    &receipt_context,
                    now,
                    matched_grant_index,
                    cap,
                    &budget_mutation,
                    receipt_metadata.clone(),
                    runtime_admission_metadata.clone(),
                    budget_lease_acquired,
                )
            });
        }

        if !self.tool_servers.contains_key(&request.server_id) {
            let msg = KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            ))
            .to_string();
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    evaluation_context: &receipt_context,
                    reason: &msg,
                    timestamp: now,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: None,
                    receipt_metadata: receipt_metadata.clone(),
                    runtime_admission_metadata: runtime_admission_metadata.clone(),
                    budget_lease_acquired,
                })
            });
        }

        let has_monetary = budget_mutation.charge_result().is_some();
        let mut post_admission_drop_guard = PostAdmissionDropGuard::new(
            self,
            request,
            cap,
            Some(matched_grant_index),
            &budget_mutation,
            None,
            PostAdmissionReceiptContext {
                evaluation_context: receipt_context.clone(),
                extra_metadata: receipt_metadata.clone(),
                runtime_admission_metadata: runtime_admission_metadata.clone(),
                pre_invocation_guard_evidence: pre_invocation_guard_evidence.clone(),
            },
            budget_lease_acquired,
        );
        // The cleanup guard remains armed while readiness is pending. Reserve
        // single-use credentials only after the cancellable, non-consuming
        // dispatch-boundary revalidation and before the payment rail is called.
        let readiness_result = self
            .wait_for_runtime_admission_dispatch_readiness(request)
            .await;
        let readiness_waited = readiness_result.as_ref().copied().unwrap_or(false);
        let dispatch_now_unix_ms = current_unix_timestamp_ms();
        let dispatch_now = dispatch_now_unix_ms / 1000;
        let dispatch_admission_result = match readiness_result {
            Ok(readiness_waited) => {
                self.revalidate_runtime_readiness_boundary(RuntimeReadinessRevalidation {
                    request,
                    dpop_required,
                    matched_grant,
                    matched_grant_index,
                    charge_result: budget_mutation.charge_result(),
                    parent_context: None,
                    session_id,
                    session_filesystem_roots,
                    receipt_admission: &receipt_admission,
                    runtime_admission_metadata: runtime_admission_metadata.as_ref(),
                    readiness_waited,
                    force_mutable_state_revalidation: false,
                    now_unix_secs: dispatch_now,
                    now_unix_ms: dispatch_now_unix_ms,
                })
            }
            Err(error) => Err(error),
        };
        if let Err(error) = dispatch_admission_result {
            post_admission_drop_guard.disarm();
            drop(post_admission_drop_guard);
            let msg = dispatch_admission_error_reason(&error);
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "dispatch admission revalidation denied");
            let cancelled = matches!(error, KernelError::RequestCancelled { .. });
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                let cleanup = PreDispatchCleanupDeny {
                    request,
                    evaluation_context: &receipt_context,
                    reason: &msg,
                    timestamp: dispatch_now,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: None,
                    receipt_metadata: receipt_metadata.clone(),
                    runtime_admission_metadata: runtime_admission_metadata.clone(),
                    budget_lease_acquired,
                };
                if cancelled {
                    self.build_pre_dispatch_cleanup_cancelled_response(cleanup)
                } else {
                    self.build_pre_dispatch_cleanup_deny_response(cleanup)
                }
            });
        }

        let mut credential_reservation = match self.reserve_dispatch_credentials(
            request,
            cap,
            dpop_required,
            dispatch_now,
        ) {
            Ok(reservation) => reservation,
            Err(error) => {
                post_admission_drop_guard.disarm();
                drop(post_admission_drop_guard);
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "dispatch credential reservation denied");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                            request,
                            evaluation_context: &receipt_context,
                            reason: &msg,
                            timestamp: dispatch_now,
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: None,
                            receipt_metadata: receipt_metadata.clone(),
                            runtime_admission_metadata: runtime_admission_metadata.clone(),
                            budget_lease_acquired,
                        })
                    },
                );
            }
        };
        let dispatch_credentials_present =
            credential_reservation.requires_post_reservation_revalidation();
        let payment_authorization_credential_reserved =
            credential_reservation.has_payment_authorization_credential();
        if dispatch_credentials_present {
            let post_reservation_now_unix_ms = current_unix_timestamp_ms();
            let post_reservation_now = post_reservation_now_unix_ms / 1000;
            if let Err(error) =
                self.revalidate_runtime_readiness_boundary(RuntimeReadinessRevalidation {
                    request,
                    dpop_required,
                    matched_grant,
                    matched_grant_index,
                    charge_result: budget_mutation.charge_result(),
                    parent_context: None,
                    session_id,
                    session_filesystem_roots,
                    receipt_admission: &receipt_admission,
                    runtime_admission_metadata: runtime_admission_metadata.as_ref(),
                    readiness_waited,
                    force_mutable_state_revalidation: true,
                    now_unix_secs: post_reservation_now,
                    now_unix_ms: post_reservation_now_unix_ms,
                })
            {
                post_admission_drop_guard.disarm();
                drop(post_admission_drop_guard);
                let mut msg = dispatch_admission_error_reason(&error);
                if let Err(rollback_error) = credential_reservation.rollback_before_dispatch() {
                    msg = format!("{msg}; {rollback_error}");
                }
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "post-reservation dispatch revalidation denied");
                let cancelled = matches!(error, KernelError::RequestCancelled { .. });
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        let cleanup = PreDispatchCleanupDeny {
                            request,
                            evaluation_context: &receipt_context,
                            reason: &msg,
                            timestamp: post_reservation_now,
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: None,
                            receipt_metadata: receipt_metadata.clone(),
                            runtime_admission_metadata: runtime_admission_metadata.clone(),
                            budget_lease_acquired,
                        };
                        if cancelled {
                            self.build_pre_dispatch_cleanup_cancelled_response(cleanup)
                        } else {
                            self.build_pre_dispatch_cleanup_deny_response(cleanup)
                        }
                    },
                );
            }
        }

        let mut payment_credential_disposition = PaymentCredentialDisposition::NonePresent;
        let payment_authorization = match self.authorize_payment_if_needed(
            request,
            budget_mutation.charge_result(),
            payment_authorization_credential_reserved,
        ) {
            Ok(Some(authorization)) => {
                // A retry after any acknowledged authorization could create a
                // second rail hold, even if later cleanup releases this one.
                match credential_reservation.retain_if_dropped() {
                    Ok(disposition) => payment_credential_disposition = disposition,
                    Err(error) => {
                        payment_credential_disposition =
                            PaymentCredentialDisposition::RetentionOutcomeUnknown;
                        let msg = format!(
                            "dispatch credential retention failed after payment authorization: {error}"
                        );
                        post_admission_drop_guard.disarm();
                        drop(post_admission_drop_guard);
                        warn!(request_id = %request.request_id, reason = %redacted!(&msg), "payment credential retention denied");
                        return self.with_pre_invocation_guard_evidence(
                            &pre_invocation_guard_evidence,
                            || {
                                self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                                    PreDispatchCleanupDeny {
                                        request,
                                        evaluation_context: &receipt_context,
                                        reason: &msg,
                                        timestamp: dispatch_now,
                                        matched_grant_index,
                                        cap,
                                        budget_mutation: &budget_mutation,
                                        payment_authorization: Some(&authorization),
                                        receipt_metadata: receipt_metadata.clone(),
                                        runtime_admission_metadata: runtime_admission_metadata
                                            .clone(),
                                        budget_lease_acquired,
                                    },
                                    payment_credential_disposition,
                                )
                            },
                        );
                    }
                }
                Some(authorization)
            }
            Ok(None) => None,
            Err(error) => {
                let outcome_unknown_reason = error.outcome_unknown_reason().map(str::to_owned);
                let mut msg = format!("payment authorization failed: {error}");
                if outcome_unknown_reason.is_some() {
                    payment_credential_disposition = match credential_reservation.commit() {
                        Ok(disposition) => disposition,
                        Err(retention_error) => {
                            msg = format!("{msg}; {retention_error}");
                            PaymentCredentialDisposition::RetentionOutcomeUnknown
                        }
                    };
                } else if let Err(rollback_error) =
                    credential_reservation.rollback_before_dispatch()
                {
                    msg = format!("{msg}; {rollback_error}");
                    payment_credential_disposition =
                        PaymentCredentialDisposition::RetentionOutcomeUnknown;
                }
                post_admission_drop_guard.disarm();
                drop(post_admission_drop_guard);
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "payment denied");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        let denial = PreDispatchCleanupDeny {
                            request,
                            evaluation_context: &receipt_context,
                            reason: &msg,
                            timestamp: dispatch_now,
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: None,
                            receipt_metadata: receipt_metadata.clone(),
                            runtime_admission_metadata: runtime_admission_metadata.clone(),
                            budget_lease_acquired,
                        };
                        if let Some(reason) = outcome_unknown_reason.as_deref() {
                            self.build_payment_authorization_outcome_unknown_deny_response(
                                denial,
                                reason,
                                payment_credential_disposition,
                            )
                        } else if payment_credential_disposition
                            == PaymentCredentialDisposition::RetentionOutcomeUnknown
                        {
                            self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                                denial,
                                payment_credential_disposition,
                            )
                        } else {
                            self.build_pre_dispatch_cleanup_deny_response(denial)
                        }
                    },
                );
            }
        };
        post_admission_drop_guard.set_payment_authorization(payment_authorization.as_ref());
        post_admission_drop_guard
            .set_payment_credential_disposition(payment_credential_disposition);

        let dispatch_now_unix_ms = current_unix_timestamp_ms();
        let dispatch_now = dispatch_now_unix_ms / 1000;
        let final_dispatch_admission =
            self.revalidate_runtime_readiness_boundary(RuntimeReadinessRevalidation {
                request,
                dpop_required,
                matched_grant,
                matched_grant_index,
                charge_result: budget_mutation.charge_result(),
                parent_context: None,
                session_id,
                session_filesystem_roots,
                receipt_admission: &receipt_admission,
                runtime_admission_metadata: runtime_admission_metadata.as_ref(),
                readiness_waited,
                force_mutable_state_revalidation: payment_authorization.is_some(),
                now_unix_secs: dispatch_now,
                now_unix_ms: dispatch_now_unix_ms,
            });
        if let Err(error) = final_dispatch_admission {
            post_admission_drop_guard.disarm();
            drop(post_admission_drop_guard);
            let mut msg = dispatch_admission_error_reason(&error);
            if payment_authorization.is_none() {
                if let Err(rollback_error) = credential_reservation.rollback_before_dispatch() {
                    msg = format!("{msg}; {rollback_error}");
                }
            } else {
                payment_credential_disposition = match credential_reservation.commit() {
                    Ok(disposition) => disposition,
                    Err(retention_error) => {
                        msg = format!("{msg}; {retention_error}");
                        PaymentCredentialDisposition::RetentionOutcomeUnknown
                    }
                };
            }
            let cancelled = matches!(error, KernelError::RequestCancelled { .. });
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                let cleanup = PreDispatchCleanupDeny {
                    request,
                    evaluation_context: &receipt_context,
                    reason: &msg,
                    timestamp: dispatch_now,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: payment_authorization.as_ref(),
                    receipt_metadata: receipt_metadata.clone(),
                    runtime_admission_metadata: runtime_admission_metadata.clone(),
                    budget_lease_acquired,
                };
                if cancelled {
                    self.build_pre_dispatch_cleanup_cancelled_response_with_credentials(
                        cleanup,
                        payment_credential_disposition,
                    )
                } else {
                    self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                        cleanup,
                        payment_credential_disposition,
                    )
                }
            });
        }
        if let Err(error) =
            self.mark_session_request_dispatch_started(session_id, &request.request_id)
        {
            post_admission_drop_guard.disarm();
            drop(post_admission_drop_guard);
            let mut msg = error.to_string();
            if payment_authorization.is_some() {
                payment_credential_disposition = match credential_reservation.commit() {
                    Ok(disposition) => disposition,
                    Err(retention_error) => {
                        msg = format!("{msg}; {retention_error}");
                        PaymentCredentialDisposition::RetentionOutcomeUnknown
                    }
                };
            } else if let Err(rollback_error) = credential_reservation.rollback_before_dispatch() {
                msg = format!("{msg}; {rollback_error}");
            }
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_cancelled_response_with_credentials(
                    PreDispatchCleanupDeny {
                        request,
                        evaluation_context: &receipt_context,
                        reason: &msg,
                        timestamp: current_unix_timestamp(),
                        matched_grant_index,
                        cap,
                        budget_mutation: &budget_mutation,
                        payment_authorization: payment_authorization.as_ref(),
                        receipt_metadata: receipt_metadata.clone(),
                        runtime_admission_metadata: runtime_admission_metadata.clone(),
                        budget_lease_acquired,
                    },
                    payment_credential_disposition,
                )
            });
        }
        if let Err(error) = credential_reservation.retain_if_dropped() {
            payment_credential_disposition = PaymentCredentialDisposition::RetentionOutcomeUnknown;
            post_admission_drop_guard.disarm();
            drop(post_admission_drop_guard);
            let msg = format!("dispatch credential retention failed before dispatch: {error}");
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                    PreDispatchCleanupDeny {
                        request,
                        evaluation_context: &receipt_context,
                        reason: &msg,
                        timestamp: current_unix_timestamp(),
                        matched_grant_index,
                        cap,
                        budget_mutation: &budget_mutation,
                        payment_authorization: payment_authorization.as_ref(),
                        receipt_metadata: receipt_metadata.clone(),
                        runtime_admission_metadata: runtime_admission_metadata.clone(),
                        budget_lease_acquired,
                    },
                    payment_credential_disposition,
                )
            });
        }
        let tool_started_at = Instant::now();
        post_admission_drop_guard.mark_dispatch_started();
        let dispatch_result = self
            .dispatch_tool_call_with_cost_after_nonce_check(request, has_monetary)
            .await;
        let (tool_output, reported_cost) = match dispatch_result {
            Ok(result) => {
                let _retention_disposition = credential_reservation.commit();
                result
            }
            Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                let _retention_disposition = credential_reservation.commit();
                let reason =
                    format!("URL elicitation requested after tool-server dispatch began: {error}");
                let retained = self.retain_post_dispatch_state(
                    receipt_metadata.clone(),
                    runtime_admission_metadata.clone(),
                    budget_mutation.charge_result(),
                    None,
                    payment_authorization.as_ref(),
                );
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "tool call requested URL elicitation after dispatch"
                );
                let result =
                    self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                        self.build_incomplete_response_with_output_and_metadata(
                            ReceiptResponseContext {
                                request,
                                evaluation_context: &receipt_context,
                                timestamp: now,
                                matched_grant_index: Some(matched_grant_index),
                                extra_metadata: retained,
                            },
                            None,
                            &reason,
                        )
                    });
                return post_admission_drop_guard.finish_terminal(result);
            }
            Err(KernelError::RequestCancelled { reason, .. }) => {
                let _retention_disposition = credential_reservation.commit();
                let retained = self.retain_post_dispatch_state(
                    receipt_metadata.clone(),
                    runtime_admission_metadata.clone(),
                    budget_mutation.charge_result(),
                    None,
                    payment_authorization.as_ref(),
                );
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "tool call cancelled"
                );
                let result =
                    self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                        self.build_cancelled_response_with_metadata(
                            request,
                            &receipt_context,
                            &reason,
                            now,
                            Some(matched_grant_index),
                            retained,
                        )
                    });
                return post_admission_drop_guard.finish_terminal(result);
            }
            Err(KernelError::RequestIncomplete(reason)) => {
                let _retention_disposition = credential_reservation.commit();
                let retained = self.retain_post_dispatch_state(
                    receipt_metadata.clone(),
                    runtime_admission_metadata.clone(),
                    budget_mutation.charge_result(),
                    None,
                    payment_authorization.as_ref(),
                );
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "tool call incomplete"
                );
                let result =
                    self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                        self.build_incomplete_response_with_output_and_metadata(
                            ReceiptResponseContext {
                                request,
                                evaluation_context: &receipt_context,
                                timestamp: now,
                                matched_grant_index: Some(matched_grant_index),
                                extra_metadata: retained,
                            },
                            None,
                            &reason,
                        )
                    });
                return post_admission_drop_guard.finish_terminal(result);
            }
            Err(e) => {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool server error");
                let _retention_disposition = credential_reservation.commit();
                let retained = self.retain_post_dispatch_state(
                    receipt_metadata.clone(),
                    runtime_admission_metadata.clone(),
                    budget_mutation.charge_result(),
                    None,
                    payment_authorization.as_ref(),
                );
                let result =
                    self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                        self.build_deny_response_with_metadata(
                            request,
                            &receipt_context,
                            &msg,
                            now,
                            Some(matched_grant_index),
                            retained,
                        )
                    });
                return post_admission_drop_guard.finish_terminal(result);
            }
        };
        let result =
            self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.finalize_budgeted_tool_output_with_cost_and_metadata(
                    request,
                    &receipt_context,
                    tool_output,
                    tool_started_at.elapsed(),
                    now,
                    matched_grant_index,
                    FinalizeToolOutputCostContext {
                        charge_result: budget_mutation.charge_result().cloned(),
                        reported_cost,
                        payment_authorization,
                        cap,
                        runtime_admission_metadata,
                        budget_reconcile_decision: post_admission_drop_guard
                            .budget_reconcile_decision(),
                    },
                    receipt_metadata,
                )
            });
        post_admission_drop_guard.finish_terminal(result)
    }
}
