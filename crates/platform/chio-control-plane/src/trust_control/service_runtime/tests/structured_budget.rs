use super::super::super::*;
use super::super::budget::build_remote_budget_store;
use super::super::client::build_client;
use super::support::{assert_json_post, assert_json_post_omits, StaticResponseServer};

const ARTIFACT_DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const APPROVAL_SET_DIGEST: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn revocation_observation(commit_index: u64) -> RevocationCommitMetadata {
    RevocationCommitMetadata {
        authority: BudgetEventAuthority {
            authority_id: "budget-authority".to_string(),
            lease_id: "budget-lease".to_string(),
            lease_epoch: 1,
        },
        guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
        commit_index,
    }
}

fn composite_request() -> Result<BudgetAuthorizeHoldRequest, Box<dyn std::error::Error>> {
    Ok(BudgetAuthorizeHoldRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        max_invocations: Some(2),
        invocation_quotas: vec![BudgetInvocationQuota {
            key: BudgetQuotaKey::grant("cap-composite", 0),
            max_invocations: 2,
        }],
        cumulative_approval: None,
        admission_binding: Some(BudgetAdmissionBinding {
            operation_id: "op-composite".to_string(),
            revocation_set: CanonicalRevocationSet::canonicalize(
                vec!["cap-composite".to_string()],
            )?,
            authorization_artifact_digests: vec![ARTIFACT_DIGEST_A.to_string()],
            last_observed_revocation: Some(revocation_observation(11)),
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }),
        requested_exposure_units: 100,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(500),
        hold_id: Some("hold-composite".to_string()),
        event_id: Some("hold-composite:authorize".to_string()),
        authority: None,
    })
}

fn structured_metadata(event_id: &str, commit_index: u64) -> BudgetCommitMetadata {
    BudgetCommitMetadata {
        authority: Some(BudgetEventAuthority {
            authority_id: "budget-authority".to_string(),
            lease_id: "budget-lease".to_string(),
            lease_epoch: 1,
        }),
        guarantee_level: BudgetGuaranteeLevel::HaLinearizable,
        budget_profile: chio_kernel::budget_store::BudgetAuthorityProfile::AuthoritativeHoldEvent,
        metering_profile:
            chio_kernel::budget_store::BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
        budget_commit_index: Some(commit_index),
        event_id: Some(event_id.to_string()),
        recorded_at_unix_seconds: Some(commit_index),
    }
}

fn structured_capture_body(
    projection: StructuredBudgetMutationResponse,
    decision: CaptureInvocationDecision,
) -> Result<String, Box<dyn std::error::Error>> {
    let expected = match decision {
        CaptureInvocationDecision::Captured => StructuredBudgetMutationDecisionView::Applied,
        CaptureInvocationDecision::AlreadyCaptured => {
            StructuredBudgetMutationDecisionView::AlreadyApplied
        }
    };
    if projection.decision != expected {
        return Err(std::io::Error::other("capture decision mismatch").into());
    }
    Ok(serde_json::to_string(&projection)?)
}

fn structured_reduce_body(
    projection: StructuredBudgetMutationResponse,
    _released_exposure_units: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(serde_json::to_string(&projection)?)
}

fn structured_reverse_body(
    projection: StructuredBudgetMutationResponse,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(serde_json::to_string(&projection)?)
}

fn structured_authorize_body(
    request: &BudgetAuthorizeHoldRequest,
) -> Result<String, Box<dyn std::error::Error>> {
    let grant_index = u32::try_from(request.grant_index)?;
    let quota = request.invocation_quotas.first().cloned().or_else(|| {
        request
            .max_invocations
            .map(|max_invocations| BudgetInvocationQuota {
                key: BudgetQuotaKey::grant(request.capability_id.clone(), grant_index),
                max_invocations,
            })
    });
    let quota = quota.ok_or_else(|| std::io::Error::other("missing test quota"))?;
    let response = StructuredBudgetAuthorizeResponse::from_core(
        request.capability_id.clone(),
        u32::try_from(request.grant_index)?,
        request
            .hold_id
            .clone()
            .ok_or_else(|| std::io::Error::other("missing test hold"))?,
        request
            .event_id
            .clone()
            .ok_or_else(|| std::io::Error::other("missing test event"))?,
        BudgetAuthorizeHoldDecision::Authorized(AuthorizedBudgetHold {
            hold_id: request.hold_id.clone(),
            admission_binding: request.admission_binding.clone(),
            authorized_exposure_units: request.requested_exposure_units,
            committed_cost_units_after: 100,
            invocation_count_after: 1,
            invocation_quota_usages: vec![BudgetInvocationQuotaUsage {
                quota,
                reserved_invocations: 1,
                captured_invocations: 0,
            }],
            cumulative_approval: None,
            invocation_state: BudgetInvocationState::Authorized,
            monetary_state: BudgetMonetaryState::Exposed,
            metadata: structured_metadata("hold-composite:authorize", 7),
        }),
        StructuredBudgetUsageView {
            capability_id: request.capability_id.clone(),
            grant_index: 0,
            invocation_count: 1,
            updated_at: 10,
            seq: Some(7),
            total_cost_exposed: 100,
            total_cost_realized_spend: 0,
        },
    )
    .map_err(std::io::Error::other)?;
    Ok(serde_json::to_string(&response)?)
}

fn cumulative_usage(
    operation_id: &str,
    state: BudgetCumulativeApprovalState,
) -> BudgetCumulativeApprovalUsage {
    let amount = |units| chio_core::capability::scope::MonetaryAmount {
        units,
        currency: "USD".to_string(),
    };
    BudgetCumulativeApprovalUsage {
        operation_id: operation_id.to_string(),
        account_key: BudgetCumulativeApprovalAccountKey {
            authority_id: "approval-authority".to_string(),
            owner_id: "approval-owner".to_string(),
            approval_budget_id: "approval-budget".to_string(),
            approval_budget_epoch: 1,
            root_grant_hash: "root-grant".to_string(),
            delegation_root_id: None,
            root_binding_digest: None,
            currency: "USD".to_string(),
        },
        authority_threshold: amount(100),
        effective_threshold: amount(80),
        requested_authorized: amount(25),
        reserved_authorized_after: amount(25),
        captured_authorized_after: amount(0),
        state,
        version: 1,
    }
}

fn structured_denied_authorize_body(
    request: &BudgetAuthorizeHoldRequest,
) -> Result<String, Box<dyn std::error::Error>> {
    let quota = request
        .invocation_quotas
        .first()
        .cloned()
        .ok_or_else(|| std::io::Error::other("missing test quota"))?;
    let event_id = request
        .event_id
        .clone()
        .ok_or_else(|| std::io::Error::other("missing test event"))?;
    let response = StructuredBudgetAuthorizeResponse::from_core(
        request.capability_id.clone(),
        u32::try_from(request.grant_index)?,
        request
            .hold_id
            .clone()
            .ok_or_else(|| std::io::Error::other("missing test hold"))?,
        event_id.clone(),
        BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
            hold_id: request.hold_id.clone(),
            admission_binding: request.admission_binding.clone(),
            attempted_exposure_units: request.requested_exposure_units,
            committed_cost_units_after: 0,
            invocation_count_after: 1,
            invocation_quota_usages: vec![BudgetInvocationQuotaUsage {
                quota,
                reserved_invocations: 0,
                captured_invocations: 1,
            }],
            cumulative_approval: None,
            invocation_state: BudgetInvocationState::Denied,
            monetary_state: BudgetMonetaryState::None,
            metadata: structured_metadata(&event_id, 7),
        }),
        StructuredBudgetUsageView {
            capability_id: request.capability_id.clone(),
            grant_index: u32::try_from(request.grant_index)?,
            invocation_count: 1,
            updated_at: 10,
            seq: None,
            total_cost_exposed: 0,
            total_cost_realized_spend: 0,
        },
    )
    .map_err(std::io::Error::other)?;
    Ok(serde_json::to_string(&response)?)
}

fn structured_reconcile_body(
    request: &BudgetAuthorizeHoldRequest,
) -> Result<String, Box<dyn std::error::Error>> {
    let projection = StructuredBudgetMutationResponse::from_core(
        request.capability_id.clone(),
        0,
        "hold-composite".to_string(),
        "hold-composite:reconcile".to_string(),
        StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied,
        BudgetHoldMutationDecision {
            hold_id: request.hold_id.clone(),
            admission_binding: request.admission_binding.clone(),
            exposure_units: 100,
            realized_spend_units: 75,
            committed_cost_units_after: 75,
            invocation_count_after: 1,
            invocation_quota_usages: vec![BudgetInvocationQuotaUsage {
                quota: request.invocation_quotas[0].clone(),
                reserved_invocations: 0,
                captured_invocations: 1,
            }],
            cumulative_approval: None,
            invocation_state: BudgetInvocationState::Captured,
            monetary_state: BudgetMonetaryState::Reconciled,
            metadata: structured_metadata("hold-composite:reconcile", 8),
        },
        BudgetUsageRecord {
            capability_id: request.capability_id.clone(),
            grant_index: 0,
            invocation_count: 1,
            updated_at: 11,
            seq: 8,
            total_cost_exposed: 0,
            total_cost_realized_spend: 75,
        }
        .into(),
    )
    .map_err(std::io::Error::other)?;
    structured_reduce_body(projection, 25)
}

fn structured_mutation_body(
    request: &BudgetAuthorizeHoldRequest,
    request_event_id: &str,
    decision: StructuredBudgetMutationDecisionView,
    invocation_state: BudgetInvocationState,
    monetary_state: BudgetMonetaryState,
    exposure_units: u64,
    realized_spend_units: u64,
    committed_cost_units_after: u64,
    invocation_count_after: u32,
    reserved_invocations: u32,
    captured_invocations: u32,
    usage_seq: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = StructuredBudgetMutationResponse::from_core(
        request.capability_id.clone(),
        u32::try_from(request.grant_index)?,
        request
            .hold_id
            .clone()
            .ok_or_else(|| std::io::Error::other("missing test hold"))?,
        request_event_id.to_string(),
        decision,
        BudgetHoldMutationDecision {
            hold_id: request.hold_id.clone(),
            admission_binding: request.admission_binding.clone(),
            exposure_units,
            realized_spend_units,
            committed_cost_units_after,
            invocation_count_after,
            invocation_quota_usages: vec![BudgetInvocationQuotaUsage {
                quota: request.invocation_quotas[0].clone(),
                reserved_invocations,
                captured_invocations,
            }],
            cumulative_approval: None,
            invocation_state,
            monetary_state,
            metadata: structured_metadata(request_event_id, usage_seq),
        },
        BudgetUsageRecord {
            capability_id: request.capability_id.clone(),
            grant_index: u32::try_from(request.grant_index)?,
            invocation_count: invocation_count_after,
            updated_at: 11,
            seq: usage_seq,
            total_cost_exposed: if matches!(monetary_state, BudgetMonetaryState::Exposed) {
                exposure_units
            } else {
                0
            },
            total_cost_realized_spend: if matches!(
                monetary_state,
                BudgetMonetaryState::Reconciled | BudgetMonetaryState::Captured
            ) {
                realized_spend_units
            } else {
                0
            },
        }
        .into(),
    )
    .map_err(std::io::Error::other)?;
    Ok(serde_json::to_string(&response)?)
}

#[test]
fn remote_budget_store_round_trips_exact_structured_authorization(
) -> Result<(), Box<dyn std::error::Error>> {
    let request = composite_request()?;
    let body = structured_authorize_body(&request)?;
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store = build_remote_budget_store(&server.url, "secret")?;

    let decision = store.authorize_budget_hold(request)?;
    let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
        return Err(std::io::Error::other("structured authorization was not authorized").into());
    };
    assert_eq!(authorized.invocation_quota_usages.len(), 1);
    assert_eq!(
        authorized
            .admission_binding
            .as_ref()
            .and_then(|binding| binding.last_observed_revocation.as_ref())
            .map(|observation| observation.commit_index),
        Some(11)
    );
    assert_eq!(
        authorized.metadata.guarantee_level,
        BudgetGuaranteeLevel::AdvisoryPosthoc
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_json_post(
        &requests[0],
        STRUCTURED_BUDGET_AUTHORIZE_PATH,
        &[
            "\"schema\":\"chio.structured-budget-request.v1\"",
            "\"authorizationArtifactDigests\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]",
            "\"lastObservedRevocation\":{",
            "\"commitIndex\":11",
        ],
    );
    Ok(())
}

#[test]
fn remote_budget_store_looks_up_exact_cumulative_operation_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    let usage = cumulative_usage("op-lookup", BudgetCumulativeApprovalState::Authorized);
    let response = StructuredBudgetCumulativeOperationResponse {
        schema: STRUCTURED_BUDGET_RESPONSE_SCHEMA.to_string(),
        operation_id: usage.operation_id.clone(),
        usage: Some(usage.clone().into()),
        approval_set_digest: Some(APPROVAL_SET_DIGEST.to_string()),
        metadata: Some(structured_metadata("op-lookup:approval", 12).into()),
    };
    let server = StaticResponseServer::spawn(
        200,
        &serde_json::to_string(&response)?,
        "application/json",
        2,
    );
    let store = build_remote_budget_store(&server.url, "secret")?;

    assert_eq!(
        store.get_cumulative_approval_operation_usage("op-lookup")?,
        Some(usage.clone())
    );
    assert_eq!(
        store.get_cumulative_approval_operation_usage("op-lookup")?,
        Some(usage)
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    for request in &requests {
        assert_json_post(
            request,
            STRUCTURED_BUDGET_CUMULATIVE_OPERATION_PATH,
            &[
                "\"schema\":\"chio.structured-budget-request.v1\"",
                "\"operationId\":\"op-lookup\"",
            ],
        );
    }
    Ok(())
}

#[test]
fn advisory_remote_authority_rejects_unescrowed_family_mutations_before_network(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = StaticResponseServer::spawn(500, "{}", "application/json", 0);
    let store = build_remote_budget_store(&server.url, "secret")?;

    let mut family = composite_request()?;
    family.max_invocations = None;
    family.invocation_quotas = vec![BudgetInvocationQuota {
        key: BudgetQuotaKey {
            profile: BudgetQuotaProfile::AggregateFamilyInvocation,
            owner_id: "family:composite".to_string(),
            grant_index: None,
        },
        max_invocations: 2,
    }];
    assert!(store.authorize_budget_hold(family).is_err_and(|error| error
        .to_string()
        .contains("without a modeled partition escrow profile")));

    let mut cumulative = composite_request()?;
    let usage = cumulative_usage(
        "op-composite",
        BudgetCumulativeApprovalState::PendingApproval,
    );
    cumulative.cumulative_approval = Some(BudgetCumulativeApprovalRequest {
        operation_id: usage.operation_id,
        account_key: usage.account_key,
        authority_threshold: usage.authority_threshold,
        effective_threshold: usage.effective_threshold,
        requested_authorized: usage.requested_authorized,
    });
    assert!(store
        .authorize_budget_hold(cumulative)
        .is_err_and(|error| error
            .to_string()
            .contains("without a modeled partition escrow profile")));

    let binding = composite_request()?
        .admission_binding
        .ok_or_else(|| std::io::Error::other("missing test admission binding"))?;
    assert!(store
        .authorize_cumulative_approval(BudgetAuthorizeCumulativeApprovalRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            operation_id: "op-composite".to_string(),
            hold_id: "hold-composite".to_string(),
            admission_binding: binding,
            approval_set_digest: APPROVAL_SET_DIGEST.to_string(),
            event_id: "hold-composite:approve".to_string(),
            authority: None,
        })
        .is_err_and(|error| error
            .to_string()
            .contains("without a modeled partition escrow profile")));
    assert!(server.requests().is_empty());
    Ok(())
}

#[test]
fn structured_authorization_normalizes_legacy_max_invocations_into_grant_quota(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut request = composite_request()?;
    request.invocation_quotas.clear();
    let body = structured_authorize_body(&request)?;
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store = build_remote_budget_store(&server.url, "secret")?;
    let BudgetAuthorizeHoldDecision::Authorized(authorized) =
        store.authorize_budget_hold(request)?
    else {
        return Err(std::io::Error::other("normalized authorization was denied").into());
    };
    assert_eq!(authorized.invocation_quota_usages.len(), 1);
    assert_eq!(
        authorized.invocation_quota_usages[0].quota.key,
        BudgetQuotaKey::grant("cap-composite", 0)
    );
    assert_json_post(
        &server.requests()[0],
        STRUCTURED_BUDGET_AUTHORIZE_PATH,
        &["\"invocationQuotas\":[{", "\"maxInvocations\":2"],
    );
    Ok(())
}

#[test]
fn structured_quota_exhaustion_denial_does_not_invent_usage_sequence(
) -> Result<(), Box<dyn std::error::Error>> {
    let request = composite_request()?;
    let body = structured_denied_authorize_body(&request)?;
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret")?,
        cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
    };
    store.cache_usage("cap-composite", 0, Some(5), Some(1), Some(0), Some(0))?;
    let BudgetAuthorizeHoldDecision::Denied(denied) = store.authorize_budget_hold(request)? else {
        return Err(std::io::Error::other("quota exhaustion was not denied").into());
    };
    assert_eq!(denied.invocation_count_after, 1);
    assert_eq!(denied.invocation_quota_usages[0].captured_invocations, 1);
    let usage = store
        .cached_usage("cap-composite", 0)
        .ok_or_else(|| std::io::Error::other("seeded usage disappeared"))?;
    assert_eq!(usage.seq, 5);
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 0);

    let mut invented: serde_json::Value =
        serde_json::from_str(&structured_denied_authorize_body(&composite_request()?)?)?;
    invented["usage"]["seq"] = serde_json::json!(7);
    let server = StaticResponseServer::spawn(200, &invented.to_string(), "application/json", 1);
    let store = build_remote_budget_store(&server.url, "secret")?;
    assert!(store.authorize_budget_hold(composite_request()?).is_err());
    Ok(())
}

#[test]
fn structured_remote_downgrades_unverified_partition_escrow_claim(
) -> Result<(), Box<dyn std::error::Error>> {
    let request = composite_request()?;
    let mut response: StructuredBudgetAuthorizeResponse =
        serde_json::from_str(&structured_authorize_body(&request)?)?;
    response.projection.metadata.guarantee_level = "partition_escrowed".to_string();
    response.projection_contract = StructuredBudgetProjectionContractView::from_projection(
        &response.projection,
        response
            .usage
            .as_ref()
            .ok_or_else(|| std::io::Error::other("missing usage"))?,
    )?;
    let server = StaticResponseServer::spawn(
        200,
        &serde_json::to_string(&response)?,
        "application/json",
        1,
    );
    let store = build_remote_budget_store(&server.url, "secret")?;

    let decision = store.authorize_budget_hold(request)?;
    let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
        return Err(std::io::Error::other("structured authorization was not authorized").into());
    };
    assert_eq!(
        authorized.metadata.guarantee_level,
        BudgetGuaranteeLevel::AdvisoryPosthoc
    );
    assert_eq!(
        store.budget_guarantee_level(),
        BudgetGuaranteeLevel::AdvisoryPosthoc
    );
    Ok(())
}

#[test]
fn structured_authorization_rejects_substitution_before_cache_mutation(
) -> Result<(), Box<dyn std::error::Error>> {
    for (pointer, replacement) in [
        (
            "/projection/admissionBinding/authorizationArtifactDigests",
            serde_json::json!(["artifact-substituted"]),
        ),
        ("/projection/monetaryState", serde_json::json!("captured")),
        ("/usage/seq", serde_json::json!(8)),
    ] {
        let request = composite_request()?;
        let mut body: serde_json::Value =
            serde_json::from_str(&structured_authorize_body(&request)?)?;
        *body
            .pointer_mut(pointer)
            .ok_or_else(|| std::io::Error::other("missing authorization response field"))? =
            replacement;
        let server = StaticResponseServer::spawn(200, &body.to_string(), "application/json", 1);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
        };
        store.cache_usage("cap-composite", 0, Some(5), Some(5), Some(50), Some(25))?;

        assert!(store.authorize_budget_hold(request).is_err());
        let cached = store
            .cached_usage("cap-composite", 0)
            .ok_or_else(|| std::io::Error::other("missing cache"))?;
        assert_eq!(cached.seq, 5);
        assert_eq!(cached.invocation_count, 5);
        assert_eq!(cached.total_cost_exposed, 50);
        assert_eq!(cached.total_cost_realized_spend, 25);
    }
    Ok(())
}

#[test]
fn structured_remote_does_not_fallback_to_legacy_on_mixed_version_peer(
) -> Result<(), Box<dyn std::error::Error>> {
    let server =
        StaticResponseServer::spawn(404, "{\"error\":\"unknown route\"}", "application/json", 1);
    let store = build_remote_budget_store(&server.url, "secret")?;
    let result = store.authorize_budget_hold(composite_request()?);
    assert!(result.is_err());
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_json_post(&requests[0], STRUCTURED_BUDGET_AUTHORIZE_PATH, &[]);
    Ok(())
}

#[test]
fn all_rich_lifecycle_methods_fail_before_mutation_after_restart_on_old_server(
) -> Result<(), Box<dyn std::error::Error>> {
    let server =
        StaticResponseServer::spawn(404, "{\"error\":\"unknown route\"}", "application/json", 7);
    let store = build_remote_budget_store(&server.url, "secret")?;

    assert!(store
        .capture_budget_hold(BudgetCaptureHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 75,
            hold_id: Some("hold-composite".to_string()),
            event_id: Some("hold-composite:capture-spend".to_string()),
            authority: None,
        })
        .is_err());
    assert!(store
        .reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            reversed_exposure_units: 100,
            hold_id: Some("hold-composite".to_string()),
            event_id: Some("hold-composite:fenced-reverse".to_string()),
            expected_cumulative_approval_state: Some(
                BudgetCumulativeApprovalState::PendingApproval,
            ),
            authority: None,
        })
        .is_err());
    assert!(store
        .cancel_captured_before_dispatch(BudgetCancelCapturedBeforeDispatchRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            hold_id: "hold-composite".to_string(),
            event_id: "hold-composite:cancel-captured".to_string(),
            authority: None,
        })
        .is_err());
    assert!(store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            hold_id: "hold-composite".to_string(),
            event_id: "hold-composite:capture-invocation".to_string(),
            trusted_time: None,
            authority: None,
        })
        .is_err());
    assert!(store
        .reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            reversed_exposure_units: 100,
            hold_id: Some("hold-composite".to_string()),
            event_id: Some("hold-composite:reverse".to_string()),
            expected_cumulative_approval_state: None,
            authority: None,
        })
        .is_err());
    assert!(store
        .release_budget_hold(BudgetReleaseHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            released_exposure_units: 25,
            hold_id: Some("hold-composite".to_string()),
            event_id: Some("hold-composite:release".to_string()),
            authority: None,
        })
        .is_err());
    assert!(store
        .reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 75,
            hold_id: Some("hold-composite".to_string()),
            event_id: Some("hold-composite:reconcile".to_string()),
            authority: None,
        })
        .is_err());

    let requests = server.requests();
    assert_eq!(requests.len(), 7);
    assert_json_post(
        &requests[0],
        STRUCTURED_BUDGET_CAPTURE_SPEND_PATH,
        &["\"schema\":\"chio.structured-budget-request.v1\""],
    );
    assert_json_post(
        &requests[1],
        STRUCTURED_BUDGET_FENCED_REVERSE_PATH,
        &["\"expectedCumulativeApprovalState\":\"pending_approval\""],
    );
    assert_json_post(&requests[2], STRUCTURED_BUDGET_CANCEL_CAPTURED_PATH, &[]);
    assert_json_post(
        &requests[3],
        STRUCTURED_BUDGET_CAPTURE_INVOCATION_PATH,
        &["\"schema\":\"chio.structured-budget-request.v1\""],
    );
    assert_json_post(
        &requests[4],
        STRUCTURED_BUDGET_FENCED_REVERSE_PATH,
        &["\"expectedCumulativeApprovalState\":null"],
    );
    assert_json_post(
        &requests[5],
        STRUCTURED_BUDGET_RELEASE_PATH,
        &["\"releasedExposureUnits\":25"],
    );
    assert_json_post(
        &requests[6],
        STRUCTURED_BUDGET_RECONCILE_PATH,
        &["\"realizedSpendUnits\":75"],
    );
    Ok(())
}

#[test]
fn structured_reconcile_uses_durable_server_state_after_client_restart(
) -> Result<(), Box<dyn std::error::Error>> {
    let request = composite_request()?;
    let body = structured_reconcile_body(&request)?;
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let restarted_store = build_remote_budget_store(&server.url, "secret")?;

    let mutation = restarted_store.reconcile_budget_hold(BudgetReconcileHoldRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 75,
        hold_id: Some("hold-composite".to_string()),
        event_id: Some("hold-composite:reconcile".to_string()),
        authority: None,
    })?;
    assert_eq!(mutation.invocation_state, BudgetInvocationState::Captured);
    assert_eq!(mutation.monetary_state, BudgetMonetaryState::Reconciled);
    assert_eq!(
        mutation.metadata.guarantee_level,
        BudgetGuaranteeLevel::AdvisoryPosthoc
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_json_post(
        &requests[0],
        STRUCTURED_BUDGET_RECONCILE_PATH,
        &[
            "\"exposedCostUnits\":100",
            "\"realizedSpendUnits\":75",
            "\"schema\":\"chio.structured-budget-request.v1\"",
        ],
    );
    assert_json_post_omits(
        &requests[0],
        STRUCTURED_BUDGET_RECONCILE_PATH,
        &["lifecycleOperation"],
    );
    Ok(())
}

#[test]
fn remote_budget_store_rejects_invalid_composite_identity_before_network_io(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = build_remote_budget_store("http://127.0.0.1:1", "secret")?;
    let partial_identity = store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        max_invocations: None,
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 10,
        max_cost_per_invocation: Some(10),
        max_total_cost_units: Some(10),
        hold_id: Some("hold-composite".to_string()),
        event_id: None,
        authority: None,
    });
    assert!(partial_identity
        .as_ref()
        .is_err_and(|error| error.to_string().contains("non-empty identifiers")));

    let empty_capture = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        hold_id: "hold-composite".to_string(),
        event_id: String::new(),
        trusted_time: None,
        authority: None,
    });
    assert!(empty_capture
        .as_ref()
        .is_err_and(|error| error.to_string().contains("non-empty hold_id and event_id")));

    let mut invalid_binding = composite_request()?;
    invalid_binding
        .admission_binding
        .as_mut()
        .ok_or_else(|| std::io::Error::other("missing admission binding"))?
        .authorization_artifact_digests = vec!["b".repeat(64), "a".repeat(64)];
    assert!(store
        .authorize_budget_hold(invalid_binding)
        .as_ref()
        .is_err_and(|error| error.to_string().contains("sorted unique")));

    assert!(store
        .release_budget_hold(BudgetReleaseHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            released_exposure_units: 0,
            hold_id: Some("hold-composite".to_string()),
            event_id: Some("hold-composite:release-zero".to_string()),
            authority: None,
        })
        .is_err_and(|error| error.to_string().contains("zero-unit")));
    assert!(store
        .reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            exposed_cost_units: 0,
            realized_spend_units: 0,
            hold_id: Some("hold-composite".to_string()),
            event_id: Some("hold-composite:reconcile-zero".to_string()),
            authority: None,
        })
        .is_err_and(|error| error.to_string().contains("zero-unit")));
    assert!(store
        .capture_budget_hold(BudgetCaptureHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            exposed_cost_units: 0,
            realized_spend_units: 0,
            hold_id: Some("hold-composite".to_string()),
            event_id: Some("hold-composite:capture-zero".to_string()),
            authority: None,
        })
        .is_err_and(|error| error.to_string().contains("zero-unit")));
    Ok(())
}

#[test]
fn remote_budget_store_preserves_structured_capture_decision(
) -> Result<(), Box<dyn std::error::Error>> {
    for (wire, expected_captured) in [
        (StructuredBudgetMutationDecisionView::Applied, true),
        (StructuredBudgetMutationDecisionView::AlreadyApplied, false),
    ] {
        let request = composite_request()?;
        let mut projection: StructuredBudgetMutationResponse =
            serde_json::from_str(&structured_mutation_body(
                &request,
                "hold-composite:capture",
                wire,
                BudgetInvocationState::Captured,
                BudgetMonetaryState::Exposed,
                100,
                0,
                100,
                1,
                0,
                1,
                7,
            )?)?;
        projection.projection.metadata.budget_commit_index = Some(8);
        projection.projection_contract = StructuredBudgetProjectionContractView::from_projection(
            &projection.projection,
            projection
                .usage
                .as_ref()
                .ok_or_else(|| std::io::Error::other("missing test usage"))?,
        )?;
        let body = structured_capture_body(
            projection,
            if expected_captured {
                CaptureInvocationDecision::Captured
            } else {
                CaptureInvocationDecision::AlreadyCaptured
            },
        )?;
        let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
        };

        let decision = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            hold_id: "hold-composite".to_string(),
            event_id: "hold-composite:capture".to_string(),
            trusted_time: None,
            authority: None,
        })?;
        let (captured, mutation) = match decision {
            BudgetInvocationCaptureDecision::Captured(mutation) => (true, mutation),
            BudgetInvocationCaptureDecision::AlreadyCaptured(mutation) => (false, mutation),
        };
        assert_eq!(captured, expected_captured);
        assert_eq!(mutation.hold_id.as_deref(), Some("hold-composite"));
        assert_eq!(mutation.invocation_state, BudgetInvocationState::Captured);
        assert_eq!(mutation.exposure_units, 100);
        assert_eq!(
            mutation.metadata.guarantee_level,
            BudgetGuaranteeLevel::AdvisoryPosthoc
        );
        let usage = store
            .get_usage("cap-composite", 0)?
            .ok_or_else(|| std::io::Error::other("captured usage was not cached"))?;
        assert_eq!(usage.invocation_count, 1);
        assert_eq!(usage.total_cost_exposed, 100);
        assert_eq!(usage.seq, 7);
        assert_eq!(usage.updated_at, 11);
        assert_eq!(mutation.metadata.budget_commit_index, Some(8));
        let requests = server.requests();
        assert_json_post(
            &requests[0],
            STRUCTURED_BUDGET_CAPTURE_INVOCATION_PATH,
            &["\"eventId\":\"hold-composite:capture\""],
        );
        assert_json_post_omits(
            &requests[0],
            STRUCTURED_BUDGET_CAPTURE_INVOCATION_PATH,
            &["trustedTime"],
        );
    }
    Ok(())
}

#[test]
fn remote_capture_retry_is_clock_free_after_delay() -> Result<(), Box<dyn std::error::Error>> {
    let request = composite_request()?;
    let projection: StructuredBudgetMutationResponse =
        serde_json::from_str(&structured_mutation_body(
            &request,
            "hold-composite:capture",
            StructuredBudgetMutationDecisionView::AlreadyApplied,
            BudgetInvocationState::Captured,
            BudgetMonetaryState::Exposed,
            100,
            0,
            100,
            1,
            0,
            1,
            7,
        )?)?;
    let body = structured_capture_body(projection, CaptureInvocationDecision::AlreadyCaptured)?;
    let server = StaticResponseServer::spawn(200, &body, "application/json", 2);
    let store = build_remote_budget_store(&server.url, "secret")?;
    let capture = || {
        store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            hold_id: "hold-composite".to_string(),
            event_id: "hold-composite:capture".to_string(),
            trusted_time: None,
            authority: None,
        })
    };
    assert!(matches!(
        capture()?,
        BudgetInvocationCaptureDecision::AlreadyCaptured(_)
    ));
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert!(matches!(
        capture()?,
        BudgetInvocationCaptureDecision::AlreadyCaptured(_)
    ));
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_json_post_omits(
        &requests[0],
        STRUCTURED_BUDGET_CAPTURE_INVOCATION_PATH,
        &["trustedTime"],
    );
    assert_eq!(requests[0].body(), requests[1].body());
    Ok(())
}

#[test]
fn remote_budget_store_rejects_structured_capture_identity_substitution(
) -> Result<(), Box<dyn std::error::Error>> {
    for (pointer, substituted) in [
        ("/capabilityId", serde_json::json!("cap-other")),
        ("/grantIndex", serde_json::json!(3)),
        ("/requestHoldId", serde_json::json!("hold-other")),
        (
            "/requestEventId",
            serde_json::json!("hold-composite:other-capture"),
        ),
        ("/projection/holdId", serde_json::json!("hold-other")),
        (
            "/projection/metadata/eventId",
            serde_json::json!("hold-composite:other-capture"),
        ),
        (
            "/projection/metadata/authority/authorityId",
            serde_json::json!("other-authority"),
        ),
    ] {
        let request = composite_request()?;
        let projection: StructuredBudgetMutationResponse =
            serde_json::from_str(&structured_mutation_body(
                &request,
                "hold-composite:capture",
                StructuredBudgetMutationDecisionView::AlreadyApplied,
                BudgetInvocationState::Captured,
                BudgetMonetaryState::Exposed,
                100,
                0,
                100,
                1,
                0,
                1,
                7,
            )?)?;
        let mut body: serde_json::Value = serde_json::from_str(&structured_capture_body(
            projection,
            CaptureInvocationDecision::AlreadyCaptured,
        )?)?;
        *body
            .pointer_mut(pointer)
            .ok_or_else(|| std::io::Error::other("missing response field"))? = substituted;
        let server = StaticResponseServer::spawn(200, &body.to_string(), "application/json", 1);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
        };
        let result = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            hold_id: "hold-composite".to_string(),
            event_id: "hold-composite:capture".to_string(),
            trusted_time: None,
            authority: None,
        });
        assert!(result.as_ref().is_err_and(|error| {
            let reason = error.to_string();
            reason.contains("request identity")
                || reason.contains("durable hold")
                || reason.contains("required durable")
                || reason.contains("mixed budget")
                || reason.contains("projection contract")
        }));
        assert!(store.cached_usage("cap-composite", 0).is_none());
    }
    Ok(())
}

#[test]
fn remote_budget_store_rejects_stripped_or_mismatched_lifecycle_coupling(
) -> Result<(), Box<dyn std::error::Error>> {
    for strip_admission in [true, false] {
        let request = composite_request()?;
        let projection: StructuredBudgetMutationResponse =
            serde_json::from_str(&structured_mutation_body(
                &request,
                "hold-composite:capture",
                StructuredBudgetMutationDecisionView::Applied,
                BudgetInvocationState::Captured,
                BudgetMonetaryState::Exposed,
                100,
                0,
                100,
                1,
                0,
                1,
                7,
            )?)?;
        let mut body: serde_json::Value = serde_json::from_str(&structured_capture_body(
            projection,
            CaptureInvocationDecision::Captured,
        )?)?;
        if strip_admission {
            body["projection"]
                .as_object_mut()
                .ok_or_else(|| std::io::Error::other("missing projection object"))?
                .remove("admissionBinding");
        } else {
            body["projection"]["invocationQuotaUsages"][0]["quota"]["key"]["ownerId"] =
                serde_json::json!("cap-other");
        }
        let server = StaticResponseServer::spawn(200, &body.to_string(), "application/json", 1);
        let store = build_remote_budget_store(&server.url, "secret")?;
        let result = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            hold_id: "hold-composite".to_string(),
            event_id: "hold-composite:capture".to_string(),
            trusted_time: None,
            authority: None,
        });
        assert!(result.is_err());
    }
    Ok(())
}

#[test]
fn remote_capture_rejects_projection_downgrade_exact_usage_swap_and_quota_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    let request = composite_request()?;
    let base = structured_mutation_body(
        &request,
        "hold-composite:capture",
        StructuredBudgetMutationDecisionView::AlreadyApplied,
        BudgetInvocationState::Captured,
        BudgetMonetaryState::Exposed,
        100,
        0,
        100,
        1,
        0,
        1,
        7,
    )?;

    let mut downgraded: serde_json::Value = serde_json::from_str(&base)?;
    downgraded["projection"]
        .as_object_mut()
        .ok_or_else(|| std::io::Error::other("missing projection"))?
        .remove("admissionBinding");
    downgraded["projection"]["invocationQuotaUsages"] = serde_json::json!([]);

    let mut swapped_usage: serde_json::Value = serde_json::from_str(&base)?;
    swapped_usage["usage"]["seq"] = serde_json::json!(6);

    let mut quota_drift: StructuredBudgetMutationResponse = serde_json::from_str(&base)?;
    quota_drift.projection.invocation_quota_usages[0].captured_invocations = 0;
    quota_drift.projection_contract = StructuredBudgetProjectionContractView::from_projection(
        &quota_drift.projection,
        quota_drift
            .usage
            .as_ref()
            .ok_or_else(|| std::io::Error::other("missing usage"))?,
    )?;

    for body in [
        downgraded.to_string(),
        swapped_usage.to_string(),
        serde_json::to_string(&quota_drift)?,
    ] {
        let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
        };
        let result = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            hold_id: "hold-composite".to_string(),
            event_id: "hold-composite:capture".to_string(),
            trusted_time: None,
            authority: None,
        });
        assert!(result.is_err());
        assert!(store.cached_usage("cap-composite", 0).is_none());
    }
    Ok(())
}

#[test]
fn remote_budget_store_rejects_structured_reconcile_mismatch_without_poisoning_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    for (pointer, replacement) in [
        ("/projection/exposureUnits", serde_json::json!(99)),
        ("/projection/realizedSpendUnits", serde_json::json!(74)),
        ("/usage/totalCostRealizedSpend", serde_json::json!(50)),
        ("/usage/seq", serde_json::json!(9)),
    ] {
        let request = composite_request()?;
        let mut body: serde_json::Value =
            serde_json::from_str(&structured_reconcile_body(&request)?)?;
        *body
            .pointer_mut(pointer)
            .ok_or_else(|| std::io::Error::other("missing response field"))? = replacement;
        let server = StaticResponseServer::spawn(200, &body.to_string(), "application/json", 1);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
        };
        store.cache_usage("cap-composite", 0, Some(5), Some(5), Some(50), Some(25))?;
        let result = store.reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 75,
            hold_id: Some("hold-composite".to_string()),
            event_id: Some("hold-composite:reconcile".to_string()),
            authority: None,
        });
        let cached = store
            .cached_usage("cap-composite", 0)
            .ok_or_else(|| std::io::Error::other("seeded cache missing"))?;
        assert!(result.is_err());
        assert_eq!(cached.seq, 5);
        assert_eq!(cached.invocation_count, 5);
        assert_eq!(cached.total_cost_exposed, 50);
        assert_eq!(cached.total_cost_realized_spend, 25);
    }
    Ok(())
}

#[test]
fn remote_budget_store_rejects_v1_shape_on_versioned_lifecycle_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let request = composite_request()?;
    let mut body: serde_json::Value = serde_json::from_str(&structured_reconcile_body(&request)?)?;
    body["invocationCount"] = serde_json::json!(2);
    body["totalExposureCharged"] = serde_json::json!(25);
    body["totalRealizedSpend"] = serde_json::json!(75);
    body["budgetAuthority"]["budgetCommitIndex"] = serde_json::json!(8);
    let server = StaticResponseServer::spawn(200, &body.to_string(), "application/json", 1);
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret")?,
        cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
    };
    store.cache_usage("cap-composite", 0, Some(5), Some(5), Some(50), Some(25))?;

    let result = store.reconcile_budget_hold(BudgetReconcileHoldRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 75,
        hold_id: Some("hold-composite".to_string()),
        event_id: Some("hold-composite:reconcile".to_string()),
        authority: None,
    });
    let cached = store
        .cached_usage("cap-composite", 0)
        .ok_or_else(|| std::io::Error::other("seeded cache missing"))?;
    assert!(result.is_err());
    assert_eq!(cached.seq, 5);
    assert_eq!(cached.invocation_count, 5);
    assert_eq!(cached.total_cost_exposed, 50);
    assert_eq!(cached.total_cost_realized_spend, 25);
    Ok(())
}

#[test]
fn remote_budget_store_rejects_structured_reconcile_identity_substitution_without_poisoning_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    for (pointer, replacement) in [
        ("/requestHoldId", serde_json::json!("hold-other")),
        (
            "/requestEventId",
            serde_json::json!("hold-composite:other-reconcile"),
        ),
        ("/projection/holdId", serde_json::json!("hold-other")),
        (
            "/projection/metadata/eventId",
            serde_json::json!("hold-composite:other-reconcile"),
        ),
    ] {
        let request = composite_request()?;
        let mut body: serde_json::Value =
            serde_json::from_str(&structured_reconcile_body(&request)?)?;
        *body
            .pointer_mut(pointer)
            .ok_or_else(|| std::io::Error::other("missing response field"))? = replacement;
        let server = StaticResponseServer::spawn(200, &body.to_string(), "application/json", 1);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
        };
        store.cache_usage("cap-composite", 0, Some(5), Some(5), Some(50), Some(25))?;
        let result = store.reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 75,
            hold_id: Some("hold-composite".to_string()),
            event_id: Some("hold-composite:reconcile".to_string()),
            authority: None,
        });
        let cached = store
            .cached_usage("cap-composite", 0)
            .ok_or_else(|| std::io::Error::other("seeded cache missing"))?;
        assert!(result.is_err());
        assert_eq!(cached.seq, 5);
        assert_eq!(cached.invocation_count, 5);
        assert_eq!(cached.total_cost_exposed, 50);
        assert_eq!(cached.total_cost_realized_spend, 25);
    }
    Ok(())
}

#[test]
fn remote_budget_store_rejects_impossible_structured_capture_event_state(
) -> Result<(), Box<dyn std::error::Error>> {
    for (pointer, invalid) in [
        (
            "/projection/invocationState",
            serde_json::json!("authorized"),
        ),
        ("/projection/committedCostUnitsAfter", serde_json::json!(99)),
        ("/projection/monetaryState", serde_json::json!("reversed")),
    ] {
        let request = composite_request()?;
        let projection: StructuredBudgetMutationResponse =
            serde_json::from_str(&structured_mutation_body(
                &request,
                "hold-composite:capture",
                StructuredBudgetMutationDecisionView::Applied,
                BudgetInvocationState::Captured,
                BudgetMonetaryState::Exposed,
                100,
                0,
                100,
                1,
                0,
                1,
                7,
            )?)?;
        let mut body: serde_json::Value = serde_json::from_str(&structured_capture_body(
            projection,
            CaptureInvocationDecision::Captured,
        )?)?;
        *body
            .pointer_mut(pointer)
            .ok_or_else(|| std::io::Error::other("missing response field"))? = invalid;
        if pointer.ends_with("committedCostUnitsAfter") {
            body["usage"]["totalCostExposed"] = serde_json::json!(99);
        }
        let server = StaticResponseServer::spawn(200, &body.to_string(), "application/json", 1);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
        };
        let result = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            hold_id: "hold-composite".to_string(),
            event_id: "hold-composite:capture".to_string(),
            trusted_time: None,
            authority: None,
        });
        assert!(result.is_err());
        assert!(store.cached_usage("cap-composite", 0).is_none());
    }
    Ok(())
}

#[test]
fn remote_budget_store_rejects_nonterminal_monetary_lifecycle_states(
) -> Result<(), Box<dyn std::error::Error>> {
    let request = composite_request()?;

    let release_body = structured_mutation_body(
        &request,
        "hold-composite:release",
        StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied,
        BudgetInvocationState::Authorized,
        BudgetMonetaryState::None,
        25,
        0,
        0,
        1,
        1,
        0,
        8,
    )?;
    let release_server = StaticResponseServer::spawn(200, &release_body, "application/json", 1);
    let release_store = build_remote_budget_store(&release_server.url, "secret")?;
    assert!(release_store
        .release_budget_hold(BudgetReleaseHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            released_exposure_units: 25,
            hold_id: Some("hold-composite".to_string()),
            event_id: Some("hold-composite:release".to_string()),
            authority: None,
        })
        .is_err());

    let reconcile_body = structured_mutation_body(
        &request,
        "hold-composite:reconcile-none",
        StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied,
        BudgetInvocationState::Captured,
        BudgetMonetaryState::None,
        100,
        75,
        0,
        1,
        0,
        1,
        9,
    )?;
    let reconcile_server = StaticResponseServer::spawn(200, &reconcile_body, "application/json", 1);
    let reconcile_store = build_remote_budget_store(&reconcile_server.url, "secret")?;
    assert!(reconcile_store
        .reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 75,
            hold_id: Some("hold-composite".to_string()),
            event_id: Some("hold-composite:reconcile-none".to_string()),
            authority: None,
        })
        .is_err());

    let capture_body = structured_mutation_body(
        &request,
        "hold-composite:capture-none",
        StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied,
        BudgetInvocationState::Captured,
        BudgetMonetaryState::None,
        100,
        75,
        0,
        1,
        0,
        1,
        10,
    )?;
    let capture_server = StaticResponseServer::spawn(200, &capture_body, "application/json", 1);
    let capture_store = build_remote_budget_store(&capture_server.url, "secret")?;
    assert!(capture_store
        .capture_budget_hold(BudgetCaptureHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 75,
            hold_id: Some("hold-composite".to_string()),
            event_id: Some("hold-composite:capture-none".to_string()),
            authority: None,
        })
        .is_err());
    Ok(())
}

#[test]
fn remote_budget_store_rejects_structured_reverse_substitution_without_poisoning_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    for (pointer, replacement) in [
        ("/capabilityId", serde_json::json!("cap-other")),
        ("/grantIndex", serde_json::json!(3)),
        ("/requestHoldId", serde_json::json!("hold-other")),
        (
            "/requestEventId",
            serde_json::json!("hold-composite:other-reverse"),
        ),
        ("/projection/exposureUnits", serde_json::json!(99)),
        ("/projection/monetaryState", serde_json::json!("captured")),
    ] {
        let request = composite_request()?;
        let projection: StructuredBudgetMutationResponse =
            serde_json::from_str(&structured_mutation_body(
                &request,
                "hold-composite:reverse",
                StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied,
                BudgetInvocationState::Reversed,
                BudgetMonetaryState::Reversed,
                100,
                0,
                0,
                0,
                0,
                0,
                7,
            )?)?;
        let mut body: serde_json::Value =
            serde_json::from_str(&structured_reverse_body(projection)?)?;
        *body
            .pointer_mut(pointer)
            .ok_or_else(|| std::io::Error::other("missing response field"))? = replacement;
        let server = StaticResponseServer::spawn(200, &body.to_string(), "application/json", 1);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
        };
        store.cache_usage("cap-composite", 0, Some(5), Some(5), Some(50), Some(25))?;
        let result = store.reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            reversed_exposure_units: 100,
            hold_id: Some("hold-composite".to_string()),
            event_id: Some("hold-composite:reverse".to_string()),
            expected_cumulative_approval_state: None,
            authority: None,
        });
        let cached = store
            .cached_usage("cap-composite", 0)
            .ok_or_else(|| std::io::Error::other("seeded cache missing"))?;
        assert!(result.is_err());
        assert_eq!(cached.seq, 5);
        assert_eq!(cached.total_cost_exposed, 50);
        assert_eq!(cached.total_cost_realized_spend, 25);
    }
    Ok(())
}

#[test]
fn fenced_reverse_requires_returned_cumulative_state_without_poisoning_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    let request = composite_request()?;
    let body = structured_mutation_body(
        &request,
        "hold-composite:fenced-reverse",
        StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied,
        BudgetInvocationState::Reversed,
        BudgetMonetaryState::Reversed,
        100,
        0,
        0,
        0,
        0,
        0,
        7,
    )?;
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret")?,
        cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
    };
    store.cache_usage("cap-composite", 0, Some(5), Some(5), Some(50), Some(25))?;

    let result = store.reverse_budget_hold(BudgetReverseHoldRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        reversed_exposure_units: 100,
        hold_id: Some("hold-composite".to_string()),
        event_id: Some("hold-composite:fenced-reverse".to_string()),
        expected_cumulative_approval_state: Some(BudgetCumulativeApprovalState::PendingApproval),
        authority: None,
    });
    let cached = store
        .cached_usage("cap-composite", 0)
        .ok_or_else(|| std::io::Error::other("seeded cache missing"))?;
    assert!(result.is_err_and(|error| error.to_string().contains("invalid reversed state")));
    assert_eq!(cached.seq, 5);
    assert_eq!(cached.total_cost_exposed, 50);
    assert_eq!(cached.total_cost_realized_spend, 25);
    assert_json_post(
        &server.requests()[0],
        STRUCTURED_BUDGET_FENCED_REVERSE_PATH,
        &[],
    );
    Ok(())
}

#[test]
fn remote_budget_store_cancels_durable_capture_without_process_local_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let request = composite_request()?;
    let body = structured_mutation_body(
        &request,
        "hold-composite:cancel",
        StructuredBudgetMutationDecisionView::Applied,
        BudgetInvocationState::Reversed,
        BudgetMonetaryState::Reversed,
        100,
        0,
        0,
        0,
        0,
        0,
        8,
    )?;
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let restarted_store = build_remote_budget_store(&server.url, "secret")?;
    let cancellation = restarted_store.cancel_captured_before_dispatch(
        BudgetCancelCapturedBeforeDispatchRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            hold_id: "hold-composite".to_string(),
            event_id: "hold-composite:cancel".to_string(),
            authority: None,
        },
    )?;
    let BudgetCapturedBeforeDispatchCancellationDecision::Cancelled(mutation) = cancellation else {
        return Err(std::io::Error::other("fresh cancellation returned replay").into());
    };
    assert_eq!(mutation.invocation_state, BudgetInvocationState::Reversed);
    assert_eq!(mutation.committed_cost_units_after, 0);
    assert_json_post(
        &server.requests()[0],
        STRUCTURED_BUDGET_CANCEL_CAPTURED_PATH,
        &[],
    );
    Ok(())
}
