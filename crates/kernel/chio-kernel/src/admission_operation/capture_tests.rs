use crate::budget_store::{BudgetInvocationQuota, BudgetQuotaKey, BudgetQuotaProfile};

use super::*;

const AUTHORIZATION_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REQUEST_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const POLICY_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const PREVIOUS_COMMIT_DIGEST: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const COMMIT_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn identifier(field: &'static str, value: &str) -> AdmissionIdentifier {
    AdmissionIdentifier::try_new(field, value).expect("test identifier must be valid")
}

fn digest(field: &'static str, value: &str) -> AdmissionDigest {
    AdmissionDigest::try_new(field, value).expect("test digest must be valid")
}

fn store_fence() -> StoreMutationFence {
    StoreMutationFence {
        store_uuid: "authority-store-1".to_string(),
        lease_id: "authority-lease-1".to_string(),
        owner_epoch: 9,
    }
}

fn authority() -> BudgetEventAuthority {
    BudgetEventAuthority {
        authority_id: "authority-store-1".to_string(),
        lease_id: "authority-lease-1".to_string(),
        lease_epoch: 9,
    }
}

fn quota(
    profile: BudgetQuotaProfile,
    owner_id: &str,
    grant_index: Option<u32>,
    maximum: u32,
    reserved: u32,
    captured: u32,
) -> BudgetInvocationQuotaUsage {
    BudgetInvocationQuotaUsage {
        quota: BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile,
                owner_id: owner_id.to_string(),
                grant_index,
            },
            max_invocations: maximum,
        },
        reserved_invocations: reserved,
        captured_invocations: captured,
    }
}

fn expected_quotas() -> Vec<BudgetInvocationQuotaUsage> {
    vec![
        quota(
            BudgetQuotaProfile::GrantInvocation,
            "cap-1",
            Some(3),
            10,
            1,
            2,
        ),
        quota(
            BudgetQuotaProfile::AggregateCapabilityInvocation,
            "capability-family-1",
            None,
            4,
            1,
            1,
        ),
    ]
}

fn captured_quotas() -> Vec<BudgetInvocationQuotaUsage> {
    expected_quotas()
        .into_iter()
        .map(|mut usage| {
            usage.reserved_invocations -= 1;
            usage.captured_invocations += 1;
            usage
        })
        .collect()
}

fn recovery_lease(operation: &AdmissionOperationV1) -> AdmissionRecoveryLease {
    let claim = UntrustedAdmissionRecoveryClaim::new(
        operation.binding.operation_id.clone(),
        identifier("claimant_id", "capture-worker-1"),
        identifier("coordinator_lease_id", "coordinator-lease-1"),
        operation.coordinator_lease_epoch,
        operation.version,
        10_000,
        store_fence(),
    )
    .expect("test recovery claim must be valid");
    qualify_recovery_claim_for_test(operation, claim, 1_000, &store_fence())
        .expect("test recovery lease must qualify")
}

fn capture_pending_operation() -> AdmissionOperationV1 {
    let namespace = AuthenticatedRequestNamespace::from_authentication_context(
        identifier("coordinator_authority_id", "https://coordinator.example"),
        "tenant-1",
    )
    .expect("test namespace must be valid");
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace,
        request_id: identifier("request_id", "request-1"),
        capability_id: identifier("capability_id", "cap-1"),
        authorization_capability_hash: digest("authorization_hash", AUTHORIZATION_HASH),
        request_binding: AdmissionRequestBindingV1::new(
            digest("immutable_request_hash", REQUEST_HASH),
            AdmissionParticipantRequirements {
                broker_attempt: true,
                budget_capture: true,
                ..AdmissionParticipantRequirements::NONE
            },
        )
        .expect("test request binding must be valid"),
        policy_hash: digest("policy_hash", POLICY_HASH),
        effect_class: SideEffectClass::SideEffecting,
    })
    .expect("test operation binding must be valid");
    let mut operation =
        AdmissionOperationV1::prepare(binding, 7).expect("test operation must prepare");
    for state in [
        AdmissionOperationState::BrokerAttemptRegistered,
        AdmissionOperationState::BudgetAuthorized,
        AdmissionOperationState::ReadyToDispatch,
        AdmissionOperationState::CapturePending,
    ] {
        let attachments = if state == AdmissionOperationState::BrokerAttemptRegistered {
            vec![AdmissionAttachment::BrokerAttempt(
                ProviderAttemptBindingV1 {
                    operation_id: operation.binding.operation_id.as_str().to_owned(),
                    attempt_id: "attempt-1".to_owned(),
                    transport_id: "transport-1".to_owned(),
                    transport_key_epoch: 1,
                },
            )]
        } else if state == AdmissionOperationState::BudgetAuthorized {
            vec![AdmissionAttachment::BudgetHoldId(identifier(
                "budget_hold_id",
                "hold-1",
            ))]
        } else {
            Vec::new()
        };
        let command = AdmissionOperationCommand::new(
            operation.binding.operation_id.clone(),
            operation.version,
            recovery_lease(&operation),
            attachments,
            Some(state),
            None,
            None,
        )
        .expect("test transition command must be valid");
        operation = operation
            .apply_command(&command, 1_000)
            .expect("test transition must apply")
            .into_operation();
    }
    operation
}

fn request(operation: &AdmissionOperationV1) -> AdmissionCaptureRequestV1 {
    AdmissionCaptureRequestV1 {
        operation_id: operation.binding.operation_id.clone(),
        expected_operation_version: operation.version,
        coordinator_lease_epoch: operation.coordinator_lease_epoch,
        capability_id: operation.binding.capability_id.clone(),
        grant_index: 3,
        hold_id: identifier("hold_id", "hold-1"),
        event_id: identifier("event_id", "capture-event-1"),
        revocation_set: CanonicalRevocationSet::canonicalize(vec![
            "ancestor-1".to_string(),
            "cap-1".to_string(),
        ])
        .expect("test revocation set must be canonical"),
        authorization_artifact_digests: vec![digest(
            "authorization_artifact_digest",
            AUTHORIZATION_HASH,
        )],
        authorization_expires_at_unix_ms: 2_000,
        expected_invocation_quota_usages: expected_quotas(),
        authority: authority(),
        previous_global_commit_sequence: 10,
        previous_global_commit_digest: digest(
            "previous_global_commit_digest",
            PREVIOUS_COMMIT_DIGEST,
        ),
        store_fence: store_fence(),
    }
}

fn record(request: &AdmissionCaptureRequestV1) -> AdmissionCaptureRecordV1 {
    AdmissionCaptureRecordV1 {
        operation_id: request.operation_id.clone(),
        operation_version: request.expected_operation_version,
        coordinator_lease_epoch: request.coordinator_lease_epoch,
        capability_id: request.capability_id.clone(),
        grant_index: request.grant_index,
        hold_id: request.hold_id.clone(),
        event_id: request.event_id.clone(),
        revocation_set: request.revocation_set.clone(),
        authorization_artifact_digests: request.authorization_artifact_digests.clone(),
        invocation_quota_usages: captured_quotas(),
        authorization_expires_at_unix_ms: request.authorization_expires_at_unix_ms,
        authority_time_unix_ms: 1_000,
        combined_commit: AdmissionCombinedCaptureCommit {
            authority: request.authority.clone(),
            guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
            previous_global_commit_sequence: request.previous_global_commit_sequence,
            previous_global_commit_digest: request.previous_global_commit_digest.clone(),
            global_commit_sequence: 11,
            global_commit_digest: digest("global_commit_digest", COMMIT_DIGEST),
            store_fence: request.store_fence.clone(),
        },
        disposition: AdmissionCaptureDisposition::Captured,
    }
}

#[derive(Clone)]
struct StaticCaptureAuthority {
    decision: AdmissionCaptureDecision,
}

impl AdmissionCaptureAuthority for StaticCaptureAuthority {
    fn capture(
        &self,
        _request: &AdmissionCaptureRequestV1,
    ) -> Result<AdmissionCaptureDecision, AdmissionCaptureError> {
        Ok(self.decision.clone())
    }

    fn lookup_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<AdmissionCaptureRecordV1>, AdmissionCaptureError> {
        Ok((self.decision.record().operation_id == *operation_id)
            .then(|| self.decision.record().clone()))
    }
}

fn qualification(
    request: &AdmissionCaptureRequestV1,
    verified_at_unix_ms: u64,
    response_digest: AdmissionDigest,
) -> TestCaptureQualification {
    TestCaptureQualification {
        authority: request.authority.clone(),
        store_fence: request.store_fence.clone(),
        verified_at_unix_ms,
        operation_id: request.operation_id.clone(),
        event_id: request.event_id.clone(),
        response_digest,
        previous_global_commit_sequence: request.previous_global_commit_sequence,
        previous_global_commit_digest: request.previous_global_commit_digest.clone(),
        global_commit_sequence: 11,
        global_commit_digest: digest("global_commit_digest", COMMIT_DIGEST),
    }
}

fn resolve(
    operation: &AdmissionOperationV1,
    request: &AdmissionCaptureRequestV1,
    decision: AdmissionCaptureDecision,
) -> Result<QualifiedAdmissionCaptureDecision, AdmissionCaptureError> {
    resolve_at(operation, request, decision, 1_100)
}

fn resolve_at(
    operation: &AdmissionOperationV1,
    request: &AdmissionCaptureRequestV1,
    decision: AdmissionCaptureDecision,
    verified_at_unix_ms: u64,
) -> Result<QualifiedAdmissionCaptureDecision, AdmissionCaptureError> {
    let response_digest = decision.response_digest().clone();
    let verifier = qualify_capture_authority_for_test(
        Arc::new(StaticCaptureAuthority { decision }),
        qualification(request, verified_at_unix_ms, response_digest),
    )
    .expect("test authority qualification must be valid");
    capture_with_qualified_verifier(operation, request, &verifier)
}

fn assert_operation_error(
    result: Result<QualifiedAdmissionCaptureDecision, AdmissionCaptureError>,
    expected: AdmissionOperationError,
) {
    assert!(
        matches!(
            &result,
            Err(AdmissionCaptureError::Operation(actual)) if actual == &expected
        ),
        "unexpected capture result: {result:?}"
    );
}

#[test]
fn qualified_capture_accepts_only_exact_new_and_replay_results() {
    let operation = capture_pending_operation();
    let request = request(&operation);
    let record = record(&request);
    let captured = resolve(
        &operation,
        &request,
        AdmissionCaptureDecision::untrusted_captured(record.clone())
            .expect("captured response must be valid"),
    )
    .expect("exact capture response must qualify");
    assert_eq!(captured.record(), &record);
    assert_eq!(
        captured.disposition(),
        &AdmissionCaptureDisposition::Captured
    );
    assert!(!captured.was_replay());
    assert_eq!(captured.verified_at_unix_ms(), 1_100);
    assert_ne!(captured.response_digest(), captured.qualification_digest());

    let replay = resolve(
        &operation,
        &request,
        AdmissionCaptureDecision::untrusted_already_captured(record)
            .expect("replay response must be valid"),
    )
    .expect("exact replay response must qualify");
    assert!(replay.was_replay());
}

#[test]
fn qualified_lookup_rechecks_the_same_record_commit_and_clock() {
    let operation = capture_pending_operation();
    let request = request(&operation);
    let record = record(&request);
    let stored = AdmissionCaptureDecision::untrusted_captured(record.clone())
        .expect("stored capture must be valid");
    let replay = AdmissionCaptureDecision::untrusted_already_captured(record.clone())
        .expect("lookup replay must be valid");
    let verifier = qualify_capture_authority_for_test(
        Arc::new(StaticCaptureAuthority { decision: stored }),
        qualification(&request, 1_100, replay.response_digest().clone()),
    )
    .expect("lookup authority qualification must be valid");
    let qualified = lookup_capture_with_qualified_verifier(&operation, &request, &verifier)
        .expect("qualified lookup must succeed")
        .expect("stored capture must be found");
    assert!(qualified.was_replay());
    assert_eq!(qualified.record(), &record);

    let wrong_digest = digest(
        "response_digest",
        "8888888888888888888888888888888888888888888888888888888888888888",
    );
    let verifier = qualify_capture_authority_for_test(
        Arc::new(StaticCaptureAuthority {
            decision: AdmissionCaptureDecision::untrusted_captured(record)
                .expect("stored capture must be valid"),
        }),
        qualification(&request, 1_100, wrong_digest),
    )
    .expect("lookup authority qualification must be valid");
    assert_operation_error(
        lookup_capture_with_qualified_verifier(&operation, &request, &verifier).and_then(|value| {
            value.ok_or_else(|| AdmissionCaptureError::Invariant("missing".into()))
        }),
        AdmissionOperationError::CaptureCommitMismatch,
    );
}

#[test]
fn authority_fence_and_global_commit_fields_reject_substitution() {
    let operation = capture_pending_operation();
    let request = request(&operation);
    let base = record(&request);
    let mut substitutions = Vec::new();

    let mut changed = base.clone();
    changed.combined_commit.authority.authority_id = "other-store".to_string();
    changed.combined_commit.store_fence.store_uuid = "other-store".to_string();
    substitutions.push(changed);

    let mut changed = base.clone();
    changed.combined_commit.authority.lease_id = "other-lease".to_string();
    changed.combined_commit.store_fence.lease_id = "other-lease".to_string();
    substitutions.push(changed);

    let mut changed = base.clone();
    changed.combined_commit.authority.lease_epoch = 10;
    changed.combined_commit.store_fence.owner_epoch = 10;
    substitutions.push(changed);

    let mut changed = base.clone();
    changed.combined_commit.previous_global_commit_sequence = 11;
    changed.combined_commit.previous_global_commit_digest =
        digest("previous_global_commit_digest", COMMIT_DIGEST);
    changed.combined_commit.global_commit_sequence = 12;
    changed.combined_commit.global_commit_digest = digest(
        "global_commit_digest",
        "3333333333333333333333333333333333333333333333333333333333333333",
    );
    substitutions.push(changed);

    let mut changed = base.clone();
    changed.combined_commit.global_commit_digest = digest(
        "global_commit_digest",
        "4444444444444444444444444444444444444444444444444444444444444444",
    );
    substitutions.push(changed);

    for changed in substitutions {
        let decision = AdmissionCaptureDecision::untrusted_captured(changed)
            .expect("substituted response remains structurally valid");
        assert!(resolve(&operation, &request, decision).is_err());
    }

    let mut changed_request = request.clone();
    changed_request.authority.authority_id = "other-store".to_string();
    changed_request.store_fence.store_uuid = "other-store".to_string();
    let decision = AdmissionCaptureDecision::untrusted_captured(record(&changed_request))
        .expect("changed request response must be valid");
    let verifier = qualify_capture_authority_for_test(
        Arc::new(StaticCaptureAuthority { decision }),
        qualification(
            &request,
            1_100,
            AdmissionCaptureDecision::untrusted_captured(record(&request))
                .expect("base response must be valid")
                .response_digest()
                .clone(),
        ),
    )
    .expect("base authority qualification must be valid");
    assert_operation_error(
        capture_with_qualified_verifier(&operation, &changed_request, &verifier),
        AdmissionOperationError::CaptureAuthorityMismatch,
    );

    let invalid_guarantee = AdmissionCaptureRecordV1 {
        combined_commit: AdmissionCombinedCaptureCommit {
            guarantee_level: BudgetGuaranteeLevel::HaLinearizable,
            ..base.combined_commit.clone()
        },
        ..base.clone()
    };
    assert_eq!(
        AdmissionCaptureDecision::untrusted_captured(invalid_guarantee),
        Err(AdmissionOperationError::CaptureCommitMismatch)
    );

    let mut digest_tamper =
        AdmissionCaptureDecision::untrusted_captured(base).expect("base response must be valid");
    let AdmissionCaptureDecision::Captured(response) = &mut digest_tamper else {
        unreachable!();
    };
    response.response_digest = digest(
        "response_digest",
        "5555555555555555555555555555555555555555555555555555555555555555",
    );
    assert_operation_error(
        resolve(&operation, &request, digest_tamper),
        AdmissionOperationError::CaptureResponseDigestMismatch,
    );

    let decision = AdmissionCaptureDecision::untrusted_captured(record(&request))
        .expect("base response must be valid");
    let verifier = qualify_capture_authority_for_test(
        Arc::new(StaticCaptureAuthority {
            decision: decision.clone(),
        }),
        qualification(
            &request,
            1_100,
            digest(
                "response_digest",
                "9999999999999999999999999999999999999999999999999999999999999999",
            ),
        ),
    )
    .expect("test authority qualification must be valid");
    assert_operation_error(
        capture_with_qualified_verifier(&operation, &request, &verifier),
        AdmissionOperationError::CaptureCommitMismatch,
    );
}

#[test]
fn authority_time_and_expiry_have_one_canonical_disposition() {
    let operation = capture_pending_operation();
    let request = request(&operation);

    let expired_capture = AdmissionCaptureRecordV1 {
        authority_time_unix_ms: request.authorization_expires_at_unix_ms,
        ..record(&request)
    };
    assert_eq!(
        AdmissionCaptureDecision::untrusted_captured(expired_capture),
        Err(AdmissionOperationError::CaptureExpiryMismatch)
    );

    let expired_denial = AdmissionCaptureRecordV1 {
        invocation_quota_usages: request.expected_invocation_quota_usages.clone(),
        authority_time_unix_ms: request.authorization_expires_at_unix_ms,
        disposition: AdmissionCaptureDisposition::Denied(
            AdmissionCaptureDenialReason::AuthorizationExpired,
        ),
        ..record(&request)
    };
    let qualified = resolve_at(
        &operation,
        &request,
        AdmissionCaptureDecision::untrusted_denied(expired_denial)
            .expect("expired denial must be structurally valid"),
        2_100,
    )
    .expect("expired denial must qualify");
    assert_eq!(
        qualified.disposition(),
        &AdmissionCaptureDisposition::Denied(AdmissionCaptureDenialReason::AuthorizationExpired)
    );

    let premature_expiry_denial = AdmissionCaptureRecordV1 {
        invocation_quota_usages: request.expected_invocation_quota_usages.clone(),
        disposition: AdmissionCaptureDisposition::Denied(
            AdmissionCaptureDenialReason::AuthorizationExpired,
        ),
        ..record(&request)
    };
    assert_eq!(
        AdmissionCaptureDecision::untrusted_denied(premature_expiry_denial),
        Err(AdmissionOperationError::CaptureExpiryMismatch)
    );

    let late_other_denial = AdmissionCaptureRecordV1 {
        invocation_quota_usages: request.expected_invocation_quota_usages.clone(),
        authority_time_unix_ms: request.authorization_expires_at_unix_ms,
        disposition: AdmissionCaptureDisposition::Denied(AdmissionCaptureDenialReason::Revoked),
        ..record(&request)
    };
    assert_eq!(
        AdmissionCaptureDecision::untrusted_denied(late_other_denial),
        Err(AdmissionOperationError::CaptureExpiryMismatch)
    );

    let future = AdmissionCaptureRecordV1 {
        authority_time_unix_ms: 1_101,
        ..record(&request)
    };
    assert_operation_error(
        resolve(
            &operation,
            &request,
            AdmissionCaptureDecision::untrusted_captured(future)
                .expect("future response is otherwise structurally valid"),
        ),
        AdmissionOperationError::CaptureAuthorityTimeMismatch,
    );
}

#[test]
fn quota_set_maximum_counts_and_capture_delta_are_exact() {
    let operation = capture_pending_operation();
    let request = request(&operation);
    let base = record(&request);
    let mut substitutions = Vec::new();

    let mut changed = base.clone();
    changed.invocation_quota_usages.pop();
    substitutions.push(changed);

    let mut changed = base.clone();
    changed.invocation_quota_usages.push(quota(
        BudgetQuotaProfile::AggregateFamilyInvocation,
        "family-1",
        None,
        5,
        0,
        1,
    ));
    substitutions.push(changed);

    let mut changed = base.clone();
    changed.invocation_quota_usages[0].quota.max_invocations = 11;
    substitutions.push(changed);

    let mut changed = base.clone();
    changed.invocation_quota_usages[1].quota.key.owner_id = "other-family".to_string();
    substitutions.push(changed);

    let mut changed = base.clone();
    changed.invocation_quota_usages[1].quota.key.profile =
        BudgetQuotaProfile::AggregateFamilyInvocation;
    substitutions.push(changed);

    let mut changed = base.clone();
    changed.invocation_quota_usages[0].reserved_invocations = 1;
    substitutions.push(changed);

    let mut changed = base.clone();
    changed.invocation_quota_usages[0].captured_invocations = 2;
    substitutions.push(changed);

    for changed in substitutions {
        let decision = AdmissionCaptureDecision::untrusted_captured(changed)
            .expect("quota substitution remains structurally bounded");
        assert_operation_error(
            resolve(&operation, &request, decision),
            AdmissionOperationError::CaptureQuotaMismatch,
        );
    }

    let invalid_maximum = AdmissionCaptureRecordV1 {
        invocation_quota_usages: vec![quota(
            BudgetQuotaProfile::GrantInvocation,
            "cap-1",
            Some(3),
            0,
            0,
            0,
        )],
        ..base.clone()
    };
    assert_eq!(
        AdmissionCaptureDecision::untrusted_captured(invalid_maximum),
        Err(AdmissionOperationError::CaptureQuotaMismatch)
    );

    let duplicate = AdmissionCaptureRecordV1 {
        invocation_quota_usages: vec![
            base.invocation_quota_usages[0].clone(),
            base.invocation_quota_usages[0].clone(),
        ],
        ..base
    };
    assert_eq!(
        AdmissionCaptureDecision::untrusted_captured(duplicate),
        Err(AdmissionOperationError::CaptureQuotaMismatch)
    );

    let wrong_grant = AdmissionCaptureRecordV1 {
        invocation_quota_usages: vec![quota(
            BudgetQuotaProfile::GrantInvocation,
            "cap-1",
            Some(4),
            10,
            0,
            3,
        )],
        ..record(&request)
    };
    assert_eq!(
        AdmissionCaptureDecision::untrusted_captured(wrong_grant),
        Err(AdmissionOperationError::CaptureQuotaMismatch)
    );

    let oversized = AdmissionCaptureRecordV1 {
        invocation_quota_usages: (0..=MAX_INVOCATION_QUOTAS_PER_ADMISSION)
            .map(|index| {
                quota(
                    BudgetQuotaProfile::AggregateFamilyInvocation,
                    &format!("family-{index:02}"),
                    None,
                    5,
                    0,
                    1,
                )
            })
            .collect(),
        ..record(&request)
    };
    assert_eq!(
        AdmissionCaptureDecision::untrusted_captured(oversized),
        Err(AdmissionOperationError::CaptureQuotaMismatch)
    );
}

#[test]
fn every_capture_request_binding_is_rechecked_after_qualification() {
    let operation = capture_pending_operation();
    let request = request(&operation);
    let base = record(&request);
    let mut substitutions = Vec::new();

    substitutions.push(AdmissionCaptureRecordV1 {
        operation_id: AdmissionOperationId::from_persisted(
            "6666666666666666666666666666666666666666666666666666666666666666",
        )
        .expect("test operation id must be valid"),
        ..base.clone()
    });
    substitutions.push(AdmissionCaptureRecordV1 {
        operation_version: base.operation_version + 1,
        ..base.clone()
    });
    substitutions.push(AdmissionCaptureRecordV1 {
        coordinator_lease_epoch: base.coordinator_lease_epoch + 1,
        ..base.clone()
    });

    let mut changed = base.clone();
    changed.capability_id = identifier("capability_id", "cap-2");
    changed.invocation_quota_usages[0].quota.key.owner_id = "cap-2".to_string();
    substitutions.push(changed);

    let mut changed = base.clone();
    changed.grant_index = 4;
    changed.invocation_quota_usages[0].quota.key.grant_index = Some(4);
    substitutions.push(changed);

    substitutions.push(AdmissionCaptureRecordV1 {
        hold_id: identifier("hold_id", "hold-2"),
        ..base.clone()
    });
    substitutions.push(AdmissionCaptureRecordV1 {
        event_id: identifier("event_id", "capture-event-2"),
        ..base.clone()
    });
    substitutions.push(AdmissionCaptureRecordV1 {
        revocation_set: CanonicalRevocationSet::canonicalize(vec!["cap-1".to_string()])
            .expect("alternate revocation set must be valid"),
        ..base.clone()
    });
    substitutions.push(AdmissionCaptureRecordV1 {
        authorization_artifact_digests: vec![digest(
            "authorization_artifact_digest",
            "7777777777777777777777777777777777777777777777777777777777777777",
        )],
        ..base.clone()
    });
    substitutions.push(AdmissionCaptureRecordV1 {
        authorization_expires_at_unix_ms: base.authorization_expires_at_unix_ms + 1,
        ..base
    });

    for changed in substitutions {
        let decision = AdmissionCaptureDecision::untrusted_captured(changed)
            .expect("binding substitution remains structurally valid");
        assert_operation_error(
            resolve(&operation, &request, decision),
            AdmissionOperationError::CaptureBindingMismatch,
        );
    }
}

#[test]
fn disposition_and_replay_tags_cannot_be_substituted() {
    let operation = capture_pending_operation();
    let request = request(&operation);
    let base = record(&request);

    let AdmissionCaptureDecision::Captured(response) =
        AdmissionCaptureDecision::untrusted_captured(base.clone()).expect("capture must be valid")
    else {
        unreachable!();
    };
    assert_operation_error(
        resolve(
            &operation,
            &request,
            AdmissionCaptureDecision::AlreadyCaptured(response),
        ),
        AdmissionOperationError::CaptureResponseDigestMismatch,
    );

    let denial = AdmissionCaptureRecordV1 {
        invocation_quota_usages: request.expected_invocation_quota_usages.clone(),
        disposition: AdmissionCaptureDisposition::Denied(AdmissionCaptureDenialReason::Revoked),
        ..base.clone()
    };
    let AdmissionCaptureDecision::Denied(response) =
        AdmissionCaptureDecision::untrusted_denied(denial.clone()).expect("denial must be valid")
    else {
        unreachable!();
    };
    assert_operation_error(
        resolve(
            &operation,
            &request,
            AdmissionCaptureDecision::Captured(response),
        ),
        AdmissionOperationError::CaptureDispositionMismatch,
    );

    let qualified_denial = resolve(
        &operation,
        &request,
        AdmissionCaptureDecision::untrusted_denied(denial).expect("denial must be valid"),
    )
    .expect("exact denial must qualify");
    assert!(!qualified_denial.was_replay());

    let denial_with_capture_delta = AdmissionCaptureRecordV1 {
        disposition: AdmissionCaptureDisposition::Denied(AdmissionCaptureDenialReason::Revoked),
        ..base
    };
    assert_operation_error(
        resolve(
            &operation,
            &request,
            AdmissionCaptureDecision::untrusted_denied(denial_with_capture_delta)
                .expect("denial response is structurally valid"),
        ),
        AdmissionOperationError::CaptureQuotaMismatch,
    );
}
