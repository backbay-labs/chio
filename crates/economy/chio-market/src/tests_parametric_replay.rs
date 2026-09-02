//! Parametric opening projection and replay retention tests.

use super::*;

fn seal_parametric_opening_projection(
    projection: &ParametricClaimOpeningProjectionV1,
    signer: &crate::crypto::Keypair,
) -> chio_core_types::economic_continuity::EconomicStateBatchV1 {
    let mut batch = projection.batch_template().clone().into_unsigned_batch();
    require_ok(batch.seal(signer), "seal parametric opening batch");
    batch
}

fn verified_parametric_opening_view(
    mut heads: Vec<chio_core_types::economic_continuity::EconomicResourceHeadV1>,
    mut absent_resource_keys: Vec<chio_core_types::economic_continuity::EconomicResourceKeyV1>,
    checkpoint_sequence: u64,
    checkpoint_digest: String,
    observed_at: u64,
    signer: &crate::crypto::Keypair,
) -> (
    chio_core_types::economic_continuity::EconomicStateAnchorPins,
    chio_core_types::economic_continuity::VerifiedEconomicStateView,
) {
    use chio_core_types::economic_continuity::{
        verify_economic_state_view, EconomicStateAnchorPins, EconomicStateAnchorViewV1,
        CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
    };

    heads.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    absent_resource_keys.sort();
    let pins = EconomicStateAnchorPins {
        anchor_id: "parametric-anchor".to_string(),
        namespace: "parametric-market".to_string(),
        signer_key_id: "parametric-anchor-key".to_string(),
        signer_key_epoch: 1,
        signer_public_key: signer.public_key(),
    };
    let mut view = EconomicStateAnchorViewV1 {
        schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_string(),
        anchor_id: pins.anchor_id.clone(),
        namespace: pins.namespace.clone(),
        checkpoint_sequence,
        checkpoint_digest,
        heads_root: String::new(),
        heads,
        absent_resource_keys,
        request_replays_root: String::new(),
        request_replays: Vec::new(),
        absent_request_keys: Vec::new(),
        observed_at,
        signer_key_id: pins.signer_key_id.clone(),
        signer_key_epoch: pins.signer_key_epoch,
        anchor_signature: String::new(),
    };
    require_ok(view.seal(signer), "seal parametric opening view");
    let verified = require_ok(
        verify_economic_state_view(view, &pins),
        "verify parametric opening view",
    );
    (pins, verified)
}

#[test]
fn parametric_opening_projects_two_direct_genesis_heads() {
    use chio_core_types::economic_continuity::{
        verify_economic_state_batch_advance, EconomicTransitionAuthorizationV1,
        EconomicTransitionProofVerifier,
    };

    let (policy, corpus, trigger, opened_at) =
        sample_parametric_opening(ParametricPayoutMode::Automatic);
    let signer = crate::crypto::Keypair::from_seed(&[62; 32]);
    let keys = vec![
        parametric_trigger_resource_key(trigger.identity()),
        parametric_claim_resource_key(trigger.identity()),
    ];
    let (pins, current) =
        verified_parametric_opening_view(Vec::new(), keys, 7, "71".repeat(32), opened_at, &signer);
    let projection = match require_ok(
        prepare_parametric_claim_opening(&current, &policy, &corpus, &trigger, opened_at),
        "project automatic opening",
    ) {
        ParametricClaimOpeningOutcomeV1::Projected(projection) => projection,
        ParametricClaimOpeningOutcomeV1::Replay(_) => panic!("new opening was replayed"),
    };
    let unsigned = projection.batch_template().unsigned_batch();
    assert!(unsigned.batch_id.is_empty());
    assert!(unsigned.checkpoint_digest.is_empty());
    assert!(unsigned.expected_heads_root.is_empty());
    assert!(unsigned.next_heads_root.is_empty());
    assert!(unsigned.anchor_signature.is_empty());
    assert_eq!(
        projection.state().trigger().signed_policy(),
        policy.signed()
    );
    assert_eq!(
        projection.state().trigger().evidence_manifest(),
        corpus.manifest()
    );
    let batch = seal_parametric_opening_projection(&projection, &signer);

    assert_eq!(projection.claim().state(), ParametricClaimStateV1::Ready);
    assert_eq!(batch.transitions.len(), 2);
    assert!(batch.effect_slots.is_empty());
    assert!(batch.request_replays.is_empty());
    assert!(batch.operation_id.is_none());
    assert!(batch.transitions.iter().all(|transition| {
        transition.expected_head_digest.is_none()
            && transition.next_head.head_version == 1
            && transition.next_head.resource_version == 1
            && transition.next_head.lifecycle_fence == 1
            && transition.next_head.trusted_clock_high_water == opened_at
            && transition.next_head.predecessor_digest.is_none()
            && transition.prepared_effect.is_none()
            && transition.transition_proof_digest == projection.proof_digest()
    }));
    assert!(batch
        .transitions
        .windows(2)
        .all(|pair| pair[0].resource_key < pair[1].resource_key));

    let verifier = ParametricClaimOpeningBatchVerifier::new(projection.as_ref().clone());
    assert_eq!(
        require_ok(
            verifier.verify_batch(&current, &batch),
            "verify exact projected batch",
        ),
        vec![EconomicTransitionAuthorizationV1::Direct; 2]
    );
    require_ok(
        verify_economic_state_batch_advance(&current, batch, &pins, &verifier),
        "verify automatic opening advance",
    );
}

#[test]
fn parametric_contestable_opening_and_progressed_replay_are_retained() {
    use chio_core_types::economic_continuity::EconomicContentV1;

    let (policy, corpus, trigger, opened_at) =
        sample_parametric_opening(ParametricPayoutMode::Contestable { window_seconds: 60 });
    let signer = crate::crypto::Keypair::from_seed(&[63; 32]);
    let keys = vec![
        parametric_trigger_resource_key(trigger.identity()),
        parametric_claim_resource_key(trigger.identity()),
    ];
    let (_, current) =
        verified_parametric_opening_view(Vec::new(), keys, 9, "72".repeat(32), opened_at, &signer);
    let projection = match require_ok(
        prepare_parametric_claim_opening(&current, &policy, &corpus, &trigger, opened_at),
        "project contestable opening",
    ) {
        ParametricClaimOpeningOutcomeV1::Projected(projection) => projection,
        ParametricClaimOpeningOutcomeV1::Replay(_) => panic!("new opening was replayed"),
    };
    let batch = seal_parametric_opening_projection(&projection, &signer);
    assert_eq!(
        projection.claim().state(),
        ParametricClaimStateV1::ContestOpen
    );
    assert_eq!(projection.claim().contest_deadline(), Some(opened_at + 60));

    let mut committed_heads = batch
        .transitions
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let claim_head = committed_heads
        .iter_mut()
        .find(|head| head.resource_key.resource_family == PARAMETRIC_CLAIM_RESOURCE_FAMILY)
        .unwrap_or_else(|| panic!("opening batch omitted claim head"));
    let predecessor_digest = require_ok(claim_head.digest(), "digest opening claim head");
    let EconomicContentV1::Inline { value } = &mut claim_head.state else {
        panic!("opening claim head did not retain inline state");
    };
    value["claim"]["state"] = serde_json::json!("contested");
    value["claim"]["version"] = serde_json::json!(2);
    value["claim"]["lifecycleFence"] = serde_json::json!(2);
    value["claim"]["contestDigest"] = serde_json::json!("ab".repeat(32));
    claim_head.head_version = 2;
    claim_head.resource_version = 2;
    claim_head.lifecycle_fence = 2;
    claim_head.lifecycle_state = "contested".to_string();
    claim_head.trusted_clock_high_water = opened_at + 10;
    claim_head.predecessor_digest = Some(predecessor_digest);
    claim_head.state_digest =
        require_ok(claim_head.state.digest(), "digest progressed claim state");
    let (_, committed) = verified_parametric_opening_view(
        committed_heads,
        Vec::new(),
        batch.checkpoint_sequence,
        batch.checkpoint_digest.clone(),
        opened_at + 11,
        &signer,
    );
    assert_eq!(
        require_err(
            prepare_parametric_claim_opening(
                &committed,
                &policy,
                &corpus,
                &trigger,
                opened_at + 10,
            ),
            "reject stale opening retry",
        ),
        ParametricLifecycleError::StaleTrustedTime
    );
    let replay = require_ok(
        prepare_parametric_claim_opening(&committed, &policy, &corpus, &trigger, opened_at + 12),
        "detect progressed opening replay",
    );
    let ParametricClaimOpeningOutcomeV1::Replay(replay) = replay else {
        panic!("progressed opening retry projected fresh state");
    };
    assert_eq!(replay.claim().state(), ParametricClaimStateV1::Contested);
    assert_eq!(replay.claim().version(), 2);

    let (_, future_poisoned) = verified_parametric_opening_view(
        committed.view().heads.clone(),
        Vec::new(),
        committed.view().checkpoint_sequence,
        committed.view().checkpoint_digest.clone(),
        opened_at + 9,
        &signer,
    );
    assert_eq!(
        require_err(
            prepare_parametric_claim_opening(
                &future_poisoned,
                &policy,
                &corpus,
                &trigger,
                opened_at + 12,
            ),
            "reject head clock beyond signed view time",
        ),
        ParametricLifecycleError::StaleTrustedTime
    );

    let mut rewritten_heads = committed.view().heads.clone();
    let rewritten_claim = rewritten_heads
        .iter_mut()
        .find(|head| head.resource_key.resource_family == PARAMETRIC_CLAIM_RESOURCE_FAMILY)
        .unwrap_or_else(|| panic!("committed view omitted claim head"));
    let EconomicContentV1::Inline { value } = &mut rewritten_claim.state else {
        panic!("progressed claim head did not retain inline state");
    };
    value["claim"]["openedAt"] = serde_json::json!(opened_at + 1);
    value["trustedOpenedAt"] = serde_json::json!(opened_at + 1);
    rewritten_claim.state_digest = require_ok(
        rewritten_claim.state.digest(),
        "digest rewritten opening time",
    );
    let (_, rewritten) = verified_parametric_opening_view(
        rewritten_heads,
        Vec::new(),
        committed.view().checkpoint_sequence,
        committed.view().checkpoint_digest.clone(),
        opened_at + 13,
        &signer,
    );
    assert_eq!(
        require_err(
            prepare_parametric_claim_opening(
                &rewritten,
                &policy,
                &corpus,
                &trigger,
                opened_at + 14,
            ),
            "reject rewritten immutable opening time",
        ),
        ParametricLifecycleError::Conflict
    );
}

#[test]
fn parametric_opening_replay_rejects_semantic_or_batch_drift() {
    use chio_core_types::economic_continuity::{
        EconomicContentV1, EconomicTransitionProofVerifier,
    };

    let (policy, corpus, trigger, opened_at) =
        sample_parametric_opening(ParametricPayoutMode::Automatic);
    let signer = crate::crypto::Keypair::from_seed(&[64; 32]);
    let keys = vec![
        parametric_trigger_resource_key(trigger.identity()),
        parametric_claim_resource_key(trigger.identity()),
    ];
    let (_, current) =
        verified_parametric_opening_view(Vec::new(), keys, 11, "73".repeat(32), opened_at, &signer);
    let projection = match require_ok(
        prepare_parametric_claim_opening(&current, &policy, &corpus, &trigger, opened_at),
        "project opening for drift checks",
    ) {
        ParametricClaimOpeningOutcomeV1::Projected(projection) => projection,
        ParametricClaimOpeningOutcomeV1::Replay(_) => panic!("new opening was replayed"),
    };
    let batch = seal_parametric_opening_projection(&projection, &signer);

    for path in [
        &["trigger", "magnitude", "value"][..],
        &["claim", "payoutAmount", "units"][..],
        &["claim", "beneficiaryId"][..],
        &["claim", "openedAt"][..],
        &["trustedOpenedAt"][..],
        &[
            "trigger",
            "signedPolicy",
            "body",
            "evaluatorAuthority",
            "authorityId",
        ][..],
    ] {
        let mut heads = batch
            .transitions
            .iter()
            .map(|transition| transition.next_head.clone())
            .collect::<Vec<_>>();
        for head in &mut heads {
            let EconomicContentV1::Inline { value } = &mut head.state else {
                panic!("opening head did not retain inline state");
            };
            let mut target = value;
            for key in &path[..path.len() - 1] {
                target = &mut target[*key];
            }
            let leaf = path[path.len() - 1];
            target[leaf] = match leaf {
                "units" | "value" => serde_json::json!(999_999),
                "openedAt" | "trustedOpenedAt" => serde_json::json!(opened_at + 1),
                _ => serde_json::json!("substituted-authority"),
            };
            head.state_digest = require_ok(head.state.digest(), "digest tampered state");
        }
        let (_, tampered) = verified_parametric_opening_view(
            heads,
            Vec::new(),
            batch.checkpoint_sequence,
            batch.checkpoint_digest.clone(),
            opened_at + 1,
            &signer,
        );
        assert_eq!(
            require_err(
                prepare_parametric_claim_opening(
                    &tampered,
                    &policy,
                    &corpus,
                    &trigger,
                    opened_at + 2,
                ),
                "reject semantic replay drift",
            ),
            ParametricLifecycleError::Conflict
        );
    }

    let mut mismatched_heads = batch
        .transitions
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    mismatched_heads[0].lifecycle_state = "fired".to_string();
    let (_, mismatched) = verified_parametric_opening_view(
        mismatched_heads,
        Vec::new(),
        batch.checkpoint_sequence,
        batch.checkpoint_digest.clone(),
        opened_at + 1,
        &signer,
    );
    assert_eq!(
        require_err(
            prepare_parametric_claim_opening(
                &mismatched,
                &policy,
                &corpus,
                &trigger,
                opened_at + 2,
            ),
            "reject mismatched trigger and claim heads",
        ),
        ParametricLifecycleError::Conflict
    );

    let verifier = ParametricClaimOpeningBatchVerifier::new(projection.as_ref().clone());
    let mut changed_batch = batch;
    changed_batch.issued_at += 1;
    require_ok(changed_batch.seal(&signer), "reseal changed opening batch");
    assert!(verifier.verify_batch(&current, &changed_batch).is_err());
}
