use super::*;

#[test]
fn native_trace_observations_are_signed_and_non_vacuous() {
    let (encoded, trusted_key) = capture_native_revocation_trace().expect("trace");
    assert_eq!(trusted_key.to_hex(), NATIVE_TRACE_OBSERVER_KEY.trim());
    let observations =
        chio_trace_validate::decode_observations(&encoded, std::slice::from_ref(&trusted_key))
            .expect("decode trace");
    assert!(observations.observations()[0]
        .body
        .trace_id
        .starts_with("runtime:"));
    let chio_trace_validate::ObservationEvent::Revoke {
        capability_id: revoked_ancestor,
        ..
    } = &observations.observations()[1].body.event
    else {
        panic!("second observation is not a revocation");
    };
    let chio_trace_validate::ObservationEvent::Evaluate {
        receipt,
        revocation_subject_ids,
        revocation_source_id,
        ..
    } = &observations.observations()[2].body.event
    else {
        panic!("third observation is not an evaluation");
    };
    assert_ne!(&receipt.capability_id, revoked_ancestor);
    assert_eq!(
        revocation_subject_ids,
        &[receipt.capability_id.clone(), revoked_ancestor.clone()]
    );
    assert_eq!(revocation_source_id.as_ref(), Some(revoked_ancestor));
    let projection =
        chio_trace_validate::project_revocation_trace(&observations).expect("project trace");

    assert_eq!(projection.action_coverage().revoke, 1);
    assert_eq!(projection.action_coverage().evaluate, 2);
    assert_eq!(projection.action_coverage().post_revocation_evaluate, 1);
    assert_eq!(projection.invariant_witnesses().attenuated_admission, 2);
}

#[test]
fn runtime_trace_refuses_a_dropped_admission_callback() {
    let error = capture_runtime_revocation_trace_with_store(
        "native-dropped-admission-calibration",
        false,
        true,
        TraceRevocationTarget::DelegationAncestor,
        RuntimeTraceMutation::None,
    )
    .expect_err("dropped admission callback must reject finalization");
    assert!(
        error.to_string().contains("no matching admission callback"),
        "unexpected recorder error: {error}"
    );
}

#[test]
fn blind_store_capture_retains_the_prior_direct_revocation() {
    let (encoded, trusted_key) = capture_runtime_revocation_trace_with_store(
        "native-blind-store-calibration-test",
        true,
        false,
        TraceRevocationTarget::PresentedCapability,
        RuntimeTraceMutation::None,
    )
    .expect("capture blind-store trace");
    let decoded = chio_trace_validate::decode_observations(&encoded, &[trusted_key])
        .expect("decode blind-store trace");
    let projection =
        chio_trace_validate::project_revocation_trace(&decoded).expect("project blind-store trace");
    assert!(projection.events().iter().any(|event| matches!(
        &event.action,
        chio_trace_validate::ProjectedAction::Evaluate {
            verdict,
            seen_epoch,
            ..
        } if verdict == "allow" && *seen_epoch > 0
    )));
}

#[test]
fn runtime_trace_mutations_reach_the_formal_projection() {
    for (context, mutation) in [
        (
            "native-monotone-calibration-test",
            RuntimeTraceMutation::DuplicateReceiptTime,
        ),
        (
            "native-attenuation-calibration-test",
            RuntimeTraceMutation::DepthAboveLimit,
        ),
        (
            "native-freshness-calibration-test",
            RuntimeTraceMutation::FutureRevocationEpoch,
        ),
    ] {
        let (encoded, trusted_key) = capture_runtime_revocation_trace_with_store(
            context,
            false,
            false,
            TraceRevocationTarget::DelegationAncestor,
            mutation,
        )
        .expect("capture calibrated runtime trace");
        let decoded = chio_trace_validate::decode_observations(&encoded, &[trusted_key])
            .expect("decode calibrated runtime trace");
        let projection = chio_trace_validate::project_revocation_trace(&decoded)
            .expect("project calibrated runtime trace");
        assert_eq!(projection.events().len(), 3);

        match mutation {
            RuntimeTraceMutation::DuplicateReceiptTime => {
                let times = projection
                    .events()
                    .iter()
                    .filter_map(|event| match &event.action {
                        chio_trace_validate::ProjectedAction::Evaluate { receipt_time, .. } => {
                            Some(*receipt_time)
                        }
                        chio_trace_validate::ProjectedAction::Revoke { .. } => None,
                    })
                    .collect::<Vec<_>>();
                assert_eq!(times, [1, 1]);
            }
            RuntimeTraceMutation::DepthAboveLimit => {
                assert_eq!(projection.depth_max(), 4);
                assert!(projection.events().iter().any(|event| matches!(
                    &event.action,
                    chio_trace_validate::ProjectedAction::Evaluate {
                        delegation_depth: 5,
                        ..
                    }
                )));
            }
            RuntimeTraceMutation::FutureRevocationEpoch => {
                assert!(projection.events().iter().any(|event| matches!(
                    &event.action,
                    chio_trace_validate::ProjectedAction::Revoke { epoch: 4 }
                )));
            }
            RuntimeTraceMutation::None => unreachable!(),
        }
    }
}

#[test]
fn load_native_scenarios_reads_checked_in_suite() {
    let repo_root = crate::default_repo_root();
    let scenarios =
        load_native_scenarios_from_dir(repo_root.join("tests/conformance/native/scenarios"))
            .expect("load native scenarios");
    assert_eq!(scenarios.len(), 6);
    assert!(scenarios
        .iter()
        .any(|scenario| { scenario.category == NativeScenarioCategory::CapabilityValidation }));
    assert!(scenarios.iter().any(|scenario| {
        scenario.category == NativeScenarioCategory::GovernedTransactionEnforcement
    }));
}

#[test]
fn load_native_scenarios_rejects_missing_directory() {
    let missing = std::env::temp_dir().join(format!(
        "chio-conformance-native-missing-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&missing);

    match load_native_scenarios_from_dir(&missing) {
        Ok(scenarios) => panic!("missing native scenario directory should fail: {scenarios:?}"),
        Err(error) => assert!(error.to_string().contains("directory")),
    }
}

#[test]
fn load_native_scenarios_rejects_empty_directory() {
    let dir = std::env::temp_dir().join(format!(
        "chio-conformance-native-empty-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create empty native scenario dir");

    match load_native_scenarios_from_dir(&dir) {
        Ok(scenarios) => panic!("empty native scenario directory should fail: {scenarios:?}"),
        Err(error) => assert!(error.to_string().contains("empty")),
    }

    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn load_native_scenarios_rejects_symlinked_json_file() {
    let dir = std::env::temp_dir().join(format!(
        "chio-conformance-native-symlink-{}",
        std::process::id()
    ));
    let outside = std::env::temp_dir().join(format!(
        "chio-conformance-native-symlink-outside-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&outside);
    fs::create_dir_all(&dir).expect("create native scenario dir");
    fs::create_dir_all(&outside).expect("create outside dir");
    fs::write(
        outside.join("escape.json"),
        r#"{
              "id": "escape",
              "title": "Escape",
              "category": "capability_validation",
              "driver": "artifact",
              "fixture": "valid-capability",
              "specVersion": "1.0",
              "assertions": []
            }"#,
    )
    .expect("write outside scenario");
    std::os::unix::fs::symlink(outside.join("escape.json"), dir.join("escape.json"))
        .expect("create scenario symlink");

    match load_native_scenarios_from_dir(&dir) {
        Ok(scenarios) => panic!("symlinked native scenario should fail: {scenarios:?}"),
        Err(error) => assert!(error.to_string().contains("symlink")),
    }

    let _ = fs::remove_dir_all(dir);
    let _ = fs::remove_dir_all(outside);
}

#[test]
fn native_fixture_responses_include_governed_receipt_metadata() {
    let request = build_governed_request();
    let messages = fixture_messages_for_request(&request);
    let (_, receipt) = terminal_response(&messages).expect("terminal response");
    assert!(receipt.verify_signature().expect("verify signature"));
    assert!(receipt
        .metadata
        .as_ref()
        .and_then(|value| value.get("governed_transaction"))
        .is_some());
}
