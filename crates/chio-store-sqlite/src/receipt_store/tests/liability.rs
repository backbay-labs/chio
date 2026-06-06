use super::super::*;
use super::support::*;

#[test]
fn liability_provider_registry_supersedes_and_resolves_latest_provider() {
    let path = unique_db_path("chio-liability-provider-registry");
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();

    let initial = signed_liability_provider(
        "lpr-1",
        "carrier-alpha",
        1_700_000_000,
        chio_kernel::LiabilityProviderLifecycleState::Active,
        None,
        true,
    );
    let superseding = signed_liability_provider(
        "lpr-2",
        "carrier-alpha",
        1_700_000_120,
        chio_kernel::LiabilityProviderLifecycleState::Active,
        Some("lpr-1"),
        true,
    );

    store.record_liability_provider(&initial).test_unwrap();
    store.record_liability_provider(&superseding).test_unwrap();

    let list = store
        .query_liability_providers(&chio_kernel::LiabilityProviderListQuery {
            provider_id: Some("carrier-alpha".to_string()),
            jurisdiction: Some("US-NY".to_string()),
            coverage_class: Some(chio_kernel::LiabilityCoverageClass::ToolExecution),
            currency: Some("usd".to_string()),
            lifecycle_state: None,
            limit: Some(10),
        })
        .test_unwrap();
    assert_eq!(list.summary.matching_providers, 2);
    assert_eq!(list.summary.active_providers, 1);
    assert_eq!(list.summary.superseded_providers, 1);
    assert_eq!(list.providers[0].provider.body.provider_record_id, "lpr-2");
    assert_eq!(list.providers[1].provider.body.provider_record_id, "lpr-1");
    assert_eq!(
        list.providers[1]
            .superseded_by_provider_record_id
            .as_deref(),
        Some("lpr-2")
    );

    let resolved = store
        .resolve_liability_provider(&chio_kernel::LiabilityProviderResolutionQuery {
            provider_id: "carrier-alpha".to_string(),
            jurisdiction: "us-ny".to_string(),
            coverage_class: chio_kernel::LiabilityCoverageClass::ToolExecution,
            currency: "USD".to_string(),
        })
        .test_unwrap();
    assert_eq!(resolved.provider.body.provider_record_id, "lpr-2");
    assert_eq!(resolved.matched_policy.jurisdiction, "us-ny");

    let _ = fs::remove_file(path);
}

#[test]
fn liability_market_workflow_tracks_quote_to_bound_coverage_with_manual_review() {
    let path = unique_db_path("chio-liability-market-workflow");
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();

    let provider = signed_liability_provider(
        "lpr-workflow-1",
        "carrier-alpha",
        1_700_000_000,
        chio_kernel::LiabilityProviderLifecycleState::Active,
        None,
        true,
    );
    let quote_request =
        signed_liability_quote_request("lqr-workflow-1", &provider, "subject-1", "USD");
    let quote_response =
        signed_liability_quote_response("lqp-workflow-1", quote_request.clone(), None);
    let authority = signed_liability_pricing_authority(
        "lpa-workflow-1",
        quote_request.clone(),
        "subject-1",
        true,
    );
    let manual_review =
        signed_manual_review_auto_bind("lab-workflow-1", authority.clone(), quote_response.clone());
    let placement = signed_liability_placement("lpl-workflow-1", quote_response.clone());
    let bound_coverage = signed_liability_bound_coverage("lbc-workflow-1", placement.clone());

    store.record_liability_provider(&provider).test_unwrap();
    store
        .record_liability_quote_request(&quote_request)
        .test_unwrap();
    store
        .record_liability_quote_response(&quote_response)
        .test_unwrap();
    store
        .record_liability_pricing_authority(&authority)
        .test_unwrap();
    store
        .record_liability_auto_bind_decision(&manual_review)
        .test_unwrap();
    store.record_liability_placement(&placement).test_unwrap();
    store
        .record_liability_bound_coverage(&bound_coverage)
        .test_unwrap();

    let report = store
        .query_liability_market_workflows(&chio_kernel::LiabilityMarketWorkflowQuery {
            quote_request_id: None,
            provider_id: Some("carrier-alpha".to_string()),
            agent_subject: Some("subject-1".to_string()),
            jurisdiction: Some("US-NY".to_string()),
            coverage_class: Some(chio_kernel::LiabilityCoverageClass::ToolExecution),
            currency: Some("usd".to_string()),
            limit: Some(10),
        })
        .test_unwrap();

    assert_eq!(report.summary.matching_requests, 1);
    assert_eq!(report.summary.quote_responses, 1);
    assert_eq!(report.summary.quoted_responses, 1);
    assert_eq!(report.summary.pricing_authorities, 1);
    assert_eq!(report.summary.auto_bind_decisions, 1);
    assert_eq!(report.summary.manual_review_decisions, 1);
    assert_eq!(report.summary.auto_bound_decisions, 0);
    assert_eq!(report.summary.placements, 1);
    assert_eq!(report.summary.bound_coverages, 1);

    let row = report.workflows.first().test_unwrap();
    assert_eq!(row.quote_request.body.quote_request_id, "lqr-workflow-1");
    assert_eq!(
        row.latest_quote_response
            .as_ref()
            .test_unwrap()
            .body
            .quote_response_id,
        "lqp-workflow-1"
    );
    assert_eq!(
        row.pricing_authority
            .as_ref()
            .test_unwrap()
            .body
            .authority_id,
        "lpa-workflow-1"
    );
    assert_eq!(
        row.latest_auto_bind_decision
            .as_ref()
            .test_unwrap()
            .body
            .disposition,
        chio_kernel::LiabilityAutoBindDisposition::ManualReview
    );
    assert_eq!(
        row.placement.as_ref().test_unwrap().body.placement_id,
        "lpl-workflow-1"
    );
    assert_eq!(
        row.bound_coverage
            .as_ref()
            .test_unwrap()
            .body
            .bound_coverage_id,
        "lbc-workflow-1"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn liability_market_rejects_unsupported_requests_and_stale_active_quotes() {
    let path = unique_db_path("chio-liability-market-conflicts");
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();

    let provider = signed_liability_provider(
        "lpr-conflict-1",
        "carrier-alpha",
        1_700_000_000,
        chio_kernel::LiabilityProviderLifecycleState::Active,
        None,
        true,
    );
    store.record_liability_provider(&provider).test_unwrap();

    let unsupported_request =
        signed_liability_quote_request("lqr-conflict-eur", &provider, "subject-1", "EUR");
    assert!(matches!(
        store.record_liability_quote_request(&unsupported_request),
        Err(chio_kernel::ReceiptStoreError::Conflict(message))
            if message.contains("does not support")
    ));

    let quote_request =
        signed_liability_quote_request("lqr-conflict-1", &provider, "subject-1", "USD");
    store
        .record_liability_quote_request(&quote_request)
        .test_unwrap();

    let initial_response =
        signed_liability_quote_response("lqp-conflict-1", quote_request.clone(), None);
    store
        .record_liability_quote_response(&initial_response)
        .test_unwrap();

    let duplicate_active =
        signed_liability_quote_response("lqp-conflict-2", quote_request.clone(), None);
    assert!(matches!(
        store.record_liability_quote_response(&duplicate_active),
        Err(chio_kernel::ReceiptStoreError::Conflict(message))
            if message.contains("already has active response")
    ));

    let superseding_response = signed_liability_quote_response(
        "lqp-conflict-3",
        quote_request.clone(),
        Some("lqp-conflict-1"),
    );
    store
        .record_liability_quote_response(&superseding_response)
        .test_unwrap();

    let stale_placement =
        signed_liability_placement("lpl-conflict-stale", initial_response.clone());
    assert!(matches!(
        store.record_liability_placement(&stale_placement),
        Err(chio_kernel::ReceiptStoreError::Conflict(message))
            if message.contains("is superseded")
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn liability_claim_lifecycle_persists_package_through_payout_receipt() {
    thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let path = unique_db_path("chio-liability-claim-lifecycle");
            let mut store = SqliteReceiptStore::open(&path).test_unwrap();
            let subject_key = "subject-claim";
            let far_future = 4_102_444_800;

            let provider = signed_liability_provider(
                "lpr-claim-1",
                "carrier-claim",
                1_700_000_000,
                chio_kernel::LiabilityProviderLifecycleState::Active,
                None,
                true,
            );
            let quote_request =
                signed_liability_quote_request("lqr-claim-1", &provider, subject_key, "USD");
            let quote_response =
                signed_liability_quote_response("lqp-claim-1", quote_request.clone(), None);
            let placement = signed_liability_placement("lpl-claim-1", quote_response.clone());
            let bound_coverage = signed_liability_bound_coverage("lbc-claim-1", placement.clone());

            let facility = signed_credit_facility_fixture(
                subject_key,
                "cfd-claim-1",
                1_700_000_100,
                far_future,
                chio_kernel::CreditFacilityDisposition::Grant,
                chio_kernel::CreditFacilityLifecycleState::Active,
                None,
            );
            let bond = signed_credit_bond_fixture(
                subject_key,
                "cfd-claim-1",
                "bond-claim-1",
                1_700_000_200,
                far_future,
                chio_kernel::CreditBondDisposition::Lock,
                chio_kernel::CreditBondLifecycleState::Active,
                None,
            );
            let loss_event = signed_credit_loss_lifecycle_fixture(
                subject_key,
                "cfd-claim-1",
                "bond-claim-1",
                "loss-claim-1",
                1_700_000_300,
                chio_kernel::CreditLossLifecycleEventKind::Delinquency,
                chio_kernel::CreditBondLifecycleState::Impaired,
                usd(5_000),
            );

            store.record_liability_provider(&provider).test_unwrap();
            store
                .record_liability_quote_request(&quote_request)
                .test_unwrap();
            store
                .record_liability_quote_response(&quote_response)
                .test_unwrap();
            store.record_liability_placement(&placement).test_unwrap();
            store
                .record_liability_bound_coverage(&bound_coverage)
                .test_unwrap();
            store.record_credit_facility(&facility).test_unwrap();
            store.record_credit_bond(&bond).test_unwrap();
            store
                .record_credit_loss_lifecycle(&loss_event)
                .test_unwrap();

            let claim_receipt_1 = sample_receipt_with_id("claim-rcpt-1");
            let claim_receipt_2 = sample_receipt_with_id("claim-rcpt-2");
            store.append_chio_receipt(&claim_receipt_1).test_unwrap();
            store.append_chio_receipt(&claim_receipt_2).test_unwrap();

            let missing_receipt_claim = signed_liability_claim_package_fixture(
                "claim-missing-receipt",
                bound_coverage.clone(),
                bond.clone(),
                loss_event.clone(),
                vec!["missing-claim-receipt".to_string()],
            );
            assert!(matches!(
                store.record_liability_claim_package(&missing_receipt_claim),
                Err(chio_kernel::ReceiptStoreError::NotFound(message))
                    if message.contains("missing-claim-receipt")
            ));

            let claim = signed_liability_claim_package_fixture(
                "claim-1",
                bound_coverage.clone(),
                bond.clone(),
                loss_event.clone(),
                vec![claim_receipt_1.id.clone(), claim_receipt_2.id.clone()],
            );
            store.record_liability_claim_package(&claim).test_unwrap();
            assert!(matches!(
                store.record_liability_claim_package(&claim),
                Err(chio_kernel::ReceiptStoreError::Conflict(message))
                    if message.contains("already exists")
            ));

            let response =
                signed_liability_claim_response_fixture("claim-response-1", claim, usd(3_000));
            store
                .record_liability_claim_response(&response)
                .test_unwrap();

            let dispute = signed_liability_claim_dispute_fixture("claim-dispute-1", response);
            store.record_liability_claim_dispute(&dispute).test_unwrap();

            let adjudication = signed_liability_claim_adjudication_fixture(
                "claim-adjudication-1",
                dispute,
                usd(4_000),
            );
            store
                .record_liability_claim_adjudication(&adjudication)
                .test_unwrap();

            let payout_instruction = signed_liability_claim_payout_instruction_fixture(
                "claim-payout-instruction-1",
                adjudication,
            );
            store
                .record_liability_claim_payout_instruction(&payout_instruction)
                .test_unwrap();

            let payout_receipt = signed_liability_claim_payout_receipt_fixture(
                "claim-payout-receipt-1",
                payout_instruction,
            );
            store
                .record_liability_claim_payout_receipt(&payout_receipt)
                .test_unwrap();

            let connection = store.connection().test_unwrap();
            for table in [
                "liability_claim_packages",
                "liability_claim_responses",
                "liability_claim_disputes",
                "liability_claim_adjudications",
                "liability_claim_payout_instructions",
                "liability_claim_payout_receipts",
            ] {
                let count: i64 = connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .test_unwrap();
                assert_eq!(count, 1, "expected one row in {table}");
            }

            let stored_claim_id: String = connection
                .query_row(
                    "SELECT claim_id
                     FROM liability_claim_payout_receipts
                     WHERE payout_receipt_id = ?1",
                    ["claim-payout-receipt-1"],
                    |row| row.get(0),
                )
                .test_unwrap();
            assert_eq!(stored_claim_id, "claim-1");

            let _ = fs::remove_file(path);
        })
        .test_unwrap()
        .join()
        .test_unwrap();
}
