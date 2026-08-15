#[test]
fn fee_schedule_issued_after_the_verification_clock_rejects() {
    with_fiscal(|resolver| {
        let mut web = base_web();
        let schedule_body = &web.schedule.body;
        let request = OpenMarketFeeScheduleIssueRequest {
            scope: schedule_body.scope.clone(),
            publication_fee: schedule_body.publication_fee.clone(),
            dispute_fee: schedule_body.dispute_fee.clone(),
            market_participation_fee: schedule_body.market_participation_fee.clone(),
            bond_requirements: schedule_body.bond_requirements.clone(),
            issued_by: schedule_body.issued_by.clone(),
            issued_at: Some(NOW + 1),
            expires_at: schedule_body.expires_at,
            note: schedule_body.note.clone(),
        };
        let future_schedule = build_open_market_fee_schedule_artifact(
            &schedule_body.governing_operator_id,
            schedule_body.governing_operator_name.clone(),
            &request,
            NOW + 1,
        )
        .test_expect("build future-issued fee schedule");
        web.schedule = SignedOpenMarketFeeSchedule::sign(future_schedule, &web.operator)
            .test_expect("sign future-issued fee schedule");
        web.schedule_sha256 =
            signed_fee_schedule_digest(&web.schedule).test_expect("future schedule digest");
        web.backing = signed_backing(
            &keypair(4),
            &web.seller,
            &web.finding,
            &web.authorization_sha256,
            &web.schedule_sha256,
            &web.terms_sha256,
        );
        web.backing_sha256 =
            signed_envelope_sha256(&web.backing).test_expect("future schedule backing digest");
        let bindings = web.bindings();
        web.admission = signed_admission(&web.venue, &web.finding, &bindings);

        let mut context = web.context(resolver);
        context.fee_schedule_gate = FindingFeeScheduleGate::Legacy;
        context.allocation_snapshot.status = FindingAllocationStatus::Available;
        context.allocation_snapshot.active_admission_id = None;
        assert_eq!(
            verify_finding_admission_for_activation(&web.admission, &context).err(),
            Some(FindingAdmissionError::FeeScheduleNotYetLive)
        );
    });
}
