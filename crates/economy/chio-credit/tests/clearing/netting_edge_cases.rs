use super::*;

#[test]
fn reverse_bilateral_flows_cancel_before_matching() -> TestResult {
    let participant_authority = Keypair::from_seed(&[3; 32]);
    let obligation_authority = Keypair::from_seed(&[4; 32]);
    let request = signed_request(
        vec![
            reserved_obligation(1, "A", "B", "USD", 100)?,
            reserved_obligation(2, "B", "A", "USD", 40)?,
        ],
        &participant_authority,
        &obligation_authority,
    )?;
    let output = compute_netting_round(
        &request,
        &trust(&participant_authority, &obligation_authority),
    )?;

    assert_eq!(output.intents.len(), 1);
    assert_eq!(output.intents[0].debtor_participant_id, "A");
    assert_eq!(output.intents[0].creditor_participant_id, "B");
    assert_eq!(output.intents[0].amount.units, 60);
    Ok(())
}

#[test]
fn balanced_cycle_emits_no_settlement_intent() -> TestResult {
    let participant_authority = Keypair::from_seed(&[7; 32]);
    let obligation_authority = Keypair::from_seed(&[8; 32]);
    let request = signed_request(
        vec![
            reserved_obligation(1, "A", "B", "USD", 100)?,
            reserved_obligation(2, "B", "C", "USD", 100)?,
            reserved_obligation(3, "C", "A", "USD", 100)?,
        ],
        &participant_authority,
        &obligation_authority,
    )?;
    let output = compute_netting_round(
        &request,
        &trust(&participant_authority, &obligation_authority),
    )?;

    assert!(output.intents.is_empty());
    assert_eq!(output.output_manifest.settlement_intent_count, 0);
    assert!(output
        .participant_statements
        .iter()
        .all(|statement| statement.net_balance.units == 0));
    Ok(())
}

#[test]
fn aggregate_that_cannot_fit_the_wire_amount_rejects() -> TestResult {
    let participant_authority = Keypair::from_seed(&[9; 32]);
    let obligation_authority = Keypair::from_seed(&[14; 32]);
    let obligations = (1..=2)
        .map(|sequence| reserved_obligation(sequence, "A", "B", "USD", (1_u64 << 53) - 1))
        .collect::<Result<Vec<_>, _>>()?;
    let request = signed_request(obligations, &participant_authority, &obligation_authority)?;

    assert!(compute_netting_round(
        &request,
        &trust(&participant_authority, &obligation_authority)
    )
    .is_err());
    Ok(())
}

#[test]
fn duplicate_mixed_currency_and_incomplete_inputs_reject() -> TestResult {
    let participant_authority = Keypair::from_seed(&[5; 32]);
    let obligation_authority = Keypair::from_seed(&[6; 32]);
    let first = reserved_obligation(1, "A", "B", "USD", 100)?;
    let mut second = first.clone();
    second.source_sequence = 2;
    let duplicate = signed_request(
        vec![first, second],
        &participant_authority,
        &obligation_authority,
    )?;
    assert!(compute_netting_round(
        &duplicate,
        &trust(&participant_authority, &obligation_authority)
    )
    .is_err());

    let mixed = signed_request(
        vec![
            reserved_obligation(1, "A", "B", "USD", 100)?,
            reserved_obligation(2, "B", "C", "EUR", 100)?,
        ],
        &participant_authority,
        &obligation_authority,
    )?;
    assert!(compute_netting_round(
        &mixed,
        &trust(&participant_authority, &obligation_authority)
    )
    .is_err());

    let mut incomplete = signed_request(
        vec![reserved_obligation(1, "A", "B", "USD", 100)?],
        &participant_authority,
        &obligation_authority,
    )?;
    incomplete.input_manifest.body.has_more = true;
    incomplete.input_manifest.body.next_cursor = Some("cursor-2".to_owned());
    incomplete.input_manifest = SignedClearingInputManifestV1::sign(
        incomplete.input_manifest.body.clone(),
        &obligation_authority,
    )?;
    assert!(compute_netting_round(
        &incomplete,
        &trust(&participant_authority, &obligation_authority)
    )
    .is_err());

    let oversized = (1..=127)
        .map(|sequence| reserved_obligation(sequence, "A", "B", "USD", 1))
        .collect::<Result<Vec<_>, _>>()?;
    let oversized = signed_request(oversized, &participant_authority, &obligation_authority)?;
    assert!(compute_netting_round(
        &oversized,
        &trust(&participant_authority, &obligation_authority)
    )
    .is_err());
    Ok(())
}
