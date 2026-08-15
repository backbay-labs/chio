#[test]
fn activation_rejects_market_terms_before_their_issuance_time() {
    with_fiscal(|resolver| {
        let mut web = base_web();
        let mut terms = web.terms.body.clone();
        terms.issued_at = NOW + 1;
        terms.terms_id.clear();
        terms.terms_id = compute_terms_id(&terms).test_expect("future terms id");
        web.terms = SignedFindingMarketTerms::sign(terms, &web.seller)
            .test_expect("sign future terms");
        web.terms_sha256 =
            signed_envelope_sha256(&web.terms).test_expect("future terms digest");
        web.admission = signed_admission(&web.venue, &web.finding, &web.bindings());

        let mut context = web.context(resolver);
        context.allocation_snapshot.status = FindingAllocationStatus::Available;
        context.allocation_snapshot.active_admission_id = None;
        assert_eq!(
            verify_finding_admission_for_activation(&web.admission, &context).err(),
            Some(FindingAdmissionError::TermsNotYetLive)
        );
    });
}

#[test]
fn verified_admission_cannot_be_reused_before_issuance() {
    with_fiscal(|resolver| {
        let web = base_web();
        let witness = verify_finding_admission(&web.admission, &web.context(resolver))
            .test_expect("admission");
        let agent = keypair(31);
        let listing = finding_listing_entry(
            &web.operator,
            &web.finding,
            witness.capability_scope(),
            900,
        );
        let request = SignedBidRequest::sign(finding_bid_request(&web.finding, 900), &agent)
            .test_expect("sign bid");
        let mut context = purchase_mint_context(&listing, &web.operator, &agent);
        context.now = witness.issued_at().saturating_sub(1);

        assert_eq!(
            bid_with_finding_admission(&request, context, &witness).err(),
            Some(FindingAdmissionError::AdmissionNotYetLive)
        );
    });
}

#[test]
fn purchase_accept_cannot_reuse_admission_before_issuance() {
    with_fiscal(|resolver| {
        let web = base_web();
        let witness = verify_finding_admission(&web.admission, &web.context(resolver))
            .test_expect("admission");
        let agent = keypair(31);
        let ask = signed_purchase_ask(&web, resolver, &agent, 900);
        let ask_digest = sha256_hex(
            &canonical_json_bytes(&ask.body).test_expect("canonical purchase ask body"),
        );
        let reservation_authority = keypair(41);
        let receipt = chio_open_market::bidding::SignedReservationReceipt::sign(
            chio_open_market::bidding::ReservationReceipt {
                schema: chio_open_market::bidding::RESERVATION_RECEIPT_SCHEMA.to_owned(),
                receipt_id: "reservation-before-admission".to_owned(),
                agent_id: ask.body.agent_id.clone(),
                listing_id: ask.body.listing_id.clone(),
                ask_digest,
                reserved_amount: ask.body.quoted_price.clone(),
            },
            &reservation_authority,
        )
        .test_expect("sign reservation");
        let reservation =
            chio_open_market::bidding::VerifiedReservationReceipt::from_signed(
                &receipt,
                &reservation_authority.public_key(),
            )
            .test_expect("verify reservation");

        assert_eq!(
            accept_finding_purchase(
                &ask,
                &reservation,
                &agent,
                witness.issued_at().saturating_sub(1),
                &witness,
                &web.finding,
            )
            .err(),
            Some(FindingAdmissionError::AdmissionNotYetLive)
        );
    });
}

#[test]
fn purchase_mint_requires_the_admitted_listing_provider() {
    with_fiscal(|resolver| {
        let web = base_web();
        let witness = verify_finding_admission(&web.admission, &web.context(resolver))
            .test_expect("admission");
        let agent = keypair(31);
        let attacker = keypair(91);
        let listing = finding_listing_entry(
            &web.operator,
            &web.finding,
            witness.capability_scope(),
            900,
        );
        let request = SignedBidRequest::sign(finding_bid_request(&web.finding, 900), &agent)
            .test_expect("sign bid");

        assert_eq!(
            bid_with_finding_purchase(
                &request,
                purchase_mint_context(&listing, &attacker, &agent),
                &witness,
                &web.finding,
            )
            .err(),
            Some(FindingAdmissionError::ProviderAuthorityMismatch)
        );
    });
}

#[test]
fn purchase_mint_requires_the_seller_authorized_reveal_tool() {
    with_fiscal(|resolver| {
        let web = base_web();
        let witness = verify_finding_admission(&web.admission, &web.context(resolver))
            .test_expect("admission");
        let agent = keypair(31);
        let listing = finding_listing_entry(
            &web.operator,
            &web.finding,
            witness.capability_scope(),
            900,
        );
        let mut request = finding_bid_request(&web.finding, 900);
        request.requested_scope.tool_name = "delete_finding".to_owned();
        let request = SignedBidRequest::sign(request, &agent).test_expect("sign wrong-tool bid");

        assert_eq!(
            bid_with_finding_purchase(
                &request,
                purchase_mint_context(&listing, &web.operator, &agent),
                &witness,
                &web.finding,
            )
            .err(),
            Some(FindingAdmissionError::ProviderToolMismatch)
        );
    });
}

#[test]
fn purchase_accept_requires_the_exact_minting_admission() {
    with_fiscal(|resolver| {
        let web = base_web();
        let original = verify_finding_admission(&web.admission, &web.context(resolver))
            .test_expect("original admission");
        let agent = keypair(31);
        let listing = finding_listing_entry(
            &web.operator,
            &web.finding,
            original.capability_scope(),
            900,
        );
        let request = SignedBidRequest::sign(finding_bid_request(&web.finding, 900), &agent)
            .test_expect("sign purchase bid");
        let ask = bid_with_finding_purchase(
            &request,
            purchase_mint_context(&listing, &web.operator, &agent),
            &original,
            &web.finding,
        )
        .test_expect("purchase mint");

        let mut replacement_body = web.admission.body.clone();
        replacement_body.metadata_url.push_str("?revision=2");
        replacement_body.admission_id.clear();
        replacement_body.admission_id =
            compute_admission_id(&replacement_body).test_expect("replacement admission id");
        let replacement = SignedFindingAdmission::sign(replacement_body, &web.venue)
            .test_expect("sign replacement admission");
        let mut replacement_context = web.context(resolver);
        replacement_context.allocation_snapshot.active_admission_id =
            Some(replacement.body.admission_id.clone());
        let replacement_witness = verify_finding_admission(&replacement, &replacement_context)
            .test_expect("replacement admission");

        let ask_digest = sha256_hex(
            &canonical_json_bytes(&ask.body).test_expect("canonical purchase ask body"),
        );
        let reservation_authority = keypair(41);
        let receipt = chio_open_market::bidding::SignedReservationReceipt::sign(
            chio_open_market::bidding::ReservationReceipt {
                schema: chio_open_market::bidding::RESERVATION_RECEIPT_SCHEMA.to_owned(),
                receipt_id: "reservation-replacement-admission".to_owned(),
                agent_id: ask.body.agent_id.clone(),
                listing_id: ask.body.listing_id.clone(),
                ask_digest,
                reserved_amount: ask.body.quoted_price.clone(),
            },
            &reservation_authority,
        )
        .test_expect("sign reservation");
        let reservation = chio_open_market::bidding::VerifiedReservationReceipt::from_signed(
            &receipt,
            &reservation_authority.public_key(),
        )
        .test_expect("verify reservation");

        assert_eq!(
            accept_finding_purchase(
                &ask,
                &reservation,
                &agent,
                NOW + 60,
                &replacement_witness,
                &web.finding,
            )
            .err(),
            Some(FindingAdmissionError::MintingAdmissionMismatch)
        );
    });
}
