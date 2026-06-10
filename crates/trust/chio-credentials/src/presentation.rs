pub fn respond_to_passport_presentation_challenge(
    holder_keypair: &Keypair,
    passport: &AgentPassport,
    challenge: &PassportPresentationChallenge,
    now: u64,
) -> Result<PassportPresentationResponse, CredentialError> {
    verify_passport_presentation_challenge(challenge, now)?;
    verify_agent_passport(passport, now)?;

    let holder_did = DidChio::from_public_key(holder_keypair.public_key())?;
    if holder_did.to_string() != passport.subject {
        return Err(CredentialError::PresentationHolderMismatch);
    }

    let passport = present_agent_passport(passport, &challenge_presentation_options(challenge))?;
    let unsigned = UnsignedPassportPresentationResponse {
        schema: PASSPORT_PRESENTATION_RESPONSE_SCHEMA.to_string(),
        challenge: challenge.clone(),
        passport: passport.clone(),
    };
    let (signature, _) = holder_keypair.sign_canonical(&unsigned)?;

    Ok(PassportPresentationResponse {
        schema: PASSPORT_PRESENTATION_RESPONSE_SCHEMA.to_string(),
        challenge: challenge.clone(),
        passport,
        proof: PresentationProof {
            proof_type: PROOF_TYPE.to_string(),
            created: rfc3339_from_unix(now)?,
            proof_purpose: PRESENTATION_PROOF_PURPOSE.to_string(),
            verification_method: holder_did.verification_method_id(),
            proof_value: signature.to_hex(),
        },
    })
}

pub fn verify_passport_presentation_response(
    response: &PassportPresentationResponse,
    expected_challenge: Option<&PassportPresentationChallenge>,
    now: u64,
) -> Result<PassportPresentationVerification, CredentialError> {
    verify_passport_presentation_response_with_policy(response, expected_challenge, now, None, None)
}

pub fn verify_passport_presentation_response_with_policy(
    response: &PassportPresentationResponse,
    expected_challenge: Option<&PassportPresentationChallenge>,
    now: u64,
    resolved_policy: Option<&PassportVerifierPolicy>,
    policy_source_override: Option<String>,
) -> Result<PassportPresentationVerification, CredentialError> {
    if !is_supported_passport_presentation_response_schema(&response.schema) {
        return Err(CredentialError::InvalidPresentationSchema);
    }
    verify_passport_presentation_challenge(&response.challenge, now)?;
    if let Some(expected_challenge) = expected_challenge {
        if expected_challenge != &response.challenge {
            return Err(CredentialError::ChallengeMismatch);
        }
    }
    if response.proof.proof_type != PROOF_TYPE {
        return Err(CredentialError::InvalidPresentationProofType);
    }
    if response.proof.proof_purpose != PRESENTATION_PROOF_PURPOSE {
        return Err(CredentialError::InvalidPresentationProofPurpose);
    }

    let passport_verification = verify_agent_passport(&response.passport, now)?;
    let subject_did = DidChio::from_str(&response.passport.subject)?;
    if response.proof.verification_method != subject_did.verification_method_id() {
        return Err(CredentialError::PresentationVerificationMethodMismatch);
    }

    if !response.challenge.issuer_allowlist.is_empty() {
        for credential in &response.passport.credentials {
            if !response
                .challenge
                .issuer_allowlist
                .contains(&credential.unsigned.issuer)
            {
                return Err(CredentialError::PresentationIssuerNotAllowed(
                    credential.unsigned.issuer.clone(),
                ));
            }
        }
    }
    if let Some(max_credentials) = response.challenge.max_credentials {
        let actual = response.passport.credentials.len();
        if actual > max_credentials {
            return Err(CredentialError::PresentationCredentialLimitExceeded {
                max: max_credentials,
                actual,
            });
        }
    }

    let challenge_issued_at = unix_from_rfc3339(&response.challenge.issued_at)?;
    let challenge_expires_at = unix_from_rfc3339(&response.challenge.expires_at)?;
    let proof_created = unix_from_rfc3339(&response.proof.created)?;
    if proof_created > now {
        return Err(CredentialError::PresentationProofFromFuture);
    }
    if proof_created < challenge_issued_at || proof_created > challenge_expires_at {
        return Err(CredentialError::PresentationProofOutsideChallengeWindow);
    }

    let unsigned = UnsignedPassportPresentationResponse {
        schema: response.schema.clone(),
        challenge: response.challenge.clone(),
        passport: response.passport.clone(),
    };
    let signature = Signature::from_hex(&response.proof.proof_value)?;
    let signed = subject_did
        .public_key()
        .verify(&canonical_json_bytes(&unsigned)?, &signature);
    if !signed {
        return Err(CredentialError::InvalidPresentationSignature);
    }

    let evaluation_policy = resolved_policy.or(response.challenge.policy.as_ref());
    let policy_source = if evaluation_policy.is_some() {
        Some(policy_source_override.unwrap_or_else(|| {
            if response.challenge.policy.is_some() {
                "embedded".to_string()
            } else if response.challenge.policy_ref.is_some() {
                "reference".to_string()
            } else {
                "resolved".to_string()
            }
        }))
    } else {
        None
    };
    let policy_evaluation = evaluation_policy
        .map(|policy| evaluate_agent_passport(&response.passport, now, policy))
        .transpose()?;
    let accepted = policy_evaluation
        .as_ref()
        .is_none_or(|evaluation| evaluation.accepted);

    Ok(PassportPresentationVerification {
        subject: passport_verification.subject,
        verifier: response.challenge.verifier.clone(),
        challenge_id: response.challenge.challenge_id.clone(),
        nonce: response.challenge.nonce.clone(),
        verified_at: now,
        passport_id: passport_verification.passport_id,
        credential_count: passport_verification.credential_count,
        valid_until: passport_verification.valid_until,
        challenge_expires_at: response.challenge.expires_at.clone(),
        accepted,
        enterprise_identity_provenance: passport_verification.enterprise_identity_provenance,
        passport_lifecycle: passport_verification.passport_lifecycle,
        policy_id: response
            .challenge
            .policy_ref
            .as_ref()
            .map(|reference| reference.policy_id.clone()),
        policy_evaluated: policy_evaluation.is_some(),
        policy_source,
        replay_state: None,
        policy_evaluation,
    })
}
