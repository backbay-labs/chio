pub fn create_signed_passport_verifier_policy(
    signer_keypair: &Keypair,
    policy_id: impl Into<String>,
    verifier: impl Into<String>,
    created_at: u64,
    expires_at: u64,
    policy: PassportVerifierPolicy,
) -> Result<SignedPassportVerifierPolicy, CredentialError> {
    let body = SignedPassportVerifierPolicyBody {
        schema: PASSPORT_VERIFIER_POLICY_SCHEMA.to_string(),
        policy_id: policy_id.into(),
        verifier: verifier.into(),
        signer_public_key: signer_keypair.public_key(),
        created_at,
        expires_at,
        policy,
    };
    verify_signed_passport_verifier_policy_body(&body)?;
    let (signature, _) = signer_keypair.sign_canonical(&body)?;
    let document = SignedPassportVerifierPolicy { body, signature };
    verify_signed_passport_verifier_policy(&document)?;
    Ok(document)
}

pub fn verify_signed_passport_verifier_policy(
    document: &SignedPassportVerifierPolicy,
) -> Result<(), CredentialError> {
    verify_signed_passport_verifier_policy_body(&document.body)?;
    if !document
        .body
        .signer_public_key
        .verify_canonical(&document.body, &document.signature)?
    {
        return Err(CredentialError::InvalidSignedVerifierPolicySignature);
    }
    Ok(())
}

pub fn ensure_signed_passport_verifier_policy_active(
    document: &SignedPassportVerifierPolicy,
    now: u64,
) -> Result<(), CredentialError> {
    if now < document.body.created_at {
        return Err(CredentialError::SignedVerifierPolicyNotYetValid);
    }
    if now > document.body.expires_at {
        return Err(CredentialError::SignedVerifierPolicyExpired);
    }
    Ok(())
}

