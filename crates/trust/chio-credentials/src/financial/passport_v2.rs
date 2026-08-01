use super::*;

#[path = "passport_v2/digest.rs"]
mod digest;
use digest::*;

pub fn issue_passport_source_manifest_v2(
    issuer_keypair: &Keypair,
    subject: &str,
    credentials: &[PassportCredentialV2],
    issued_at: u64,
    expires_at: u64,
) -> Result<
    (
        SignedPassportSourceManifestV2,
        Vec<PassportCredentialMembershipProofV2>,
    ),
    CredentialError,
> {
    issue_passport_source_manifest_v2_with_trust_tier(
        issuer_keypair,
        subject,
        credentials,
        issued_at,
        expires_at,
        None,
    )
}

fn issue_passport_source_manifest_v2_with_trust_tier(
    issuer_keypair: &Keypair,
    subject: &str,
    credentials: &[PassportCredentialV2],
    issued_at: u64,
    expires_at: u64,
    trust_tier: Option<TrustTier>,
) -> Result<
    (
        SignedPassportSourceManifestV2,
        Vec<PassportCredentialMembershipProofV2>,
    ),
    CredentialError,
> {
    if credentials.is_empty() || credentials.len() > MAX_FINANCIAL_SOURCE_ARTIFACTS {
        return invalid_financial("source passport credential count is invalid");
    }
    validate_time("sourceManifest.issuedAt", issued_at)?;
    validate_time("sourceManifest.expiresAt", expires_at)?;
    if issued_at >= expires_at {
        return Err(CredentialError::InvalidCredentialValidityWindow);
    }
    let subject = DidChio::from_str(subject)?.to_string();
    let issuer = DidChio::from_public_key(issuer_keypair.public_key())?.to_string();
    let mut leaves = Vec::with_capacity(credentials.len());
    let mut ids = BTreeSet::new();
    let mut refs = BTreeSet::new();
    let mut committed_expires_at = expires_at;
    for credential in credentials {
        validate_manifest_credential(credential, &issuer, &subject, issued_at)?;
        committed_expires_at =
            committed_expires_at.min(manifest_credential_expiration(credential)?);
        let leaf = passport_manifest_leaf_v2(credential)?;
        if !ids.insert(leaf.credential_id.clone())
            || !refs.insert(leaf.credential_ref_digest.clone())
        {
            return invalid_financial("source passport contains duplicate credentials");
        }
        leaves.push(leaf);
    }
    if issued_at >= committed_expires_at {
        return Err(CredentialError::InvalidCredentialValidityWindow);
    }
    leaves.sort();
    let leaf_bytes = leaves
        .iter()
        .map(canonical_json_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    let tree = chio_core::MerkleTree::from_leaves(&leaf_bytes)?;
    let (merkle_roots, enterprise_identity_provenance) = derive_passport_metadata(credentials)?;
    let mut body = PassportSourceManifestV2 {
        schema: FINANCIAL_AGENT_PASSPORT_SOURCE_MANIFEST_SCHEMA_V1.to_string(),
        source_passport_id: String::new(),
        issuer,
        subject,
        issued_at,
        expires_at: committed_expires_at,
        credential_count: u64::try_from(leaves.len())
            .map_err(|_| invalid_financial_error("source passport credential count overflow"))?,
        credential_root: tree.root().to_hex(),
        merkle_roots,
        enterprise_identity_provenance,
        trust_tier,
    };
    body.source_passport_id = recompute_source_passport_id(&body)?;
    let signed = SignedPassportSourceManifestV2::sign(body, issuer_keypair)?;
    let proofs = leaves
        .into_iter()
        .enumerate()
        .map(|(index, leaf)| {
            Ok(PassportCredentialMembershipProofV2 {
                leaf,
                proof: tree.inclusion_proof(index)?,
            })
        })
        .collect::<Result<Vec<_>, CredentialError>>()?;
    Ok((signed, proofs))
}

pub fn build_agent_passport_v2(
    issuer_keypair: &Keypair,
    subject: impl Into<String>,
    credentials: Vec<PassportCredentialV2>,
    merkle_roots: Vec<String>,
    enterprise_identity_provenance: Vec<EnterpriseIdentityProvenance>,
    validity: PassportValidityWindowV2,
    trust_tier: Option<TrustTier>,
) -> Result<(AgentPassportV2, Vec<PassportCredentialMembershipProofV2>), CredentialError> {
    let subject = subject.into();
    let (derived_merkle_roots, derived_enterprise_identity_provenance) =
        derive_passport_metadata(&credentials)?;
    if merkle_roots != derived_merkle_roots {
        return invalid_financial("agent passport merkle roots do not match its credentials");
    }
    if enterprise_identity_provenance != derived_enterprise_identity_provenance {
        return Err(CredentialError::PassportEnterpriseIdentityProvenanceMismatch);
    }
    let (source_manifest, membership_proofs) = issue_passport_source_manifest_v2_with_trust_tier(
        issuer_keypair,
        &subject,
        &credentials,
        validity.issued_at,
        validity.expires_at,
        trust_tier,
    )?;
    let passport = AgentPassportV2 {
        schema: FINANCIAL_AGENT_PASSPORT_SCHEMA_V1.to_string(),
        subject,
        credentials,
        merkle_roots,
        enterprise_identity_provenance,
        issued_at: rfc3339_from_unix(validity.issued_at)?,
        valid_until: rfc3339_from_unix(source_manifest.body.expires_at)?,
        trust_tier,
        source_manifest: Some(source_manifest),
    };
    validate_agent_passport_v2_contract(&passport)?;
    Ok((passport, membership_proofs))
}

pub fn inspect_agent_passport_v2(
    passport: &AgentPassportV2,
    now: u64,
) -> Result<(), CredentialError> {
    let (issued_at, valid_until) = validate_agent_passport_v2_contract(passport)?;
    validate_time("agentPassport.now", now)?;
    if now < issued_at {
        return Err(CredentialError::CredentialNotYetValid);
    }
    if now >= valid_until {
        return Err(CredentialError::CredentialExpired);
    }
    match passport.source_manifest.as_ref() {
        Some(source_manifest) => validate_passport_source_manifest_credential_set(
            source_manifest,
            &passport.credentials,
            now,
        ),
        None => verify_agent_passport(&legacy_passport_view(passport)?, now).map(|_| ()),
    }
}

pub fn inspect_passport_source_manifest_v2_signature(
    manifest: &SignedPassportSourceManifestV2,
    now: u64,
) -> Result<(), CredentialError> {
    let body = &manifest.body;
    if body.schema != FINANCIAL_AGENT_PASSPORT_SOURCE_MANIFEST_SCHEMA_V1 {
        return invalid_financial("source passport manifest schema is invalid");
    }
    validate_digest("sourcePassportId", &body.source_passport_id)?;
    validate_digest("credentialRoot", &body.credential_root)?;
    validate_manifest_metadata_contract(body)?;
    validate_time("sourceManifest.issuedAt", body.issued_at)?;
    validate_time("sourceManifest.expiresAt", body.expires_at)?;
    if body.issued_at >= body.expires_at {
        return Err(CredentialError::InvalidCredentialValidityWindow);
    }
    if now < body.issued_at {
        return Err(CredentialError::CredentialNotYetValid);
    }
    if now >= body.expires_at {
        return Err(CredentialError::CredentialExpired);
    }
    if body.credential_count == 0 || body.credential_count > MAX_FINANCIAL_SOURCE_ARTIFACTS as u64 {
        return invalid_financial("source passport credential count is invalid");
    }
    let issuer = DidChio::from_str(&body.issuer)?;
    DidChio::from_str(&body.subject)?;
    if issuer.public_key() != &manifest.signer_key {
        return Err(CredentialError::IssuerVerificationMethodMismatch);
    }
    if recompute_source_passport_id(body)? != body.source_passport_id {
        return invalid_financial("source passport ID does not match its manifest");
    }
    if manifest.verify_signature()? {
        Ok(())
    } else {
        Err(CredentialError::InvalidCredentialSignature)
    }
}

pub(super) fn validate_agent_passport_v2_contract(
    passport: &AgentPassportV2,
) -> Result<(u64, u64), CredentialError> {
    if passport.schema != FINANCIAL_AGENT_PASSPORT_SCHEMA_V1 {
        return Err(CredentialError::UnsupportedVersionedPassportSchema(
            passport.schema.clone(),
        ));
    }
    DidChio::from_str(&passport.subject)?;
    if passport.credentials.is_empty()
        || passport.credentials.len() > MAX_FINANCIAL_SOURCE_ARTIFACTS
    {
        return invalid_financial("agent passport v2 credential count is invalid");
    }
    let issued_at = unix_from_rfc3339(&passport.issued_at)?;
    let valid_until = unix_from_rfc3339(&passport.valid_until)?;
    validate_time("agentPassport.issuedAt", issued_at)?;
    validate_time("agentPassport.validUntil", valid_until)?;
    if issued_at > valid_until {
        return Err(CredentialError::InvalidCredentialValidityWindow);
    }
    for provenance in &passport.enterprise_identity_provenance {
        provenance.validate()?;
    }
    match passport.source_manifest.as_ref() {
        Some(source_manifest) => {
            if source_manifest.body.subject != passport.subject
                || source_manifest.body.issued_at != issued_at
                || source_manifest.body.expires_at != valid_until
                || source_manifest.body.merkle_roots != passport.merkle_roots
                || source_manifest.body.enterprise_identity_provenance
                    != passport.enterprise_identity_provenance
                || source_manifest.body.trust_tier != passport.trust_tier
            {
                return invalid_financial("agent passport v2 source manifest binding is invalid");
            }
            validate_passport_source_manifest_credential_set(
                source_manifest,
                &passport.credentials,
                issued_at,
            )?;
        }
        None => {
            verify_agent_passport(&legacy_passport_view(passport)?, issued_at)?;
        }
    }
    Ok((issued_at, valid_until))
}

fn legacy_passport_view(passport: &AgentPassportV2) -> Result<AgentPassport, CredentialError> {
    let credentials = passport
        .credentials
        .iter()
        .map(|credential| match credential {
            PassportCredentialV2::Reputation(credential) => Ok(credential.as_ref().clone()),
            PassportCredentialV2::Financial(_) => {
                invalid_financial("financial credentials require a signed source manifest")
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AgentPassport {
        schema: PASSPORT_SCHEMA.to_string(),
        subject: passport.subject.clone(),
        credentials,
        merkle_roots: passport.merkle_roots.clone(),
        enterprise_identity_provenance: passport.enterprise_identity_provenance.clone(),
        issued_at: passport.issued_at.clone(),
        valid_until: passport.valid_until.clone(),
        trust_tier: passport.trust_tier,
    })
}

fn validate_passport_source_manifest_credential_set(
    manifest: &SignedPassportSourceManifestV2,
    credentials: &[PassportCredentialV2],
    now: u64,
) -> Result<(), CredentialError> {
    inspect_passport_source_manifest_v2_signature(manifest, now)?;
    if credentials.is_empty()
        || credentials.len() > MAX_FINANCIAL_SOURCE_ARTIFACTS
        || manifest.body.credential_count
            != u64::try_from(credentials.len())
                .map_err(|_| invalid_financial_error("source passport credential count overflow"))?
    {
        return invalid_financial("source passport credential count is inconsistent");
    }
    let mut leaves = Vec::with_capacity(credentials.len());
    let mut ids = BTreeSet::new();
    let mut refs = BTreeSet::new();
    for credential in credentials {
        validate_manifest_credential(
            credential,
            &manifest.body.issuer,
            &manifest.body.subject,
            now,
        )?;
        let leaf = passport_manifest_leaf_v2(credential)?;
        if !ids.insert(leaf.credential_id.clone())
            || !refs.insert(leaf.credential_ref_digest.clone())
        {
            return invalid_financial("source passport contains duplicate credentials");
        }
        leaves.push(leaf);
    }
    leaves.sort();
    let leaf_bytes = leaves
        .iter()
        .map(canonical_json_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    let tree = chio_core::MerkleTree::from_leaves(&leaf_bytes)?;
    if tree.root().to_hex() != manifest.body.credential_root {
        return invalid_financial("source passport credential root is invalid");
    }
    let (merkle_roots, enterprise_identity_provenance) = derive_passport_metadata(credentials)?;
    if manifest.body.merkle_roots != merkle_roots
        || manifest.body.enterprise_identity_provenance != enterprise_identity_provenance
    {
        return invalid_financial("source passport metadata does not match its credentials");
    }
    Ok(())
}

pub fn create_passport_presentation_challenge_v2(
    verifier_keypair: &Keypair,
    verifier_key_epoch: u64,
    challenge_id: impl Into<String>,
    nonce: impl Into<String>,
    source_passport_id: impl Into<String>,
    selectors: Vec<PassportCredentialSelectorV2>,
    validity: PassportValidityWindowV2,
) -> Result<SignedPassportPresentationChallengeV2, CredentialError> {
    let mut challenge = PassportPresentationChallengeV2 {
        schema: FINANCIAL_PASSPORT_PRESENTATION_CHALLENGE_SCHEMA_V1.to_string(),
        verifier: DidChio::from_public_key(verifier_keypair.public_key())?.to_string(),
        verifier_key_epoch,
        challenge_id: challenge_id.into(),
        nonce: nonce.into(),
        issued_at: rfc3339_from_unix(validity.issued_at)?,
        expires_at: rfc3339_from_unix(validity.expires_at)?,
        source_passport_id: source_passport_id.into(),
        selectors: normalize_selectors(selectors)?,
        challenge_digest: String::new(),
    };
    challenge.challenge_digest = passport_presentation_challenge_digest_v2(&challenge)?;
    validate_passport_presentation_challenge_v2_body_contract(&challenge)?;
    let signed = SignedPassportPresentationChallengeV2::sign(challenge, verifier_keypair)?;
    validate_passport_presentation_challenge_v2_contract(&signed)?;
    Ok(signed)
}

pub fn inspect_passport_presentation_challenge_v2(
    challenge: &SignedPassportPresentationChallengeV2,
    now: u64,
) -> Result<(), CredentialError> {
    let (issued_at, expires_at) = validate_passport_presentation_challenge_v2_contract(challenge)?;
    validate_time("challenge.now", now)?;
    if now < issued_at {
        return Err(CredentialError::ChallengeNotYetValid);
    }
    if now >= expires_at {
        return Err(CredentialError::ChallengeExpired);
    }
    Ok(())
}

pub fn build_presented_agent_passport_v2(
    source_manifest: SignedPassportSourceManifestV2,
    credentials: Vec<PassportCredentialV2>,
    membership_proofs: Vec<PassportCredentialMembershipProofV2>,
    challenge: &SignedPassportPresentationChallengeV2,
) -> Result<PresentedAgentPassportV2, CredentialError> {
    validate_passport_presentation_challenge_v2_contract(challenge)?;
    if source_manifest.body.source_passport_id != challenge.body.source_passport_id {
        return Err(CredentialError::ChallengeMismatch);
    }
    if credentials.is_empty() || credentials.len() > MAX_FINANCIAL_SOURCE_ARTIFACTS {
        return invalid_financial("presented credential count is invalid");
    }
    let mut entries = Vec::with_capacity(credentials.len());
    for credential in credentials {
        let leaf = passport_manifest_leaf_v2(&credential)?;
        let mut matches = membership_proofs.iter().filter(|proof| proof.leaf == leaf);
        let proof = matches
            .next()
            .ok_or_else(|| invalid_financial_error("credential membership proof is missing"))?;
        if matches.next().is_some() {
            return invalid_financial("credential membership proof is ambiguous");
        }
        entries.push((leaf, credential, proof.clone()));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return invalid_financial("presentation contains duplicate credentials");
    }
    let selected = normalize_selectors(
        entries
            .iter()
            .map(|(leaf, _, _)| PassportCredentialSelectorV2 {
                family: leaf.family.clone(),
                credential_ref_digest: leaf.credential_ref_digest.clone(),
            })
            .collect::<Vec<_>>(),
    )?;
    if selected != challenge.body.selectors {
        return Err(CredentialError::PresentationSelectorMismatch);
    }
    let credentials = entries
        .iter()
        .map(|(_, credential, _)| credential.clone())
        .collect::<Vec<_>>();
    let membership_proofs = entries
        .into_iter()
        .map(|(_, _, proof)| proof)
        .collect::<Vec<_>>();
    let challenge_digest = challenge.body.challenge_digest.clone();
    let presentation_digest =
        recompute_presentation_digest(&source_manifest, &challenge_digest, &membership_proofs)?;
    Ok(PresentedAgentPassportV2 {
        schema: PRESENTED_FINANCIAL_AGENT_PASSPORT_SCHEMA_V1.to_string(),
        source_manifest,
        credentials,
        membership_proofs,
        challenge_digest,
        presentation_digest,
    })
}

pub fn inspect_presented_agent_passport_v2(
    presentation: &PresentedAgentPassportV2,
    expected_challenge: &SignedPassportPresentationChallengeV2,
    now: u64,
) -> Result<(), CredentialError> {
    inspect_passport_presentation_challenge_v2(expected_challenge, now)?;
    validate_presented_agent_passport_v2_contract(presentation, now, true)?;
    if presentation.source_manifest.body.source_passport_id
        != expected_challenge.body.source_passport_id
    {
        return Err(CredentialError::ChallengeMismatch);
    }
    validate_digest("challengeDigest", &presentation.challenge_digest)?;
    if expected_challenge.body.challenge_digest != presentation.challenge_digest {
        return Err(CredentialError::ChallengeMismatch);
    }
    let selected = normalize_selectors(
        presentation
            .membership_proofs
            .iter()
            .map(|proof| PassportCredentialSelectorV2 {
                family: proof.leaf.family.clone(),
                credential_ref_digest: proof.leaf.credential_ref_digest.clone(),
            })
            .collect::<Vec<_>>(),
    )?;
    if selected != expected_challenge.body.selectors {
        return Err(CredentialError::PresentationSelectorMismatch);
    }
    Ok(())
}

pub(super) fn validate_presented_agent_passport_v2_authority_contract(
    presentation: &PresentedAgentPassportV2,
    now: u64,
) -> Result<(), CredentialError> {
    validate_presented_agent_passport_v2_contract(presentation, now, false)
}

fn validate_presented_agent_passport_v2_contract(
    presentation: &PresentedAgentPassportV2,
    now: u64,
    validate_sources: bool,
) -> Result<(), CredentialError> {
    if presentation.schema != PRESENTED_FINANCIAL_AGENT_PASSPORT_SCHEMA_V1 {
        return invalid_financial("presented passport schema is invalid");
    }
    inspect_passport_source_manifest_v2_signature(&presentation.source_manifest, now)?;
    validate_digest("challengeDigest", &presentation.challenge_digest)?;
    validate_digest("presentationDigest", &presentation.presentation_digest)?;
    if presentation.credentials.is_empty()
        || presentation.credentials.len() != presentation.membership_proofs.len()
        || presentation.credentials.len() > MAX_FINANCIAL_SOURCE_ARTIFACTS
    {
        return invalid_financial("presented passport credential count is invalid");
    }
    let manifest = &presentation.source_manifest.body;
    let root = chio_core::Hash::from_hex(&manifest.credential_root)?;
    let tree_size = usize::try_from(manifest.credential_count)
        .map_err(|_| invalid_financial_error("source passport credential count overflow"))?;
    let mut previous = None;
    for (credential, membership) in presentation
        .credentials
        .iter()
        .zip(&presentation.membership_proofs)
    {
        if validate_sources {
            validate_manifest_credential(credential, &manifest.issuer, &manifest.subject, now)?;
        } else {
            validate_manifest_credential_shape(
                credential,
                &manifest.issuer,
                &manifest.subject,
                now,
            )?;
        }
        let leaf = passport_manifest_leaf_v2(credential)?;
        if leaf != membership.leaf || membership.proof.tree_size != tree_size {
            return invalid_financial("presented credential membership binding is invalid");
        }
        if previous.as_ref().is_some_and(|prior| prior >= &leaf) {
            return invalid_financial("presented credentials must be sorted and unique");
        }
        let bytes = canonical_json_bytes(&leaf)?;
        if !membership.proof.verify(&bytes, &root) {
            return invalid_financial("presented credential membership proof is invalid");
        }
        previous = Some(leaf);
    }
    let expected = recompute_presentation_digest(
        &presentation.source_manifest,
        &presentation.challenge_digest,
        &presentation.membership_proofs,
    )?;
    if expected != presentation.presentation_digest {
        return invalid_financial("presentation digest does not match the selected credentials");
    }
    Ok(())
}

pub fn respond_to_passport_presentation_challenge_v2(
    holder_keypair: &Keypair,
    source_manifest: SignedPassportSourceManifestV2,
    credentials: Vec<PassportCredentialV2>,
    membership_proofs: Vec<PassportCredentialMembershipProofV2>,
    challenge: &SignedPassportPresentationChallengeV2,
    now: u64,
) -> Result<PassportPresentationResponseV2, CredentialError> {
    inspect_passport_presentation_challenge_v2(challenge, now)?;
    inspect_passport_source_manifest_v2_signature(&source_manifest, now)?;
    let holder = DidChio::from_public_key(holder_keypair.public_key())?;
    if holder.to_string() != source_manifest.body.subject {
        return Err(CredentialError::PresentationHolderMismatch);
    }
    let presentation = build_presented_agent_passport_v2(
        source_manifest,
        credentials,
        membership_proofs,
        challenge,
    )?;
    inspect_presented_agent_passport_v2(&presentation, challenge, now)?;
    let unsigned = UnsignedPassportPresentationResponseV2 {
        schema: FINANCIAL_PASSPORT_PRESENTATION_RESPONSE_SCHEMA_V1,
        challenge,
        presentation: &presentation,
    };
    let (signature, _) = holder_keypair.sign_canonical(&unsigned)?;
    Ok(PassportPresentationResponseV2 {
        schema: FINANCIAL_PASSPORT_PRESENTATION_RESPONSE_SCHEMA_V1.to_string(),
        challenge: challenge.clone(),
        presentation,
        proof: PresentationProof {
            proof_type: PROOF_TYPE.to_string(),
            created: rfc3339_from_unix(now)?,
            proof_purpose: PRESENTATION_PROOF_PURPOSE.to_string(),
            verification_method: holder.verification_method_id(),
            proof_value: signature.to_hex(),
        },
    })
}

pub fn inspect_passport_presentation_response_v2(
    response: &PassportPresentationResponseV2,
    expected_challenge: &SignedPassportPresentationChallengeV2,
    now: u64,
    challenge_use_store: &mut impl PassportPresentationChallengeUseStore,
) -> Result<(), CredentialError> {
    if response.schema != FINANCIAL_PASSPORT_PRESENTATION_RESPONSE_SCHEMA_V1 {
        return Err(CredentialError::InvalidPresentationSchema);
    }
    if &response.challenge != expected_challenge {
        return Err(CredentialError::ChallengeMismatch);
    }
    inspect_presented_agent_passport_v2(&response.presentation, expected_challenge, now)?;
    if response.proof.proof_type != PROOF_TYPE {
        return Err(CredentialError::InvalidPresentationProofType);
    }
    if response.proof.proof_purpose != PRESENTATION_PROOF_PURPOSE {
        return Err(CredentialError::InvalidPresentationProofPurpose);
    }
    let holder = DidChio::from_str(&response.presentation.source_manifest.body.subject)?;
    if response.proof.verification_method != holder.verification_method_id() {
        return Err(CredentialError::PresentationVerificationMethodMismatch);
    }
    let challenge_issued_at = unix_from_rfc3339(&expected_challenge.body.issued_at)?;
    let challenge_expires_at = unix_from_rfc3339(&expected_challenge.body.expires_at)?;
    let proof_created = unix_from_rfc3339(&response.proof.created)?;
    if proof_created > now {
        return Err(CredentialError::PresentationProofFromFuture);
    }
    if proof_created < challenge_issued_at || proof_created >= challenge_expires_at {
        return Err(CredentialError::PresentationProofOutsideChallengeWindow);
    }
    let unsigned = UnsignedPassportPresentationResponseV2 {
        schema: &response.schema,
        challenge: &response.challenge,
        presentation: &response.presentation,
    };
    let signature = Signature::from_hex(&response.proof.proof_value)?;
    if !holder
        .public_key()
        .verify(&canonical_json_bytes(&unsigned)?, &signature)
    {
        return Err(CredentialError::InvalidPresentationSignature);
    }
    let identity = PassportPresentationChallengeIdentityV2 {
        verifier: expected_challenge.body.verifier.clone(),
        challenge_id: expected_challenge.body.challenge_id.clone(),
        nonce: expected_challenge.body.nonce.clone(),
    };
    challenge_use_store
        .consume_once(&identity)
        .map_err(|error| match error {
            PassportPresentationChallengeUseError::AlreadyUsed => {
                CredentialError::PresentationReplay
            }
            PassportPresentationChallengeUseError::Unavailable => {
                CredentialError::PresentationReplayStoreUnavailable
            }
        })?;
    Ok(())
}

fn validate_passport_presentation_challenge_v2_contract(
    challenge: &SignedPassportPresentationChallengeV2,
) -> Result<(u64, u64), CredentialError> {
    let validity = validate_passport_presentation_challenge_v2_body_contract(&challenge.body)?;
    let verifier = DidChio::from_str(&challenge.body.verifier)?;
    if verifier.public_key() != &challenge.signer_key {
        return Err(CredentialError::ChallengeVerifierKeyMismatch);
    }
    if challenge.verify_signature()? {
        Ok(validity)
    } else {
        Err(CredentialError::InvalidChallengeSignature)
    }
}

fn validate_passport_presentation_challenge_v2_body_contract(
    challenge: &PassportPresentationChallengeV2,
) -> Result<(u64, u64), CredentialError> {
    if challenge.schema != FINANCIAL_PASSPORT_PRESENTATION_CHALLENGE_SCHEMA_V1 {
        return Err(CredentialError::InvalidChallengeSchema);
    }
    validate_text("challenge.verifier", &challenge.verifier)?;
    if challenge.verifier_key_epoch == 0 || challenge.verifier_key_epoch > I_JSON_MAX_SAFE_INTEGER {
        return Err(CredentialError::InvalidChallengeVerifierKeyEpoch);
    }
    validate_text("challenge.challengeId", &challenge.challenge_id)?;
    validate_text("challenge.nonce", &challenge.nonce)?;
    validate_digest("challenge.sourcePassportId", &challenge.source_passport_id)?;
    let issued_at = unix_from_rfc3339(&challenge.issued_at)?;
    let expires_at = unix_from_rfc3339(&challenge.expires_at)?;
    validate_time("challenge.issuedAt", issued_at)?;
    validate_time("challenge.expiresAt", expires_at)?;
    if issued_at >= expires_at {
        return Err(CredentialError::InvalidChallengeValidityWindow);
    }
    if normalize_selectors(challenge.selectors.clone())? != challenge.selectors {
        return Err(CredentialError::PresentationSelectorMismatch);
    }
    validate_digest("challenge.challengeDigest", &challenge.challenge_digest)?;
    if passport_presentation_challenge_digest_v2(challenge)? != challenge.challenge_digest {
        return Err(CredentialError::InvalidChallengeDigest);
    }
    Ok((issued_at, expires_at))
}

fn normalize_selectors(
    mut selectors: Vec<PassportCredentialSelectorV2>,
) -> Result<Vec<PassportCredentialSelectorV2>, CredentialError> {
    if selectors.is_empty() || selectors.len() > MAX_FINANCIAL_SOURCE_ARTIFACTS {
        return Err(CredentialError::PresentationSelectorMismatch);
    }
    for selector in &selectors {
        validate_digest(
            "challenge.selector.credentialRefDigest",
            &selector.credential_ref_digest,
        )?;
    }
    selectors.sort();
    if selectors.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CredentialError::PresentationSelectorMismatch);
    }
    Ok(selectors)
}

fn validate_manifest_credential(
    credential: &PassportCredentialV2,
    issuer: &str,
    subject: &str,
    now: u64,
) -> Result<(), CredentialError> {
    match credential {
        PassportCredentialV2::Reputation(credential) => {
            verify_reputation_credential(credential, now)?;
            if now < unix_from_rfc3339(&credential.unsigned.issuance_date)? {
                return Err(CredentialError::CredentialNotYetValid);
            }
            if credential.unsigned.issuer != issuer
                || credential.unsigned.credential_subject.id != subject
            {
                return invalid_financial("source manifest reputation binding is invalid");
            }
        }
        PassportCredentialV2::Financial(credential) => {
            inspect_financial_credential_signature(credential, now)?;
            if credential.issuer != issuer || credential.credential_subject.id() != subject {
                return invalid_financial("source manifest financial binding is invalid");
            }
        }
    }
    Ok(())
}

fn validate_manifest_credential_shape(
    credential: &PassportCredentialV2,
    issuer: &str,
    subject: &str,
    now: u64,
) -> Result<(), CredentialError> {
    match credential {
        PassportCredentialV2::Reputation(credential) => {
            verify_reputation_credential(credential, now)?;
            if credential.unsigned.issuer != issuer
                || credential.unsigned.credential_subject.id != subject
            {
                return invalid_financial("source manifest reputation binding is invalid");
            }
        }
        PassportCredentialV2::Financial(credential) => {
            let (issued_at, expires_at) = credential.validate_contract_shape()?;
            if now < issued_at {
                return Err(CredentialError::CredentialNotYetValid);
            }
            if now >= expires_at {
                return Err(CredentialError::CredentialExpired);
            }
            if credential.issuer != issuer || credential.credential_subject.id() != subject {
                return invalid_financial("source manifest financial binding is invalid");
            }
        }
    }
    Ok(())
}

fn derive_passport_metadata(
    credentials: &[PassportCredentialV2],
) -> Result<(Vec<String>, Vec<EnterpriseIdentityProvenance>), CredentialError> {
    let mut merkle_roots = BTreeSet::new();
    let mut reputation_credentials = Vec::new();
    for credential in credentials {
        if let PassportCredentialV2::Reputation(credential) = credential {
            merkle_roots.extend(
                credential
                    .unsigned
                    .evidence
                    .checkpoint_roots
                    .iter()
                    .cloned(),
            );
            reputation_credentials.push(credential.as_ref().clone());
        }
    }
    Ok((
        merkle_roots.into_iter().collect(),
        aggregate_enterprise_identity_provenance(&reputation_credentials)?,
    ))
}

fn validate_manifest_metadata_contract(
    body: &PassportSourceManifestV2,
) -> Result<(), CredentialError> {
    if body.merkle_roots.len() > MAX_FINANCIAL_SOURCE_ARTIFACTS
        || body.enterprise_identity_provenance.len() > MAX_FINANCIAL_SOURCE_ARTIFACTS
    {
        return invalid_financial("source passport metadata count is invalid");
    }
    let mut normalized_roots = body.merkle_roots.clone();
    for root in &normalized_roots {
        validate_text("sourceManifest.merkleRoot", root)?;
    }
    normalized_roots.sort();
    normalized_roots.dedup();
    if normalized_roots != body.merkle_roots {
        return invalid_financial("source passport merkle roots must be sorted and unique");
    }
    let provenance_keys = body
        .enterprise_identity_provenance
        .iter()
        .map(|provenance| {
            provenance.validate()?;
            Ok(canonical_json_bytes(provenance)?)
        })
        .collect::<Result<Vec<_>, CredentialError>>()?;
    if provenance_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid_financial(
            "source passport enterprise provenance must be sorted and unique",
        );
    }
    Ok(())
}

fn manifest_credential_expiration(
    credential: &PassportCredentialV2,
) -> Result<u64, CredentialError> {
    match credential {
        PassportCredentialV2::Reputation(credential) => {
            unix_from_rfc3339(&credential.unsigned.expiration_date)
        }
        PassportCredentialV2::Financial(credential) => {
            unix_from_rfc3339(&credential.expiration_date)
        }
    }
}
