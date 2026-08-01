#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportPresentationOptions {
    pub issuer_allowlist: BTreeSet<String>,
    pub max_credentials: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportPresentationChallengeArgs {
    pub verifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub options: PassportPresentationOptions,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<PassportVerifierPolicyReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PassportVerifierPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportPresentationChallenge {
    pub schema: String,
    pub verifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub issuer_allowlist: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_credentials: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<PassportVerifierPolicyReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PassportVerifierPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PresentationProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: String,
    pub proof_purpose: String,
    pub verification_method: String,
    pub proof_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportPresentationResponse {
    pub schema: String,
    pub challenge: PassportPresentationChallenge,
    pub passport: AgentPassport,
    pub proof: PresentationProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportPresentationVerification {
    pub subject: String,
    pub verifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
    pub nonce: String,
    pub verified_at: u64,
    pub passport_id: String,
    pub credential_count: usize,
    pub valid_until: String,
    pub challenge_expires_at: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enterprise_identity_provenance: Vec<EnterpriseIdentityProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_lifecycle: Option<PassportLifecycleResolution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub policy_evaluated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_evaluation: Option<PassportPolicyEvaluation>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedPassportPresentationResponse {
    schema: String,
    challenge: PassportPresentationChallenge,
    passport: AgentPassport,
}

fn rfc3339_from_unix(timestamp: u64) -> Result<String, CredentialError> {
    let timestamp =
        i64::try_from(timestamp).map_err(|_| CredentialError::InvalidUnixTimestamp(timestamp))?;
    let datetime = Utc
        .timestamp_opt(timestamp, 0)
        .single()
        .ok_or(CredentialError::InvalidUnixTimestamp(timestamp as u64))?;
    Ok(datetime.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn unix_from_rfc3339(value: &str) -> Result<u64, CredentialError> {
    let datetime = DateTime::parse_from_rfc3339(value)
        .map_err(|error| CredentialError::InvalidTimestamp(error.to_string()))?;
    u64::try_from(datetime.timestamp())
        .map_err(|_| CredentialError::InvalidTimestamp(value.to_string()))
}

pub fn issue_reputation_credential(
    issuer_keypair: &Keypair,
    scorecard: LocalReputationScorecard,
    evidence: ChioCredentialEvidence,
    issued_at: u64,
    valid_until: u64,
) -> Result<ReputationCredential, CredentialError> {
    issue_reputation_credential_with_enterprise_identity(
        issuer_keypair,
        scorecard,
        evidence,
        None,
        issued_at,
        valid_until,
    )
}

pub fn issue_reputation_credential_with_enterprise_identity(
    issuer_keypair: &Keypair,
    scorecard: LocalReputationScorecard,
    evidence: ChioCredentialEvidence,
    enterprise_identity_provenance: Option<EnterpriseIdentityProvenance>,
    issued_at: u64,
    valid_until: u64,
) -> Result<ReputationCredential, CredentialError> {
    if issued_at > valid_until {
        return Err(CredentialError::InvalidCredentialValidityWindow);
    }
    if let Some(provenance) = enterprise_identity_provenance.as_ref() {
        provenance.validate()?;
    }

    let issuer = DidChio::from_public_key(issuer_keypair.public_key())?;
    let subject_did =
        DidChio::from_public_key(chio_core::PublicKey::from_hex(&scorecard.subject_key)?)?;
    let unsigned = UnsignedReputationCredential {
        context: vec![
            VC_CONTEXT_V1.to_string(),
            CHIO_CREDENTIAL_CONTEXT_V1.to_string(),
        ],
        credential_type: vec![VC_TYPE.to_string(), REPUTATION_ATTESTATION_TYPE.to_string()],
        issuer: issuer.to_string(),
        issuance_date: rfc3339_from_unix(issued_at)?,
        expiration_date: rfc3339_from_unix(valid_until)?,
        credential_subject: ReputationCredentialSubject {
            id: subject_did.to_string(),
            metrics: scorecard,
        },
        evidence,
        enterprise_identity_provenance,
    };

    let (signature, _) = issuer_keypair.sign_canonical(&unsigned)?;
    Ok(ReputationCredential {
        unsigned,
        proof: CredentialProof {
            proof_type: PROOF_TYPE.to_string(),
            created: rfc3339_from_unix(issued_at)?,
            proof_purpose: PROOF_PURPOSE.to_string(),
            verification_method: issuer.verification_method_id(),
            proof_value: signature.to_hex(),
        },
    })
}

pub fn verify_reputation_credential(
    credential: &ReputationCredential,
    now: u64,
) -> Result<(), CredentialError> {
    if credential.proof.proof_type != PROOF_TYPE {
        return Err(CredentialError::InvalidProofType);
    }
    if credential.proof.proof_purpose != PROOF_PURPOSE {
        return Err(CredentialError::InvalidProofPurpose);
    }
    let issuer = DidChio::from_str(&credential.unsigned.issuer)?;
    if credential.proof.verification_method != issuer.verification_method_id() {
        return Err(CredentialError::IssuerVerificationMethodMismatch);
    }
    let subject = DidChio::from_str(&credential.unsigned.credential_subject.id)?;
    if subject.public_key().to_hex() != credential.unsigned.credential_subject.metrics.subject_key {
        return Err(CredentialError::SubjectDidMismatch);
    }

    let issuance_date = unix_from_rfc3339(&credential.unsigned.issuance_date)?;
    let expiration_date = unix_from_rfc3339(&credential.unsigned.expiration_date)?;
    if issuance_date > expiration_date {
        return Err(CredentialError::InvalidCredentialValidityWindow);
    }
    if now < issuance_date {
        return Err(CredentialError::CredentialNotYetValid);
    }
    if now > expiration_date {
        return Err(CredentialError::CredentialExpired);
    }
    if let Some(provenance) = credential.unsigned.enterprise_identity_provenance.as_ref() {
        provenance.validate()?;
    }

    let signature = Signature::from_hex(&credential.proof.proof_value)?;
    let signed = issuer
        .public_key()
        .verify(&canonical_json_bytes(&credential.unsigned)?, &signature);
    if !signed {
        return Err(CredentialError::InvalidCredentialSignature);
    }
    Ok(())
}

pub fn build_agent_passport(
    subject: &str,
    credentials: Vec<ReputationCredential>,
) -> Result<AgentPassport, CredentialError> {
    if credentials.is_empty() {
        return Err(CredentialError::EmptyPassport);
    }

    let subject = DidChio::from_str(subject)?.to_string();
    let mut merkle_roots = BTreeSet::new();
    let mut issued_at = u64::MAX;
    let mut valid_until = u64::MAX;

    for credential in &credentials {
        if credential.unsigned.credential_subject.id != subject {
            return Err(CredentialError::PassportSubjectMismatch(
                credential.unsigned.credential_subject.id.clone(),
            ));
        }
        issued_at = issued_at.min(unix_from_rfc3339(&credential.unsigned.issuance_date)?);
        valid_until = valid_until.min(unix_from_rfc3339(&credential.unsigned.expiration_date)?);
        merkle_roots.extend(
            credential
                .unsigned
                .evidence
                .checkpoint_roots
                .iter()
                .cloned(),
        );
    }
    let enterprise_identity_provenance = aggregate_enterprise_identity_provenance(&credentials)?;

    Ok(AgentPassport {
        schema: PASSPORT_SCHEMA.to_string(),
        subject,
        credentials,
        merkle_roots: merkle_roots.into_iter().collect(),
        enterprise_identity_provenance,
        issued_at: rfc3339_from_unix(issued_at)?,
        valid_until: rfc3339_from_unix(valid_until)?,
        trust_tier: None,
    })
}

pub fn passport_artifact_id(passport: &AgentPassport) -> Result<String, CredentialError> {
    Ok(sha256_hex(&canonical_json_bytes(passport)?))
}

pub fn verify_agent_passport(
    passport: &AgentPassport,
    now: u64,
) -> Result<PassportVerification, CredentialError> {
    if !is_supported_passport_schema(&passport.schema) {
        return Err(CredentialError::InvalidPassportSchema);
    }
    if passport.credentials.is_empty() {
        return Err(CredentialError::EmptyPassport);
    }

    let subject = DidChio::from_str(&passport.subject)?.to_string();
    let passport_valid_until = unix_from_rfc3339(&passport.valid_until)?;
    let mut issuers = BTreeSet::new();
    let mut merkle_roots = BTreeSet::new();
    let mut min_credential_valid_until = u64::MAX;

    for credential in &passport.credentials {
        verify_reputation_credential(credential, now)?;
        if credential.unsigned.credential_subject.id != subject {
            return Err(CredentialError::PassportSubjectMismatch(
                credential.unsigned.credential_subject.id.clone(),
            ));
        }
        issuers.insert(credential.unsigned.issuer.clone());
        let credential_valid_until = unix_from_rfc3339(&credential.unsigned.expiration_date)?;
        min_credential_valid_until = min_credential_valid_until.min(credential_valid_until);
        merkle_roots.extend(
            credential
                .unsigned
                .evidence
                .checkpoint_roots
                .iter()
                .cloned(),
        );
    }

    if passport_valid_until > min_credential_valid_until {
        return Err(CredentialError::PassportValidityMismatch);
    }
    let enterprise_identity_provenance =
        aggregate_enterprise_identity_provenance(&passport.credentials)?;
    if passport.enterprise_identity_provenance != enterprise_identity_provenance {
        return Err(CredentialError::PassportEnterpriseIdentityProvenanceMismatch);
    }
    let issuers = issuers.into_iter().collect::<Vec<_>>();

    Ok(PassportVerification {
        passport_id: passport_artifact_id(passport)?,
        subject,
        issuer: if issuers.len() == 1 {
            issuers.first().cloned()
        } else {
            None
        },
        issuers: issuers.clone(),
        issuer_count: issuers.len(),
        credential_count: passport.credentials.len(),
        merkle_root_count: merkle_roots.len(),
        enterprise_identity_provenance,
        passport_lifecycle: None,
        verified_at: now,
        valid_until: passport.valid_until.clone(),
    })
}

pub fn present_agent_passport(
    passport: &AgentPassport,
    options: &PassportPresentationOptions,
) -> Result<AgentPassport, CredentialError> {
    let mut credentials: Vec<ReputationCredential> = passport
        .credentials
        .iter()
        .filter(|credential| {
            options.issuer_allowlist.is_empty()
                || options
                    .issuer_allowlist
                    .contains(&credential.unsigned.issuer)
        })
        .cloned()
        .collect();

    if let Some(limit) = options.max_credentials {
        credentials.truncate(limit);
    }

    build_agent_passport(&passport.subject, credentials)
}

fn aggregate_enterprise_identity_provenance(
    credentials: &[ReputationCredential],
) -> Result<Vec<EnterpriseIdentityProvenance>, CredentialError> {
    let mut unique = Vec::<(Vec<u8>, EnterpriseIdentityProvenance)>::new();
    for credential in credentials {
        let Some(provenance) = credential.unsigned.enterprise_identity_provenance.as_ref() else {
            continue;
        };
        provenance.validate()?;
        let canonical = canonical_json_bytes(provenance)?;
        if unique.iter().any(|(existing, _)| *existing == canonical) {
            continue;
        }
        unique.push((canonical, provenance.clone()));
    }
    unique.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(unique
        .into_iter()
        .map(|(_, provenance)| provenance)
        .collect())
}

pub fn evaluate_agent_passport(
    passport: &AgentPassport,
    now: u64,
    policy: &PassportVerifierPolicy,
) -> Result<PassportPolicyEvaluation, CredentialError> {
    policy.validate()?;
    let verification = verify_agent_passport(passport, now)?;
    let mut matched_credential_indexes = Vec::new();
    let mut matched_issuers = BTreeSet::new();
    let credential_results = passport
        .credentials
        .iter()
        .enumerate()
        .map(|(index, credential)| {
            let evaluation = evaluate_credential_against_policy(index, credential, now, policy);
            if evaluation.accepted {
                matched_credential_indexes.push(index);
                matched_issuers.insert(evaluation.issuer.clone());
            }
            evaluation
        })
        .collect::<Vec<_>>();

    Ok(PassportPolicyEvaluation {
        verification,
        accepted: !matched_credential_indexes.is_empty(),
        matched_credential_indexes,
        matched_issuers: matched_issuers.into_iter().collect(),
        passport_reasons: Vec::new(),
        policy: policy.clone(),
        credential_results,
    })
}

pub fn create_passport_presentation_challenge(
    verifier: impl Into<String>,
    nonce: impl Into<String>,
    issued_at: u64,
    expires_at: u64,
    options: PassportPresentationOptions,
    policy: Option<PassportVerifierPolicy>,
) -> Result<PassportPresentationChallenge, CredentialError> {
    create_passport_presentation_challenge_with_reference(PassportPresentationChallengeArgs {
        verifier: verifier.into(),
        challenge_id: None,
        nonce: nonce.into(),
        issued_at,
        expires_at,
        options,
        policy_ref: None,
        policy,
    })
}

pub fn create_passport_presentation_challenge_with_reference(
    args: PassportPresentationChallengeArgs,
) -> Result<PassportPresentationChallenge, CredentialError> {
    let PassportPresentationChallengeArgs {
        verifier,
        challenge_id,
        nonce,
        issued_at,
        expires_at,
        options,
        policy_ref,
        policy,
    } = args;
    if issued_at > expires_at {
        return Err(CredentialError::InvalidChallengeValidityWindow);
    }
    validate_challenge_identity_fields(&verifier, &nonce)?;
    if let Some(policy) = &policy {
        policy.validate()?;
    }

    Ok(PassportPresentationChallenge {
        schema: PASSPORT_PRESENTATION_CHALLENGE_SCHEMA.to_string(),
        verifier,
        challenge_id,
        nonce,
        issued_at: rfc3339_from_unix(issued_at)?,
        expires_at: rfc3339_from_unix(expires_at)?,
        issuer_allowlist: options.issuer_allowlist,
        max_credentials: options.max_credentials,
        policy_ref,
        policy,
    })
}

pub fn verify_passport_presentation_challenge(
    challenge: &PassportPresentationChallenge,
    now: u64,
) -> Result<(), CredentialError> {
    if !is_supported_passport_presentation_challenge_schema(&challenge.schema) {
        return Err(CredentialError::InvalidChallengeSchema);
    }
    validate_challenge_identity_fields(&challenge.verifier, &challenge.nonce)?;

    let issued_at = unix_from_rfc3339(&challenge.issued_at)?;
    let expires_at = unix_from_rfc3339(&challenge.expires_at)?;
    if issued_at > expires_at {
        return Err(CredentialError::InvalidChallengeValidityWindow);
    }
    if now < issued_at {
        return Err(CredentialError::ChallengeNotYetValid);
    }
    if now > expires_at {
        return Err(CredentialError::ChallengeExpired);
    }
    if let Some(policy) = &challenge.policy {
        policy.validate()?;
    }
    Ok(())
}

fn validate_challenge_identity_fields(verifier: &str, nonce: &str) -> Result<(), CredentialError> {
    let verifier_trimmed = verifier.trim();
    if verifier_trimmed.is_empty()
        || verifier_trimmed != verifier
        || verifier.chars().any(char::is_control)
    {
        return Err(CredentialError::MissingChallengeVerifier);
    }
    let nonce_trimmed = nonce.trim();
    if nonce_trimmed.is_empty() || nonce_trimmed != nonce || nonce.chars().any(char::is_control) {
        return Err(CredentialError::MissingChallengeNonce);
    }
    Ok(())
}
