use super::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PassportSourceManifestIdPreimageV2<'a> {
    schema: &'a str,
    issuer: &'a str,
    subject: &'a str,
    issued_at: u64,
    expires_at: u64,
    credential_count: u64,
    credential_root: &'a str,
    merkle_roots: &'a [String],
    enterprise_identity_provenance: &'a [EnterpriseIdentityProvenance],
    trust_tier: Option<TrustTier>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PassportCredentialRefPreimageV2<'a> {
    family: PassportCredentialFamilyV2,
    credential: &'a PassportCredentialV2,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PassportPresentationDigestPreimageV2<'a> {
    source_manifest_digest: &'a str,
    challenge_digest: &'a str,
    credentials: &'a [PassportPresentationDigestEntryV2<'a>],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PassportPresentationDigestEntryV2<'a> {
    credential_id: &'a str,
    credential_ref_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PassportPresentationChallengeDigestPreimageV2<'a> {
    schema: &'a str,
    verifier: &'a str,
    verifier_key_epoch: u64,
    challenge_id: &'a str,
    nonce: &'a str,
    issued_at: &'a str,
    expires_at: &'a str,
    source_passport_id: &'a str,
    selectors: &'a [PassportCredentialSelectorV2],
}

pub(super) fn passport_presentation_challenge_digest_v2(
    challenge: &PassportPresentationChallengeV2,
) -> Result<String, CredentialError> {
    domain_digest(
        PASSPORT_PRESENTATION_CHALLENGE_DIGEST_DOMAIN,
        &PassportPresentationChallengeDigestPreimageV2 {
            schema: &challenge.schema,
            verifier: &challenge.verifier,
            verifier_key_epoch: challenge.verifier_key_epoch,
            challenge_id: &challenge.challenge_id,
            nonce: &challenge.nonce,
            issued_at: &challenge.issued_at,
            expires_at: &challenge.expires_at,
            source_passport_id: &challenge.source_passport_id,
            selectors: &challenge.selectors,
        },
    )
}

pub(super) fn passport_manifest_leaf_v2(
    credential: &PassportCredentialV2,
) -> Result<PassportCredentialManifestLeafV2, CredentialError> {
    let family = match credential {
        PassportCredentialV2::Reputation(_) => PassportCredentialFamilyV2::Reputation,
        PassportCredentialV2::Financial(credential) => match credential.family {
            FinancialCredentialFamilyV1::CreditScorecard => {
                PassportCredentialFamilyV2::CreditScorecard
            }
            FinancialCredentialFamilyV1::ExposureHistory => {
                PassportCredentialFamilyV2::ExposureHistory
            }
            FinancialCredentialFamilyV1::SettlementReliability => {
                PassportCredentialFamilyV2::SettlementReliability
            }
            FinancialCredentialFamilyV1::PremiumHistory => {
                PassportCredentialFamilyV2::PremiumHistory
            }
            FinancialCredentialFamilyV1::LossHistory => PassportCredentialFamilyV2::LossHistory,
        },
    };
    let credential_ref_digest = domain_digest(
        PASSPORT_CREDENTIAL_REF_DOMAIN,
        &PassportCredentialRefPreimageV2 {
            family: family.clone(),
            credential,
        },
    )?;
    let credential_id = match credential {
        PassportCredentialV2::Reputation(_) => credential_ref_digest.clone(),
        PassportCredentialV2::Financial(credential) => credential.credential_id.clone(),
    };
    Ok(PassportCredentialManifestLeafV2 {
        credential_id,
        family,
        credential_ref_digest,
    })
}

pub(super) fn recompute_source_passport_id(
    body: &PassportSourceManifestV2,
) -> Result<String, CredentialError> {
    domain_digest(
        PASSPORT_SOURCE_MANIFEST_ID_DOMAIN,
        &PassportSourceManifestIdPreimageV2 {
            schema: &body.schema,
            issuer: &body.issuer,
            subject: &body.subject,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            credential_count: body.credential_count,
            credential_root: &body.credential_root,
            merkle_roots: &body.merkle_roots,
            enterprise_identity_provenance: &body.enterprise_identity_provenance,
            trust_tier: body.trust_tier,
        },
    )
}

pub(super) fn recompute_presentation_digest(
    manifest: &SignedPassportSourceManifestV2,
    challenge_digest: &str,
    proofs: &[PassportCredentialMembershipProofV2],
) -> Result<String, CredentialError> {
    let source_manifest_digest = sha256_hex(&canonical_json_bytes(manifest)?);
    let entries = proofs
        .iter()
        .map(|proof| PassportPresentationDigestEntryV2 {
            credential_id: &proof.leaf.credential_id,
            credential_ref_digest: &proof.leaf.credential_ref_digest,
        })
        .collect::<Vec<_>>();
    domain_digest(
        PASSPORT_PRESENTATION_DIGEST_DOMAIN,
        &PassportPresentationDigestPreimageV2 {
            source_manifest_digest: &source_manifest_digest,
            challenge_digest,
            credentials: &entries,
        },
    )
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, CredentialError> {
    let canonical = canonical_json_bytes(value)?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}
