use std::collections::{BTreeMap, BTreeSet};

use chio_federation::frost::{
    FrostAuthorizationBodyV1, FrostAuthorizationV1, FrostRosterV1, CHIO_FROST_AUTHORIZATION_SCHEMA,
};
use frost_ed25519::keys::{PublicKeyPackage, VerifyingShare};
use frost_ed25519::{round1, round2, Identifier, SigningPackage, VerifyingKey};

const MAX_COMMITMENT_BYTES: usize = 4096;
const MAX_SIGNATURE_SHARE_BYTES: usize = 1024;
const MAX_SIGNING_PACKAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrostCoordinatorError {
    #[error("invalid FROST coordinator input: {0}")]
    Invalid(&'static str),
    #[error("FROST coordinator cryptography failed: {0}")]
    Crypto(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostCoordinatorSigningPackage {
    participant_ids: Vec<String>,
    bytes: Vec<u8>,
}

impl FrostCoordinatorSigningPackage {
    #[must_use]
    pub fn participant_ids(&self) -> &[String] {
        &self.participant_ids
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub fn frost_participant_identifier_bytes(
    participant_id: &str,
) -> Result<Vec<u8>, FrostCoordinatorError> {
    Ok(participant_identifier(participant_id)?.serialize())
}

pub fn validate_frost_signing_commitment(
    roster: &FrostRosterV1,
    participant_id: &str,
    signer_identifier_bytes: &[u8],
    commitment_bytes: &[u8],
) -> Result<(), FrostCoordinatorError> {
    validate_roster_participant(roster, participant_id)?;
    let identifier = participant_identifier(participant_id)?;
    if identifier.serialize() != signer_identifier_bytes {
        return Err(FrostCoordinatorError::Invalid(
            "signer identifier does not match the roster participant",
        ));
    }
    decode_commitment(commitment_bytes)?;
    Ok(())
}

pub fn build_frost_signing_package(
    body: &FrostAuthorizationBodyV1,
    roster: &FrostRosterV1,
    commitments: &BTreeMap<String, Vec<u8>>,
) -> Result<FrostCoordinatorSigningPackage, FrostCoordinatorError> {
    validate_authorization_roster(body, roster)?;
    if commitments.len() < usize::from(roster.threshold) {
        return Err(FrostCoordinatorError::Invalid(
            "fewer than the threshold commitments are available",
        ));
    }
    if commitments.len() > usize::from(roster.participant_count) {
        return Err(FrostCoordinatorError::Invalid(
            "commitment set exceeds the roster",
        ));
    }
    for (participant_id, commitment_bytes) in commitments {
        validate_roster_participant(roster, participant_id)?;
        decode_commitment(commitment_bytes)?;
    }
    let mut selected = BTreeMap::new();
    let mut participant_ids = Vec::with_capacity(usize::from(roster.threshold));
    for (participant_id, commitment_bytes) in commitments.iter().take(usize::from(roster.threshold))
    {
        validate_roster_participant(roster, participant_id)?;
        let identifier = participant_identifier(participant_id)?;
        selected.insert(identifier, decode_commitment(commitment_bytes)?);
        participant_ids.push(participant_id.clone());
    }
    let message = body
        .signing_bytes()
        .map_err(|error| FrostCoordinatorError::Crypto(error.to_string()))?;
    let bytes = SigningPackage::new(selected, &message)
        .serialize()
        .map_err(crypto_error)?;
    Ok(FrostCoordinatorSigningPackage {
        participant_ids,
        bytes,
    })
}

pub fn verify_frost_signature_share(
    body: &FrostAuthorizationBodyV1,
    roster: &FrostRosterV1,
    signing_package_bytes: &[u8],
    participant_id: &str,
    signature_share_bytes: &[u8],
) -> Result<(), FrostCoordinatorError> {
    validate_authorization_roster(body, roster)?;
    let signing_package = decode_signing_package(body, signing_package_bytes)?;
    let identifier = participant_identifier(participant_id)?;
    if !signing_package
        .signing_commitments()
        .contains_key(&identifier)
    {
        return Err(FrostCoordinatorError::Invalid(
            "participant is not in the persisted signing set",
        ));
    }
    let public_keys = public_key_package(roster)?;
    let verifying_share =
        public_keys
            .verifying_shares()
            .get(&identifier)
            .ok_or(FrostCoordinatorError::Invalid(
                "participant is absent from the roster key package",
            ))?;
    let signature_share = decode_signature_share(signature_share_bytes)?;
    frost_core::verify_signature_share::<frost_ed25519::Ed25519Sha512>(
        identifier,
        verifying_share,
        &signature_share,
        &signing_package,
        public_keys.verifying_key(),
    )
    .map_err(crypto_error)
}

pub fn aggregate_frost_authorization(
    body: &FrostAuthorizationBodyV1,
    roster: &FrostRosterV1,
    signing_package_bytes: &[u8],
    shares: &BTreeMap<String, Vec<u8>>,
) -> Result<FrostAuthorizationV1, FrostCoordinatorError> {
    validate_authorization_roster(body, roster)?;
    let signing_package = decode_signing_package(body, signing_package_bytes)?;
    let participant_map = roster
        .participants
        .iter()
        .map(|participant| {
            Ok((
                participant_identifier(&participant.participant_id)?,
                participant.participant_id.as_str(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, FrostCoordinatorError>>()?;
    let selected = signing_package
        .signing_commitments()
        .keys()
        .map(|identifier| {
            participant_map
                .get(identifier)
                .copied()
                .ok_or(FrostCoordinatorError::Invalid(
                    "signing package contains an unknown participant",
                ))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if selected != shares.keys().map(String::as_str).collect() {
        return Err(FrostCoordinatorError::Invalid(
            "signature share set differs from the persisted signing set",
        ));
    }
    let mut decoded_shares = BTreeMap::new();
    for (participant_id, share_bytes) in shares {
        let identifier = participant_identifier(participant_id)?;
        decoded_shares.insert(identifier, decode_signature_share(share_bytes)?);
    }
    let public_keys = public_key_package(roster)?;
    let signature = frost_ed25519::aggregate(&signing_package, &decoded_shares, &public_keys)
        .map_err(crypto_error)?;
    let signature_bytes = signature.serialize().map_err(crypto_error)?;
    let proof = FrostAuthorizationV1 {
        schema: CHIO_FROST_AUTHORIZATION_SCHEMA.to_string(),
        body: body.clone(),
        suite_id: roster.suite_id.clone(),
        group_signature: hex::encode(signature_bytes),
    };
    proof
        .validate()
        .map_err(|error| FrostCoordinatorError::Crypto(error.to_string()))?;
    Ok(proof)
}

fn validate_authorization_roster(
    body: &FrostAuthorizationBodyV1,
    roster: &FrostRosterV1,
) -> Result<(), FrostCoordinatorError> {
    body.validate()
        .map_err(|error| FrostCoordinatorError::Crypto(error.to_string()))?;
    roster
        .validate_for_active_resolution()
        .map_err(|error| FrostCoordinatorError::Crypto(error.to_string()))?;
    if body.scope_id != roster.scope_id
        || body.roster_digest != roster.roster_digest
        || body.key_epoch != roster.key_epoch
        || body.quorum_n != roster.threshold
        || body.quorum_m != roster.participant_count
        || body.quorum_scope != roster.authority_scope
        || !roster.allowed_domains.contains(&body.domain)
    {
        return Err(FrostCoordinatorError::Invalid(
            "authorization does not match the roster",
        ));
    }
    Ok(())
}

fn validate_roster_participant(
    roster: &FrostRosterV1,
    participant_id: &str,
) -> Result<(), FrostCoordinatorError> {
    if roster
        .participants
        .iter()
        .any(|participant| participant.participant_id == participant_id)
    {
        Ok(())
    } else {
        Err(FrostCoordinatorError::Invalid(
            "participant is absent from the roster",
        ))
    }
}

fn participant_identifier(participant_id: &str) -> Result<Identifier, FrostCoordinatorError> {
    Identifier::derive(participant_id.as_bytes()).map_err(crypto_error)
}

fn decode_commitment(bytes: &[u8]) -> Result<round1::SigningCommitments, FrostCoordinatorError> {
    if bytes.is_empty() || bytes.len() > MAX_COMMITMENT_BYTES {
        return Err(FrostCoordinatorError::Invalid(
            "commitment length is outside the supported range",
        ));
    }
    round1::SigningCommitments::deserialize(bytes).map_err(crypto_error)
}

fn decode_signing_package(
    body: &FrostAuthorizationBodyV1,
    bytes: &[u8],
) -> Result<SigningPackage, FrostCoordinatorError> {
    if bytes.is_empty() || bytes.len() > MAX_SIGNING_PACKAGE_BYTES {
        return Err(FrostCoordinatorError::Invalid(
            "signing package length is outside the supported range",
        ));
    }
    let package = SigningPackage::deserialize(bytes).map_err(crypto_error)?;
    let expected_message = body
        .signing_bytes()
        .map_err(|error| FrostCoordinatorError::Crypto(error.to_string()))?;
    if package.message().as_slice() != expected_message.as_slice() {
        return Err(FrostCoordinatorError::Invalid(
            "signing package message differs from the authorization",
        ));
    }
    Ok(package)
}

fn decode_signature_share(bytes: &[u8]) -> Result<round2::SignatureShare, FrostCoordinatorError> {
    if bytes.is_empty() || bytes.len() > MAX_SIGNATURE_SHARE_BYTES {
        return Err(FrostCoordinatorError::Invalid(
            "signature share length is outside the supported range",
        ));
    }
    round2::SignatureShare::deserialize(bytes).map_err(crypto_error)
}

fn public_key_package(roster: &FrostRosterV1) -> Result<PublicKeyPackage, FrostCoordinatorError> {
    let mut verifying_shares = BTreeMap::new();
    for participant in &roster.participants {
        let identifier = participant_identifier(&participant.participant_id)?;
        let bytes = hex::decode(&participant.verification_share)
            .map_err(|_| FrostCoordinatorError::Invalid("verification share is not hexadecimal"))?;
        let share = VerifyingShare::deserialize(&bytes).map_err(crypto_error)?;
        verifying_shares.insert(identifier, share);
    }
    let group_key = hex::decode(&roster.group_public_key)
        .map_err(|_| FrostCoordinatorError::Invalid("group key is not hexadecimal"))?;
    let verifying_key = VerifyingKey::deserialize(&group_key).map_err(crypto_error)?;
    Ok(PublicKeyPackage::new(
        verifying_shares,
        verifying_key,
        Some(roster.threshold),
    ))
}

fn crypto_error(error: impl std::fmt::Display) -> FrostCoordinatorError {
    FrostCoordinatorError::Crypto(error.to_string())
}
