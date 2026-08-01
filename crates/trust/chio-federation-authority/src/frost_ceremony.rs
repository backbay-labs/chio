use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::{sha256_hex, Keypair, PublicKey, Signature, SigningAlgorithm};
use frost_ed25519::keys::dkg::{self, round1, round2};
use frost_ed25519::keys::{KeyPackage, PublicKeyPackage};
use frost_ed25519::rand_core::{CryptoRng, RngCore};
use frost_ed25519::Identifier;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const DKG_PACKAGE_SCHEMA: &str = "chio.frost.dkg-package.v1";
const CEREMONY_ID_PREFIX: &[u8] = b"chio.frost.ceremony.id.v1\0";
const PARTICIPANT_SET_DIGEST_PREFIX: &[u8] = b"chio.frost.participant-set.digest.v1\0";
const DKG_PACKAGE_SIGNING_PREFIX: &[u8] = b"CHIO-FROST-DKG-PACKAGE-V1\0";
const TRANSCRIPT_DIGEST_PREFIX: &[u8] = b"chio.frost.ceremony-transcript.digest.v1\0";
const MAX_DKG_PACKAGE_BYTES: usize = 256 * 1024;
const MAX_CUSTODY_SECRET_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrostCeremonyError {
    #[error("invalid FROST ceremony configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("invalid FROST ceremony secret: {0}")]
    InvalidSecret(&'static str),
    #[error("FROST DKG package authentication failed for {participant_id}: {detail}")]
    PackageAuthentication {
        participant_id: String,
        detail: &'static str,
    },
    #[error("duplicate FROST DKG package from {sender_participant_id} in {round:?}")]
    DuplicatePackage {
        round: FrostDkgRound,
        sender_participant_id: String,
    },
    #[error("invalid FROST DKG transcript: {0}")]
    Transcript(&'static str),
    #[error("FROST DKG cryptography failed: {0}")]
    Crypto(String),
    #[error("FROST DKG canonical encoding failed: {0}")]
    Canonical(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCeremonyParticipant {
    pub participant_id: String,
    pub transport_key_id: String,
    pub transport_public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCeremonyConfig {
    pub scope_id: String,
    pub key_epoch: u64,
    pub threshold: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_roster_digest: Option<String>,
    pub participants: Vec<FrostCeremonyParticipant>,
    pub local_participant_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrostDkgRound {
    Round1,
    Round2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrostCeremonySecretKind {
    Round1,
    Round2,
    KeyPackage,
}

pub struct FrostCeremonySecret {
    kind: FrostCeremonySecretKind,
    bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for FrostCeremonySecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrostCeremonySecret")
            .field("kind", &self.kind)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl FrostCeremonySecret {
    pub fn from_custody_bytes(
        kind: FrostCeremonySecretKind,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Self, FrostCeremonyError> {
        if bytes.is_empty() || bytes.len() > MAX_CUSTODY_SECRET_BYTES {
            return Err(FrostCeremonyError::InvalidSecret(
                "custody payload length is outside the supported range",
            ));
        }
        validate_secret_bytes(kind, &bytes)?;
        Ok(Self { kind, bytes })
    }

    #[must_use]
    pub const fn kind(&self) -> FrostCeremonySecretKind {
        self.kind
    }

    #[must_use]
    pub fn custody_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_custody_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }

    fn new(kind: FrostCeremonySecretKind, bytes: Vec<u8>) -> Result<Self, FrostCeremonyError> {
        Self::from_custody_bytes(kind, Zeroizing::new(bytes))
    }
}

impl FrostCeremonyConfig {
    pub fn validate(&self) -> Result<(), FrostCeremonyError> {
        validate_config(self)
    }

    pub fn ceremony_id(&self) -> Result<String, FrostCeremonyError> {
        Ok(ValidatedCeremony::new_without_key(self)?.ceremony_id)
    }

    pub fn participant_set_digest(&self) -> Result<String, FrostCeremonyError> {
        self.validate()?;
        participant_set_digest(self)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostAuthenticatedDkgPackage {
    schema: String,
    ceremony_id: String,
    participant_set_digest: String,
    key_epoch: u64,
    round: FrostDkgRound,
    sender_participant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_participant_id: Option<String>,
    package_digest: String,
    package_hex: Zeroizing<String>,
    transport_key_id: String,
    transport_signature: String,
}

impl std::fmt::Debug for FrostAuthenticatedDkgPackage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrostAuthenticatedDkgPackage")
            .field("ceremony_id", &self.ceremony_id)
            .field("round", &self.round)
            .field("sender_participant_id", &self.sender_participant_id)
            .field("recipient_participant_id", &self.recipient_participant_id)
            .field("package_digest", &self.package_digest)
            .field("package", &"<redacted>")
            .finish()
    }
}

impl FrostAuthenticatedDkgPackage {
    #[must_use]
    pub const fn round(&self) -> FrostDkgRound {
        self.round
    }

    #[must_use]
    pub fn sender_participant_id(&self) -> &str {
        &self.sender_participant_id
    }

    #[must_use]
    pub fn recipient_participant_id(&self) -> Option<&str> {
        self.recipient_participant_id.as_deref()
    }

    #[must_use]
    pub fn package_digest(&self) -> &str {
        &self.package_digest
    }

    fn package_bytes(&self) -> Result<Zeroizing<Vec<u8>>, FrostCeremonyError> {
        let bytes = hex::decode(self.package_hex.as_bytes()).map_err(|_| {
            package_authentication_error(&self.sender_participant_id, "package is not hexadecimal")
        })?;
        if bytes.is_empty() || bytes.len() > MAX_DKG_PACKAGE_BYTES {
            return Err(package_authentication_error(
                &self.sender_participant_id,
                "package length is outside the supported range",
            ));
        }
        Ok(Zeroizing::new(bytes))
    }

    fn signing_preimage(&self) -> DkgPackageSigningPreimage<'_> {
        DkgPackageSigningPreimage {
            schema: &self.schema,
            ceremony_id: &self.ceremony_id,
            participant_set_digest: &self.participant_set_digest,
            key_epoch: self.key_epoch,
            round: self.round,
            sender_participant_id: &self.sender_participant_id,
            recipient_participant_id: self.recipient_participant_id.as_deref(),
            package_digest: &self.package_digest,
            transport_key_id: &self.transport_key_id,
        }
    }
}

#[derive(Debug)]
pub struct FrostRound1Transition {
    pub secret: FrostCeremonySecret,
    pub package: FrostAuthenticatedDkgPackage,
}

#[derive(Debug)]
pub struct FrostRound2Transition {
    pub secret: FrostCeremonySecret,
    pub packages: Vec<FrostAuthenticatedDkgPackage>,
    pub round1_transcript_digest: String,
}

#[derive(Debug)]
pub struct FrostCeremonyCompletion {
    pub key_package: FrostCeremonySecret,
    pub public_key_package: Vec<u8>,
    pub group_public_key: String,
    pub verification_shares: BTreeMap<String, String>,
    pub transcript_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParticipantSetPreimage<'a> {
    scope_id: &'a str,
    key_epoch: u64,
    threshold: u16,
    predecessor_roster_digest: Option<&'a str>,
    participants: &'a [FrostCeremonyParticipant],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CeremonyIdPreimage<'a> {
    participant_set_digest: &'a str,
    scope_id: &'a str,
    key_epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DkgPackageSigningPreimage<'a> {
    schema: &'a str,
    ceremony_id: &'a str,
    participant_set_digest: &'a str,
    key_epoch: u64,
    round: FrostDkgRound,
    sender_participant_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient_participant_id: Option<&'a str>,
    package_digest: &'a str,
    transport_key_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TranscriptEntry<'a> {
    round: FrostDkgRound,
    sender_participant_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient_participant_id: Option<&'a str>,
    package_digest: &'a str,
    transport_key_id: &'a str,
    transport_signature: &'a str,
}

pub fn begin_frost_ceremony<R: CryptoRng + RngCore>(
    config: &FrostCeremonyConfig,
    transport_key: &Keypair,
    rng: &mut R,
) -> Result<FrostRound1Transition, FrostCeremonyError> {
    let context = ValidatedCeremony::new(config, transport_key)?;
    let local_identifier = context.local_identifier()?;
    let participant_count = context.participant_count()?;
    let (secret, package) = dkg::part1(local_identifier, participant_count, config.threshold, rng)
        .map_err(crypto_error)?;
    let secret = FrostCeremonySecret::new(
        FrostCeremonySecretKind::Round1,
        secret.serialize().map_err(crypto_error)?,
    )?;
    let package = authenticated_package(
        &context,
        FrostDkgRound::Round1,
        None,
        package.serialize().map_err(crypto_error)?,
        transport_key,
    )?;
    Ok(FrostRound1Transition { secret, package })
}

pub fn advance_frost_ceremony(
    config: &FrostCeremonyConfig,
    transport_key: &Keypair,
    secret: FrostCeremonySecret,
    round1_packages: &[FrostAuthenticatedDkgPackage],
) -> Result<FrostRound2Transition, FrostCeremonyError> {
    let context = ValidatedCeremony::new(config, transport_key)?;
    if secret.kind != FrostCeremonySecretKind::Round1 {
        return Err(FrostCeremonyError::InvalidSecret(
            "round two requires a round-one custody record",
        ));
    }
    let secret_package = round1::SecretPackage::deserialize(secret.custody_bytes())
        .map_err(|_| FrostCeremonyError::InvalidSecret("round-one package does not decode"))?;
    if secret_package.identifier() != &context.local_identifier()? {
        return Err(FrostCeremonyError::InvalidSecret(
            "round-one package belongs to another participant",
        ));
    }
    let validated = validate_round1_transcript(&context, round1_packages)?;
    let mut packages = BTreeMap::new();
    for package in validated {
        if package.sender_participant_id == config.local_participant_id {
            continue;
        }
        let identifier = context.identifier(&package.sender_participant_id)?;
        let bytes = package.package_bytes()?;
        let decoded = round1::Package::deserialize(&bytes).map_err(|_| {
            package_authentication_error(
                &package.sender_participant_id,
                "round-one package does not decode",
            )
        })?;
        packages.insert(identifier, decoded);
    }
    let (round2_secret, outbound) = dkg::part2(secret_package, &packages).map_err(crypto_error)?;
    let round2_secret = FrostCeremonySecret::new(
        FrostCeremonySecretKind::Round2,
        round2_secret.serialize().map_err(crypto_error)?,
    )?;
    let mut outbound = outbound
        .into_iter()
        .map(|(identifier, package)| {
            let recipient = context.participant_id(identifier)?;
            authenticated_package(
                &context,
                FrostDkgRound::Round2,
                Some(recipient),
                package.serialize().map_err(crypto_error)?,
                transport_key,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    outbound.sort_by(|left, right| {
        left.recipient_participant_id
            .cmp(&right.recipient_participant_id)
    });
    Ok(FrostRound2Transition {
        secret: round2_secret,
        packages: outbound,
        round1_transcript_digest: transcript_digest(round1_packages)?,
    })
}

pub fn complete_frost_ceremony(
    config: &FrostCeremonyConfig,
    secret: FrostCeremonySecret,
    round1_packages: &[FrostAuthenticatedDkgPackage],
    round2_packages: &[FrostAuthenticatedDkgPackage],
) -> Result<FrostCeremonyCompletion, FrostCeremonyError> {
    let context = ValidatedCeremony::new_without_key(config)?;
    if secret.kind != FrostCeremonySecretKind::Round2 {
        return Err(FrostCeremonyError::InvalidSecret(
            "completion requires a round-two custody record",
        ));
    }
    let secret_package = round2::SecretPackage::deserialize(secret.custody_bytes())
        .map_err(|_| FrostCeremonyError::InvalidSecret("round-two package does not decode"))?;
    if secret_package.identifier() != &context.local_identifier()? {
        return Err(FrostCeremonyError::InvalidSecret(
            "round-two package belongs to another participant",
        ));
    }
    let round1_packages = validate_round1_transcript(&context, round1_packages)?;
    let round2_packages = validate_round2_transcript(&context, round2_packages)?;

    let mut upstream_round1 = BTreeMap::new();
    for package in &round1_packages {
        if package.sender_participant_id == config.local_participant_id {
            continue;
        }
        let bytes = package.package_bytes()?;
        upstream_round1.insert(
            context.identifier(&package.sender_participant_id)?,
            round1::Package::deserialize(&bytes).map_err(|_| {
                package_authentication_error(
                    &package.sender_participant_id,
                    "round-one package does not decode",
                )
            })?,
        );
    }
    let mut upstream_round2 = BTreeMap::new();
    for package in &round2_packages {
        if package.recipient_participant_id.as_deref() != Some(&config.local_participant_id) {
            continue;
        }
        let bytes = package.package_bytes()?;
        upstream_round2.insert(
            context.identifier(&package.sender_participant_id)?,
            round2::Package::deserialize(&bytes).map_err(|_| {
                package_authentication_error(
                    &package.sender_participant_id,
                    "round-two package does not decode",
                )
            })?,
        );
    }
    let (key_package, public_key_package) =
        dkg::part3(&secret_package, &upstream_round1, &upstream_round2).map_err(crypto_error)?;
    completion_from_packages(
        &context,
        key_package,
        public_key_package,
        round1_packages,
        round2_packages,
    )
}

pub fn verify_frost_ceremony_round1_transcript(
    config: &FrostCeremonyConfig,
    packages: &[FrostAuthenticatedDkgPackage],
) -> Result<String, FrostCeremonyError> {
    let context = ValidatedCeremony::new_without_key(config)?;
    let packages = validate_round1_transcript(&context, packages)?;
    transcript_digest(&packages)
}

pub fn verify_frost_ceremony_transcript(
    config: &FrostCeremonyConfig,
    round1_packages: &[FrostAuthenticatedDkgPackage],
    round2_packages: &[FrostAuthenticatedDkgPackage],
) -> Result<String, FrostCeremonyError> {
    let context = ValidatedCeremony::new_without_key(config)?;
    let round1 = validate_round1_transcript(&context, round1_packages)?;
    let round2 = validate_round2_transcript(&context, round2_packages)?;
    let mut transcript = Vec::with_capacity(round1.len() + round2.len());
    transcript.extend(round1);
    transcript.extend(round2);
    transcript_digest(&transcript)
}

struct ValidatedCeremony<'a> {
    config: &'a FrostCeremonyConfig,
    ceremony_id: String,
    participant_set_digest: String,
    identifiers: BTreeMap<String, Identifier>,
}

impl<'a> ValidatedCeremony<'a> {
    fn new(
        config: &'a FrostCeremonyConfig,
        transport_key: &Keypair,
    ) -> Result<Self, FrostCeremonyError> {
        let context = Self::new_without_key(config)?;
        let local = context.local_participant()?;
        if local.transport_public_key != transport_key.public_key() {
            return Err(FrostCeremonyError::InvalidConfig(
                "local transport key does not match the configured participant",
            ));
        }
        Ok(context)
    }

    fn new_without_key(config: &'a FrostCeremonyConfig) -> Result<Self, FrostCeremonyError> {
        validate_config(config)?;
        let participant_set_digest = participant_set_digest(config)?;
        let ceremony_id = canonical_digest(
            CEREMONY_ID_PREFIX,
            &CeremonyIdPreimage {
                participant_set_digest: &participant_set_digest,
                scope_id: &config.scope_id,
                key_epoch: config.key_epoch,
            },
        )?;
        let mut identifiers = BTreeMap::new();
        let mut unique_identifiers = BTreeSet::new();
        for participant in &config.participants {
            let identifier = Identifier::derive(participant.participant_id.as_bytes())
                .map_err(|error| FrostCeremonyError::Crypto(error.to_string()))?;
            if !unique_identifiers.insert(identifier) {
                return Err(FrostCeremonyError::InvalidConfig(
                    "participant identifiers collide",
                ));
            }
            identifiers.insert(participant.participant_id.clone(), identifier);
        }
        Ok(Self {
            config,
            ceremony_id,
            participant_set_digest,
            identifiers,
        })
    }

    fn local_participant(&self) -> Result<&FrostCeremonyParticipant, FrostCeremonyError> {
        self.config
            .participants
            .iter()
            .find(|participant| participant.participant_id == self.config.local_participant_id)
            .ok_or(FrostCeremonyError::InvalidConfig(
                "local participant is not in the participant set",
            ))
    }

    fn local_identifier(&self) -> Result<Identifier, FrostCeremonyError> {
        self.identifier(&self.config.local_participant_id)
    }

    fn identifier(&self, participant_id: &str) -> Result<Identifier, FrostCeremonyError> {
        self.identifiers
            .get(participant_id)
            .copied()
            .ok_or(FrostCeremonyError::Transcript(
                "package names an unknown participant",
            ))
    }

    fn participant_id(&self, identifier: Identifier) -> Result<&str, FrostCeremonyError> {
        self.identifiers
            .iter()
            .find_map(|(participant_id, candidate)| {
                (*candidate == identifier).then_some(participant_id.as_str())
            })
            .ok_or(FrostCeremonyError::Crypto(
                "upstream DKG returned an unknown participant identifier".to_string(),
            ))
    }

    fn participant_count(&self) -> Result<u16, FrostCeremonyError> {
        u16::try_from(self.config.participants.len()).map_err(|_| {
            FrostCeremonyError::InvalidConfig("participant count exceeds the FROST limit")
        })
    }
}

fn completion_from_packages(
    context: &ValidatedCeremony<'_>,
    key_package: KeyPackage,
    public_key_package: PublicKeyPackage,
    round1_packages: Vec<&FrostAuthenticatedDkgPackage>,
    round2_packages: Vec<&FrostAuthenticatedDkgPackage>,
) -> Result<FrostCeremonyCompletion, FrostCeremonyError> {
    if public_key_package.min_signers() != Some(context.config.threshold)
        || public_key_package.max_signers() != context.participant_count()?
    {
        return Err(FrostCeremonyError::Crypto(
            "upstream public key package changed the configured quorum".to_string(),
        ));
    }
    let mut verification_shares = BTreeMap::new();
    for (identifier, share) in public_key_package.verifying_shares() {
        let participant_id = context.participant_id(*identifier)?;
        let serialized = share.serialize().map_err(crypto_error)?;
        verification_shares.insert(participant_id.to_string(), hex::encode(serialized));
    }
    if verification_shares.len() != context.config.participants.len() {
        return Err(FrostCeremonyError::Crypto(
            "upstream public key package omitted a participant".to_string(),
        ));
    }
    let mut transcript = Vec::with_capacity(round1_packages.len() + round2_packages.len());
    transcript.extend(round1_packages);
    transcript.extend(round2_packages);
    Ok(FrostCeremonyCompletion {
        key_package: FrostCeremonySecret::new(
            FrostCeremonySecretKind::KeyPackage,
            key_package.serialize().map_err(crypto_error)?,
        )?,
        public_key_package: public_key_package.serialize().map_err(crypto_error)?,
        group_public_key: hex::encode(
            public_key_package
                .verifying_key()
                .serialize()
                .map_err(crypto_error)?,
        ),
        verification_shares,
        transcript_digest: transcript_digest(&transcript)?,
    })
}

fn validate_config(config: &FrostCeremonyConfig) -> Result<(), FrostCeremonyError> {
    validate_identifier(&config.scope_id).map_err(FrostCeremonyError::InvalidConfig)?;
    validate_identifier(&config.local_participant_id).map_err(FrostCeremonyError::InvalidConfig)?;
    if config.key_epoch == 0 {
        return Err(FrostCeremonyError::InvalidConfig(
            "key epoch must be non-zero",
        ));
    }
    match (
        config.key_epoch,
        config.predecessor_roster_digest.as_deref(),
    ) {
        (1, None) => {}
        (1, Some(_)) => {
            return Err(FrostCeremonyError::InvalidConfig(
                "the first epoch must not have a predecessor",
            ));
        }
        (_, Some(digest)) if valid_digest(digest) => {}
        (_, Some(_)) => {
            return Err(FrostCeremonyError::InvalidConfig(
                "predecessor roster digest is invalid",
            ));
        }
        (_, None) => {
            return Err(FrostCeremonyError::InvalidConfig(
                "rotated epochs require a predecessor roster digest",
            ));
        }
    }
    let participant_count = u16::try_from(config.participants.len()).map_err(|_| {
        FrostCeremonyError::InvalidConfig("participant count exceeds the FROST limit")
    })?;
    if participant_count < 2 {
        return Err(FrostCeremonyError::InvalidConfig(
            "at least two participants are required",
        ));
    }
    if config.threshold < 2 || config.threshold > participant_count {
        return Err(FrostCeremonyError::InvalidConfig(
            "threshold must be between two and the participant count",
        ));
    }
    let mut transport_key_ids = BTreeSet::new();
    let mut transport_keys = BTreeSet::new();
    for (index, participant) in config.participants.iter().enumerate() {
        validate_identifier(&participant.participant_id)
            .map_err(FrostCeremonyError::InvalidConfig)?;
        validate_identifier(&participant.transport_key_id)
            .map_err(FrostCeremonyError::InvalidConfig)?;
        if participant.transport_public_key.algorithm() != SigningAlgorithm::Ed25519 {
            return Err(FrostCeremonyError::InvalidConfig(
                "transport keys must use Ed25519",
            ));
        }
        if index > 0 && config.participants[index - 1].participant_id >= participant.participant_id
        {
            return Err(FrostCeremonyError::InvalidConfig(
                "participants must be sorted by unique participant id",
            ));
        }
        if !transport_key_ids.insert(&participant.transport_key_id) {
            return Err(FrostCeremonyError::InvalidConfig(
                "transport key ids must be unique",
            ));
        }
        if !transport_keys.insert(participant.transport_public_key.to_hex()) {
            return Err(FrostCeremonyError::InvalidConfig(
                "transport public keys must be unique",
            ));
        }
    }
    if !config
        .participants
        .iter()
        .any(|participant| participant.participant_id == config.local_participant_id)
    {
        return Err(FrostCeremonyError::InvalidConfig(
            "local participant is not in the participant set",
        ));
    }
    Ok(())
}

fn validate_round1_transcript<'a>(
    context: &ValidatedCeremony<'_>,
    packages: &'a [FrostAuthenticatedDkgPackage],
) -> Result<Vec<&'a FrostAuthenticatedDkgPackage>, FrostCeremonyError> {
    let mut seen = BTreeSet::new();
    let mut validated = Vec::with_capacity(packages.len());
    for package in packages {
        validate_package(context, package, FrostDkgRound::Round1)?;
        if !seen.insert(package.sender_participant_id.as_str()) {
            return Err(FrostCeremonyError::DuplicatePackage {
                round: FrostDkgRound::Round1,
                sender_participant_id: package.sender_participant_id.clone(),
            });
        }
        validated.push(package);
    }
    if seen.len() != context.config.participants.len()
        || !context
            .config
            .participants
            .iter()
            .all(|participant| seen.contains(participant.participant_id.as_str()))
    {
        return Err(FrostCeremonyError::Transcript(
            "round one must contain exactly one package from every participant",
        ));
    }
    validated.sort_by(|left, right| left.sender_participant_id.cmp(&right.sender_participant_id));
    Ok(validated)
}

fn validate_round2_transcript<'a>(
    context: &ValidatedCeremony<'_>,
    packages: &'a [FrostAuthenticatedDkgPackage],
) -> Result<Vec<&'a FrostAuthenticatedDkgPackage>, FrostCeremonyError> {
    let mut seen = BTreeSet::new();
    let mut validated = Vec::with_capacity(packages.len());
    for package in packages {
        validate_package(context, package, FrostDkgRound::Round2)?;
        let recipient =
            package
                .recipient_participant_id
                .as_deref()
                .ok_or(FrostCeremonyError::Transcript(
                    "round-two package lacks a recipient",
                ))?;
        let key = (package.sender_participant_id.as_str(), recipient);
        if !seen.insert(key) {
            return Err(FrostCeremonyError::DuplicatePackage {
                round: FrostDkgRound::Round2,
                sender_participant_id: package.sender_participant_id.clone(),
            });
        }
        validated.push(package);
    }
    let expected = context
        .config
        .participants
        .len()
        .checked_mul(context.config.participants.len().saturating_sub(1))
        .ok_or(FrostCeremonyError::Transcript(
            "round-two package count overflowed",
        ))?;
    if seen.len() != expected {
        return Err(FrostCeremonyError::Transcript(
            "round two must contain every directed participant package exactly once",
        ));
    }
    for sender in &context.config.participants {
        for recipient in &context.config.participants {
            if sender.participant_id != recipient.participant_id
                && !seen.contains(&(
                    sender.participant_id.as_str(),
                    recipient.participant_id.as_str(),
                ))
            {
                return Err(FrostCeremonyError::Transcript(
                    "round two is missing a directed participant package",
                ));
            }
        }
    }
    validated.sort_by(|left, right| {
        (&left.sender_participant_id, &left.recipient_participant_id).cmp(&(
            &right.sender_participant_id,
            &right.recipient_participant_id,
        ))
    });
    Ok(validated)
}

fn validate_package(
    context: &ValidatedCeremony<'_>,
    package: &FrostAuthenticatedDkgPackage,
    expected_round: FrostDkgRound,
) -> Result<(), FrostCeremonyError> {
    if package.schema != DKG_PACKAGE_SCHEMA
        || package.ceremony_id != context.ceremony_id
        || package.participant_set_digest != context.participant_set_digest
        || package.key_epoch != context.config.key_epoch
        || package.round != expected_round
    {
        return Err(package_authentication_error(
            &package.sender_participant_id,
            "package ceremony binding does not match",
        ));
    }
    let sender = context
        .config
        .participants
        .iter()
        .find(|participant| participant.participant_id == package.sender_participant_id)
        .ok_or_else(|| {
            package_authentication_error(
                &package.sender_participant_id,
                "sender is not a ceremony participant",
            )
        })?;
    if sender.transport_key_id != package.transport_key_id {
        return Err(package_authentication_error(
            &package.sender_participant_id,
            "transport key id does not match",
        ));
    }
    match expected_round {
        FrostDkgRound::Round1 if package.recipient_participant_id.is_some() => {
            return Err(package_authentication_error(
                &package.sender_participant_id,
                "round-one package must be broadcast",
            ));
        }
        FrostDkgRound::Round2 => {
            let recipient = package.recipient_participant_id.as_deref().ok_or_else(|| {
                package_authentication_error(
                    &package.sender_participant_id,
                    "round-two package lacks a recipient",
                )
            })?;
            if recipient == package.sender_participant_id
                || !context
                    .config
                    .participants
                    .iter()
                    .any(|participant| participant.participant_id == recipient)
            {
                return Err(package_authentication_error(
                    &package.sender_participant_id,
                    "round-two recipient is invalid",
                ));
            }
        }
        FrostDkgRound::Round1 => {}
    }
    let bytes = package.package_bytes()?;
    if sha256_hex(&bytes) != package.package_digest {
        return Err(package_authentication_error(
            &package.sender_participant_id,
            "package digest does not match",
        ));
    }
    if !valid_digest(&package.package_digest) {
        return Err(package_authentication_error(
            &package.sender_participant_id,
            "package digest is invalid",
        ));
    }
    let signature = Signature::from_hex(&package.transport_signature).map_err(|_| {
        package_authentication_error(
            &package.sender_participant_id,
            "transport signature is invalid",
        )
    })?;
    let signing_bytes =
        canonical_prefixed_bytes(DKG_PACKAGE_SIGNING_PREFIX, &package.signing_preimage())?;
    if !sender
        .transport_public_key
        .verify(&signing_bytes, &signature)
    {
        return Err(package_authentication_error(
            &package.sender_participant_id,
            "transport signature does not verify",
        ));
    }
    Ok(())
}

fn authenticated_package(
    context: &ValidatedCeremony<'_>,
    round: FrostDkgRound,
    recipient_participant_id: Option<&str>,
    package_bytes: Vec<u8>,
    transport_key: &Keypair,
) -> Result<FrostAuthenticatedDkgPackage, FrostCeremonyError> {
    if package_bytes.is_empty() || package_bytes.len() > MAX_DKG_PACKAGE_BYTES {
        return Err(FrostCeremonyError::Crypto(
            "upstream DKG package length is outside the supported range".to_string(),
        ));
    }
    let local = context.local_participant()?;
    let mut package = FrostAuthenticatedDkgPackage {
        schema: DKG_PACKAGE_SCHEMA.to_string(),
        ceremony_id: context.ceremony_id.clone(),
        participant_set_digest: context.participant_set_digest.clone(),
        key_epoch: context.config.key_epoch,
        round,
        sender_participant_id: local.participant_id.clone(),
        recipient_participant_id: recipient_participant_id.map(str::to_string),
        package_digest: sha256_hex(&package_bytes),
        package_hex: Zeroizing::new(hex::encode(package_bytes)),
        transport_key_id: local.transport_key_id.clone(),
        transport_signature: String::new(),
    };
    package.transport_signature = transport_key
        .sign(&canonical_prefixed_bytes(
            DKG_PACKAGE_SIGNING_PREFIX,
            &package.signing_preimage(),
        )?)
        .to_hex();
    validate_package(context, &package, round)?;
    Ok(package)
}

fn transcript_digest(
    packages: &[impl std::borrow::Borrow<FrostAuthenticatedDkgPackage>],
) -> Result<String, FrostCeremonyError> {
    let mut packages = packages
        .iter()
        .map(std::borrow::Borrow::borrow)
        .collect::<Vec<_>>();
    packages.sort_by(|left, right| {
        (
            left.round,
            &left.sender_participant_id,
            &left.recipient_participant_id,
        )
            .cmp(&(
                right.round,
                &right.sender_participant_id,
                &right.recipient_participant_id,
            ))
    });
    let entries = packages
        .iter()
        .map(|package| TranscriptEntry {
            round: package.round,
            sender_participant_id: &package.sender_participant_id,
            recipient_participant_id: package.recipient_participant_id.as_deref(),
            package_digest: &package.package_digest,
            transport_key_id: &package.transport_key_id,
            transport_signature: &package.transport_signature,
        })
        .collect::<Vec<_>>();
    canonical_digest(TRANSCRIPT_DIGEST_PREFIX, &entries)
}

fn participant_set_digest(config: &FrostCeremonyConfig) -> Result<String, FrostCeremonyError> {
    canonical_digest(
        PARTICIPANT_SET_DIGEST_PREFIX,
        &ParticipantSetPreimage {
            scope_id: &config.scope_id,
            key_epoch: config.key_epoch,
            threshold: config.threshold,
            predecessor_roster_digest: config.predecessor_roster_digest.as_deref(),
            participants: &config.participants,
        },
    )
}

fn canonical_digest<T: Serialize>(prefix: &[u8], value: &T) -> Result<String, FrostCeremonyError> {
    Ok(sha256_hex(&canonical_prefixed_bytes(prefix, value)?))
}

fn canonical_prefixed_bytes<T: Serialize>(
    prefix: &[u8],
    value: &T,
) -> Result<Vec<u8>, FrostCeremonyError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| FrostCeremonyError::Canonical(error.to_string()))?;
    let mut bytes = Vec::with_capacity(prefix.len() + canonical.len());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn validate_secret_bytes(
    kind: FrostCeremonySecretKind,
    bytes: &[u8],
) -> Result<(), FrostCeremonyError> {
    let valid = match kind {
        FrostCeremonySecretKind::Round1 => round1::SecretPackage::deserialize(bytes).is_ok(),
        FrostCeremonySecretKind::Round2 => round2::SecretPackage::deserialize(bytes).is_ok(),
        FrostCeremonySecretKind::KeyPackage => KeyPackage::deserialize(bytes).is_ok(),
    };
    if !valid {
        return Err(FrostCeremonyError::InvalidSecret(
            "custody payload does not match its declared kind",
        ));
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.trim() != value
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err("identifiers must contain only unpadded printable ASCII");
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn package_authentication_error(participant_id: &str, detail: &'static str) -> FrostCeremonyError {
    FrostCeremonyError::PackageAuthentication {
        participant_id: participant_id.to_string(),
        detail,
    }
}

fn crypto_error(error: impl std::fmt::Display) -> FrostCeremonyError {
    FrostCeremonyError::Crypto(error.to_string())
}
