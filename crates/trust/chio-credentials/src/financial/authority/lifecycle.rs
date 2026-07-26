use super::*;
use super::trust::validate_epoch;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CrossIssuerLifecycleStatusV2 {
    Active,
    Suspended,
    Superseded,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleSourceIndexLeafV2 {
    pub source_passport_id: String,
    pub result_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerLifecycleCheckpointV2 {
    pub schema: String,
    pub resolver_identity: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub issuer_did: String,
    pub store_generation: u64,
    pub source_index_root: String,
    pub source_index_count: u64,
    pub trusted_clock_high_water: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_checkpoint_digest: Option<String>,
    pub checkpoint_digest: String,
}

pub type SignedIssuerLifecycleCheckpointV2 =
    chio_core::receipt::lineage::SignedExportEnvelope<IssuerLifecycleCheckpointV2>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossIssuerLifecycleResultV2 {
    pub schema: String,
    pub resolver_identity: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub issuer_did: String,
    pub store_generation: u64,
    pub status_version: u64,
    pub status: CrossIssuerLifecycleStatusV2,
    pub source_passport_id: String,
    pub source_manifest_digest: String,
    pub effective_at: u64,
    pub trusted_clock_high_water: u64,
    pub source_index_leaf: LifecycleSourceIndexLeafV2,
    pub source_index_proof: chio_core::MerkleProof,
    pub result_digest: String,
}

pub type SignedCrossIssuerLifecycleResultV2 =
    chio_core::receipt::lineage::SignedExportEnvelope<CrossIssuerLifecycleResultV2>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinglePassportLifecycleSnapshotInputV2 {
    pub resolver_identity: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub issuer_did: String,
    pub store_generation: u64,
    pub status_version: u64,
    pub status: CrossIssuerLifecycleStatusV2,
    pub source_passport_id: String,
    pub source_manifest_digest: String,
    pub effective_at: u64,
    pub trusted_clock_high_water: u64,
    pub predecessor_checkpoint_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinglePassportLifecycleSnapshotV2 {
    pub checkpoint: SignedIssuerLifecycleCheckpointV2,
    pub result: SignedCrossIssuerLifecycleResultV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerLifecycleGenerationPinV2 {
    pub schema: String,
    pub anchor_id: String,
    pub signer_key_epoch: u64,
    pub resolver_identity: String,
    pub issuer_did: String,
    pub store_generation: u64,
    pub checkpoint_digest: String,
    pub source_index_root: String,
    pub source_index_count: u64,
    pub trusted_clock_high_water: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_pin_digest: Option<String>,
    pub pin_digest: String,
}

pub type SignedIssuerLifecycleGenerationPinV2 =
    chio_core::receipt::lineage::SignedExportEnvelope<IssuerLifecycleGenerationPinV2>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleCheckpointPinCandidateV2 {
    pub resolver_identity: String,
    pub issuer_did: String,
    pub source_passport_id: String,
    pub store_generation: u64,
    pub status_version: u64,
    pub status: CrossIssuerLifecycleStatusV2,
    pub result_digest: String,
    pub checkpoint_digest: String,
    pub generation_pin_digest: String,
    pub trusted_clock_high_water: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleCheckpointPinV2 {
    pub schema: String,
    pub store_id: String,
    pub signer_key_epoch: u64,
    pub resolver_identity: String,
    pub issuer_did: String,
    pub source_passport_id: String,
    pub store_generation: u64,
    pub status_version: u64,
    pub status: CrossIssuerLifecycleStatusV2,
    pub result_digest: String,
    pub checkpoint_digest: String,
    pub generation_pin_digest: String,
    pub trusted_clock_high_water: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_pin_digest: Option<String>,
    pub pin_digest: String,
}

pub type SignedLifecycleCheckpointPinV2 =
    chio_core::receipt::lineage::SignedExportEnvelope<LifecycleCheckpointPinV2>;

pub trait TrustedClock {
    fn now(&self) -> Result<u64, FinancialAuthorityAvailabilityError>;
}

pub trait CrossIssuerLifecycleResolver {
    fn issuer_checkpoint(
        &self,
        resolver_identity: &str,
        issuer_did: &str,
        now: u64,
    ) -> Result<SignedIssuerLifecycleCheckpointV2, FinancialAuthorityAvailabilityError>;

    fn passport_result(
        &self,
        resolver_identity: &str,
        issuer_did: &str,
        source_passport_id: &str,
        now: u64,
    ) -> Result<SignedCrossIssuerLifecycleResultV2, FinancialAuthorityAvailabilityError>;
}

pub trait CrossIssuerLifecycleGenerationAnchor {
    fn compare_and_swap(
        &self,
        checkpoint: &SignedIssuerLifecycleCheckpointV2,
    ) -> Result<SignedIssuerLifecycleGenerationPinV2, FinancialAuthorityAvailabilityError>;
}

pub trait CrossIssuerLifecycleHighWaterStore {
    fn compare_and_swap(
        &self,
        candidate: &LifecycleCheckpointPinCandidateV2,
    ) -> Result<SignedLifecycleCheckpointPinV2, FinancialAuthorityAvailabilityError>;
}

#[derive(Debug, Clone)]
pub struct VerifiedCrossIssuerLifecycleV2 {
    generation: u64,
    status_version: u64,
    result_digest: String,
    generation_pin_digest: String,
    checkpoint_pin_digest: String,
    checkpoint_digest: String,
    source_index_proof_digest: String,
}

impl VerifiedCrossIssuerLifecycleV2 {
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn status_version(&self) -> u64 {
        self.status_version
    }

    #[must_use]
    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }

    #[must_use]
    pub fn generation_pin_digest(&self) -> &str {
        &self.generation_pin_digest
    }

    #[must_use]
    pub fn checkpoint_pin_digest(&self) -> &str {
        &self.checkpoint_pin_digest
    }

    #[must_use]
    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint_digest
    }

    #[must_use]
    pub fn source_index_proof_digest(&self) -> &str {
        &self.source_index_proof_digest
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LifecycleResultDigestPreimageV2<'a> {
    schema: &'a str,
    resolver_identity: &'a str,
    signer_key_id: &'a str,
    signer_key_epoch: u64,
    issuer_did: &'a str,
    store_generation: u64,
    status_version: u64,
    status: CrossIssuerLifecycleStatusV2,
    source_passport_id: &'a str,
    source_manifest_digest: &'a str,
    effective_at: u64,
    trusted_clock_high_water: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LifecycleCheckpointDigestPreimageV2<'a> {
    schema: &'a str,
    resolver_identity: &'a str,
    signer_key_id: &'a str,
    signer_key_epoch: u64,
    issuer_did: &'a str,
    store_generation: u64,
    source_index_root: &'a str,
    source_index_count: u64,
    trusted_clock_high_water: u64,
    predecessor_checkpoint_digest: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LifecycleGenerationPinDigestPreimageV2<'a> {
    schema: &'a str,
    anchor_id: &'a str,
    signer_key_epoch: u64,
    resolver_identity: &'a str,
    issuer_did: &'a str,
    store_generation: u64,
    checkpoint_digest: &'a str,
    source_index_root: &'a str,
    source_index_count: u64,
    trusted_clock_high_water: u64,
    previous_pin_digest: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LifecycleCheckpointPinDigestPreimageV2<'a> {
    schema: &'a str,
    store_id: &'a str,
    signer_key_epoch: u64,
    resolver_identity: &'a str,
    issuer_did: &'a str,
    source_passport_id: &'a str,
    store_generation: u64,
    status_version: u64,
    status: CrossIssuerLifecycleStatusV2,
    result_digest: &'a str,
    checkpoint_digest: &'a str,
    generation_pin_digest: &'a str,
    trusted_clock_high_water: u64,
    previous_pin_digest: Option<&'a str>,
}

pub fn sign_single_passport_lifecycle_snapshot_v2(
    signer: &Keypair,
    input: SinglePassportLifecycleSnapshotInputV2,
) -> Result<SinglePassportLifecycleSnapshotV2, CredentialError> {
    validate_snapshot_input(&input)?;
    let result_digest = authority_digest(
        LIFECYCLE_RESULT_DIGEST_DOMAIN,
        &LifecycleResultDigestPreimageV2 {
            schema: FINANCIAL_CROSS_ISSUER_LIFECYCLE_RESULT_SCHEMA_V1,
            resolver_identity: &input.resolver_identity,
            signer_key_id: &input.signer_key_id,
            signer_key_epoch: input.signer_key_epoch,
            issuer_did: &input.issuer_did,
            store_generation: input.store_generation,
            status_version: input.status_version,
            status: input.status,
            source_passport_id: &input.source_passport_id,
            source_manifest_digest: &input.source_manifest_digest,
            effective_at: input.effective_at,
            trusted_clock_high_water: input.trusted_clock_high_water,
        },
    )?;
    let leaf = LifecycleSourceIndexLeafV2 {
        source_passport_id: input.source_passport_id.clone(),
        result_digest: result_digest.clone(),
    };
    let leaf_bytes = canonical_json_bytes(&leaf)?;
    let tree = chio_core::MerkleTree::from_leaves(&[leaf_bytes])?;
    let mut checkpoint = IssuerLifecycleCheckpointV2 {
        schema: FINANCIAL_ISSUER_LIFECYCLE_CHECKPOINT_SCHEMA_V1.to_string(),
        resolver_identity: input.resolver_identity.clone(),
        signer_key_id: input.signer_key_id.clone(),
        signer_key_epoch: input.signer_key_epoch,
        issuer_did: input.issuer_did.clone(),
        store_generation: input.store_generation,
        source_index_root: tree.root().to_hex(),
        source_index_count: 1,
        trusted_clock_high_water: input.trusted_clock_high_water,
        predecessor_checkpoint_digest: input.predecessor_checkpoint_digest,
        checkpoint_digest: String::new(),
    };
    checkpoint.checkpoint_digest = recompute_lifecycle_checkpoint_digest(&checkpoint)?;
    let checkpoint = SignedIssuerLifecycleCheckpointV2::sign(checkpoint, signer)?;
    let result = CrossIssuerLifecycleResultV2 {
        schema: FINANCIAL_CROSS_ISSUER_LIFECYCLE_RESULT_SCHEMA_V1.to_string(),
        resolver_identity: input.resolver_identity,
        signer_key_id: input.signer_key_id,
        signer_key_epoch: input.signer_key_epoch,
        issuer_did: input.issuer_did,
        store_generation: input.store_generation,
        status_version: input.status_version,
        status: input.status,
        source_passport_id: input.source_passport_id,
        source_manifest_digest: input.source_manifest_digest,
        effective_at: input.effective_at,
        trusted_clock_high_water: input.trusted_clock_high_water,
        source_index_leaf: leaf,
        source_index_proof: tree.inclusion_proof(0)?,
        result_digest,
    };
    Ok(SinglePassportLifecycleSnapshotV2 {
        checkpoint,
        result: SignedCrossIssuerLifecycleResultV2::sign(result, signer)?,
    })
}

pub fn sign_issuer_lifecycle_generation_pin_v2(
    signer: &Keypair,
    anchor_id: &str,
    signer_key_epoch: u64,
    checkpoint: &SignedIssuerLifecycleCheckpointV2,
    previous_pin_digest: Option<&str>,
) -> Result<SignedIssuerLifecycleGenerationPinV2, CredentialError> {
    validate_text("generationPin.anchorId", anchor_id)?;
    validate_epoch("generationPin.signerKeyEpoch", signer_key_epoch)?;
    validate_optional_digest("generationPin.previousPinDigest", previous_pin_digest)?;
    let mut body = IssuerLifecycleGenerationPinV2 {
        schema: FINANCIAL_ISSUER_LIFECYCLE_GENERATION_PIN_SCHEMA_V1.to_string(),
        anchor_id: anchor_id.to_string(),
        signer_key_epoch,
        resolver_identity: checkpoint.body.resolver_identity.clone(),
        issuer_did: checkpoint.body.issuer_did.clone(),
        store_generation: checkpoint.body.store_generation,
        checkpoint_digest: checkpoint.body.checkpoint_digest.clone(),
        source_index_root: checkpoint.body.source_index_root.clone(),
        source_index_count: checkpoint.body.source_index_count,
        trusted_clock_high_water: checkpoint.body.trusted_clock_high_water,
        previous_pin_digest: previous_pin_digest.map(str::to_string),
        pin_digest: String::new(),
    };
    validate_generation_pin_body(&body, false)?;
    body.pin_digest = recompute_generation_pin_digest(&body)?;
    Ok(SignedIssuerLifecycleGenerationPinV2::sign(body, signer)?)
}

pub fn sign_lifecycle_checkpoint_pin_v2(
    signer: &Keypair,
    store_id: &str,
    signer_key_epoch: u64,
    candidate: &LifecycleCheckpointPinCandidateV2,
    previous_pin_digest: Option<&str>,
) -> Result<SignedLifecycleCheckpointPinV2, CredentialError> {
    validate_text("checkpointPin.storeId", store_id)?;
    validate_epoch("checkpointPin.signerKeyEpoch", signer_key_epoch)?;
    validate_checkpoint_pin_candidate(candidate)?;
    validate_optional_digest("checkpointPin.previousPinDigest", previous_pin_digest)?;
    let mut body = LifecycleCheckpointPinV2 {
        schema: FINANCIAL_LIFECYCLE_CHECKPOINT_PIN_SCHEMA_V1.to_string(),
        store_id: store_id.to_string(),
        signer_key_epoch,
        resolver_identity: candidate.resolver_identity.clone(),
        issuer_did: candidate.issuer_did.clone(),
        source_passport_id: candidate.source_passport_id.clone(),
        store_generation: candidate.store_generation,
        status_version: candidate.status_version,
        status: candidate.status,
        result_digest: candidate.result_digest.clone(),
        checkpoint_digest: candidate.checkpoint_digest.clone(),
        generation_pin_digest: candidate.generation_pin_digest.clone(),
        trusted_clock_high_water: candidate.trusted_clock_high_water,
        previous_pin_digest: previous_pin_digest.map(str::to_string),
        pin_digest: String::new(),
    };
    validate_checkpoint_pin_body(&body, false)?;
    body.pin_digest = recompute_checkpoint_pin_digest(&body)?;
    Ok(SignedLifecycleCheckpointPinV2::sign(body, signer)?)
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_cross_issuer_lifecycle_v2(
    resolver_identity: &str,
    issuer_did: &str,
    source_passport_id: &str,
    source_manifest_digest: &str,
    trust: &CrossIssuerTrustRegistryV2,
    resolver: &dyn CrossIssuerLifecycleResolver,
    generation_anchor: &dyn CrossIssuerLifecycleGenerationAnchor,
    high_water: &dyn CrossIssuerLifecycleHighWaterStore,
    clock: &dyn TrustedClock,
) -> Result<VerifiedCrossIssuerLifecycleV2, CredentialError> {
    validate_text("lifecycle.resolverIdentity", resolver_identity)?;
    DidChio::from_str(issuer_did)?;
    validate_digest("lifecycle.sourcePassportId", source_passport_id)?;
    validate_digest("lifecycle.sourceManifestDigest", source_manifest_digest)?;
    let now = clock
        .now()
        .map_err(|error| availability_error("trusted clock", error))?;
    validate_time("lifecycle.now", now)?;
    let checkpoint = resolver
        .issuer_checkpoint(resolver_identity, issuer_did, now)
        .map_err(|error| availability_error("lifecycle resolver checkpoint", error))?;
    verify_lifecycle_checkpoint(&checkpoint, resolver_identity, issuer_did, trust, now)?;
    let generation_pin = generation_anchor
        .compare_and_swap(&checkpoint)
        .map_err(|error| availability_error("lifecycle generation anchor", error))?;
    verify_generation_pin(&generation_pin, &checkpoint, trust)?;
    let result = resolver
        .passport_result(resolver_identity, issuer_did, source_passport_id, now)
        .map_err(|error| availability_error("lifecycle resolver result", error))?;
    let source_index_proof_digest = verify_lifecycle_result(
        &result,
        &checkpoint,
        source_passport_id,
        source_manifest_digest,
        trust,
        now,
    )?;
    let candidate = LifecycleCheckpointPinCandidateV2 {
        resolver_identity: resolver_identity.to_string(),
        issuer_did: issuer_did.to_string(),
        source_passport_id: source_passport_id.to_string(),
        store_generation: result.body.store_generation,
        status_version: result.body.status_version,
        status: result.body.status,
        result_digest: result.body.result_digest.clone(),
        checkpoint_digest: checkpoint.body.checkpoint_digest.clone(),
        generation_pin_digest: generation_pin.body.pin_digest.clone(),
        trusted_clock_high_water: result.body.trusted_clock_high_water,
    };
    let checkpoint_pin = high_water
        .compare_and_swap(&candidate)
        .map_err(|error| availability_error("lifecycle high-water store", error))?;
    verify_checkpoint_pin(&checkpoint_pin, &candidate, trust)?;
    if result.body.status != CrossIssuerLifecycleStatusV2::Active {
        return Err(authority_error(
            "cross-issuer lifecycle status is not active",
        ));
    }
    Ok(VerifiedCrossIssuerLifecycleV2 {
        generation: result.body.store_generation,
        status_version: result.body.status_version,
        result_digest: result.body.result_digest.clone(),
        generation_pin_digest: generation_pin.body.pin_digest.clone(),
        checkpoint_pin_digest: checkpoint_pin.body.pin_digest.clone(),
        checkpoint_digest: checkpoint.body.checkpoint_digest.clone(),
        source_index_proof_digest,
    })
}

fn verify_lifecycle_checkpoint(
    checkpoint: &SignedIssuerLifecycleCheckpointV2,
    resolver_identity: &str,
    issuer_did: &str,
    trust: &CrossIssuerTrustRegistryV2,
    now: u64,
) -> Result<(), CredentialError> {
    validate_lifecycle_checkpoint_body(&checkpoint.body)?;
    if checkpoint.body.resolver_identity != resolver_identity
        || checkpoint.body.issuer_did != issuer_did
        || checkpoint.body.trusted_clock_high_water > now
        || recompute_lifecycle_checkpoint_digest(&checkpoint.body)?
            != checkpoint.body.checkpoint_digest
    {
        return Err(authority_error("lifecycle checkpoint binding is invalid"));
    }
    let key = trust.resolver_key(
        resolver_identity,
        &checkpoint.body.signer_key_id,
        checkpoint.body.signer_key_epoch,
    )?;
    if key.public_key != checkpoint.signer_key || !checkpoint.verify_signature()? {
        return Err(authority_error(
            "lifecycle checkpoint signer does not match local trust",
        ));
    }
    Ok(())
}

fn verify_generation_pin(
    pin: &SignedIssuerLifecycleGenerationPinV2,
    checkpoint: &SignedIssuerLifecycleCheckpointV2,
    trust: &CrossIssuerTrustRegistryV2,
) -> Result<(), CredentialError> {
    validate_generation_pin_body(&pin.body, true)?;
    if pin.body.resolver_identity != checkpoint.body.resolver_identity
        || pin.body.issuer_did != checkpoint.body.issuer_did
        || pin.body.store_generation != checkpoint.body.store_generation
        || pin.body.checkpoint_digest != checkpoint.body.checkpoint_digest
        || pin.body.source_index_root != checkpoint.body.source_index_root
        || pin.body.source_index_count != checkpoint.body.source_index_count
        || pin.body.trusted_clock_high_water != checkpoint.body.trusted_clock_high_water
        || recompute_generation_pin_digest(&pin.body)? != pin.body.pin_digest
    {
        return Err(authority_error(
            "lifecycle generation anchor acknowledgement is invalid",
        ));
    }
    let key = trust.generation_anchor_key(&pin.body.anchor_id, pin.body.signer_key_epoch)?;
    if key.public_key != pin.signer_key || !pin.verify_signature()? {
        return Err(authority_error(
            "lifecycle generation anchor signer does not match local trust",
        ));
    }
    Ok(())
}

fn verify_lifecycle_result(
    result: &SignedCrossIssuerLifecycleResultV2,
    checkpoint: &SignedIssuerLifecycleCheckpointV2,
    source_passport_id: &str,
    source_manifest_digest: &str,
    trust: &CrossIssuerTrustRegistryV2,
    now: u64,
) -> Result<String, CredentialError> {
    validate_lifecycle_result_body(&result.body)?;
    if result.body.resolver_identity != checkpoint.body.resolver_identity
        || result.body.signer_key_id != checkpoint.body.signer_key_id
        || result.body.signer_key_epoch != checkpoint.body.signer_key_epoch
        || result.body.issuer_did != checkpoint.body.issuer_did
        || result.body.store_generation != checkpoint.body.store_generation
        || result.body.source_passport_id != source_passport_id
        || result.body.source_manifest_digest != source_manifest_digest
        || result.body.effective_at > now
        || result.body.trusted_clock_high_water != checkpoint.body.trusted_clock_high_water
        || result.body.trusted_clock_high_water > now
        || recompute_lifecycle_result_digest(&result.body)? != result.body.result_digest
        || result.body.source_index_leaf.source_passport_id != source_passport_id
        || result.body.source_index_leaf.result_digest != result.body.result_digest
    {
        return Err(authority_error("lifecycle result binding is invalid"));
    }
    let expected_count = usize::try_from(checkpoint.body.source_index_count)
        .map_err(|_| authority_error("lifecycle source index count overflows"))?;
    let root = chio_core::Hash::from_hex(&checkpoint.body.source_index_root)?;
    if result.body.source_index_proof.tree_size != expected_count
        || !result.body.source_index_proof.verify(
            &canonical_json_bytes(&result.body.source_index_leaf)?,
            &root,
        )
    {
        return Err(authority_error("lifecycle source index proof is invalid"));
    }
    let key = trust.resolver_key(
        &result.body.resolver_identity,
        &result.body.signer_key_id,
        result.body.signer_key_epoch,
    )?;
    if key.public_key != result.signer_key || !result.verify_signature()? {
        return Err(authority_error(
            "lifecycle result signer does not match local trust",
        ));
    }
    Ok(sha256_hex(&canonical_json_bytes(
        &result.body.source_index_proof,
    )?))
}

fn verify_checkpoint_pin(
    pin: &SignedLifecycleCheckpointPinV2,
    candidate: &LifecycleCheckpointPinCandidateV2,
    trust: &CrossIssuerTrustRegistryV2,
) -> Result<(), CredentialError> {
    validate_checkpoint_pin_body(&pin.body, true)?;
    if pin.body.resolver_identity != candidate.resolver_identity
        || pin.body.issuer_did != candidate.issuer_did
        || pin.body.source_passport_id != candidate.source_passport_id
        || pin.body.store_generation != candidate.store_generation
        || pin.body.status_version != candidate.status_version
        || pin.body.status != candidate.status
        || pin.body.result_digest != candidate.result_digest
        || pin.body.checkpoint_digest != candidate.checkpoint_digest
        || pin.body.generation_pin_digest != candidate.generation_pin_digest
        || pin.body.trusted_clock_high_water != candidate.trusted_clock_high_water
        || recompute_checkpoint_pin_digest(&pin.body)? != pin.body.pin_digest
    {
        return Err(authority_error(
            "lifecycle high-water acknowledgement is invalid",
        ));
    }
    let key = trust.high_water_key(&pin.body.store_id, pin.body.signer_key_epoch)?;
    if key.public_key != pin.signer_key || !pin.verify_signature()? {
        return Err(authority_error(
            "lifecycle high-water signer does not match local trust",
        ));
    }
    Ok(())
}

fn validate_snapshot_input(
    input: &SinglePassportLifecycleSnapshotInputV2,
) -> Result<(), CredentialError> {
    validate_text("lifecycle.resolverIdentity", &input.resolver_identity)?;
    validate_text("lifecycle.signerKeyId", &input.signer_key_id)?;
    validate_epoch("lifecycle.signerKeyEpoch", input.signer_key_epoch)?;
    DidChio::from_str(&input.issuer_did)?;
    validate_epoch("lifecycle.storeGeneration", input.store_generation)?;
    validate_epoch("lifecycle.statusVersion", input.status_version)?;
    validate_digest("lifecycle.sourcePassportId", &input.source_passport_id)?;
    validate_digest(
        "lifecycle.sourceManifestDigest",
        &input.source_manifest_digest,
    )?;
    validate_time("lifecycle.effectiveAt", input.effective_at)?;
    validate_time(
        "lifecycle.trustedClockHighWater",
        input.trusted_clock_high_water,
    )?;
    if input.effective_at > input.trusted_clock_high_water {
        return Err(authority_error("lifecycle effective time is in the future"));
    }
    validate_optional_digest(
        "lifecycle.predecessorCheckpointDigest",
        input.predecessor_checkpoint_digest.as_deref(),
    )
}

fn validate_lifecycle_checkpoint_body(
    body: &IssuerLifecycleCheckpointV2,
) -> Result<(), CredentialError> {
    if body.schema != FINANCIAL_ISSUER_LIFECYCLE_CHECKPOINT_SCHEMA_V1 {
        return Err(authority_error("lifecycle checkpoint schema is invalid"));
    }
    validate_text("checkpoint.resolverIdentity", &body.resolver_identity)?;
    validate_text("checkpoint.signerKeyId", &body.signer_key_id)?;
    validate_epoch("checkpoint.signerKeyEpoch", body.signer_key_epoch)?;
    DidChio::from_str(&body.issuer_did)?;
    validate_epoch("checkpoint.storeGeneration", body.store_generation)?;
    validate_digest("checkpoint.sourceIndexRoot", &body.source_index_root)?;
    validate_epoch("checkpoint.sourceIndexCount", body.source_index_count)?;
    validate_time(
        "checkpoint.trustedClockHighWater",
        body.trusted_clock_high_water,
    )?;
    validate_optional_digest(
        "checkpoint.predecessorCheckpointDigest",
        body.predecessor_checkpoint_digest.as_deref(),
    )?;
    validate_digest("checkpoint.checkpointDigest", &body.checkpoint_digest)
}

fn validate_lifecycle_result_body(
    body: &CrossIssuerLifecycleResultV2,
) -> Result<(), CredentialError> {
    if body.schema != FINANCIAL_CROSS_ISSUER_LIFECYCLE_RESULT_SCHEMA_V1 {
        return Err(authority_error("lifecycle result schema is invalid"));
    }
    validate_text("lifecycleResult.resolverIdentity", &body.resolver_identity)?;
    validate_text("lifecycleResult.signerKeyId", &body.signer_key_id)?;
    validate_epoch("lifecycleResult.signerKeyEpoch", body.signer_key_epoch)?;
    DidChio::from_str(&body.issuer_did)?;
    validate_epoch("lifecycleResult.storeGeneration", body.store_generation)?;
    validate_epoch("lifecycleResult.statusVersion", body.status_version)?;
    validate_digest("lifecycleResult.sourcePassportId", &body.source_passport_id)?;
    validate_digest(
        "lifecycleResult.sourceManifestDigest",
        &body.source_manifest_digest,
    )?;
    validate_time("lifecycleResult.effectiveAt", body.effective_at)?;
    validate_time(
        "lifecycleResult.trustedClockHighWater",
        body.trusted_clock_high_water,
    )?;
    if body.effective_at > body.trusted_clock_high_water {
        return Err(authority_error("lifecycle result time is invalid"));
    }
    validate_digest(
        "lifecycleResult.leaf.sourcePassportId",
        &body.source_index_leaf.source_passport_id,
    )?;
    validate_digest(
        "lifecycleResult.leaf.resultDigest",
        &body.source_index_leaf.result_digest,
    )?;
    validate_digest("lifecycleResult.resultDigest", &body.result_digest)
}

fn validate_generation_pin_body(
    body: &IssuerLifecycleGenerationPinV2,
    require_digest: bool,
) -> Result<(), CredentialError> {
    if body.schema != FINANCIAL_ISSUER_LIFECYCLE_GENERATION_PIN_SCHEMA_V1 {
        return Err(authority_error(
            "lifecycle generation pin schema is invalid",
        ));
    }
    validate_text("generationPin.anchorId", &body.anchor_id)?;
    validate_epoch("generationPin.signerKeyEpoch", body.signer_key_epoch)?;
    validate_text("generationPin.resolverIdentity", &body.resolver_identity)?;
    DidChio::from_str(&body.issuer_did)?;
    validate_epoch("generationPin.storeGeneration", body.store_generation)?;
    validate_digest("generationPin.checkpointDigest", &body.checkpoint_digest)?;
    validate_digest("generationPin.sourceIndexRoot", &body.source_index_root)?;
    validate_epoch("generationPin.sourceIndexCount", body.source_index_count)?;
    validate_time(
        "generationPin.trustedClockHighWater",
        body.trusted_clock_high_water,
    )?;
    validate_optional_digest(
        "generationPin.previousPinDigest",
        body.previous_pin_digest.as_deref(),
    )?;
    if require_digest {
        validate_digest("generationPin.pinDigest", &body.pin_digest)?;
    }
    Ok(())
}

fn validate_checkpoint_pin_candidate(
    candidate: &LifecycleCheckpointPinCandidateV2,
) -> Result<(), CredentialError> {
    validate_text(
        "checkpointPin.resolverIdentity",
        &candidate.resolver_identity,
    )?;
    DidChio::from_str(&candidate.issuer_did)?;
    validate_digest(
        "checkpointPin.sourcePassportId",
        &candidate.source_passport_id,
    )?;
    validate_epoch("checkpointPin.storeGeneration", candidate.store_generation)?;
    validate_epoch("checkpointPin.statusVersion", candidate.status_version)?;
    validate_digest("checkpointPin.resultDigest", &candidate.result_digest)?;
    validate_digest(
        "checkpointPin.checkpointDigest",
        &candidate.checkpoint_digest,
    )?;
    validate_digest(
        "checkpointPin.generationPinDigest",
        &candidate.generation_pin_digest,
    )?;
    validate_time(
        "checkpointPin.trustedClockHighWater",
        candidate.trusted_clock_high_water,
    )
}

fn validate_checkpoint_pin_body(
    body: &LifecycleCheckpointPinV2,
    require_digest: bool,
) -> Result<(), CredentialError> {
    if body.schema != FINANCIAL_LIFECYCLE_CHECKPOINT_PIN_SCHEMA_V1 {
        return Err(authority_error(
            "lifecycle checkpoint pin schema is invalid",
        ));
    }
    validate_text("checkpointPin.storeId", &body.store_id)?;
    validate_epoch("checkpointPin.signerKeyEpoch", body.signer_key_epoch)?;
    validate_checkpoint_pin_candidate(&LifecycleCheckpointPinCandidateV2 {
        resolver_identity: body.resolver_identity.clone(),
        issuer_did: body.issuer_did.clone(),
        source_passport_id: body.source_passport_id.clone(),
        store_generation: body.store_generation,
        status_version: body.status_version,
        status: body.status,
        result_digest: body.result_digest.clone(),
        checkpoint_digest: body.checkpoint_digest.clone(),
        generation_pin_digest: body.generation_pin_digest.clone(),
        trusted_clock_high_water: body.trusted_clock_high_water,
    })?;
    validate_optional_digest(
        "checkpointPin.previousPinDigest",
        body.previous_pin_digest.as_deref(),
    )?;
    if require_digest {
        validate_digest("checkpointPin.pinDigest", &body.pin_digest)?;
    }
    Ok(())
}

fn recompute_lifecycle_checkpoint_digest(
    body: &IssuerLifecycleCheckpointV2,
) -> Result<String, CredentialError> {
    authority_digest(
        LIFECYCLE_CHECKPOINT_DIGEST_DOMAIN,
        &LifecycleCheckpointDigestPreimageV2 {
            schema: &body.schema,
            resolver_identity: &body.resolver_identity,
            signer_key_id: &body.signer_key_id,
            signer_key_epoch: body.signer_key_epoch,
            issuer_did: &body.issuer_did,
            store_generation: body.store_generation,
            source_index_root: &body.source_index_root,
            source_index_count: body.source_index_count,
            trusted_clock_high_water: body.trusted_clock_high_water,
            predecessor_checkpoint_digest: body.predecessor_checkpoint_digest.as_deref(),
        },
    )
}

fn recompute_lifecycle_result_digest(
    body: &CrossIssuerLifecycleResultV2,
) -> Result<String, CredentialError> {
    authority_digest(
        LIFECYCLE_RESULT_DIGEST_DOMAIN,
        &LifecycleResultDigestPreimageV2 {
            schema: &body.schema,
            resolver_identity: &body.resolver_identity,
            signer_key_id: &body.signer_key_id,
            signer_key_epoch: body.signer_key_epoch,
            issuer_did: &body.issuer_did,
            store_generation: body.store_generation,
            status_version: body.status_version,
            status: body.status,
            source_passport_id: &body.source_passport_id,
            source_manifest_digest: &body.source_manifest_digest,
            effective_at: body.effective_at,
            trusted_clock_high_water: body.trusted_clock_high_water,
        },
    )
}

fn recompute_generation_pin_digest(
    body: &IssuerLifecycleGenerationPinV2,
) -> Result<String, CredentialError> {
    authority_digest(
        LIFECYCLE_GENERATION_PIN_DIGEST_DOMAIN,
        &LifecycleGenerationPinDigestPreimageV2 {
            schema: &body.schema,
            anchor_id: &body.anchor_id,
            signer_key_epoch: body.signer_key_epoch,
            resolver_identity: &body.resolver_identity,
            issuer_did: &body.issuer_did,
            store_generation: body.store_generation,
            checkpoint_digest: &body.checkpoint_digest,
            source_index_root: &body.source_index_root,
            source_index_count: body.source_index_count,
            trusted_clock_high_water: body.trusted_clock_high_water,
            previous_pin_digest: body.previous_pin_digest.as_deref(),
        },
    )
}

fn recompute_checkpoint_pin_digest(
    body: &LifecycleCheckpointPinV2,
) -> Result<String, CredentialError> {
    authority_digest(
        LIFECYCLE_CHECKPOINT_PIN_DIGEST_DOMAIN,
        &LifecycleCheckpointPinDigestPreimageV2 {
            schema: &body.schema,
            store_id: &body.store_id,
            signer_key_epoch: body.signer_key_epoch,
            resolver_identity: &body.resolver_identity,
            issuer_did: &body.issuer_did,
            source_passport_id: &body.source_passport_id,
            store_generation: body.store_generation,
            status_version: body.status_version,
            status: body.status,
            result_digest: &body.result_digest,
            checkpoint_digest: &body.checkpoint_digest,
            generation_pin_digest: &body.generation_pin_digest,
            trusted_clock_high_water: body.trusted_clock_high_water,
            previous_pin_digest: body.previous_pin_digest.as_deref(),
        },
    )
}
