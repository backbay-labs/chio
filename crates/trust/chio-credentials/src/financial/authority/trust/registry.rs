use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerTrustKeyV2 {
    pub issuer_did: String,
    pub verification_method: String,
    pub key_epoch: u64,
    pub public_key: PublicKey,
    pub status: TrustedKeyStatusV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifierTrustKeyV2 {
    pub verifier_id: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub public_key: PublicKey,
    pub status: TrustedKeyStatusV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MigrationAttesterTrustKeyV2 {
    pub attester_id: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub public_key: PublicKey,
    pub status: TrustedKeyStatusV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleResolverTrustKeyV2 {
    pub resolver_identity: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub public_key: PublicKey,
    pub status: TrustedKeyStatusV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleGenerationAnchorTrustKeyV2 {
    pub anchor_id: String,
    pub signer_key_epoch: u64,
    pub public_key: PublicKey,
    pub status: TrustedKeyStatusV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleHighWaterTrustKeyV2 {
    pub store_id: String,
    pub signer_key_epoch: u64,
    pub public_key: PublicKey,
    pub status: TrustedKeyStatusV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyReputationTrustKeyV2 {
    pub issuer_did: String,
    pub verification_method: String,
    pub key_id: String,
    pub public_key: PublicKey,
    pub valid_from: u64,
    pub valid_until: u64,
    pub status: TrustedKeyStatusV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyIssuanceAnchorAuthorityTrustKeyV2 {
    pub authority_id: String,
    pub signer_key_epoch: u64,
    pub public_key: PublicKey,
    pub status: TrustedKeyStatusV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedLegacyIssuanceCheckpointV2 {
    pub authority_id: String,
    pub signer_key_epoch: u64,
    pub registry_generation: u64,
    pub checkpoint_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerActivationMetadataV2 {
    pub issuer_did: String,
    pub profile_family: String,
    pub source_kind: CrossIssuerPortfolioEntryKind,
    pub certification_refs: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CrossIssuerTrustRegistryConfigV2 {
    pub issuer_keys: Vec<IssuerTrustKeyV2>,
    pub verifier_keys: Vec<VerifierTrustKeyV2>,
    pub migration_attester_keys: Vec<MigrationAttesterTrustKeyV2>,
    pub legacy_reputation_keys: Vec<LegacyReputationTrustKeyV2>,
    pub legacy_issuance_anchor_authorities: Vec<LegacyIssuanceAnchorAuthorityTrustKeyV2>,
    pub trusted_legacy_issuance_checkpoints: Vec<TrustedLegacyIssuanceCheckpointV2>,
    pub lifecycle_resolver_keys: Vec<LifecycleResolverTrustKeyV2>,
    pub lifecycle_generation_anchor_keys: Vec<LifecycleGenerationAnchorTrustKeyV2>,
    pub lifecycle_high_water_keys: Vec<LifecycleHighWaterTrustKeyV2>,
    pub activation_metadata: Vec<IssuerActivationMetadataV2>,
}

#[derive(Debug, Clone, Default)]
pub struct CrossIssuerTrustRegistryV2 {
    issuer_keys: BTreeMap<(String, String, u64), IssuerTrustKeyV2>,
    verifier_keys: BTreeMap<(String, String, u64), VerifierTrustKeyV2>,
    migration_attester_keys: BTreeMap<(String, String, u64), MigrationAttesterTrustKeyV2>,
    legacy_reputation_keys: BTreeMap<(String, String), Vec<LegacyReputationTrustKeyV2>>,
    legacy_issuance_anchor_authorities:
        BTreeMap<(String, u64), LegacyIssuanceAnchorAuthorityTrustKeyV2>,
    trusted_legacy_issuance_checkpoints: BTreeSet<TrustedLegacyIssuanceCheckpointV2>,
    lifecycle_resolver_keys: BTreeMap<(String, String, u64), LifecycleResolverTrustKeyV2>,
    lifecycle_generation_anchor_keys: BTreeMap<(String, u64), LifecycleGenerationAnchorTrustKeyV2>,
    lifecycle_high_water_keys: BTreeMap<(String, u64), LifecycleHighWaterTrustKeyV2>,
    activation_metadata: BTreeMap<String, IssuerActivationMetadataV2>,
}

impl CrossIssuerTrustRegistryV2 {
    pub fn new(config: CrossIssuerTrustRegistryConfigV2) -> Result<Self, CredentialError> {
        let mut registry = Self::default();
        for entry in config.issuer_keys {
            DidChio::from_str(&entry.issuer_did)?;
            validate_text("issuerTrust.verificationMethod", &entry.verification_method)?;
            validate_epoch("issuerTrust.keyEpoch", entry.key_epoch)?;
            insert_unique(
                &mut registry.issuer_keys,
                (
                    entry.issuer_did.clone(),
                    entry.verification_method.clone(),
                    entry.key_epoch,
                ),
                entry,
                "duplicate issuer trust key",
            )?;
        }
        for entry in config.verifier_keys {
            validate_text("verifierTrust.verifierId", &entry.verifier_id)?;
            validate_text("verifierTrust.signerKeyId", &entry.signer_key_id)?;
            validate_epoch("verifierTrust.signerKeyEpoch", entry.signer_key_epoch)?;
            insert_unique(
                &mut registry.verifier_keys,
                (
                    entry.verifier_id.clone(),
                    entry.signer_key_id.clone(),
                    entry.signer_key_epoch,
                ),
                entry,
                "duplicate verifier trust key",
            )?;
        }
        for entry in config.migration_attester_keys {
            validate_text("migrationTrust.attesterId", &entry.attester_id)?;
            validate_text("migrationTrust.signerKeyId", &entry.signer_key_id)?;
            validate_epoch("migrationTrust.signerKeyEpoch", entry.signer_key_epoch)?;
            insert_unique(
                &mut registry.migration_attester_keys,
                (
                    entry.attester_id.clone(),
                    entry.signer_key_id.clone(),
                    entry.signer_key_epoch,
                ),
                entry,
                "duplicate migration attester trust key",
            )?;
        }
        for entry in config.legacy_reputation_keys {
            DidChio::from_str(&entry.issuer_did)?;
            validate_text("legacyTrust.verificationMethod", &entry.verification_method)?;
            validate_text("legacyTrust.keyId", &entry.key_id)?;
            if entry.valid_from >= entry.valid_until {
                return Err(authority_error("legacy reputation key interval is invalid"));
            }
            registry
                .legacy_reputation_keys
                .entry((entry.issuer_did.clone(), entry.verification_method.clone()))
                .or_default()
                .push(entry);
        }
        for entries in registry.legacy_reputation_keys.values_mut() {
            entries.sort_by_key(|entry| (entry.valid_from, entry.valid_until));
            if entries
                .windows(2)
                .any(|pair| pair[0].valid_until > pair[1].valid_from)
            {
                return Err(authority_error("legacy reputation key intervals overlap"));
            }
        }
        for entry in config.legacy_issuance_anchor_authorities {
            validate_text("legacyAnchorTrust.authorityId", &entry.authority_id)?;
            validate_epoch("legacyAnchorTrust.signerKeyEpoch", entry.signer_key_epoch)?;
            insert_unique(
                &mut registry.legacy_issuance_anchor_authorities,
                (entry.authority_id.clone(), entry.signer_key_epoch),
                entry,
                "duplicate legacy issuance anchor authority",
            )?;
        }
        for checkpoint in config.trusted_legacy_issuance_checkpoints {
            validate_text("legacyCheckpoint.authorityId", &checkpoint.authority_id)?;
            validate_epoch(
                "legacyCheckpoint.signerKeyEpoch",
                checkpoint.signer_key_epoch,
            )?;
            validate_epoch(
                "legacyCheckpoint.registryGeneration",
                checkpoint.registry_generation,
            )?;
            validate_digest(
                "legacyCheckpoint.checkpointDigest",
                &checkpoint.checkpoint_digest,
            )?;
            if !registry
                .trusted_legacy_issuance_checkpoints
                .insert(checkpoint)
            {
                return Err(authority_error(
                    "duplicate trusted legacy issuance checkpoint",
                ));
            }
        }
        for entry in config.lifecycle_resolver_keys {
            validate_text(
                "lifecycleResolver.resolverIdentity",
                &entry.resolver_identity,
            )?;
            validate_text("lifecycleResolver.signerKeyId", &entry.signer_key_id)?;
            validate_epoch("lifecycleResolver.signerKeyEpoch", entry.signer_key_epoch)?;
            insert_unique(
                &mut registry.lifecycle_resolver_keys,
                (
                    entry.resolver_identity.clone(),
                    entry.signer_key_id.clone(),
                    entry.signer_key_epoch,
                ),
                entry,
                "duplicate lifecycle resolver key",
            )?;
        }
        for entry in config.lifecycle_generation_anchor_keys {
            validate_text("lifecycleAnchor.anchorId", &entry.anchor_id)?;
            validate_epoch("lifecycleAnchor.signerKeyEpoch", entry.signer_key_epoch)?;
            insert_unique(
                &mut registry.lifecycle_generation_anchor_keys,
                (entry.anchor_id.clone(), entry.signer_key_epoch),
                entry,
                "duplicate lifecycle generation anchor key",
            )?;
        }
        for entry in config.lifecycle_high_water_keys {
            validate_text("lifecycleHighWater.storeId", &entry.store_id)?;
            validate_epoch("lifecycleHighWater.signerKeyEpoch", entry.signer_key_epoch)?;
            insert_unique(
                &mut registry.lifecycle_high_water_keys,
                (entry.store_id.clone(), entry.signer_key_epoch),
                entry,
                "duplicate lifecycle high-water key",
            )?;
        }
        for mut entry in config.activation_metadata {
            DidChio::from_str(&entry.issuer_did)?;
            validate_text("activationMetadata.profileFamily", &entry.profile_family)?;
            normalize_strings(&mut entry.certification_refs, "certificationRefs")?;
            if registry
                .activation_metadata
                .insert(entry.issuer_did.clone(), entry)
                .is_some()
            {
                return Err(authority_error("duplicate issuer activation metadata"));
            }
        }
        Ok(registry)
    }

    #[must_use]
    pub fn verifier_keys(&self) -> Vec<VerifierTrustKeyV2> {
        self.verifier_keys.values().cloned().collect()
    }

    #[must_use]
    pub fn lifecycle_resolver_identities(&self) -> BTreeSet<String> {
        self.lifecycle_resolver_keys
            .values()
            .filter(|entry| entry.status == TrustedKeyStatusV2::Active)
            .map(|entry| entry.resolver_identity.clone())
            .collect()
    }

    pub(crate) fn legacy_verifier_key(
        &self,
        verifier_id: &str,
        claimed_key: &PublicKey,
    ) -> Result<&PublicKey, CredentialError> {
        let matches = self
            .verifier_keys
            .values()
            .filter(|entry| {
                entry.status == TrustedKeyStatusV2::Active
                    && entry.verifier_id == verifier_id
                    && &entry.public_key == claimed_key
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(authority_error(
                "legacy trust-pack signer does not resolve to one active local key",
            ));
        }
        Ok(&matches[0].public_key)
    }

    pub(in crate::financial_authority) fn issuer_key(
        &self,
        issuer: &str,
        verification_method: &str,
        epoch: u64,
    ) -> Result<&IssuerTrustKeyV2, CredentialError> {
        active_key(
            self.issuer_keys
                .get(&(issuer.to_string(), verification_method.to_string(), epoch)),
            "trusted issuer key is unknown or inactive",
        )
    }

    pub(in crate::financial_authority) fn manifest_issuer_key(
        &self,
        issuer: &str,
        signer_key: &PublicKey,
    ) -> Result<&IssuerTrustKeyV2, CredentialError> {
        let matches = self
            .issuer_keys
            .values()
            .filter(|entry| {
                entry.status == TrustedKeyStatusV2::Active
                    && entry.issuer_did == issuer
                    && &entry.public_key == signer_key
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(authority_error(
                "source manifest signer does not resolve to one active local issuer key",
            ));
        }
        Ok(matches[0])
    }

    pub(super) fn verifier_key(
        &self,
        verifier_id: &str,
        signer_key_id: &str,
        epoch: u64,
    ) -> Result<&VerifierTrustKeyV2, CredentialError> {
        active_key(
            self.verifier_keys
                .get(&(verifier_id.to_string(), signer_key_id.to_string(), epoch)),
            "trusted verifier key is unknown or inactive",
        )
    }

    pub(super) fn migration_key(
        &self,
        attester_id: &str,
        signer_key_id: &str,
        epoch: u64,
    ) -> Result<&MigrationAttesterTrustKeyV2, CredentialError> {
        active_key(
            self.migration_attester_keys.get(&(
                attester_id.to_string(),
                signer_key_id.to_string(),
                epoch,
            )),
            "trusted migration attester key is unknown or inactive",
        )
    }

    pub(in crate::financial_authority) fn resolver_key(
        &self,
        resolver_identity: &str,
        signer_key_id: &str,
        epoch: u64,
    ) -> Result<&LifecycleResolverTrustKeyV2, CredentialError> {
        active_key(
            self.lifecycle_resolver_keys.get(&(
                resolver_identity.to_string(),
                signer_key_id.to_string(),
                epoch,
            )),
            "trusted lifecycle resolver key is unknown or inactive",
        )
    }

    pub(in crate::financial_authority) fn generation_anchor_key(
        &self,
        anchor_id: &str,
        epoch: u64,
    ) -> Result<&LifecycleGenerationAnchorTrustKeyV2, CredentialError> {
        active_key(
            self.lifecycle_generation_anchor_keys
                .get(&(anchor_id.to_string(), epoch)),
            "trusted lifecycle generation anchor key is unknown or inactive",
        )
    }

    pub(in crate::financial_authority) fn high_water_key(
        &self,
        store_id: &str,
        epoch: u64,
    ) -> Result<&LifecycleHighWaterTrustKeyV2, CredentialError> {
        active_key(
            self.lifecycle_high_water_keys
                .get(&(store_id.to_string(), epoch)),
            "trusted lifecycle high-water key is unknown or inactive",
        )
    }

    pub(in crate::financial_authority) fn activation_metadata(
        &self,
        issuer: &str,
    ) -> Result<&IssuerActivationMetadataV2, CredentialError> {
        self.activation_metadata
            .get(issuer)
            .ok_or_else(|| authority_error("issuer activation metadata is unavailable"))
    }

    pub(super) fn legacy_reputation_key(
        &self,
        issuer: &str,
        verification_method: &str,
        key_id: &str,
        observed_issued_at: u64,
    ) -> Result<&LegacyReputationTrustKeyV2, CredentialError> {
        let matches = self
            .legacy_reputation_keys
            .get(&(issuer.to_string(), verification_method.to_string()))
            .into_iter()
            .flatten()
            .filter(|entry| {
                entry.status == TrustedKeyStatusV2::Active
                    && entry.key_id == key_id
                    && entry.valid_from <= observed_issued_at
                    && observed_issued_at < entry.valid_until
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(authority_error(
                "legacy reputation issuance interval is missing or ambiguous",
            ));
        }
        Ok(matches[0])
    }

    pub(super) fn verify_legacy_anchor_authority(
        &self,
        anchor: &SignedLegacyCredentialIssuanceAnchorV2,
    ) -> Result<(), CredentialError> {
        let authority = active_key(
            self.legacy_issuance_anchor_authorities.get(&(
                anchor.body.authority_id.clone(),
                anchor.body.signer_key_epoch,
            )),
            "trusted legacy issuance anchor authority is unknown or inactive",
        )?;
        if authority.public_key != anchor.signer_key {
            return Err(authority_error(
                "legacy issuance anchor signer does not match local trust",
            ));
        }
        let checkpoint = TrustedLegacyIssuanceCheckpointV2 {
            authority_id: anchor.body.authority_id.clone(),
            signer_key_epoch: anchor.body.signer_key_epoch,
            registry_generation: anchor.body.registry_generation,
            checkpoint_digest: anchor.body.registry_checkpoint_digest.clone(),
        };
        if !self
            .trusted_legacy_issuance_checkpoints
            .contains(&checkpoint)
        {
            return Err(authority_error(
                "legacy issuance anchor checkpoint is not locally trusted",
            ));
        }
        Ok(())
    }
}
