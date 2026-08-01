use chio_core_types::crypto::{canonical_json_bytes, Keypair};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::{fiscal_signer_key_id, FiscalDomain, FiscalError};

use super::proposal::FiscalGenesisPolicy;
use super::support::{
    all_fiscal_domains, canonical_digest, lifecycle_digest, require_digest, require_positive,
    require_text, signed_envelope_digest, verify_envelope, MAX_SIGNED_LIFECYCLE_BYTES,
};

pub const FISCAL_RUNTIME_READINESS_SCHEMA: &str = "chio.fiscal.consumer-readiness.v1";
pub const FISCAL_RUNTIME_READINESS_ID_DOMAIN: &str = "chio.fiscal.consumer-readiness.id.v1";
pub const FISCAL_RUNTIME_ADAPTER_REGISTRY_SCHEMA: &str = "chio.fiscal.runtime-adapter-registry.v1";
pub const FISCAL_RUNTIME_ADAPTER_COUNT: usize = 7;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalRuntimeAdapter {
    pub id: String,
    pub implementation_version: String,
}

impl FiscalRuntimeAdapter {
    pub fn new(id: String, implementation_version: String) -> Result<Self, FiscalError> {
        let adapter = Self {
            id,
            implementation_version,
        };
        adapter.validate()?;
        Ok(adapter)
    }

    fn validate(&self) -> Result<(), FiscalError> {
        require_text(&self.id, "runtime_adapter.id")?;
        require_text(
            &self.implementation_version,
            "runtime_adapter.implementation_version",
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalRuntimeAdapterRegistry {
    schema: String,
    build_id: String,
    schema_version: String,
    adapters: Vec<FiscalRuntimeAdapter>,
}

impl FiscalRuntimeAdapterRegistry {
    pub fn new(
        build_id: String,
        schema_version: String,
        mut adapters: Vec<FiscalRuntimeAdapter>,
    ) -> Result<Self, FiscalError> {
        adapters.sort_by(|left, right| left.id.cmp(&right.id));
        let registry = Self {
            schema: FISCAL_RUNTIME_ADAPTER_REGISTRY_SCHEMA.to_owned(),
            build_id,
            schema_version,
            adapters,
        };
        registry.validate()?;
        Ok(registry)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, FiscalError> {
        if bytes.is_empty() || bytes.len() > MAX_SIGNED_LIFECYCLE_BYTES {
            return Err(FiscalError::InvalidField("runtime_registry.size"));
        }
        let registry: Self = serde_json::from_slice(bytes)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))?;
        registry.validate()?;
        if registry.canonical_bytes()?.as_slice() != bytes {
            return Err(FiscalError::Canonicalization(
                "fiscal runtime adapter registry is not canonical".to_owned(),
            ));
        }
        Ok(registry)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FiscalError> {
        self.validate()?;
        canonical_json_bytes(self).map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }

    pub fn digest(&self) -> Result<String, FiscalError> {
        self.validate()?;
        canonical_digest(self)
    }

    fn validate(&self) -> Result<(), FiscalError> {
        if self.schema != FISCAL_RUNTIME_ADAPTER_REGISTRY_SCHEMA {
            return Err(FiscalError::UnknownSchema(self.schema.clone()));
        }
        require_text(&self.build_id, "runtime_registry.build_id")?;
        require_text(&self.schema_version, "runtime_registry.schema_version")?;
        if self.adapters.len() != FISCAL_RUNTIME_ADAPTER_COUNT {
            return Err(FiscalError::InvalidField("runtime_registry.adapters.size"));
        }
        for adapter in &self.adapters {
            adapter.validate()?;
        }
        if self
            .adapters
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(FiscalError::InvalidField("runtime_registry.adapters.order"));
        }
        Ok(())
    }

    #[must_use]
    pub fn build_id(&self) -> &str {
        &self.build_id
    }

    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    #[must_use]
    pub fn adapters(&self) -> &[FiscalRuntimeAdapter] {
        &self.adapters
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalRuntimeReadiness {
    pub schema: String,
    pub readiness_id: String,
    pub governing_operator_id: String,
    pub genesis_policy_id: String,
    pub genesis_policy_digest: String,
    pub readiness_sequence: u64,
    pub runtime_registry_digest: String,
    pub ready_domains: Vec<FiscalDomain>,
    pub attested_at: u64,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalRuntimeReadinessIdPreimage<'a> {
    schema: &'a str,
    governing_operator_id: &'a str,
    genesis_policy_id: &'a str,
    genesis_policy_digest: &'a str,
    readiness_sequence: u64,
    runtime_registry_digest: &'a str,
    ready_domains: &'a [FiscalDomain],
    attested_at: u64,
    signer_key_id: &'a str,
    signer_key_epoch: u64,
}

impl FiscalRuntimeReadiness {
    pub fn expected_id(&self) -> Result<String, FiscalError> {
        lifecycle_digest(
            FISCAL_RUNTIME_READINESS_ID_DOMAIN,
            &FiscalRuntimeReadinessIdPreimage {
                schema: &self.schema,
                governing_operator_id: &self.governing_operator_id,
                genesis_policy_id: &self.genesis_policy_id,
                genesis_policy_digest: &self.genesis_policy_digest,
                readiness_sequence: self.readiness_sequence,
                runtime_registry_digest: &self.runtime_registry_digest,
                ready_domains: &self.ready_domains,
                attested_at: self.attested_at,
                signer_key_id: &self.signer_key_id,
                signer_key_epoch: self.signer_key_epoch,
            },
        )
    }
}

pub type SignedFiscalRuntimeReadiness = SignedExportEnvelope<FiscalRuntimeReadiness>;

#[derive(Debug, Clone)]
pub struct FiscalRuntimeReadinessBuilder {
    pub readiness_sequence: u64,
    pub runtime_registry: FiscalRuntimeAdapterRegistry,
    pub attested_at: u64,
}

impl FiscalRuntimeReadinessBuilder {
    pub fn sign(
        self,
        policy: &FiscalGenesisPolicy,
        keypair: &Keypair,
    ) -> Result<SignedFiscalRuntimeReadiness, FiscalError> {
        let runtime_registry_digest = self.runtime_registry.digest()?;
        let mut body = FiscalRuntimeReadiness {
            schema: FISCAL_RUNTIME_READINESS_SCHEMA.to_owned(),
            readiness_id: String::new(),
            governing_operator_id: policy.governing_operator_id.clone(),
            genesis_policy_id: policy.policy_id.clone(),
            genesis_policy_digest: policy.digest()?,
            readiness_sequence: self.readiness_sequence,
            runtime_registry_digest,
            ready_domains: all_fiscal_domains().to_vec(),
            attested_at: self.attested_at,
            signer_key_id: fiscal_signer_key_id(&keypair.public_key())?,
            signer_key_epoch: policy.anchor_signer_key_epoch,
        };
        body.readiness_id = body.expected_id()?;
        SignedFiscalRuntimeReadiness::sign(body, keypair)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedFiscalRuntimeReadiness {
    signed: SignedFiscalRuntimeReadiness,
    digest: String,
    runtime_registry: FiscalRuntimeAdapterRegistry,
}

impl VerifiedFiscalRuntimeReadiness {
    pub fn verify(
        signed: SignedFiscalRuntimeReadiness,
        policy: &FiscalGenesisPolicy,
        runtime_registry: FiscalRuntimeAdapterRegistry,
    ) -> Result<Self, FiscalError> {
        let runtime_registry_digest = runtime_registry.digest()?;
        let body = &signed.body;
        if body.schema != FISCAL_RUNTIME_READINESS_SCHEMA {
            return Err(FiscalError::UnknownSchema(body.schema.clone()));
        }
        require_positive(body.readiness_sequence, "readiness.readiness_sequence")?;
        require_positive(body.attested_at, "readiness.attested_at")?;
        require_digest(
            &body.runtime_registry_digest,
            "readiness.runtime_registry_digest",
        )?;
        if body.readiness_id != body.expected_id()?
            || body.governing_operator_id != policy.governing_operator_id
            || body.genesis_policy_id != policy.policy_id
            || body.genesis_policy_digest != policy.digest()?
            || body.runtime_registry_digest != runtime_registry_digest
            || body.ready_domains.as_slice() != all_fiscal_domains()
            || body.signer_key_id != policy.anchor_signer_key_id
            || body.signer_key_epoch != policy.anchor_signer_key_epoch
            || signed.signer_key != policy.anchor_authority_key
        {
            return Err(FiscalError::InvalidField("readiness.binding"));
        }
        verify_envelope(&signed)?;
        let digest = signed_envelope_digest(&signed)?;
        Ok(Self {
            signed,
            digest,
            runtime_registry,
        })
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        policy: &FiscalGenesisPolicy,
        runtime_registry: FiscalRuntimeAdapterRegistry,
    ) -> Result<Self, FiscalError> {
        if bytes.is_empty() || bytes.len() > MAX_SIGNED_LIFECYCLE_BYTES {
            return Err(FiscalError::InvalidField("signed_readiness.size"));
        }
        let signed: SignedFiscalRuntimeReadiness = serde_json::from_slice(bytes)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))?;
        let verified = Self::verify(signed, policy, runtime_registry)?;
        if verified.canonical_bytes()?.as_slice() != bytes {
            return Err(FiscalError::Canonicalization(
                "signed fiscal runtime readiness is not canonical".to_owned(),
            ));
        }
        Ok(verified)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FiscalError> {
        canonical_json_bytes(&self.signed)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }

    #[must_use]
    pub const fn body(&self) -> &FiscalRuntimeReadiness {
        &self.signed.body
    }

    #[must_use]
    pub const fn signed(&self) -> &SignedFiscalRuntimeReadiness {
        &self.signed
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    #[must_use]
    pub const fn runtime_registry(&self) -> &FiscalRuntimeAdapterRegistry {
        &self.runtime_registry
    }
}
