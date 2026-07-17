use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chio_core::{canonical_json_bytes, sha256_hex, Keypair};
use chio_credentials::{
    build_oid4vci_passport_offer, ensure_signed_passport_verifier_policy_active,
    issue_chio_passport_jwt_vc_json, issue_chio_passport_sd_jwt_vc, verify_agent_passport,
    verify_passport_presentation_challenge, verify_signed_passport_verifier_policy, AgentPassport,
    Oid4vciChioPassportStatusReference, Oid4vciCredentialIssuerMetadata, Oid4vciCredentialOffer,
    Oid4vciCredentialRequest, Oid4vciCredentialResponse, Oid4vciTokenRequest, Oid4vciTokenResponse,
    Oid4vpRequestObject, PassportLifecycleRecord, PassportLifecycleResolution,
    PassportLifecycleState, PassportPresentationChallenge, PassportStatusDistribution,
    SignedPassportVerifierPolicy, WalletExchangeTransactionState, WalletExchangeTransactionStatus,
    CHIO_PASSPORT_JWT_VC_JSON_FORMAT, CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID,
    CHIO_PASSPORT_SD_JWT_VC_FORMAT,
};
use chrono::DateTime;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::CliError;

const VERIFIER_POLICY_REGISTRY_VERSION: &str = "chio.passport-verifier-policies.v1";
const PASSPORT_STATUS_REGISTRY_VERSION: &str = "chio.passport-status-registry.v1";
const PASSPORT_ISSUANCE_REGISTRY_VERSION: &str = "chio.passport-issuance-offers.v1";
const CHALLENGE_STATUS_ISSUED: &str = "issued";
const CHALLENGE_STATUS_CONSUMED: &str = "consumed";
const CHALLENGE_STATUS_EXPIRED: &str = "expired";
const OID4VP_TRANSACTION_STATUS_ISSUED: &str = "issued";
const OID4VP_TRANSACTION_STATUS_CONSUMED: &str = "consumed";
const OID4VP_TRANSACTION_STATUS_EXPIRED: &str = "expired";

fn sqlite_i64(value: u64, field: &str) -> Result<i64, CliError> {
    i64::try_from(value).map_err(|_| {
        CliError::cli_other_error(format!(
            "{field} value {value} exceeds SQLite INTEGER range"
        ))
    })
}

fn sqlite_u64(value: i64, field: &str) -> Result<u64, CliError> {
    u64::try_from(value).map_err(|_| {
        CliError::cli_other_error(format!(
            "{field} value {value} is outside the supported u64 range"
        ))
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierPolicyRegistry {
    pub version: String,
    #[serde(default)]
    pub policies: BTreeMap<String, SignedPassportVerifierPolicy>,
}

impl Default for VerifierPolicyRegistry {
    fn default() -> Self {
        Self {
            version: VERIFIER_POLICY_REGISTRY_VERSION.to_string(),
            policies: BTreeMap::new(),
        }
    }
}

impl VerifierPolicyRegistry {
    pub fn load(path: &Path) -> Result<Self, CliError> {
        match fs::read(path) {
            Ok(bytes) => {
                let mut registry: Self = serde_json::from_slice(&bytes)?;
                if registry.version != VERIFIER_POLICY_REGISTRY_VERSION {
                    return Err(CliError::policy_error(format!(
                        "unsupported verifier policy registry version: {}",
                        registry.version
                    )));
                }
                registry.version = VERIFIER_POLICY_REGISTRY_VERSION.to_string();
                for document in registry.policies.values() {
                    verify_signed_passport_verifier_policy(document)
                        .map_err(|error| CliError::policy_error(error.to_string()))?;
                }
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(CliError::Io(error)),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn get(&self, policy_id: &str) -> Option<&SignedPassportVerifierPolicy> {
        self.policies.get(policy_id)
    }

    pub fn active_policy(
        &self,
        policy_id: &str,
        now: u64,
    ) -> Result<&SignedPassportVerifierPolicy, CliError> {
        let Some(document) = self.get(policy_id) else {
            return Err(CliError::policy_error(format!(
                "verifier policy `{policy_id}` was not found"
            )));
        };
        verify_signed_passport_verifier_policy(document)
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        ensure_signed_passport_verifier_policy_active(document, now)
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        Ok(document)
    }

    pub fn upsert(&mut self, document: SignedPassportVerifierPolicy) -> Result<(), CliError> {
        verify_signed_passport_verifier_policy(&document)
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        self.policies
            .insert(document.body.policy_id.clone(), document);
        Ok(())
    }

    pub fn remove(&mut self, policy_id: &str) -> bool {
        self.policies.remove(policy_id).is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportStatusRegistry {
    pub version: String,
    #[serde(default)]
    pub passports: BTreeMap<String, PassportLifecycleRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportStatusListResponse {
    pub configured: bool,
    pub count: usize,
    pub passports: Vec<PassportLifecycleRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishPassportStatusRequest {
    pub passport: AgentPassport,
    #[serde(default, skip_serializing_if = "PassportStatusDistribution::is_empty")]
    pub distribution: PassportStatusDistribution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportStatusRevocationRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PassportIssuanceOfferState {
    Offered,
    TokenIssued,
    CredentialIssued,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PassportIssuanceOfferRecord {
    pub offer_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub state: PassportIssuanceOfferState,
    pub offer: Oid4vciCredentialOffer,
    pub passport: AgentPassport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token_expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_issued_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_issued_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PassportIssuanceOfferRegistry {
    pub version: String,
    #[serde(default)]
    pub offers: BTreeMap<String, PassportIssuanceOfferRecord>,
}

impl Default for PassportStatusRegistry {
    fn default() -> Self {
        Self {
            version: PASSPORT_STATUS_REGISTRY_VERSION.to_string(),
            passports: BTreeMap::new(),
        }
    }
}

impl Default for PassportIssuanceOfferRegistry {
    fn default() -> Self {
        Self {
            version: PASSPORT_ISSUANCE_REGISTRY_VERSION.to_string(),
            offers: BTreeMap::new(),
        }
    }
}

impl PassportStatusRegistry {
    pub fn load(path: &Path) -> Result<Self, CliError> {
        match fs::read(path) {
            Ok(bytes) => {
                let mut registry: Self = serde_json::from_slice(&bytes)?;
                if registry.version != PASSPORT_STATUS_REGISTRY_VERSION {
                    return Err(CliError::policy_error(format!(
                        "unsupported passport status registry version: {}",
                        registry.version
                    )));
                }
                registry.version = PASSPORT_STATUS_REGISTRY_VERSION.to_string();
                for record in registry.passports.values_mut() {
                    if record.updated_at == 0 {
                        record.updated_at = record.revoked_at.unwrap_or(record.published_at);
                    }
                }
                for record in registry.passports.values() {
                    verify_passport_lifecycle_record(record)?;
                }
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(CliError::Io(error)),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn get(&self, passport_id: &str) -> Option<&PassportLifecycleRecord> {
        self.passports.get(passport_id)
    }

    pub fn publish(
        &mut self,
        passport: &AgentPassport,
        published_at: u64,
        distribution: PassportStatusDistribution,
    ) -> Result<PassportLifecycleRecord, CliError> {
        let verification = verify_agent_passport(passport, published_at)
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        self.version = PASSPORT_STATUS_REGISTRY_VERSION.to_string();
        if let Some(existing) = self.passports.get(&verification.passport_id) {
            return Ok(existing.clone());
        }

        for existing in self.passports.values_mut() {
            if existing.subject == verification.subject
                && existing.issuers == verification.issuers
                && existing.status == PassportLifecycleState::Active
            {
                existing.status = PassportLifecycleState::Superseded;
                existing.superseded_by = Some(verification.passport_id.clone());
                existing.updated_at = published_at;
            }
        }

        let record = PassportLifecycleRecord {
            passport_id: verification.passport_id.clone(),
            subject: verification.subject.clone(),
            issuers: verification.issuers.clone(),
            issuer_count: verification.issuer_count,
            published_at,
            updated_at: published_at,
            status: PassportLifecycleState::Active,
            superseded_by: None,
            revoked_at: None,
            revoked_reason: None,
            distribution,
            valid_until: verification.valid_until.clone(),
        };
        self.passports
            .insert(verification.passport_id, record.clone());
        Ok(record)
    }

    pub fn resolve_for_passport(
        &self,
        passport: &AgentPassport,
        at: u64,
    ) -> Result<PassportLifecycleResolution, CliError> {
        let verification = verify_agent_passport(passport, at)
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        Ok(self
            .get(&verification.passport_id)
            .map(|record| passport_lifecycle_resolution_from_record(record, at))
            .unwrap_or_else(|| PassportLifecycleResolution {
                passport_id: verification.passport_id,
                subject: verification.subject,
                issuers: verification.issuers,
                issuer_count: verification.issuer_count,
                state: PassportLifecycleState::NotFound,
                published_at: None,
                updated_at: None,
                superseded_by: None,
                revoked_at: None,
                revoked_reason: None,
                distribution: PassportStatusDistribution::default(),
                valid_until: verification.valid_until,
                source: None,
            }))
    }

    pub fn resolve(&self, passport_id: &str) -> PassportLifecycleResolution {
        self.resolve_at(passport_id, unix_timestamp_now())
    }

    pub fn resolve_at(&self, passport_id: &str, at: u64) -> PassportLifecycleResolution {
        self.get(passport_id)
            .map(|record| passport_lifecycle_resolution_from_record(record, at))
            .unwrap_or_else(|| PassportLifecycleResolution {
                passport_id: passport_id.to_string(),
                subject: String::new(),
                issuers: Vec::new(),
                issuer_count: 0,
                state: PassportLifecycleState::NotFound,
                published_at: None,
                updated_at: None,
                superseded_by: None,
                revoked_at: None,
                revoked_reason: None,
                distribution: PassportStatusDistribution::default(),
                valid_until: String::new(),
                source: None,
            })
    }

    pub fn revoke(
        &mut self,
        passport_id: &str,
        reason: Option<&str>,
        revoked_at: Option<u64>,
    ) -> Result<PassportLifecycleRecord, CliError> {
        let Some(entry) = self.passports.get_mut(passport_id) else {
            return Err(CliError::policy_error(format!(
                "passport `{passport_id}` was not found in the lifecycle registry"
            )));
        };
        entry.status = PassportLifecycleState::Revoked;
        let revoked_at = revoked_at.unwrap_or_else(unix_timestamp_now);
        entry.revoked_at = Some(revoked_at);
        entry.updated_at = revoked_at;
        entry.revoked_reason = reason.map(str::to_string);
        // Passport lifecycle revocation is NOT a capability revocation, so it
        // must not emit chio_capability_revocation_lag_seconds. That family is
        // observed from the actual capability revoke paths instead, keeping the
        // capability-revocation SLO measured on real capability revokes.
        Ok(entry.clone())
    }

    pub fn portable_status_reference_for_passport(
        &self,
        passport: &AgentPassport,
        at: u64,
    ) -> Result<Oid4vciChioPassportStatusReference, CliError> {
        let resolution = self.resolve_for_passport(passport, at)?;
        resolution
            .validate()
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        match resolution.state {
            PassportLifecycleState::Active => {}
            PassportLifecycleState::Stale => {
                return Err(CliError::policy_error(format!(
                    "passport `{}` has stale lifecycle state and cannot be delivered with portable lifecycle support",
                    resolution.passport_id
                )))
            }
            PassportLifecycleState::Superseded => {
                return Err(CliError::policy_error(format!(
                    "passport `{}` is superseded and cannot be delivered with portable lifecycle support",
                    resolution.passport_id
                )))
            }
            PassportLifecycleState::Revoked => {
                return Err(CliError::policy_error(format!(
                    "passport `{}` is revoked and cannot be delivered with portable lifecycle support",
                    resolution.passport_id
                )))
            }
            PassportLifecycleState::NotFound => {
                return Err(CliError::policy_error(format!(
                    "passport `{}` must be published into the lifecycle registry before portable issuance can advertise lifecycle support",
                    resolution.passport_id
                )))
            }
        }
        if resolution.distribution.is_empty() {
            return Err(CliError::policy_error(format!(
                "passport `{}` must publish at least one resolve_url before portable issuance can advertise lifecycle support",
                resolution.passport_id
            )));
        }
        Ok(Oid4vciChioPassportStatusReference {
            passport_id: resolution.passport_id,
            distribution: resolution.distribution,
        })
    }
}

impl PassportIssuanceOfferRegistry {
    pub fn load(path: &Path) -> Result<Self, CliError> {
        match fs::read(path) {
            Ok(bytes) => {
                let mut registry: Self = serde_json::from_slice(&bytes)?;
                if registry.version != PASSPORT_ISSUANCE_REGISTRY_VERSION {
                    return Err(CliError::policy_error(format!(
                        "unsupported passport issuance registry version: {}",
                        registry.version
                    )));
                }
                registry.version = PASSPORT_ISSUANCE_REGISTRY_VERSION.to_string();
                for record in registry.offers.values() {
                    verify_passport_issuance_offer_record(record)?;
                }
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(CliError::Io(error)),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn issue_offer(
        &mut self,
        metadata: &Oid4vciCredentialIssuerMetadata,
        passport: AgentPassport,
        credential_configuration_id: Option<&str>,
        ttl_secs: u64,
        now: u64,
    ) -> Result<PassportIssuanceOfferRecord, CliError> {
        if ttl_secs == 0 {
            return Err(CliError::cli_other_error(
                "passport issuance offers require ttl_secs greater than zero".to_string(),
            ));
        }
        let credential_configuration_id = credential_configuration_id
            .unwrap_or(CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID);
        metadata
            .credential_configuration(credential_configuration_id)
            .map_err(CliError::from)?;
        let offer_id = KeyId::generate();
        let pre_authorized_code = KeyId::generate();
        let expires_at = now.saturating_add(ttl_secs);
        let offer = build_oid4vci_passport_offer(
            metadata,
            credential_configuration_id,
            &pre_authorized_code,
            &passport,
            expires_at,
        )?;
        let record = PassportIssuanceOfferRecord {
            offer_id: offer_id.clone(),
            issued_at: now,
            expires_at,
            state: PassportIssuanceOfferState::Offered,
            offer,
            passport,
            access_token: None,
            access_token_expires_at: None,
            token_issued_at: None,
            credential_issued_at: None,
        };
        verify_passport_issuance_offer_record(&record)?;
        self.offers.insert(offer_id, record.clone());
        Ok(record)
    }

    pub fn redeem_pre_authorized_code(
        &mut self,
        metadata: &Oid4vciCredentialIssuerMetadata,
        request: &Oid4vciTokenRequest,
        now: u64,
        token_ttl_secs: u64,
    ) -> Result<Oid4vciTokenResponse, CliError> {
        request.validate()?;
        metadata.validate()?;
        let Some(offer_id) = self
            .offers
            .iter()
            .find(|(_, record)| {
                record
                    .offer
                    .grants
                    .pre_authorized_code
                    .as_ref()
                    .is_some_and(|grant| grant.pre_authorized_code == request.pre_authorized_code)
            })
            .map(|(offer_id, _)| offer_id.clone())
        else {
            return Err(CliError::cli_other_error(
                "pre-authorized code is not present in the issuance registry".to_string(),
            ));
        };
        let Some(record) = self.offers.get_mut(&offer_id) else {
            return Err(CliError::cli_other_error(
                "pre-authorized code resolved to a missing issuance offer".to_string(),
            ));
        };
        refresh_passport_issuance_offer_state(record, now);
        if normalize_credential_issuer(&record.offer.credential_issuer)?
            != normalize_credential_issuer(&metadata.credential_issuer)?
        {
            return Err(CliError::policy_error(
                "offer credential_issuer does not match the configured issuer metadata".to_string(),
            ));
        }
        match record.state {
            PassportIssuanceOfferState::Offered => {}
            PassportIssuanceOfferState::TokenIssued => {
                return Err(CliError::cli_other_error(
                    "pre-authorized code has already been redeemed".to_string(),
                ))
            }
            PassportIssuanceOfferState::CredentialIssued => {
                return Err(CliError::policy_error(
                    "credential has already been issued for this offer".to_string(),
                ))
            }
            PassportIssuanceOfferState::Expired => {
                return Err(CliError::cli_other_error(
                    "issuance offer has expired".to_string(),
                ))
            }
        }
        let access_token = KeyId::generate();
        let token_expires_at = now
            .saturating_add(token_ttl_secs.max(1))
            .min(record.expires_at);
        if token_expires_at <= now {
            record.state = PassportIssuanceOfferState::Expired;
            return Err(CliError::cli_other_error(
                "issuance offer expired before an access token could be minted".to_string(),
            ));
        }
        record.access_token = Some(access_token.clone());
        record.access_token_expires_at = Some(token_expires_at);
        record.token_issued_at = Some(now);
        record.state = PassportIssuanceOfferState::TokenIssued;
        Ok(Oid4vciTokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: token_expires_at.saturating_sub(now),
        })
    }

    pub fn redeem_credential(
        &mut self,
        metadata: &Oid4vciCredentialIssuerMetadata,
        access_token: &str,
        request: &Oid4vciCredentialRequest,
        now: u64,
        portable_signing_keypair: Option<&Keypair>,
        portable_status_registry: Option<&PassportStatusRegistry>,
    ) -> Result<Oid4vciCredentialResponse, CliError> {
        request.validate()?;
        metadata.validate()?;
        let Some(offer_id) = self
            .offers
            .iter()
            .find(|(_, record)| record.access_token.as_deref() == Some(access_token))
            .map(|(offer_id, _)| offer_id.clone())
        else {
            return Err(CliError::cli_other_error(
                "access token is not present in the issuance registry".to_string(),
            ));
        };
        let Some(record) = self.offers.get_mut(&offer_id) else {
            return Err(CliError::cli_other_error(
                "access token resolved to a missing issuance offer".to_string(),
            ));
        };
        refresh_passport_issuance_offer_state(record, now);
        if normalize_credential_issuer(&record.offer.credential_issuer)?
            != normalize_credential_issuer(&metadata.credential_issuer)?
        {
            return Err(CliError::policy_error(
                "offer credential_issuer does not match the configured issuer metadata".to_string(),
            ));
        }
        match record.state {
            PassportIssuanceOfferState::TokenIssued => {}
            PassportIssuanceOfferState::Offered => {
                return Err(CliError::cli_other_error(
                    "access token has not been issued for this offer".to_string(),
                ))
            }
            PassportIssuanceOfferState::CredentialIssued => {
                return Err(CliError::cli_other_error(
                    "credential has already been issued for this access token".to_string(),
                ))
            }
            PassportIssuanceOfferState::Expired => {
                return Err(CliError::cli_other_error(
                    "issuance offer has expired".to_string(),
                ))
            }
        }

        let credential_configuration_id = request
            .validate_against_metadata(metadata)
            .map_err(CliError::from)?;
        let expected_configuration_id = record.offer.primary_configuration_id()?;
        if credential_configuration_id != expected_configuration_id {
            return Err(CliError::policy_error(format!(
                "credential_configuration_id `{credential_configuration_id}` does not match offer configuration `{expected_configuration_id}`"
            )));
        }

        let expected_subject = record
            .offer
            .chio_offer_context
            .as_ref()
            .map(|context| context.subject.as_str())
            .unwrap_or(record.passport.subject.as_str());
        if request.subject != expected_subject {
            return Err(CliError::cli_other_error(format!(
                "credential request subject `{}` does not match offer subject `{expected_subject}`",
                request.subject
            )));
        }

        let format = metadata
            .credential_configuration(expected_configuration_id)
            .map_err(CliError::from)?
            .format
            .clone();
        if request
            .format
            .as_ref()
            .is_some_and(|requested_format| requested_format != &format)
        {
            return Err(CliError::cli_other_error(format!(
                "credential request format does not match offer format `{format}`"
            )));
        }
        let portable_status_reference = portable_status_registry
            .map(|registry| registry.portable_status_reference_for_passport(&record.passport, now))
            .transpose()?;

        let response = if format == CHIO_PASSPORT_SD_JWT_VC_FORMAT {
            let keypair = portable_signing_keypair.ok_or_else(|| {
                CliError::cli_other_error(
                    "portable sd-jwt vc issuance requires a signing keypair".to_string(),
                )
            })?;
            let status_reference = portable_status_reference.clone();
            let envelope = issue_chio_passport_sd_jwt_vc(
                &record.passport,
                &metadata.credential_issuer,
                keypair,
                now,
                status_reference.clone(),
            )
            .map_err(|error| CliError::policy_error(error.to_string()))?;
            Oid4vciCredentialResponse::new_portable_sd_jwt(
                format.clone(),
                envelope.compact,
                envelope.passport_id,
                envelope.subject_did,
                status_reference,
                envelope.issuer_jwk,
            )
            .map_err(|error| CliError::policy_error(error.to_string()))?
        } else if format == CHIO_PASSPORT_JWT_VC_JSON_FORMAT {
            let keypair = portable_signing_keypair.ok_or_else(|| {
                CliError::cli_other_error(
                    "portable jwt_vc_json issuance requires a signing keypair".to_string(),
                )
            })?;
            let status_reference = portable_status_reference.clone();
            let envelope = issue_chio_passport_jwt_vc_json(
                &record.passport,
                &metadata.credential_issuer,
                keypair,
                now,
                status_reference.clone(),
            )
            .map_err(|error| CliError::policy_error(error.to_string()))?;
            Oid4vciCredentialResponse::new_portable_jwt_vc_json(
                format.clone(),
                envelope.compact,
                envelope.passport_id,
                envelope.subject_did,
                status_reference,
                envelope.issuer_jwk,
            )
            .map_err(|error| CliError::policy_error(error.to_string()))?
        } else {
            Oid4vciCredentialResponse::new_with_status_reference(
                format.clone(),
                record.passport.clone(),
                portable_status_reference,
            )
            .map_err(|error| CliError::policy_error(error.to_string()))?
        };
        response.validate(now, Some(&format), Some(expected_subject))?;
        record.state = PassportIssuanceOfferState::CredentialIssued;
        record.credential_issued_at = Some(now);
        Ok(response)
    }
}

#[derive(Debug, Clone)]
pub struct PassportVerifierChallengeStore {
    path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Oid4vpVerifierTransactionStore {
    path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Oid4vpTransactionSnapshot {
    pub request: Oid4vpRequestObject,
    pub request_jwt: String,
    pub transaction: WalletExchangeTransactionState,
}

impl PassportVerifierChallengeStore {
    pub fn open(path: &Path) -> Result<Self, CliError> {
        let store = Self {
            path: path.to_path_buf(),
        };
        let connection = store.connection()?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS passport_verifier_challenges (
                challenge_id TEXT PRIMARY KEY,
                verifier TEXT NOT NULL,
                nonce TEXT NOT NULL,
                policy_id TEXT,
                challenge_hash TEXT NOT NULL,
                challenge_json TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                consumed_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_passport_verifier_challenges_status
                ON passport_verifier_challenges(status, expires_at);",
        )?;
        Ok(store)
    }

    pub fn register(&self, challenge: &PassportPresentationChallenge) -> Result<(), CliError> {
        let connection = self.connection()?;
        let stored = stored_challenge_row(challenge)?;
        connection.execute(
            "INSERT INTO passport_verifier_challenges (
                challenge_id,
                verifier,
                nonce,
                policy_id,
                challenge_hash,
                challenge_json,
                issued_at,
                expires_at,
                status,
                consumed_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
            params![
                stored.challenge_id,
                stored.verifier,
                stored.nonce,
                stored.policy_id,
                stored.challenge_hash,
                stored.challenge_json,
                sqlite_i64(stored.issued_at, "passport verifier challenge issued_at")?,
                sqlite_i64(stored.expires_at, "passport verifier challenge expires_at")?,
                CHALLENGE_STATUS_ISSUED,
            ],
        )?;
        Ok(())
    }

    pub fn fetch_active(
        &self,
        challenge_id: &str,
        now: u64,
    ) -> Result<PassportPresentationChallenge, CliError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let Some((challenge_json, status, expires_at_raw)) = transaction
            .query_row(
                "SELECT challenge_json, status, expires_at
                 FROM passport_verifier_challenges
                 WHERE challenge_id = ?1",
                [challenge_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
        else {
            return Err(CliError::cli_other_error(format!(
                "challenge `{challenge_id}` is not registered in the verifier challenge store"
            )));
        };
        let expires_at = sqlite_u64(expires_at_raw, "passport verifier challenge expires_at")?;
        match status.as_str() {
            CHALLENGE_STATUS_ISSUED => {}
            CHALLENGE_STATUS_CONSUMED => {
                return Err(CliError::cli_other_error(format!(
                    "challenge `{challenge_id}` has already been consumed"
                )))
            }
            CHALLENGE_STATUS_EXPIRED => {
                return Err(CliError::cli_other_error(format!(
                    "challenge `{challenge_id}` has already expired"
                )))
            }
            other => {
                return Err(CliError::cli_other_error(format!(
                    "challenge `{challenge_id}` has unknown stored status `{other}`"
                )))
            }
        }
        if now > expires_at {
            transaction.execute(
                "UPDATE passport_verifier_challenges
                 SET status = ?2
                 WHERE challenge_id = ?1",
                params![challenge_id, CHALLENGE_STATUS_EXPIRED],
            )?;
            transaction.commit()?;
            return Err(CliError::cli_other_error(format!(
                "challenge `{challenge_id}` expired before it could be fetched"
            )));
        }
        let challenge: PassportPresentationChallenge = serde_json::from_str(&challenge_json)?;
        verify_passport_presentation_challenge(&challenge, now)
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        transaction.commit()?;
        Ok(challenge)
    }

    pub fn consume(
        &self,
        challenge: &PassportPresentationChallenge,
        now: u64,
    ) -> Result<(), CliError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let challenge_id = challenge_identifier(challenge);
        let Some((stored_challenge_hash, status, expires_at_raw)) = transaction
            .query_row(
                "SELECT challenge_hash, status, expires_at
                 FROM passport_verifier_challenges
                 WHERE challenge_id = ?1",
                [AsRef::<str>::as_ref(&challenge_id)],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
        else {
            return Err(CliError::cli_other_error(format!(
                "challenge `{}` is not registered in the verifier challenge store",
                challenge_id
            )));
        };
        let expected_hash = challenge_hash(challenge)?;
        if stored_challenge_hash != expected_hash {
            return Err(CliError::cli_other_error(format!(
                "stored verifier challenge `{}` does not match the provided challenge payload",
                challenge_id
            )));
        }
        let expires_at = sqlite_u64(expires_at_raw, "passport verifier challenge expires_at")?;
        match status.as_str() {
            CHALLENGE_STATUS_CONSUMED => {
                return Err(CliError::cli_other_error(format!(
                    "challenge `{}` has already been consumed",
                    challenge_id
                )))
            }
            CHALLENGE_STATUS_EXPIRED => {
                return Err(CliError::cli_other_error(format!(
                    "challenge `{}` has already expired",
                    challenge_id
                )))
            }
            CHALLENGE_STATUS_ISSUED => {}
            other => {
                return Err(CliError::cli_other_error(format!(
                    "challenge `{}` has unknown stored status `{other}`",
                    challenge_id
                )))
            }
        }
        if now > expires_at {
            transaction.execute(
                "UPDATE passport_verifier_challenges
                 SET status = ?2
                 WHERE challenge_id = ?1",
                params![
                    AsRef::<str>::as_ref(&challenge_id),
                    CHALLENGE_STATUS_EXPIRED
                ],
            )?;
            transaction.commit()?;
            return Err(CliError::cli_other_error(format!(
                "challenge `{}` expired before it could be consumed",
                challenge_id
            )));
        }
        let updated = transaction.execute(
            "UPDATE passport_verifier_challenges
             SET status = ?2, consumed_at = ?3
             WHERE challenge_id = ?1 AND status = ?4",
            params![
                AsRef::<str>::as_ref(&challenge_id),
                CHALLENGE_STATUS_CONSUMED,
                sqlite_i64(now, "passport verifier challenge consumed_at")?,
                CHALLENGE_STATUS_ISSUED,
            ],
        )?;
        if updated != 1 {
            return Err(CliError::cli_other_error(format!(
                "challenge `{}` could not be consumed safely",
                challenge_id
            )));
        }
        transaction.commit()?;
        Ok(())
    }

    fn connection(&self) -> Result<Connection, CliError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(Connection::open(&self.path)?)
    }
}

impl Oid4vpVerifierTransactionStore {
    pub fn open(path: &Path) -> Result<Self, CliError> {
        let store = Self {
            path: path.to_path_buf(),
        };
        let connection = store.connection()?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS passport_oid4vp_transactions (
                request_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                state TEXT NOT NULL,
                response_uri TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                request_json TEXT NOT NULL,
                request_jwt TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                consumed_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_passport_oid4vp_transactions_status
                ON passport_oid4vp_transactions(status, expires_at);",
        )?;
        Ok(store)
    }

    pub fn register(
        &self,
        request: &Oid4vpRequestObject,
        request_jwt: &str,
    ) -> Result<(), CliError> {
        let connection = self.connection()?;
        let stored = stored_oid4vp_request_row(request, request_jwt)?;
        connection.execute(
            "INSERT INTO passport_oid4vp_transactions (
                request_id,
                client_id,
                nonce,
                state,
                response_uri,
                request_hash,
                request_json,
                request_jwt,
                issued_at,
                expires_at,
                status,
                consumed_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL)",
            params![
                stored.request_id,
                stored.client_id,
                stored.nonce,
                stored.state,
                stored.response_uri,
                stored.request_hash,
                stored.request_json,
                stored.request_jwt,
                sqlite_i64(stored.issued_at, "OID4VP transaction issued_at")?,
                sqlite_i64(stored.expires_at, "OID4VP transaction expires_at")?,
                OID4VP_TRANSACTION_STATUS_ISSUED,
            ],
        )?;
        Ok(())
    }

    pub fn fetch_active(
        &self,
        request_id: &str,
        now: u64,
    ) -> Result<(Oid4vpRequestObject, String), CliError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let Some((request_json, request_jwt, status, expires_at_raw)) = transaction
            .query_row(
                "SELECT request_json, request_jwt, status, expires_at
                 FROM passport_oid4vp_transactions
                 WHERE request_id = ?1",
                [request_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
        else {
            return Err(CliError::cli_other_error(format!(
                "OID4VP request `{request_id}` is not registered in the verifier transaction store"
            )));
        };
        let expires_at = sqlite_u64(expires_at_raw, "OID4VP transaction expires_at")?;
        match status.as_str() {
            OID4VP_TRANSACTION_STATUS_ISSUED => {}
            OID4VP_TRANSACTION_STATUS_CONSUMED => {
                return Err(CliError::cli_other_error(format!(
                    "OID4VP request `{request_id}` has already been consumed"
                )))
            }
            OID4VP_TRANSACTION_STATUS_EXPIRED => {
                return Err(CliError::cli_other_error(format!(
                    "OID4VP request `{request_id}` has already expired"
                )))
            }
            other => {
                return Err(CliError::cli_other_error(format!(
                    "OID4VP request `{request_id}` has unknown stored status `{other}`"
                )))
            }
        }
        if now > expires_at {
            transaction.execute(
                "UPDATE passport_oid4vp_transactions
                 SET status = ?2
                 WHERE request_id = ?1",
                params![request_id, OID4VP_TRANSACTION_STATUS_EXPIRED],
            )?;
            transaction.commit()?;
            return Err(CliError::cli_other_error(format!(
                "OID4VP request `{request_id}` expired before it could be fetched"
            )));
        }
        let request: Oid4vpRequestObject = serde_json::from_str(&request_json)?;
        transaction.commit()?;
        Ok((request, request_jwt))
    }

    pub fn snapshot(
        &self,
        request_id: &str,
        now: u64,
    ) -> Result<Oid4vpTransactionSnapshot, CliError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let Some((
            request_json,
            request_jwt,
            status,
            issued_at_raw,
            expires_at_raw,
            consumed_at_raw,
        )) = transaction
            .query_row(
                "SELECT request_json, request_jwt, status, issued_at, expires_at, consumed_at
                 FROM passport_oid4vp_transactions
                 WHERE request_id = ?1",
                [request_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                    ))
                },
            )
            .optional()?
        else {
            return Err(CliError::cli_other_error(format!(
                "OID4VP request `{request_id}` is not registered in the verifier transaction store"
            )));
        };
        let issued_at = sqlite_u64(issued_at_raw, "OID4VP transaction issued_at")?;
        let expires_at = sqlite_u64(expires_at_raw, "OID4VP transaction expires_at")?;
        let consumed_at = consumed_at_raw
            .map(|value| sqlite_u64(value, "OID4VP transaction consumed_at"))
            .transpose()?;
        let mut status = wallet_exchange_status_from_store(status.as_str())?;
        if status == WalletExchangeTransactionStatus::Issued && now > expires_at {
            transaction.execute(
                "UPDATE passport_oid4vp_transactions
                 SET status = ?2
                 WHERE request_id = ?1",
                params![request_id, OID4VP_TRANSACTION_STATUS_EXPIRED],
            )?;
            status = WalletExchangeTransactionStatus::Expired;
        }
        let request: Oid4vpRequestObject = serde_json::from_str(&request_json)?;
        if request.jti != request_id {
            return Err(CliError::cli_other_error(format!(
                "stored OID4VP request payload did not match request_id `{request_id}`"
            )));
        }
        let transaction_state = build_wallet_exchange_transaction_state(
            &request.jti,
            status,
            issued_at,
            expires_at,
            consumed_at,
        )?;
        transaction.commit()?;
        Ok(Oid4vpTransactionSnapshot {
            request,
            request_jwt,
            transaction: transaction_state,
        })
    }

    pub fn consume(
        &self,
        request: &Oid4vpRequestObject,
        request_jwt: &str,
        now: u64,
    ) -> Result<(), CliError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let Some((request_hash, status, expires_at_raw)) = transaction
            .query_row(
                "SELECT request_hash, status, expires_at
                 FROM passport_oid4vp_transactions
                 WHERE request_id = ?1",
                [request.jti.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
        else {
            return Err(CliError::cli_other_error(format!(
                "OID4VP request `{}` is not registered in the verifier transaction store",
                request.jti
            )));
        };
        let expected_hash = sha256_hex(request_jwt.as_bytes());
        if request_hash != expected_hash {
            return Err(CliError::cli_other_error(format!(
                "stored OID4VP request `{}` does not match the provided request JWT",
                request.jti
            )));
        }
        let expires_at = sqlite_u64(expires_at_raw, "OID4VP transaction expires_at")?;
        match status.as_str() {
            OID4VP_TRANSACTION_STATUS_CONSUMED => {
                return Err(CliError::cli_other_error(format!(
                    "OID4VP request `{}` has already been consumed",
                    request.jti
                )))
            }
            OID4VP_TRANSACTION_STATUS_EXPIRED => {
                return Err(CliError::cli_other_error(format!(
                    "OID4VP request `{}` has already expired",
                    request.jti
                )))
            }
            OID4VP_TRANSACTION_STATUS_ISSUED => {}
            other => {
                return Err(CliError::cli_other_error(format!(
                    "OID4VP request `{}` has unknown stored status `{other}`",
                    request.jti
                )))
            }
        }
        if now > expires_at {
            transaction.execute(
                "UPDATE passport_oid4vp_transactions
                 SET status = ?2
                 WHERE request_id = ?1",
                params![request.jti.as_str(), OID4VP_TRANSACTION_STATUS_EXPIRED],
            )?;
            transaction.commit()?;
            return Err(CliError::cli_other_error(format!(
                "OID4VP request `{}` expired before it could be consumed",
                request.jti
            )));
        }
        let updated = transaction.execute(
            "UPDATE passport_oid4vp_transactions
             SET status = ?2, consumed_at = ?3
             WHERE request_id = ?1 AND status = ?4",
            params![
                request.jti.as_str(),
                OID4VP_TRANSACTION_STATUS_CONSUMED,
                sqlite_i64(now, "OID4VP transaction consumed_at")?,
                OID4VP_TRANSACTION_STATUS_ISSUED,
            ],
        )?;
        if updated != 1 {
            return Err(CliError::cli_other_error(format!(
                "OID4VP request `{}` could not be consumed safely",
                request.jti
            )));
        }
        transaction.commit()?;
        Ok(())
    }

    fn connection(&self) -> Result<Connection, CliError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(Connection::open(&self.path)?)
    }
}

#[derive(Debug)]
struct StoredChallengeRow {
    challenge_id: String,
    verifier: String,
    nonce: String,
    policy_id: Option<String>,
    challenge_hash: String,
    challenge_json: String,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Debug)]
struct StoredOid4vpRequestRow {
    request_id: String,
    client_id: String,
    nonce: String,
    state: String,
    response_uri: String,
    request_hash: String,
    request_json: String,
    request_jwt: String,
    issued_at: u64,
    expires_at: u64,
}

fn wallet_exchange_status_from_store(
    value: &str,
) -> Result<WalletExchangeTransactionStatus, CliError> {
    match value {
        OID4VP_TRANSACTION_STATUS_ISSUED => Ok(WalletExchangeTransactionStatus::Issued),
        OID4VP_TRANSACTION_STATUS_CONSUMED => Ok(WalletExchangeTransactionStatus::Consumed),
        OID4VP_TRANSACTION_STATUS_EXPIRED => Ok(WalletExchangeTransactionStatus::Expired),
        other => Err(CliError::cli_other_error(format!(
            "OID4VP request has unknown stored status `{other}`"
        ))),
    }
}

fn build_wallet_exchange_transaction_state(
    request_id: &str,
    status: WalletExchangeTransactionStatus,
    issued_at: u64,
    expires_at: u64,
    consumed_at: Option<u64>,
) -> Result<WalletExchangeTransactionState, CliError> {
    let state = match status {
        WalletExchangeTransactionStatus::Issued => {
            WalletExchangeTransactionState::issued(request_id, request_id, issued_at, expires_at)
        }
        WalletExchangeTransactionStatus::Consumed => {
            let consumed_at = consumed_at.ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "OID4VP request `{request_id}` is marked consumed without consumed_at"
                ))
            })?;
            WalletExchangeTransactionState::consumed(
                request_id,
                request_id,
                issued_at,
                expires_at,
                consumed_at,
            )
        }
        WalletExchangeTransactionStatus::Expired => {
            WalletExchangeTransactionState::expired(request_id, request_id, issued_at, expires_at)
        }
    };
    state
        .validate()
        .map_err(|error| CliError::policy_error(error.to_string()))?;
    Ok(state)
}

fn stored_challenge_row(
    challenge: &PassportPresentationChallenge,
) -> Result<StoredChallengeRow, CliError> {
    Ok(StoredChallengeRow {
        challenge_id: challenge_identifier(challenge).into_owned(),
        verifier: challenge.verifier.clone(),
        nonce: challenge.nonce.clone(),
        policy_id: challenge
            .policy_ref
            .as_ref()
            .map(|reference| reference.policy_id.clone()),
        challenge_hash: challenge_hash(challenge)?,
        challenge_json: serde_json::to_string(challenge)?,
        issued_at: unix_from_rfc3339(&challenge.issued_at)?,
        expires_at: unix_from_rfc3339(&challenge.expires_at)?,
    })
}

fn stored_oid4vp_request_row(
    request: &Oid4vpRequestObject,
    request_jwt: &str,
) -> Result<StoredOid4vpRequestRow, CliError> {
    Ok(StoredOid4vpRequestRow {
        request_id: request.jti.clone(),
        client_id: request.client_id.clone(),
        nonce: request.nonce.clone(),
        state: request.state.clone(),
        response_uri: request.response_uri.clone(),
        request_hash: sha256_hex(request_jwt.as_bytes()),
        request_json: serde_json::to_string(request)?,
        request_jwt: request_jwt.to_string(),
        issued_at: request.iat,
        expires_at: request.exp,
    })
}

pub fn challenge_identifier(challenge: &PassportPresentationChallenge) -> Cow<'_, str> {
    challenge
        .challenge_id
        .as_deref()
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Cow::Borrowed(&challenge.nonce))
}

fn challenge_hash(challenge: &PassportPresentationChallenge) -> Result<String, CliError> {
    Ok(sha256_hex(&canonical_json_bytes(challenge)?))
}

fn unix_from_rfc3339(value: &str) -> Result<u64, CliError> {
    let datetime = DateTime::parse_from_rfc3339(value).map_err(|error| {
        CliError::cli_other_error(format!("invalid RFC3339 timestamp: {error}"))
    })?;
    u64::try_from(datetime.timestamp())
        .map_err(|_| CliError::cli_other_error(format!("invalid RFC3339 timestamp: {value}")))
}

fn unix_timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn verify_passport_lifecycle_record(record: &PassportLifecycleRecord) -> Result<(), CliError> {
    record
        .validate()
        .map_err(|error| CliError::policy_error(error.to_string()))
}

fn passport_lifecycle_resolution_from_record(
    record: &PassportLifecycleRecord,
    at: u64,
) -> PassportLifecycleResolution {
    let state = if record.status == PassportLifecycleState::Active
        && passport_lifecycle_is_stale(record, at)
    {
        PassportLifecycleState::Stale
    } else {
        record.status
    };
    PassportLifecycleResolution {
        passport_id: record.passport_id.clone(),
        subject: record.subject.clone(),
        issuers: record.issuers.clone(),
        issuer_count: record.issuer_count,
        state,
        published_at: Some(record.published_at),
        updated_at: Some(record.updated_at),
        superseded_by: record.superseded_by.clone(),
        revoked_at: record.revoked_at,
        revoked_reason: record.revoked_reason.clone(),
        distribution: record.distribution.clone(),
        valid_until: record.valid_until.clone(),
        source: None,
    }
}

fn passport_lifecycle_is_stale(record: &PassportLifecycleRecord, at: u64) -> bool {
    record
        .distribution
        .cache_ttl_secs
        .is_some_and(|ttl| record.updated_at.saturating_add(ttl) < at)
}

fn verify_passport_issuance_offer_record(
    record: &PassportIssuanceOfferRecord,
) -> Result<(), CliError> {
    if record.offer_id.trim().is_empty() {
        return Err(CliError::cli_other_error(
            "passport issuance offer entries must include a non-empty offer_id".to_string(),
        ));
    }
    record.offer.validate().map_err(CliError::from)?;
    let verification =
        verify_agent_passport(&record.passport, record.issued_at).map_err(CliError::from)?;
    if let Some(context) = record.offer.chio_offer_context.as_ref() {
        if context.passport_id != verification.passport_id {
            return Err(CliError::cli_other_error(format!(
                    "passport issuance offer `{}` stores a passport_id that does not match the embedded passport",
                record.offer_id
            )));
        }
        if context.subject != verification.subject {
            return Err(CliError::cli_other_error(format!(
                    "passport issuance offer `{}` stores a subject that does not match the embedded passport",
                record.offer_id
            )));
        }
        if unix_from_rfc3339(&context.expires_at)? != record.expires_at {
            return Err(CliError::cli_other_error(format!(
                "passport issuance offer `{}` has mismatched expires_at metadata",
                record.offer_id
            )));
        }
    }
    if record.state == PassportIssuanceOfferState::TokenIssued && record.access_token.is_none() {
        return Err(CliError::cli_other_error(format!(
            "passport issuance offer `{}` cannot be token-issued without an access_token",
            record.offer_id
        )));
    }
    if record.state == PassportIssuanceOfferState::CredentialIssued
        && record.credential_issued_at.is_none()
    {
        return Err(CliError::cli_other_error(format!(
            "passport issuance offer `{}` cannot be credential-issued without credential_issued_at",
            record.offer_id
        )));
    }
    Ok(())
}

fn refresh_passport_issuance_offer_state(record: &mut PassportIssuanceOfferRecord, now: u64) {
    if record.state == PassportIssuanceOfferState::CredentialIssued {
        return;
    }
    if now > record.expires_at
        || record
            .access_token_expires_at
            .is_some_and(|expires_at| now > expires_at)
    {
        record.state = PassportIssuanceOfferState::Expired;
    }
}

fn normalize_credential_issuer(value: &str) -> Result<String, CliError> {
    let normalized = value.trim().trim_end_matches('/');
    if normalized.is_empty() {
        return Err(CliError::policy_constraint_error(
            "credential_issuer must be non-empty".to_string(),
        ));
    }
    Ok(normalized.to_string())
}

struct KeyId;

impl KeyId {
    fn generate() -> String {
        chio_core::Keypair::generate().public_key().to_hex()
    }
}

#[cfg(test)]
mod revocation_lag_tests {
    use super::*;

    /// Insert a minimal active lifecycle record so revoke() finds an entry.
    fn seed_one_passport(registry: &mut PassportStatusRegistry) -> String {
        let passport_id = "passport-revocation-lag".to_string();
        let record = PassportLifecycleRecord {
            passport_id: passport_id.clone(),
            subject: "did:example:subject".to_string(),
            issuers: Vec::new(),
            issuer_count: 0,
            published_at: 1_000,
            updated_at: 1_000,
            status: PassportLifecycleState::Active,
            superseded_by: None,
            revoked_at: None,
            revoked_reason: None,
            distribution: PassportStatusDistribution::default(),
            valid_until: "2099-01-01T00:00:00Z".to_string(),
        };
        registry.passports.insert(passport_id.clone(), record);
        passport_id
    }

    #[test]
    fn passport_lifecycle_revoke_does_not_observe_capability_revocation_lag() {
        // A passport lifecycle revoke must NOT emit the capability-revocation lag
        // family; that SLO is observed from the actual capability revoke paths
        // (see the cluster delta module).
        let mut registry = PassportStatusRegistry::default();
        let passport_id = seed_one_passport(&mut registry);

        let mut before = String::new();
        chio_metrics_spec::runtime::families::CAPABILITY_REVOCATION_LAG.render(&mut before);

        let now = unix_timestamp_now();
        let revoked_at = now.saturating_sub(45);
        let _ = registry
            .revoke(&passport_id, Some("compromise"), Some(revoked_at))
            .unwrap_or_else(|error| panic!("revoke succeeds: {error:?}"));

        let mut after = String::new();
        chio_metrics_spec::runtime::families::CAPABILITY_REVOCATION_LAG.render(&mut after);
        assert_eq!(
            before, after,
            "a passport lifecycle revoke must not observe a capability revocation lag sample"
        );
    }
}
