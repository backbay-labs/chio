use std::collections::BTreeSet;

use chio_attest_buyer_core::trust_bundle::{
    ChioTrustedGovernanceAuthority, ChioTrustedLeaseAuthority,
};

use crate::{
    required_window, validate_hex, validate_key_id_matches_public_key, validate_non_empty,
    validate_sha256, AuthorityProfileDocument, ChioAuthorityError, ChioRevocationAuthority,
    AUTHORITY_PROFILE_SCHEMA,
};

impl AuthorityProfileDocument {
    pub fn validate(&self) -> Result<(), ChioAuthorityError> {
        if self.schema != AUTHORITY_PROFILE_SCHEMA {
            return Err(ChioAuthorityError::Profile(format!(
                "authority profile schema {} is unsupported",
                self.schema
            )));
        }
        if self.trusted_bbs_issuers.is_empty()
            || self.lease_authorities.is_empty()
            || self.governance_authorities.is_empty()
            || self.runtime_policy_issuer_public_keys.is_empty()
        {
            return Err(ChioAuthorityError::Profile(
                "authority profile must contain BBS issuers, lease authorities, governance authorities, and runtime policy issuers".to_string(),
            ));
        }
        let mut issuers = BTreeSet::new();
        for issuer in &self.trusted_bbs_issuers {
            validate_sha256(
                &issuer.issuer_fingerprint,
                "trustedBbsIssuers.issuerFingerprint",
            )
            .map_err(ChioAuthorityError::Profile)?;
            validate_hex(&issuer.public_key_hex, "trustedBbsIssuers.publicKeyHex")
                .map_err(ChioAuthorityError::Profile)?;
            if !issuers.insert(&issuer.issuer_fingerprint) {
                return Err(ChioAuthorityError::Profile(format!(
                    "duplicate BBS issuer {}",
                    issuer.issuer_fingerprint
                )));
            }
        }

        let mut lease_issuers = BTreeSet::new();
        for authority in &self.lease_authorities {
            validate_non_empty(&authority.issuer, "leaseAuthorities.issuer")
                .map_err(ChioAuthorityError::Profile)?;
            validate_key_id_matches_public_key(
                authority.key_id.as_deref(),
                &authority.public_key,
                "leaseAuthorities.keyId",
            )
            .map_err(ChioAuthorityError::Profile)?;
            let (valid_from, valid_until) = required_window(
                authority.valid_from_unix_ms,
                authority.valid_until_unix_ms,
                "leaseAuthorities",
            )
            .map_err(ChioAuthorityError::Profile)?;
            if valid_until <= valid_from {
                return Err(ChioAuthorityError::Profile(
                    "lease authority validity window is empty".to_string(),
                ));
            }
            if authority.status.is_none() {
                return Err(ChioAuthorityError::Profile(
                    "lease authority status is required".to_string(),
                ));
            }
            if authority.allowed_action_classes.is_empty() {
                return Err(ChioAuthorityError::Profile(
                    "lease authority allowed action classes are required".to_string(),
                ));
            }
            if !lease_issuers.insert(&authority.issuer) {
                return Err(ChioAuthorityError::Profile(format!(
                    "duplicate lease authority {}",
                    authority.issuer
                )));
            }
        }

        let mut governance_kernels = BTreeSet::new();
        for authority in &self.governance_authorities {
            validate_non_empty(
                &authority.authorizing_kernel,
                "governanceAuthorities.authorizingKernel",
            )
            .map_err(ChioAuthorityError::Profile)?;
            validate_key_id_matches_public_key(
                authority.key_id.as_deref(),
                &authority.public_key,
                "governanceAuthorities.keyId",
            )
            .map_err(ChioAuthorityError::Profile)?;
            let (valid_from, valid_until) = required_window(
                authority.valid_from_unix_ms,
                authority.valid_until_unix_ms,
                "governanceAuthorities",
            )
            .map_err(ChioAuthorityError::Profile)?;
            if valid_until <= valid_from {
                return Err(ChioAuthorityError::Profile(
                    "governance authority validity window is empty".to_string(),
                ));
            }
            if authority.status.is_none() {
                return Err(ChioAuthorityError::Profile(
                    "governance authority status is required".to_string(),
                ));
            }
            if authority.allowed_case_kinds.is_empty() {
                return Err(ChioAuthorityError::Profile(
                    "governance authority allowed case kinds are required".to_string(),
                ));
            }
            if !governance_kernels.insert(&authority.authorizing_kernel) {
                return Err(ChioAuthorityError::Profile(format!(
                    "duplicate governance authority {}",
                    authority.authorizing_kernel
                )));
            }
        }

        let mut runtime_policy_issuer_keys = BTreeSet::new();
        let mut reserved_authority_keys = BTreeSet::new();
        for authority in &self.lease_authorities {
            reserved_authority_keys.insert(authority.public_key.to_hex());
        }
        for authority in &self.governance_authorities {
            reserved_authority_keys.insert(authority.public_key.to_hex());
        }
        reserved_authority_keys.insert(self.revocation_authority.public_key.to_hex());
        for public_key in &self.runtime_policy_issuer_public_keys {
            let public_key_hex = public_key.to_hex();
            if !runtime_policy_issuer_keys.insert(public_key_hex.clone()) {
                return Err(ChioAuthorityError::Profile(format!(
                    "duplicate runtime policy issuer public key {public_key_hex}"
                )));
            }
            if reserved_authority_keys.contains(&public_key_hex) {
                return Err(ChioAuthorityError::Profile(
                    "runtime policy issuer key must be distinct from lease, governance, and revocation authority keys".to_string(),
                ));
            }
        }

        self.revocation_authority.validate()?;
        Ok(())
    }

    pub(crate) fn lease_authority(
        &self,
        issuer: &str,
    ) -> Result<&ChioTrustedLeaseAuthority, ChioAuthorityError> {
        self.lease_authorities
            .iter()
            .find(|authority| authority.issuer == issuer)
            .ok_or_else(|| {
                ChioAuthorityError::Issuance(format!(
                    "lease authority {issuer} is not in the authority profile"
                ))
            })
    }

    pub(crate) fn governance_authority(
        &self,
        authorizing_kernel: &str,
    ) -> Result<&ChioTrustedGovernanceAuthority, ChioAuthorityError> {
        self.governance_authorities
            .iter()
            .find(|authority| authority.authorizing_kernel == authorizing_kernel)
            .ok_or_else(|| {
                ChioAuthorityError::Issuance(format!(
                    "governance authority {authorizing_kernel} is not in the authority profile"
                ))
            })
    }
}

impl ChioRevocationAuthority {
    fn validate(&self) -> Result<(), ChioAuthorityError> {
        validate_non_empty(&self.authority_id, "revocationAuthority.authorityId")
            .map_err(ChioAuthorityError::Profile)?;
        validate_key_id_matches_public_key(
            Some(&self.key_id),
            &self.public_key,
            "revocationAuthority.keyId",
        )
        .map_err(ChioAuthorityError::Profile)?;
        if self.valid_until_unix_ms <= self.valid_from_unix_ms {
            return Err(ChioAuthorityError::Profile(
                "revocation authority validity window is empty".to_string(),
            ));
        }
        Ok(())
    }
}
