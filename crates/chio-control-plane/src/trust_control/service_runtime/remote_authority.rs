use super::client::build_client;
use super::*;

pub fn build_remote_capability_authority(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn CapabilityAuthority>, CliError> {
    let client = build_client(control_url, control_token)?;
    let status = client.authority_status()?;
    let cache = AuthorityKeyCache::from_status(&status)?;
    Ok(Box::new(RemoteCapabilityAuthority {
        client,
        cache: Mutex::new(cache),
    }))
}

impl RemoteCapabilityAuthority {
    pub fn refresh_status(&self) -> Result<(), CliError> {
        let status = self.client.authority_status()?;
        let cache = AuthorityKeyCache::from_status(&status)?;
        match self.cache.lock() {
            Ok(mut guard) => *guard = cache,
            Err(poisoned) => *poisoned.into_inner() = cache,
        }
        Ok(())
    }

    fn refresh_status_if_stale(&self) {
        let should_refresh = match self.cache.lock() {
            Ok(guard) => guard.refreshed_at.elapsed() >= AUTHORITY_CACHE_TTL,
            Err(poisoned) => poisoned.into_inner().refreshed_at.elapsed() >= AUTHORITY_CACHE_TTL,
        };
        if should_refresh {
            let _ = self.refresh_status();
        }
    }
}

impl RemoteCapabilityAuthority {
    /// Fail-closed substitute for a missing current authority key.
    ///
    /// `AuthorityKeyCache::from_status` rejects any status without a current
    /// key, so a primed cache always carries one. If that invariant is ever
    /// violated we must NOT abort the process and must NOT return a key an
    /// attacker could control. We return a freshly
    /// generated ephemeral public key whose private half is discarded
    /// immediately: it can never validate a real capability, so callers that
    /// fold this value into a trust set gain no usable issuer. The effect is a
    /// denial (zero trust granted) rather than a panic.
    fn deny_sentinel_public_key() -> PublicKey {
        tracing::error!(
            "remote capability authority cache missing current key; \
             returning a non-trusting sentinel so admission fails closed"
        );
        Keypair::generate().public_key()
    }
}

impl CapabilityAuthority for RemoteCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.refresh_status_if_stale();
        match self.cache.lock() {
            Ok(guard) => match &guard.current {
                Some(public_key) => public_key.clone(),
                None => Self::deny_sentinel_public_key(),
            },
            Err(poisoned) => match &poisoned.into_inner().current {
                Some(public_key) => public_key.clone(),
                None => Self::deny_sentinel_public_key(),
            },
        }
    }

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        self.refresh_status_if_stale();
        match self.cache.lock() {
            Ok(guard) => guard.trusted.clone(),
            Err(poisoned) => poisoned.into_inner().trusted.clone(),
        }
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        self.issue_capability_with_attestation(subject, scope, ttl_seconds, None)
    }

    fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        let capability = self
            .client
            .issue_capability_with_attestation(subject, scope, ttl_seconds, runtime_attestation)
            .map_err(|error| {
                chio_kernel::KernelError::CapabilityIssuanceFailed(error.to_string())
            })?;
        match self.cache.lock() {
            Ok(mut guard) => {
                guard.current = Some(capability.issuer.clone());
                if !guard.trusted.contains(&capability.issuer) {
                    guard.trusted.push(capability.issuer.clone());
                }
                guard.refreshed_at = Instant::now();
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.current = Some(capability.issuer.clone());
                if !guard.trusted.contains(&capability.issuer) {
                    guard.trusted.push(capability.issuer.clone());
                }
                guard.refreshed_at = Instant::now();
            }
        }
        Ok(capability)
    }
}

impl AuthorityKeyCache {
    pub(crate) fn from_status(status: &TrustAuthorityStatus) -> Result<Self, CliError> {
        if !status.configured {
            return Err(CliError::cli_other_error(
                "trust control service does not have an authority configured".to_string(),
            ));
        }
        let current = status
            .public_key
            .as_deref()
            .map(PublicKey::from_hex)
            .transpose()?;
        if current.is_none() {
            return Err(CliError::cli_other_error(
                "trust control service returned no current authority public key".to_string(),
            ));
        }
        let trusted = status
            .trusted_public_keys
            .iter()
            .map(|value| PublicKey::from_hex(value))
            .collect::<Result<Vec<_>, _>>()?;
        let mut trusted = trusted;
        if let Some(current) = current.as_ref() {
            if !trusted.iter().any(|public_key| public_key == current) {
                trusted.push(current.clone());
            }
        }
        Ok(Self {
            current,
            trusted,
            refreshed_at: Instant::now(),
        })
    }
}
