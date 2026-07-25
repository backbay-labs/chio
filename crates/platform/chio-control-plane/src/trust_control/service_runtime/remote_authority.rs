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
        refresh_lock: Mutex::new(()),
    }))
}

impl RemoteCapabilityAuthority {
    pub fn refresh_status(&self) -> Result<(), CliError> {
        let _refresh_guard = self.lock_refresh();
        let cache = self.fetch_status_cache()?;
        self.install_status_cache(cache)
    }

    fn fetch_status_cache(&self) -> Result<AuthorityKeyCache, CliError> {
        let status = self.client.authority_status()?;
        AuthorityKeyCache::from_status(&status)
    }

    fn lock_refresh(&self) -> std::sync::MutexGuard<'_, ()> {
        match self.refresh_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn install_status_cache(&self, cache: AuthorityKeyCache) -> Result<(), CliError> {
        let mut guard = match self.cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        cache.ensure_not_older_than(&guard)?;
        *guard = cache;
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

    fn trusted_keys_snapshot(&self) -> Vec<PublicKey> {
        match self.cache.lock() {
            Ok(guard) => guard.trusted.clone(),
            Err(poisoned) => poisoned.into_inner().trusted.clone(),
        }
    }

    fn issuance_key_snapshot(&self) -> Result<(PublicKey, bool), chio_kernel::KernelError> {
        let (current, stale) = match self.cache.lock() {
            Ok(guard) => (
                guard.current.clone(),
                guard.refreshed_at.elapsed() >= AUTHORITY_CACHE_TTL,
            ),
            Err(poisoned) => {
                let guard = poisoned.into_inner();
                (
                    guard.current.clone(),
                    guard.refreshed_at.elapsed() >= AUTHORITY_CACHE_TTL,
                )
            }
        };
        current.map(|current| (current, stale)).ok_or_else(|| {
            chio_kernel::KernelError::CapabilityIssuanceFailed(
                "remote capability-authority cache has no current issuer key".to_string(),
            )
        })
    }

    fn verify_issuance_response(
        &self,
        capability: &CapabilityToken,
        requested_subject: &PublicKey,
        requested_scope: &ChioScope,
        requested_ttl_seconds: u64,
    ) -> Result<(), chio_kernel::KernelError> {
        let _refresh_guard = self.lock_refresh();
        let (current, stale) = self.issuance_key_snapshot()?;
        if capability.issuer == current && !stale {
            return chio_kernel::validate_issued_capability_response(
                capability,
                requested_subject,
                requested_scope,
                requested_ttl_seconds,
                &current,
            );
        }

        let refreshed = self.fetch_status_cache().map_err(|error| {
            chio_kernel::KernelError::CapabilityIssuanceFailed(format!(
                "failed to refresh remote capability-authority trust: {error}"
            ))
        })?;
        self.install_verified_status_cache(
            capability,
            requested_subject,
            requested_scope,
            requested_ttl_seconds,
            refreshed,
        )
    }

    fn install_verified_status_cache(
        &self,
        capability: &CapabilityToken,
        requested_subject: &PublicKey,
        requested_scope: &ChioScope,
        requested_ttl_seconds: u64,
        refreshed: AuthorityKeyCache,
    ) -> Result<(), chio_kernel::KernelError> {
        let current = refreshed.current.as_ref().ok_or_else(|| {
            chio_kernel::KernelError::CapabilityIssuanceFailed(
                "refreshed capability-authority status has no current issuer key".to_string(),
            )
        })?;
        chio_kernel::validate_issued_capability_response(
            capability,
            requested_subject,
            requested_scope,
            requested_ttl_seconds,
            current,
        )?;
        self.install_status_cache(refreshed).map_err(|error| {
            chio_kernel::KernelError::CapabilityIssuanceFailed(error.to_string())
        })?;
        Ok(())
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
        self.trusted_keys_snapshot()
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
        chio_kernel::ensure_capability_issuance_supported(&scope)?;
        let capability = self
            .client
            .issue_capability_with_attestation(
                subject,
                scope.clone(),
                ttl_seconds,
                runtime_attestation,
            )
            .map_err(|error| {
                chio_kernel::KernelError::CapabilityIssuanceFailed(error.to_string())
            })?;
        self.verify_issuance_response(&capability, subject, &scope, ttl_seconds)?;
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
        if status.generation.is_some() != status.rotated_at.is_some() {
            return Err(CliError::cli_other_error(
                "trust control service returned incomplete authority fence metadata".to_string(),
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
        trusted.sort_by_key(PublicKey::to_hex);
        trusted.dedup();
        Ok(Self {
            current,
            trusted,
            generation: status.generation,
            rotated_at: status.rotated_at,
            refreshed_at: Instant::now(),
        })
    }

    fn ensure_not_older_than(&self, installed: &Self) -> Result<(), CliError> {
        match (
            self.generation,
            self.rotated_at,
            installed.generation,
            installed.rotated_at,
        ) {
            (Some(candidate_generation), Some(_), Some(current_generation), Some(_))
                if candidate_generation < current_generation =>
            {
                Err(CliError::cli_other_error(format!(
                    "refusing to replace remote authority cache generation {current_generation} with stale generation {candidate_generation}"
                )))
            }
            (
                Some(candidate_generation),
                Some(candidate_rotated_at),
                Some(current_generation),
                Some(current_rotated_at),
            ) if candidate_generation == current_generation
                && (candidate_rotated_at != current_rotated_at
                    || self.current != installed.current
                    || self.trusted != installed.trusted) =>
            {
                Err(CliError::cli_other_error(format!(
                    "remote authority cache generation {current_generation} equivocated"
                )))
            }
            (
                Some(candidate_generation),
                Some(candidate_rotated_at),
                Some(current_generation),
                Some(current_rotated_at),
            ) if candidate_generation > current_generation
                && candidate_rotated_at < current_rotated_at =>
            {
                Err(CliError::cli_other_error(format!(
                    "remote authority cache generation {candidate_generation} moved rotated_at backward from {current_rotated_at} to {candidate_rotated_at}"
                )))
            }
            (None, None, Some(current_generation), Some(_)) => {
                Err(CliError::cli_other_error(format!(
                    "refusing to replace versioned remote authority cache generation {current_generation} with generationless status"
                )))
            }
            (Some(_), Some(_), Some(_), Some(_))
            | (Some(_), Some(_), None, None)
            | (None, None, None, None) => Ok(()),
            _ => Err(CliError::cli_other_error(
                "remote authority cache has incomplete fence metadata".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_kernel::LocalCapabilityAuthority;

    struct IssuedTestCapability {
        capability: CapabilityToken,
        subject: PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    }

    fn issue_test_capability(
        authority: &LocalCapabilityAuthority,
    ) -> Result<IssuedTestCapability, chio_kernel::KernelError> {
        let subject = Keypair::generate().public_key();
        let scope = ChioScope::default();
        let ttl_seconds = 300;
        let capability = authority.issue_capability(&subject, scope.clone(), ttl_seconds)?;
        Ok(IssuedTestCapability {
            capability,
            subject,
            scope,
            ttl_seconds,
        })
    }

    fn remote_with_trusted_key(
        public_key: PublicKey,
    ) -> Result<RemoteCapabilityAuthority, CliError> {
        Ok(RemoteCapabilityAuthority {
            client: build_client("http://127.0.0.1:1", "test-token")?,
            cache: Mutex::new(AuthorityKeyCache {
                current: Some(public_key.clone()),
                trusted: vec![public_key],
                generation: Some(1),
                rotated_at: Some(1),
                refreshed_at: Instant::now(),
            }),
            refresh_lock: Mutex::new(()),
        })
    }

    #[test]
    fn issuance_response_accepts_trusted_valid_signature() -> Result<(), Box<dyn std::error::Error>>
    {
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let issued = issue_test_capability(&authority)?;
        let remote = remote_with_trusted_key(authority.authority_public_key())?;

        remote.verify_issuance_response(
            &issued.capability,
            &issued.subject,
            &issued.scope,
            issued.ttl_seconds,
        )?;
        Ok(())
    }

    #[test]
    fn issuance_response_rejects_unknown_issuer_without_changing_trust(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let trusted_authority = LocalCapabilityAuthority::new(Keypair::generate());
        let untrusted_authority = LocalCapabilityAuthority::new(Keypair::generate());
        let issued = issue_test_capability(&untrusted_authority)?;
        let current = trusted_authority.authority_public_key();

        let result = chio_kernel::validate_issued_capability_response(
            &issued.capability,
            &issued.subject,
            &issued.scope,
            issued.ttl_seconds,
            &current,
        );

        assert!(matches!(
            result,
            Err(chio_kernel::KernelError::UntrustedIssuer)
        ));
        Ok(())
    }

    #[test]
    fn issuance_response_rejects_invalid_signature_from_trusted_issuer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let mut issued = issue_test_capability(&authority)?;
        issued.capability.subject = Keypair::generate().public_key();

        let result = chio_kernel::validate_issued_capability_response(
            &issued.capability,
            &issued.subject,
            &issued.scope,
            issued.ttl_seconds,
            &authority.authority_public_key(),
        );

        assert!(matches!(
            result,
            Err(chio_kernel::KernelError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn historical_rotated_issuance_does_not_install_refreshed_trust(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let previous = LocalCapabilityAuthority::new(Keypair::generate());
        let rotated = LocalCapabilityAuthority::new(Keypair::generate());
        let previous_key = previous.authority_public_key();
        let rotated_key = rotated.authority_public_key();
        let remote = remote_with_trusted_key(previous_key.clone())?;
        let issued = issue_test_capability(&previous)?;
        let refreshed = AuthorityKeyCache {
            current: Some(rotated_key.clone()),
            trusted: vec![previous_key.clone(), rotated_key],
            generation: Some(2),
            rotated_at: Some(2),
            refreshed_at: Instant::now(),
        };

        let result = remote.install_verified_status_cache(
            &issued.capability,
            &issued.subject,
            &issued.scope,
            issued.ttl_seconds,
            refreshed,
        );

        assert!(matches!(
            result,
            Err(chio_kernel::KernelError::UntrustedIssuer)
        ));
        assert_eq!(remote.trusted_keys_snapshot(), vec![previous_key]);
        Ok(())
    }

    #[test]
    fn valid_rotated_issuance_installs_status_derived_trust(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let previous = LocalCapabilityAuthority::new(Keypair::generate());
        let rotated = LocalCapabilityAuthority::new(Keypair::generate());
        let previous_key = previous.authority_public_key();
        let rotated_key = rotated.authority_public_key();
        let remote = remote_with_trusted_key(previous_key.clone())?;
        let issued = issue_test_capability(&rotated)?;
        let refreshed = AuthorityKeyCache {
            current: Some(rotated_key.clone()),
            trusted: vec![previous_key.clone(), rotated_key.clone()],
            generation: Some(2),
            rotated_at: Some(2),
            refreshed_at: Instant::now(),
        };

        remote.install_verified_status_cache(
            &issued.capability,
            &issued.subject,
            &issued.scope,
            issued.ttl_seconds,
            refreshed,
        )?;

        assert_eq!(
            remote.trusted_keys_snapshot(),
            vec![previous_key, rotated_key]
        );
        Ok(())
    }

    #[test]
    fn issuance_response_fails_closed_when_cached_or_refreshed_current_key_is_absent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let issued = issue_test_capability(&authority)?;
        let remote = RemoteCapabilityAuthority {
            client: build_client("http://127.0.0.1:1", "test-token")?,
            cache: Mutex::new(AuthorityKeyCache {
                current: None,
                trusted: vec![authority.authority_public_key()],
                generation: Some(1),
                rotated_at: Some(1),
                refreshed_at: Instant::now(),
            }),
            refresh_lock: Mutex::new(()),
        };

        let result = remote.verify_issuance_response(
            &issued.capability,
            &issued.subject,
            &issued.scope,
            issued.ttl_seconds,
        );

        assert!(matches!(
            result,
            Err(chio_kernel::KernelError::CapabilityIssuanceFailed(_))
        ));

        let current_key = authority.authority_public_key();
        let remote = remote_with_trusted_key(current_key.clone())?;
        let result = remote.install_verified_status_cache(
            &issued.capability,
            &issued.subject,
            &issued.scope,
            issued.ttl_seconds,
            AuthorityKeyCache {
                current: None,
                trusted: vec![current_key.clone()],
                generation: Some(2),
                rotated_at: Some(2),
                refreshed_at: Instant::now(),
            },
        );
        assert!(matches!(
            result,
            Err(chio_kernel::KernelError::CapabilityIssuanceFailed(_))
        ));
        assert_eq!(remote.issuance_key_snapshot()?.0, current_key);
        Ok(())
    }

    #[test]
    fn trusted_signed_substitution_is_rejected_before_return(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let issued = issue_test_capability(&authority)?;
        let substituted = authority.issue_capability(
            &Keypair::generate().public_key(),
            issued.scope.clone(),
            issued.ttl_seconds,
        )?;
        let remote = remote_with_trusted_key(authority.authority_public_key())?;

        let result = remote.verify_issuance_response(
            &substituted,
            &issued.subject,
            &issued.scope,
            issued.ttl_seconds,
        );

        assert!(matches!(
            result,
            Err(chio_kernel::KernelError::CapabilityIssuanceFailed(_))
        ));
        Ok(())
    }

    #[test]
    fn stale_current_key_is_refreshed_before_issuance_acceptance(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let issued = issue_test_capability(&authority)?;
        let remote = RemoteCapabilityAuthority {
            client: build_client("http://127.0.0.1:1", "test-token")?,
            cache: Mutex::new(AuthorityKeyCache {
                current: Some(authority.authority_public_key()),
                trusted: vec![authority.authority_public_key()],
                generation: Some(1),
                rotated_at: Some(1),
                refreshed_at: Instant::now() - AUTHORITY_CACHE_TTL,
            }),
            refresh_lock: Mutex::new(()),
        };

        let result = remote.verify_issuance_response(
            &issued.capability,
            &issued.subject,
            &issued.scope,
            issued.ttl_seconds,
        );

        assert!(matches!(
            result,
            Err(chio_kernel::KernelError::CapabilityIssuanceFailed(_))
        ));
        Ok(())
    }

    #[test]
    fn stale_generation_cannot_roll_back_newer_cache() -> Result<(), Box<dyn std::error::Error>> {
        let older_key = Keypair::generate().public_key();
        let newer_key = Keypair::generate().public_key();
        let remote = RemoteCapabilityAuthority {
            client: build_client("http://127.0.0.1:1", "test-token")?,
            cache: Mutex::new(AuthorityKeyCache {
                current: Some(newer_key.clone()),
                trusted: vec![older_key.clone(), newer_key.clone()],
                generation: Some(2),
                rotated_at: Some(20),
                refreshed_at: Instant::now(),
            }),
            refresh_lock: Mutex::new(()),
        };
        let stale = AuthorityKeyCache {
            current: Some(older_key.clone()),
            trusted: vec![older_key],
            generation: Some(1),
            rotated_at: Some(10),
            refreshed_at: Instant::now(),
        };

        let _refresh_guard = remote.lock_refresh();
        let result = remote.install_status_cache(stale);

        assert!(result.is_err());
        assert_eq!(remote.issuance_key_snapshot()?.0, newer_key);
        Ok(())
    }

    #[test]
    fn same_generation_equivocation_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let current_key = Keypair::generate().public_key();
        let historical_key = Keypair::generate().public_key();
        let equivocated_key = Keypair::generate().public_key();
        let remote = RemoteCapabilityAuthority {
            client: build_client("http://127.0.0.1:1", "test-token")?,
            cache: Mutex::new(AuthorityKeyCache {
                current: Some(current_key.clone()),
                trusted: vec![current_key.clone(), historical_key.clone()],
                generation: Some(2),
                rotated_at: Some(20),
                refreshed_at: Instant::now(),
            }),
            refresh_lock: Mutex::new(()),
        };
        let _refresh_guard = remote.lock_refresh();

        for equivocated in [
            AuthorityKeyCache {
                current: Some(equivocated_key.clone()),
                trusted: vec![equivocated_key, historical_key.clone()],
                generation: Some(2),
                rotated_at: Some(20),
                refreshed_at: Instant::now(),
            },
            AuthorityKeyCache {
                current: Some(current_key.clone()),
                trusted: vec![current_key.clone()],
                generation: Some(2),
                rotated_at: Some(20),
                refreshed_at: Instant::now(),
            },
            AuthorityKeyCache {
                current: Some(current_key.clone()),
                trusted: vec![current_key.clone(), historical_key.clone()],
                generation: Some(2),
                rotated_at: Some(21),
                refreshed_at: Instant::now(),
            },
        ] {
            assert!(remote.install_status_cache(equivocated).is_err());
        }

        assert_eq!(remote.issuance_key_snapshot()?.0, current_key);
        Ok(())
    }

    #[test]
    fn higher_generation_cannot_move_rotation_time_backward(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let current_key = Keypair::generate().public_key();
        let next_key = Keypair::generate().public_key();
        let remote = RemoteCapabilityAuthority {
            client: build_client("http://127.0.0.1:1", "test-token")?,
            cache: Mutex::new(AuthorityKeyCache {
                current: Some(current_key.clone()),
                trusted: vec![current_key.clone()],
                generation: Some(2),
                rotated_at: Some(20),
                refreshed_at: Instant::now(),
            }),
            refresh_lock: Mutex::new(()),
        };
        let _refresh_guard = remote.lock_refresh();

        let result = remote.install_status_cache(AuthorityKeyCache {
            current: Some(next_key.clone()),
            trusted: vec![current_key.clone(), next_key],
            generation: Some(3),
            rotated_at: Some(19),
            refreshed_at: Instant::now(),
        });

        assert!(result.is_err());
        assert_eq!(remote.issuance_key_snapshot()?.0, current_key);
        Ok(())
    }

    #[test]
    fn status_cache_deduplicates_trusted_keys() -> Result<(), Box<dyn std::error::Error>> {
        let current = Keypair::generate().public_key();
        let cache = AuthorityKeyCache::from_status(&TrustAuthorityStatus {
            configured: true,
            backend: Some("sqlite".to_string()),
            public_key: Some(current.to_hex()),
            generation: Some(1),
            rotated_at: Some(10),
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![current.to_hex(), current.to_hex()],
        })?;

        assert_eq!(cache.trusted, vec![current]);
        Ok(())
    }

    #[test]
    fn generationless_refreshes_are_serialized_in_completion_order(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let first_key = Keypair::generate().public_key();
        let second_key = Keypair::generate().public_key();
        let remote = Arc::new(RemoteCapabilityAuthority {
            client: build_client("http://127.0.0.1:1", "test-token")?,
            cache: Mutex::new(AuthorityKeyCache {
                current: Some(Keypair::generate().public_key()),
                trusted: Vec::new(),
                generation: None,
                rotated_at: None,
                refreshed_at: Instant::now(),
            }),
            refresh_lock: Mutex::new(()),
        });
        let (first_locked_tx, first_locked_rx) = std::sync::mpsc::channel();
        let (release_first_tx, release_first_rx) = std::sync::mpsc::channel();
        let first_remote = Arc::clone(&remote);
        let first_key_for_thread = first_key.clone();
        let first = std::thread::spawn(move || {
            let _refresh_guard = first_remote.lock_refresh();
            assert!(first_locked_tx.send(()).is_ok());
            assert!(release_first_rx.recv().is_ok());
            assert!(first_remote
                .install_status_cache(AuthorityKeyCache {
                    current: Some(first_key_for_thread.clone()),
                    trusted: vec![first_key_for_thread],
                    generation: None,
                    rotated_at: None,
                    refreshed_at: Instant::now(),
                })
                .is_ok());
        });
        assert!(first_locked_rx.recv().is_ok());

        let (second_started_tx, second_started_rx) = std::sync::mpsc::channel();
        let second_remote = Arc::clone(&remote);
        let second_key_for_thread = second_key.clone();
        let second = std::thread::spawn(move || {
            assert!(second_started_tx.send(()).is_ok());
            let _refresh_guard = second_remote.lock_refresh();
            assert!(second_remote
                .install_status_cache(AuthorityKeyCache {
                    current: Some(second_key_for_thread.clone()),
                    trusted: vec![second_key_for_thread],
                    generation: None,
                    rotated_at: None,
                    refreshed_at: Instant::now(),
                })
                .is_ok());
        });
        assert!(second_started_rx.recv().is_ok());
        assert!(release_first_tx.send(()).is_ok());
        assert!(first.join().is_ok());
        assert!(second.join().is_ok());

        assert_eq!(remote.issuance_key_snapshot()?.0, second_key);
        Ok(())
    }
}
