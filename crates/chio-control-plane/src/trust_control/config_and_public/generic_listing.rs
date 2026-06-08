use super::*;

fn public_generic_listing_boundary() -> GenericListingBoundary {
    GenericListingBoundary::default()
}

pub(crate) fn public_generic_registry_publisher(
    config: &TrustServiceConfig,
) -> Result<GenericRegistryPublisher, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "generic registry listings require --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    let registry_url = normalize_namespace(advertise_url);
    if registry_url.is_empty() {
        return Err(CliError::cli_other_error(
            "generic registry listings require a non-empty advertise_url".to_string(),
        ));
    }
    let publisher = GenericRegistryPublisher {
        role: GenericRegistryPublisherRole::Origin,
        operator_id: registry_url.clone(),
        operator_name: None,
        registry_url,
        upstream_registry_urls: Vec::new(),
    };
    publisher.validate().map_err(CliError::cli_other_error)?;
    Ok(publisher)
}

fn public_generic_listing_freshness_window(generated_at: u64) -> GenericListingFreshnessWindow {
    GenericListingFreshnessWindow {
        max_age_secs: DEFAULT_GENERIC_LISTING_REPORT_MAX_AGE_SECS,
        valid_until: generated_at.saturating_add(DEFAULT_GENERIC_LISTING_REPORT_MAX_AGE_SECS),
    }
}

fn public_generic_listing_search_policy() -> GenericListingSearchPolicy {
    GenericListingSearchPolicy::default()
}

fn configured_generic_namespace_ownership(
    config: &TrustServiceConfig,
    signer_public_key: PublicKey,
    registered_at: u64,
) -> Result<GenericNamespaceOwnership, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "generic registry listings require --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    let namespace = normalize_namespace(advertise_url);
    if namespace.is_empty() {
        return Err(CliError::cli_other_error(
            "generic registry listings require a non-empty advertise_url".to_string(),
        ));
    }
    let ownership = GenericNamespaceOwnership {
        namespace: namespace.clone(),
        owner_id: namespace.clone(),
        owner_name: None,
        registry_url: namespace,
        signer_public_key,
        registered_at,
        transferred_from_owner_id: None,
    };
    ownership.validate().map_err(CliError::cli_other_error)?;
    Ok(ownership)
}

pub(crate) fn build_signed_generic_namespace(
    config: &TrustServiceConfig,
) -> Result<SignedGenericNamespace, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let registered_at = now_unix_secs()?;
    let ownership =
        configured_generic_namespace_ownership(config, signer_keypair.public_key(), registered_at)?;
    let namespace_id_input = canonical_json_bytes(&(
        GENERIC_NAMESPACE_ARTIFACT_SCHEMA,
        &ownership.namespace,
        &ownership.owner_id,
        &ownership.registry_url,
        &ownership.signer_public_key,
    ))
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let artifact = GenericNamespaceArtifact {
        schema: GENERIC_NAMESPACE_ARTIFACT_SCHEMA.to_string(),
        namespace_id: format!("ns-{}", sha256_hex(&namespace_id_input)),
        lifecycle_state: GenericNamespaceLifecycleState::Active,
        ownership,
        boundary: public_generic_listing_boundary(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    SignedGenericNamespace::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign generic namespace artifact: {error}"
        ))
    })
}

fn generic_listing_id(
    namespace: &str,
    actor_kind: GenericListingActorKind,
    actor_id: &str,
    source_artifact_id: &str,
) -> Result<String, CliError> {
    let listing_id_input = canonical_json_bytes(&(
        GENERIC_LISTING_ARTIFACT_SCHEMA,
        namespace,
        actor_kind,
        actor_id,
        source_artifact_id,
    ))
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(format!("gl-{}", sha256_hex(&listing_id_input)))
}

fn generic_listing_status_from_certification(
    status: crate::certify::CertificationRegistryState,
) -> GenericListingStatus {
    match status {
        crate::certify::CertificationRegistryState::Active => GenericListingStatus::Active,
        crate::certify::CertificationRegistryState::Superseded => GenericListingStatus::Superseded,
        crate::certify::CertificationRegistryState::Revoked => GenericListingStatus::Revoked,
    }
}

fn generic_listing_status_from_provider(
    status: chio_kernel::LiabilityProviderLifecycleState,
) -> GenericListingStatus {
    match status {
        chio_kernel::LiabilityProviderLifecycleState::Active => GenericListingStatus::Active,
        chio_kernel::LiabilityProviderLifecycleState::Suspended => GenericListingStatus::Suspended,
        chio_kernel::LiabilityProviderLifecycleState::Superseded => {
            GenericListingStatus::Superseded
        }
        chio_kernel::LiabilityProviderLifecycleState::Retired => GenericListingStatus::Retired,
    }
}

fn build_signed_generic_listing_from_certification_entry(
    entry: &crate::certify::CertificationRegistryEntry,
    metadata: &CertificationPublicMetadata,
    ownership: &GenericNamespaceOwnership,
    signer_keypair: &Keypair,
) -> Result<SignedGenericListing, CliError> {
    let listing_id = generic_listing_id(
        &ownership.namespace,
        GenericListingActorKind::ToolServer,
        &entry.tool_server_id,
        &entry.artifact_id,
    )?;
    let artifact = GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id,
        namespace: ownership.namespace.clone(),
        published_at: entry.published_at,
        expires_at: Some(metadata.expires_at),
        status: generic_listing_status_from_certification(entry.status),
        namespace_ownership: ownership.clone(),
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::ToolServer,
            actor_id: entry.tool_server_id.clone(),
            display_name: entry.tool_server_name.clone(),
            metadata_url: Some(metadata.public_search_path.clone()),
            resolution_url: Some(
                metadata
                    .public_resolve_path_template
                    .replace("{tool_server_id}", &entry.tool_server_id),
            ),
            homepage_url: None,
        },
        compatibility: GenericListingCompatibilityReference {
            source_schema: "chio.certify.check.v1".to_string(),
            source_artifact_id: entry.artifact_id.clone(),
            source_artifact_sha256: entry.artifact_sha256.clone(),
        },
        boundary: public_generic_listing_boundary(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    SignedGenericListing::sign(artifact, signer_keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign generic listing projection for certification `{}`: {error}",
            entry.artifact_id
        ))
    })
}

fn build_signed_generic_listing_from_public_issuer(
    document: &SignedPublicIssuerDiscovery,
    ownership: &GenericNamespaceOwnership,
    signer_keypair: &Keypair,
) -> Result<SignedGenericListing, CliError> {
    let source_sha256 = sha256_hex(
        &canonical_json_bytes(document)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    );
    let listing_id = generic_listing_id(
        &ownership.namespace,
        GenericListingActorKind::CredentialIssuer,
        &document.body.issuer,
        &document.body.discovery_id,
    )?;
    let artifact = GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id,
        namespace: ownership.namespace.clone(),
        published_at: document.body.published_at,
        expires_at: Some(document.body.expires_at),
        status: GenericListingStatus::Active,
        namespace_ownership: ownership.clone(),
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::CredentialIssuer,
            actor_id: document.body.issuer.clone(),
            display_name: None,
            metadata_url: Some(document.body.metadata_url.clone()),
            resolution_url: document
                .body
                .passport_status_distribution
                .resolve_urls
                .first()
                .cloned(),
            homepage_url: Some(document.body.issuer.clone()),
        },
        compatibility: GenericListingCompatibilityReference {
            source_schema: document.body.schema.clone(),
            source_artifact_id: document.body.discovery_id.clone(),
            source_artifact_sha256: source_sha256,
        },
        boundary: public_generic_listing_boundary(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    SignedGenericListing::sign(artifact, signer_keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign generic listing projection for issuer `{}`: {error}",
            document.body.discovery_id
        ))
    })
}

fn build_signed_generic_listing_from_public_verifier(
    document: &SignedPublicVerifierDiscovery,
    ownership: &GenericNamespaceOwnership,
    signer_keypair: &Keypair,
) -> Result<SignedGenericListing, CliError> {
    let source_sha256 = sha256_hex(
        &canonical_json_bytes(document)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    );
    let listing_id = generic_listing_id(
        &ownership.namespace,
        GenericListingActorKind::CredentialVerifier,
        &document.body.verifier,
        &document.body.discovery_id,
    )?;
    let artifact = GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id,
        namespace: ownership.namespace.clone(),
        published_at: document.body.published_at,
        expires_at: Some(document.body.expires_at),
        status: GenericListingStatus::Active,
        namespace_ownership: ownership.clone(),
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::CredentialVerifier,
            actor_id: document.body.verifier.clone(),
            display_name: None,
            metadata_url: Some(document.body.metadata_url.clone()),
            resolution_url: None,
            homepage_url: Some(document.body.verifier.clone()),
        },
        compatibility: GenericListingCompatibilityReference {
            source_schema: document.body.schema.clone(),
            source_artifact_id: document.body.discovery_id.clone(),
            source_artifact_sha256: source_sha256,
        },
        boundary: public_generic_listing_boundary(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    SignedGenericListing::sign(artifact, signer_keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign generic listing projection for verifier `{}`: {error}",
            document.body.discovery_id
        ))
    })
}

fn build_signed_generic_listing_from_liability_provider(
    row: &chio_kernel::LiabilityProviderRow,
    ownership: &GenericNamespaceOwnership,
    signer_keypair: &Keypair,
) -> Result<SignedGenericListing, CliError> {
    let source_sha256 = sha256_hex(
        &canonical_json_bytes(&row.provider)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    );
    let provider = &row.provider.body;
    let listing_id = generic_listing_id(
        &ownership.namespace,
        GenericListingActorKind::LiabilityProvider,
        &provider.report.provider_id,
        &provider.provider_record_id,
    )?;
    let artifact = GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id,
        namespace: ownership.namespace.clone(),
        published_at: provider.issued_at,
        expires_at: None,
        status: generic_listing_status_from_provider(row.lifecycle_state),
        namespace_ownership: ownership.clone(),
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::LiabilityProvider,
            actor_id: provider.report.provider_id.clone(),
            display_name: Some(provider.report.display_name.clone()),
            metadata_url: None,
            resolution_url: None,
            homepage_url: provider.report.provider_url.clone(),
        },
        compatibility: GenericListingCompatibilityReference {
            source_schema: provider.schema.clone(),
            source_artifact_id: provider.provider_record_id.clone(),
            source_artifact_sha256: source_sha256,
        },
        boundary: public_generic_listing_boundary(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    SignedGenericListing::sign(artifact, signer_keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign generic listing projection for provider `{}`: {error}",
            provider.provider_record_id
        ))
    })
}

pub(crate) fn build_public_generic_listing_report(
    config: &TrustServiceConfig,
    query: &GenericListingQuery,
) -> Result<GenericListingReport, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let generated_at = now_unix_secs()?;
    let namespace =
        configured_generic_namespace_ownership(config, signer_keypair.public_key(), generated_at)?;
    let publisher = public_generic_registry_publisher(config)?;
    let normalized_query = query.normalized();

    let mut listings = Vec::<SignedGenericListing>::new();
    if config.certification_registry_file.is_some() {
        let metadata = configured_public_certification_metadata(config)?;
        let (_, registry) = load_certification_registry_for_admin(config)?;
        let public = registry.search_public(
            &metadata.publisher,
            metadata.expires_at,
            &crate::certify::CertificationPublicSearchQuery::default(),
        );
        for result in public.results {
            listings.push(build_signed_generic_listing_from_certification_entry(
                &result.entry,
                &metadata,
                &namespace,
                &signer_keypair,
            )?);
        }
    }

    listings.push(build_signed_generic_listing_from_public_issuer(
        &build_public_issuer_discovery(config)?,
        &namespace,
        &signer_keypair,
    )?);
    listings.push(build_signed_generic_listing_from_public_verifier(
        &build_public_verifier_discovery(config)?,
        &namespace,
        &signer_keypair,
    )?);

    if let Some(receipt_db_path) = config.receipt_db_path.as_deref() {
        let provider_report =
            list_liability_providers(receipt_db_path, &LiabilityProviderListQuery::default())?;
        for row in &provider_report.providers {
            listings.push(build_signed_generic_listing_from_liability_provider(
                row,
                &namespace,
                &signer_keypair,
            )?);
        }
    }

    ensure_generic_listing_namespace_consistency(listings.iter().map(|listing| &listing.body))
        .map_err(CliError::cli_other_error)?;

    listings.sort_by(|left, right| {
        left.body
            .subject
            .actor_kind
            .cmp(&right.body.subject.actor_kind)
            .then(left.body.subject.actor_id.cmp(&right.body.subject.actor_id))
            .then(right.body.published_at.cmp(&left.body.published_at))
            .then(left.body.listing_id.cmp(&right.body.listing_id))
    });

    let filtered = listings
        .into_iter()
        .filter(|listing| {
            normalized_query
                .namespace
                .as_deref()
                .is_none_or(|query_namespace| {
                    normalize_namespace(&listing.body.namespace) == query_namespace
                })
        })
        .filter(|listing| {
            normalized_query
                .actor_kind
                .is_none_or(|actor_kind| listing.body.subject.actor_kind == actor_kind)
        })
        .filter(|listing| {
            normalized_query
                .actor_id
                .as_deref()
                .is_none_or(|actor_id| listing.body.subject.actor_id == actor_id)
        })
        .filter(|listing| {
            normalized_query
                .status
                .is_none_or(|status| listing.body.status == status)
        })
        .collect::<Vec<_>>();

    let summary = GenericListingSummary {
        matching_listings: filtered.len() as u64,
        returned_listings: filtered.len().min(normalized_query.limit_or_default()) as u64,
        active_listings: filtered
            .iter()
            .filter(|listing| listing.body.status == GenericListingStatus::Active)
            .count() as u64,
        suspended_listings: filtered
            .iter()
            .filter(|listing| listing.body.status == GenericListingStatus::Suspended)
            .count() as u64,
        superseded_listings: filtered
            .iter()
            .filter(|listing| listing.body.status == GenericListingStatus::Superseded)
            .count() as u64,
        revoked_listings: filtered
            .iter()
            .filter(|listing| listing.body.status == GenericListingStatus::Revoked)
            .count() as u64,
        retired_listings: filtered
            .iter()
            .filter(|listing| listing.body.status == GenericListingStatus::Retired)
            .count() as u64,
    };

    Ok(GenericListingReport {
        schema: GENERIC_LISTING_REPORT_SCHEMA.to_string(),
        generated_at,
        query: normalized_query.clone(),
        namespace,
        publisher,
        freshness: public_generic_listing_freshness_window(generated_at),
        search_policy: public_generic_listing_search_policy(),
        summary,
        listings: filtered
            .into_iter()
            .take(normalized_query.limit_or_default())
            .collect(),
    })
}
