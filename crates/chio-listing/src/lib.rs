//! Generic listing and trust-activation contracts for the Chio protocol.
//!
//! This crate is used to publish, discover, compare, and activate marketplace
//! listings. It defines the signed `Listing` artifact, listing search and
//! comparison, SLA and pricing-hint shapes, and the trust-activation flow that
//! turns a discovered listing into a locally admissible one. Listings are
//! signed by their namespace owner and verification is pure. The governance
//! and open-market crates build on these types.
//!
//! # Modules
//!
//! - [`discovery`] -- listing search, comparison, and admissibility
//!   resolution.

#![forbid(unsafe_code)]

pub use chio_core_types::capability::MonetaryAmount;
pub use chio_core_types::{canonical_json_bytes, crypto, receipt};

pub mod discovery;
pub use discovery::{
    compare, provider_signing_key, resolve_admissible_listing, search, Listing, ListingComparison,
    ListingComparisonRow, ListingPricingHint, ListingQuery, ListingSearchResponse, ListingSla,
    SignedListingPricingHint, LISTING_COMPARISON_SCHEMA, LISTING_PRICING_HINT_SCHEMA,
    LISTING_SEARCH_SCHEMA, MAX_MARKETPLACE_SEARCH_LIMIT,
};

mod listing;
mod search;
mod trust_activation;
mod util;

pub use listing::*;
pub use search::*;
pub use trust_activation::*;
pub use util::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn require_ok<T, E>(result: Result<T, E>, context: &'static str) -> T
    where
        E: std::fmt::Debug,
    {
        result.unwrap_or_else(|error| panic!("{context}: {error:?}"))
    }

    fn require_err<T, E>(result: Result<T, E>, context: &'static str) -> E
    where
        T: std::fmt::Debug,
    {
        match result {
            Ok(value) => panic!("{context} unexpectedly succeeded: {value:?}"),
            Err(error) => error,
        }
    }

    fn sample_namespace(owner_id: &str, keypair: &Keypair) -> GenericNamespaceOwnership {
        GenericNamespaceOwnership {
            namespace: "https://registry.chio.example".to_string(),
            owner_id: owner_id.to_string(),
            owner_name: Some("Chio Registry".to_string()),
            registry_url: "https://registry.chio.example".to_string(),
            signer_public_key: keypair.public_key(),
            registered_at: 1,
            transferred_from_owner_id: None,
        }
    }

    fn sample_listing(
        owner_id: &str,
        keypair: &Keypair,
        artifact_id: &str,
        source_sha256: &str,
    ) -> GenericListingArtifact {
        GenericListingArtifact {
            schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
            listing_id: format!("listing-{artifact_id}"),
            namespace: "https://registry.chio.example".to_string(),
            published_at: 10,
            expires_at: Some(20),
            status: GenericListingStatus::Active,
            namespace_ownership: sample_namespace(owner_id, keypair),
            subject: GenericListingSubject {
                actor_kind: GenericListingActorKind::ToolServer,
                actor_id: "demo-server".to_string(),
                display_name: Some("Demo Server".to_string()),
                metadata_url: Some("https://registry.chio.example/metadata".to_string()),
                resolution_url: Some(
                    "https://registry.chio.example/v1/public/certifications/resolve/demo-server"
                        .to_string(),
                ),
                homepage_url: Some("https://demo.chio.example".to_string()),
            },
            compatibility: GenericListingCompatibilityReference {
                source_schema: "chio.certify.check.v1".to_string(),
                source_artifact_id: artifact_id.to_string(),
                source_artifact_sha256: source_sha256.to_string(),
            },
            boundary: GenericListingBoundary::default(),
        }
    }

    fn signed_sample_listing(
        owner_id: &str,
        signing_keypair: &Keypair,
        artifact_id: &str,
        source_sha256: &str,
    ) -> SignedGenericListing {
        require_ok(
            SignedGenericListing::sign(
                sample_listing(owner_id, signing_keypair, artifact_id, source_sha256),
                signing_keypair,
            ),
            "sign sample listing",
        )
    }

    fn sample_publisher(
        role: GenericRegistryPublisherRole,
        operator_id: &str,
    ) -> GenericRegistryPublisher {
        GenericRegistryPublisher {
            role,
            operator_id: operator_id.to_string(),
            operator_name: Some(format!("Operator {operator_id}")),
            registry_url: format!("https://{operator_id}.chio.example"),
            upstream_registry_urls: Vec::new(),
        }
    }

    fn sample_report(
        role: GenericRegistryPublisherRole,
        operator_id: &str,
        generated_at: u64,
        max_age_secs: u64,
        listings: Vec<SignedGenericListing>,
    ) -> GenericListingReport {
        let keypair = Keypair::generate();
        GenericListingReport {
            schema: GENERIC_LISTING_REPORT_SCHEMA.to_string(),
            generated_at,
            query: GenericListingQuery::default(),
            namespace: sample_namespace("https://registry.chio.example", &keypair),
            publisher: sample_publisher(role, operator_id),
            freshness: GenericListingFreshnessWindow {
                max_age_secs,
                valid_until: generated_at + max_age_secs,
            },
            search_policy: GenericListingSearchPolicy::default(),
            summary: GenericListingSummary {
                matching_listings: listings.len() as u64,
                returned_listings: listings.len() as u64,
                active_listings: listings.len() as u64,
                suspended_listings: 0,
                superseded_listings: 0,
                revoked_listings: 0,
                retired_listings: 0,
            },
            listings,
        }
    }

    fn sample_review_context(
        role: GenericRegistryPublisherRole,
        operator_id: &str,
        freshness_state: GenericListingFreshnessState,
    ) -> GenericTrustActivationReviewContext {
        GenericTrustActivationReviewContext {
            publisher: sample_publisher(role, operator_id),
            freshness: GenericListingReplicaFreshness {
                state: freshness_state,
                age_secs: 5,
                max_age_secs: 300,
                valid_until: 400,
                generated_at: 100,
            },
        }
    }

    fn sample_activation_issue_request(
        listing: SignedGenericListing,
        admission_class: GenericTrustAdmissionClass,
        disposition: GenericTrustActivationDisposition,
    ) -> GenericTrustActivationIssueRequest {
        GenericTrustActivationIssueRequest {
            listing,
            admission_class,
            disposition,
            eligibility: GenericTrustActivationEligibility {
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                allowed_publisher_roles: vec![GenericRegistryPublisherRole::Origin],
                allowed_statuses: vec![GenericListingStatus::Active],
                require_fresh_listing: true,
                require_bond_backing: false,
                required_listing_operator_ids: Vec::new(),
                policy_reference: Some("policy/open-registry/default".to_string()),
            },
            review_context: sample_review_context(
                GenericRegistryPublisherRole::Origin,
                "origin-a",
                GenericListingFreshnessState::Fresh,
            ),
            requested_by: "ops@chio.example".to_string(),
            reviewed_by: Some("reviewer@chio.example".to_string()),
            requested_at: Some(120),
            reviewed_at: Some(130),
            expires_at: Some(200),
            note: Some("reviewed under default local activation policy".to_string()),
        }
    }

    fn issue_request_for(
        listing: SignedGenericListing,
        admission_class: GenericTrustAdmissionClass,
        disposition: GenericTrustActivationDisposition,
    ) -> GenericTrustActivationIssueRequest {
        GenericTrustActivationIssueRequest {
            reviewed_by: match disposition {
                GenericTrustActivationDisposition::PendingReview => None,
                GenericTrustActivationDisposition::Approved
                | GenericTrustActivationDisposition::Denied => {
                    Some("reviewer@chio.example".to_string())
                }
            },
            reviewed_at: match disposition {
                GenericTrustActivationDisposition::PendingReview => None,
                GenericTrustActivationDisposition::Approved
                | GenericTrustActivationDisposition::Denied => Some(130),
            },
            ..sample_activation_issue_request(listing, admission_class, disposition)
        }
    }

    fn signed_activation(
        listing: SignedGenericListing,
        admission_class: GenericTrustAdmissionClass,
        disposition: GenericTrustActivationDisposition,
    ) -> SignedGenericTrustActivation {
        let authority_keypair = sample_authority_keypair();
        let artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(listing, admission_class, disposition),
                130,
            ),
            "build activation artifact",
        );
        require_ok(
            SignedGenericTrustActivation::sign(artifact, &authority_keypair),
            "sign activation",
        )
    }

    fn sample_authority_keypair() -> Keypair {
        Keypair::from_seed(&[42_u8; 32])
    }

    fn evaluation_request(
        listing: SignedGenericListing,
        activation: Option<SignedGenericTrustActivation>,
        freshness_state: GenericListingFreshnessState,
        publisher_role: GenericRegistryPublisherRole,
        publisher_operator_id: &str,
        evaluated_at: u64,
    ) -> GenericTrustActivationEvaluationRequest {
        GenericTrustActivationEvaluationRequest {
            listing,
            current_publisher: sample_publisher(publisher_role, publisher_operator_id),
            current_freshness: GenericListingReplicaFreshness {
                state: freshness_state,
                age_secs: 5,
                max_age_secs: 300,
                valid_until: 400,
                generated_at: 100,
            },
            activation,
            evaluated_at: Some(evaluated_at),
        }
    }

    #[test]
    fn generic_listing_boundary_rejects_automatic_trust_admission() {
        let boundary = GenericListingBoundary {
            visibility_only: true,
            explicit_trust_activation_required: true,
            automatic_trust_admission: true,
        };
        assert!(
            require_err(boundary.validate(), "automatic trust admission rejected")
                .contains("must not auto-admit trust")
        );
    }

    #[test]
    fn generic_listing_boundary_rejects_missing_explicit_activation_gate() {
        let boundary = GenericListingBoundary {
            visibility_only: true,
            explicit_trust_activation_required: false,
            automatic_trust_admission: false,
        };
        assert!(require_err(
            boundary.validate(),
            "missing explicit trust activation gate rejected",
        )
        .contains("must require explicit trust activation"));
    }

    #[test]
    fn generic_namespace_artifact_rejects_wrong_schema() {
        let keypair = Keypair::generate();
        let artifact = GenericNamespaceArtifact {
            schema: "chio.registry.namespace.v0".to_string(),
            namespace_id: "registry.chio.example".to_string(),
            lifecycle_state: GenericNamespaceLifecycleState::Active,
            ownership: sample_namespace("operator-a", &keypair),
            boundary: GenericListingBoundary::default(),
        };

        assert!(
            require_err(artifact.validate(), "wrong namespace schema rejected")
                .contains("unsupported generic namespace schema")
        );
    }

    #[test]
    fn generic_listing_rejects_namespace_mismatch() {
        let keypair = Keypair::generate();
        let mut listing = sample_listing("operator-a", &keypair, "artifact-1", "deadbeef");
        listing.namespace = "https://other.chio.example".to_string();
        assert!(
            require_err(listing.validate(), "namespace mismatch rejected")
                .contains("does not match namespace ownership")
        );
    }

    #[test]
    fn generic_listing_rejects_non_increasing_expiry() {
        let keypair = Keypair::generate();
        let mut listing = sample_listing("operator-a", &keypair, "artifact-1", "deadbeef");
        listing.expires_at = Some(listing.published_at);

        assert!(
            require_err(listing.validate(), "non-increasing expiry rejected")
                .contains("expiry must be greater")
        );
    }

    #[test]
    fn generic_listing_query_normalizes_namespace_actor_and_limit() {
        let normalized = GenericListingQuery {
            namespace: Some(" https://registry.chio.example/ ".to_string()),
            actor_kind: Some(GenericListingActorKind::ToolServer),
            actor_id: Some("   ".to_string()),
            status: Some(GenericListingStatus::Active),
            limit: Some(999),
        }
        .normalized();

        assert_eq!(
            normalized.namespace.as_deref(),
            Some("https://registry.chio.example")
        );
        assert_eq!(normalized.actor_id, None);
        assert_eq!(normalized.limit, Some(MAX_GENERIC_LISTING_LIMIT));
    }

    #[test]
    fn generic_listing_freshness_window_rejects_invalid_bounds_and_assesses_stale() {
        assert!(require_err(
            GenericListingFreshnessWindow {
                max_age_secs: 0,
                valid_until: 200,
            }
            .validate(100),
            "zero max age rejected",
        )
        .contains("greater than zero"));

        assert!(require_err(
            GenericListingFreshnessWindow {
                max_age_secs: 30,
                valid_until: 100,
            }
            .validate(100),
            "non-increasing valid_until rejected",
        )
        .contains("greater than generated_at"));

        let freshness = GenericListingFreshnessWindow {
            max_age_secs: 30,
            valid_until: 150,
        }
        .assess(100, 200);
        assert_eq!(freshness.state, GenericListingFreshnessState::Stale);
        assert_eq!(freshness.age_secs, 100);
    }

    #[test]
    fn generic_listing_search_policy_rejects_non_reproducible_modes() {
        let policy = GenericListingSearchPolicy {
            reproducible_ordering: false,
            ..GenericListingSearchPolicy::default()
        };
        assert!(
            require_err(policy.validate(), "non-reproducible policy rejected")
                .contains("must remain reproducible")
        );

        let policy = GenericListingSearchPolicy {
            visibility_only: false,
            ..GenericListingSearchPolicy::default()
        };
        assert!(
            require_err(policy.validate(), "non-visibility-only policy rejected")
                .contains("must remain visibility-only")
        );

        let policy = GenericListingSearchPolicy {
            explicit_trust_activation_required: false,
            ..GenericListingSearchPolicy::default()
        };
        assert!(require_err(
            policy.validate(),
            "missing explicit trust activation rejected",
        )
        .contains("must require explicit trust activation"));
    }

    #[test]
    fn generic_listing_replica_freshness_rejects_invalid_window() {
        let freshness = GenericListingReplicaFreshness {
            state: GenericListingFreshnessState::Fresh,
            age_secs: 5,
            max_age_secs: 0,
            valid_until: 100,
            generated_at: 100,
        };
        assert!(
            require_err(freshness.validate(), "invalid freshness rejected")
                .contains("greater than zero")
        );
    }

    #[test]
    fn generic_trust_activation_eligibility_rejects_invalid_role_and_bond_rules() {
        assert!(require_err(
            GenericTrustActivationEligibility {
                required_listing_operator_ids: vec![],
                ..GenericTrustActivationEligibility {
                    allowed_actor_kinds: vec![],
                    allowed_publisher_roles: vec![],
                    allowed_statuses: vec![],
                    require_fresh_listing: true,
                    require_bond_backing: false,
                    required_listing_operator_ids: vec![],
                    policy_reference: None,
                }
            }
            .validate(GenericTrustAdmissionClass::RoleGated),
            "role-gated operators required",
        )
        .contains("requires required_listing_operator_ids"));

        assert!(require_err(
            GenericTrustActivationEligibility {
                require_bond_backing: false,
                ..GenericTrustActivationEligibility {
                    allowed_actor_kinds: vec![],
                    allowed_publisher_roles: vec![],
                    allowed_statuses: vec![],
                    require_fresh_listing: true,
                    require_bond_backing: false,
                    required_listing_operator_ids: vec![],
                    policy_reference: None,
                }
            }
            .validate(GenericTrustAdmissionClass::BondBacked),
            "bond-backed admission must require bonds",
        )
        .contains("must require bond backing"));

        assert!(require_err(
            GenericTrustActivationEligibility {
                require_bond_backing: true,
                ..GenericTrustActivationEligibility {
                    allowed_actor_kinds: vec![],
                    allowed_publisher_roles: vec![],
                    allowed_statuses: vec![],
                    require_fresh_listing: true,
                    require_bond_backing: true,
                    required_listing_operator_ids: vec![],
                    policy_reference: None,
                }
            }
            .validate(GenericTrustAdmissionClass::Reviewable),
            "non-bond admission cannot require bonds",
        )
        .contains("only valid for bond_backed"));
    }

    #[test]
    fn generic_trust_activation_artifact_validate_rejects_review_field_misconfigurations() {
        let keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &keypair,
            "artifact-1",
            "deadbeef",
        );
        let mut artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        artifact.reviewed_at = Some(100);
        assert!(require_err(
            artifact.validate(),
            "reviewed_at before requested_at rejected",
        )
        .contains("reviewed_at must be greater"));

        let mut artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        artifact.expires_at = Some(120);
        assert!(
            require_err(artifact.validate(), "expiry before requested_at rejected")
                .contains("expires_at must be greater")
        );

        let mut artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        artifact.disposition = GenericTrustActivationDisposition::PendingReview;
        artifact.reviewed_by = Some("reviewer@chio.example".to_string());
        artifact.reviewed_at = Some(130);
        assert!(require_err(
            artifact.validate(),
            "pending review cannot carry review completion",
        )
        .contains("must not carry review completion fields"));

        let mut artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing,
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        artifact.reviewed_by = None;
        assert!(
            require_err(artifact.validate(), "approved activation requires reviewer",)
                .contains("requires reviewed_at and reviewed_by")
        );
    }

    #[test]
    fn generic_trust_activation_issue_request_validate_rejects_stale_approved_context() {
        let signing_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let mut request = issue_request_for(
            listing,
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );
        request.review_context.freshness.state = GenericListingFreshnessState::Stale;

        assert!(require_err(
            request.validate(),
            "approved activation requires fresh context",
        )
        .contains("requires fresh listing review context"));
    }

    #[test]
    fn generic_trust_activation_issue_request_rejects_listing_signer_mismatch() {
        let namespace_keypair = Keypair::generate();
        let attacker_keypair = Keypair::generate();
        let listing = require_ok(
            SignedGenericListing::sign(
                sample_listing(
                    "https://registry.chio.example",
                    &namespace_keypair,
                    "artifact-1",
                    "deadbeef",
                ),
                &attacker_keypair,
            ),
            "sign listing with mismatched signer",
        );
        let request = issue_request_for(
            listing,
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );

        assert!(
            require_err(request.validate(), "listing signer mismatch rejected")
                .contains("namespace ownership signer")
        );
    }

    #[test]
    fn build_generic_trust_activation_artifact_defaults_reviewed_at_for_approved() {
        let signing_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let mut request = issue_request_for(
            listing,
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );
        request.reviewed_at = None;
        let artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &request,
                130,
            ),
            "build activation",
        );

        assert_eq!(artifact.reviewed_at, Some(130));
    }

    #[test]
    fn generic_listing_namespace_consistency_rejects_conflicting_owners() {
        let keypair_a = Keypair::generate();
        let keypair_b = Keypair::generate();
        let listing_a = sample_listing("operator-a", &keypair_a, "artifact-1", "deadbeef");
        let listing_b = sample_listing("operator-b", &keypair_b, "artifact-1", "deadbeef");
        assert!(require_err(
            ensure_generic_listing_namespace_consistency([&listing_a, &listing_b]),
            "conflicting namespace ownership rejected",
        )
        .contains("conflicting ownership"));
    }

    #[test]
    fn generic_listing_search_prefers_fresh_origin_and_collapses_identical_replicas() {
        let signing_keypair = Keypair::generate();
        let origin = sample_report(
            GenericRegistryPublisherRole::Origin,
            "origin-a",
            100,
            300,
            vec![signed_sample_listing(
                "https://registry.chio.example",
                &signing_keypair,
                "artifact-1",
                "deadbeef",
            )],
        );
        let mirror = sample_report(
            GenericRegistryPublisherRole::Mirror,
            "mirror-a",
            105,
            300,
            vec![signed_sample_listing(
                "https://registry.chio.example",
                &signing_keypair,
                "artifact-1",
                "deadbeef",
            )],
        );
        let indexer = sample_report(
            GenericRegistryPublisherRole::Indexer,
            "indexer-a",
            106,
            300,
            vec![signed_sample_listing(
                "https://registry.chio.example",
                &signing_keypair,
                "artifact-1",
                "deadbeef",
            )],
        );

        let response = aggregate_generic_listing_reports(
            &[origin, mirror, indexer],
            &GenericListingQuery::default(),
            120,
        );
        assert_eq!(response.peer_count, 3);
        assert_eq!(response.reachable_count, 3);
        assert_eq!(response.result_count, 1);
        assert_eq!(response.divergence_count, 0);
        assert_eq!(
            response.results[0].publisher.role,
            GenericRegistryPublisherRole::Origin
        );
        assert_eq!(response.results[0].replica_operator_ids.len(), 2);
    }

    #[test]
    fn generic_listing_search_rejects_stale_reports() {
        let signing_keypair = Keypair::generate();
        let stale = sample_report(
            GenericRegistryPublisherRole::Mirror,
            "mirror-a",
            100,
            10,
            vec![signed_sample_listing(
                "https://registry.chio.example",
                &signing_keypair,
                "artifact-1",
                "deadbeef",
            )],
        );

        let response =
            aggregate_generic_listing_reports(&[stale], &GenericListingQuery::default(), 200);
        assert_eq!(response.peer_count, 1);
        assert_eq!(response.reachable_count, 0);
        assert_eq!(response.stale_peer_count, 1);
        assert_eq!(response.result_count, 0);
        assert_eq!(response.errors.len(), 1);
        assert!(response.errors[0].error.contains("stale"));
    }

    #[test]
    fn generic_listing_search_excludes_divergent_results() {
        let signing_keypair = Keypair::generate();
        let origin = sample_report(
            GenericRegistryPublisherRole::Origin,
            "origin-a",
            100,
            300,
            vec![signed_sample_listing(
                "https://registry.chio.example",
                &signing_keypair,
                "artifact-1",
                "deadbeef",
            )],
        );
        let mirror = sample_report(
            GenericRegistryPublisherRole::Mirror,
            "mirror-a",
            101,
            300,
            vec![signed_sample_listing(
                "https://registry.chio.example",
                &signing_keypair,
                "artifact-1",
                "cafebabe",
            )],
        );

        let response = aggregate_generic_listing_reports(
            &[origin, mirror],
            &GenericListingQuery::default(),
            120,
        );
        assert_eq!(response.result_count, 0);
        assert_eq!(response.divergence_count, 1);
        assert_eq!(response.divergences[0].publisher_operator_ids.len(), 2);
    }

    #[test]
    fn generic_listing_search_rejects_reports_with_invalid_listing_signatures() {
        let signing_keypair = Keypair::generate();
        let mut report = sample_report(
            GenericRegistryPublisherRole::Mirror,
            "mirror-a",
            100,
            300,
            vec![signed_sample_listing(
                "https://registry.chio.example",
                &signing_keypair,
                "artifact-1",
                "deadbeef",
            )],
        );
        report.listings[0].body.status = GenericListingStatus::Revoked;

        let response =
            aggregate_generic_listing_reports(&[report], &GenericListingQuery::default(), 120);
        assert_eq!(response.peer_count, 1);
        assert_eq!(response.reachable_count, 0);
        assert_eq!(response.result_count, 0);
        assert_eq!(response.errors.len(), 1);
        assert!(response.errors[0].error.contains("signature is invalid"));
    }

    #[test]
    fn generic_trust_activation_requires_explicit_artifact() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = sample_authority_keypair();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let report = require_ok(
            evaluate_generic_trust_activation(
                &GenericTrustActivationEvaluationRequest {
                    listing,
                    current_publisher: sample_publisher(
                        GenericRegistryPublisherRole::Origin,
                        "origin-a",
                    ),
                    current_freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Fresh,
                        age_secs: 5,
                        max_age_secs: 300,
                        valid_until: 400,
                        generated_at: 100,
                    },
                    activation: None,
                    evaluated_at: Some(150),
                },
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate missing activation",
        );
        assert!(!report.admitted);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::MissingActivation
        );
    }

    #[test]
    fn generic_trust_activation_admits_reviewable_activation() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let issue_request = sample_activation_issue_request(
            listing.clone(),
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );
        let activation_artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request,
                130,
            ),
            "build activation artifact",
        );
        let activation = require_ok(
            SignedGenericTrustActivation::sign(activation_artifact, &authority_keypair),
            "sign activation",
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &GenericTrustActivationEvaluationRequest {
                    listing,
                    current_publisher: sample_publisher(
                        GenericRegistryPublisherRole::Origin,
                        "origin-a",
                    ),
                    current_freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Fresh,
                        age_secs: 5,
                        max_age_secs: 300,
                        valid_until: 400,
                        generated_at: 100,
                    },
                    activation: Some(activation),
                    evaluated_at: Some(150),
                },
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate activation",
        );
        assert!(report.admitted);
        assert!(report.findings.is_empty());
        assert_eq!(
            report.admission_class,
            Some(GenericTrustAdmissionClass::Reviewable)
        );
    }

    #[test]
    fn generic_trust_activation_fails_closed_on_stale_listing() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let issue_request = sample_activation_issue_request(
            listing.clone(),
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );
        let activation_artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request,
                130,
            ),
            "build activation artifact",
        );
        let activation = require_ok(
            SignedGenericTrustActivation::sign(activation_artifact, &authority_keypair),
            "sign activation",
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &GenericTrustActivationEvaluationRequest {
                    listing,
                    current_publisher: sample_publisher(
                        GenericRegistryPublisherRole::Origin,
                        "origin-a",
                    ),
                    current_freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Stale,
                        age_secs: 500,
                        max_age_secs: 300,
                        valid_until: 400,
                        generated_at: 100,
                    },
                    activation: Some(activation),
                    evaluated_at: Some(700),
                },
                700,
                &authority_keypair.public_key(),
            ),
            "evaluate stale listing",
        );
        assert!(!report.admitted);
        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::ListingStale
        );
    }

    #[test]
    fn generic_trust_activation_public_untrusted_never_admits() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let issue_request = sample_activation_issue_request(
            listing.clone(),
            GenericTrustAdmissionClass::PublicUntrusted,
            GenericTrustActivationDisposition::Approved,
        );
        let activation_artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request,
                130,
            ),
            "build activation artifact",
        );
        let activation = require_ok(
            SignedGenericTrustActivation::sign(activation_artifact, &authority_keypair),
            "sign activation",
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &GenericTrustActivationEvaluationRequest {
                    listing,
                    current_publisher: sample_publisher(
                        GenericRegistryPublisherRole::Origin,
                        "origin-a",
                    ),
                    current_freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Fresh,
                        age_secs: 5,
                        max_age_secs: 300,
                        valid_until: 400,
                        generated_at: 100,
                    },
                    activation: Some(activation),
                    evaluated_at: Some(150),
                },
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate public_untrusted",
        );
        assert!(!report.admitted);
        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::AdmissionClassUntrusted
        );
    }

    #[test]
    fn generic_trust_activation_flags_unverifiable_listing_signature() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = sample_authority_keypair();
        let mut listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        listing.body.status = GenericListingStatus::Revoked;

        let report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    None,
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate invalid listing signature",
        );

        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::ListingUnverifiable
        );
    }

    #[test]
    fn generic_trust_activation_flags_listing_signer_mismatch() {
        let namespace_keypair = Keypair::generate();
        let attacker_keypair = Keypair::generate();
        let authority_keypair = sample_authority_keypair();
        let listing = require_ok(
            SignedGenericListing::sign(
                sample_listing(
                    "https://registry.chio.example",
                    &namespace_keypair,
                    "artifact-1",
                    "deadbeef",
                ),
                &attacker_keypair,
            ),
            "sign listing with mismatched signer",
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    None,
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate mismatched listing signer",
        );

        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::ListingUnverifiable
        );
        assert!(report.findings[0]
            .message
            .contains("namespace ownership signer"));
    }

    #[test]
    fn generic_trust_activation_flags_unverifiable_activation_signature() {
        let signing_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let mut activation = signed_activation(
            listing.clone(),
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );
        let trusted_signer = activation.signer_key.clone();
        activation.body.local_operator_id = "https://tampered.chio.example".to_string();

        let report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    Some(activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &trusted_signer,
            ),
            "evaluate invalid activation signature",
        );

        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::ActivationUnverifiable
        );
    }

    #[test]
    fn generic_trust_activation_flags_invalid_activation_body() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let mut artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        artifact.reviewed_by = None;
        let activation = require_ok(
            SignedGenericTrustActivation::sign(artifact, &authority_keypair),
            "sign activation",
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    Some(activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate invalid activation body",
        );

        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::ActivationUnverifiable
        );
    }

    #[test]
    fn generic_trust_activation_rejects_listing_mismatch() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let mut artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        artifact.listing_sha256 = "different".to_string();
        let activation = require_ok(
            SignedGenericTrustActivation::sign(artifact, &authority_keypair),
            "sign activation",
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    Some(activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate mismatched activation",
        );

        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::ListingMismatch
        );
    }

    #[test]
    fn generic_trust_activation_rejects_divergent_listing_context() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = sample_authority_keypair();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let activation = signed_activation(
            listing.clone(),
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    Some(activation),
                    GenericListingFreshnessState::Divergent,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate divergent listing",
        );

        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::ListingDivergent
        );
    }

    #[test]
    fn generic_trust_activation_rejects_expired_pending_and_denied_activations() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let default_authority_keypair = sample_authority_keypair();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );

        let mut expired_artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        expired_artifact.expires_at = Some(140);
        let expired = require_ok(
            SignedGenericTrustActivation::sign(expired_artifact, &authority_keypair),
            "sign expired activation",
        );
        let expired_report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing.clone(),
                    Some(expired),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate expired activation",
        );
        assert_eq!(
            expired_report.findings[0].code,
            GenericTrustActivationFindingCode::ActivationExpired
        );

        let pending = signed_activation(
            listing.clone(),
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::PendingReview,
        );
        let pending_report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing.clone(),
                    Some(pending),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &default_authority_keypair.public_key(),
            ),
            "evaluate pending activation",
        );
        assert_eq!(
            pending_report.findings[0].code,
            GenericTrustActivationFindingCode::ActivationPendingReview
        );

        let denied = signed_activation(
            listing,
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Denied,
        );
        let denied_report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    signed_sample_listing(
                        "https://registry.chio.example",
                        &signing_keypair,
                        "artifact-1",
                        "deadbeef",
                    ),
                    Some(denied),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &default_authority_keypair.public_key(),
            ),
            "evaluate denied activation",
        );
        assert_eq!(
            denied_report.findings[0].code,
            GenericTrustActivationFindingCode::ActivationDenied
        );
    }

    #[test]
    fn generic_trust_activation_rejects_ineligible_actor_publisher_status_and_operator() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );

        let mut actor_artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        actor_artifact.eligibility.allowed_actor_kinds =
            vec![GenericListingActorKind::CredentialIssuer];
        let actor_activation = require_ok(
            SignedGenericTrustActivation::sign(actor_artifact, &authority_keypair),
            "sign actor-limited activation",
        );
        let actor_report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing.clone(),
                    Some(actor_activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate actor ineligible",
        );
        assert_eq!(
            actor_report.findings[0].code,
            GenericTrustActivationFindingCode::ActorKindIneligible
        );

        let mut publisher_artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        publisher_artifact.eligibility.allowed_publisher_roles =
            vec![GenericRegistryPublisherRole::Mirror];
        let publisher_activation = require_ok(
            SignedGenericTrustActivation::sign(publisher_artifact, &authority_keypair),
            "sign publisher-limited activation",
        );
        let publisher_report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing.clone(),
                    Some(publisher_activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate publisher ineligible",
        );
        assert_eq!(
            publisher_report.findings[0].code,
            GenericTrustActivationFindingCode::PublisherRoleIneligible
        );

        let status_listing = require_ok(
            SignedGenericListing::sign(
                GenericListingArtifact {
                    status: GenericListingStatus::Suspended,
                    ..sample_listing(
                        "https://registry.chio.example",
                        &signing_keypair,
                        "artifact-1",
                        "deadbeef",
                    )
                },
                &signing_keypair,
            ),
            "sign suspended listing",
        );
        let status_activation = signed_activation(
            status_listing.clone(),
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );
        let default_authority_keypair = sample_authority_keypair();
        let status_report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    status_listing,
                    Some(status_activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &default_authority_keypair.public_key(),
            ),
            "evaluate status ineligible",
        );
        assert_eq!(
            status_report.findings[0].code,
            GenericTrustActivationFindingCode::ListingStatusIneligible
        );

        let mut operator_artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        operator_artifact.eligibility.required_listing_operator_ids = vec!["mirror-a".to_string()];
        let operator_activation = require_ok(
            SignedGenericTrustActivation::sign(operator_artifact, &authority_keypair),
            "sign operator-limited activation",
        );
        let operator_report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    Some(operator_activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate operator ineligible",
        );
        assert_eq!(
            operator_report.findings[0].code,
            GenericTrustActivationFindingCode::ListingOperatorIneligible
        );
    }

    #[test]
    fn generic_trust_activation_bond_backed_policy_remains_review_visible_only() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let mut request = issue_request_for(
            listing.clone(),
            GenericTrustAdmissionClass::BondBacked,
            GenericTrustActivationDisposition::Approved,
        );
        request.eligibility.require_bond_backing = true;
        let artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &request,
                130,
            ),
            "build activation",
        );
        let activation = require_ok(
            SignedGenericTrustActivation::sign(artifact, &authority_keypair),
            "sign activation",
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    Some(activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate bond-backed activation",
        );

        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::BondBackingRequired
        );
    }
}
