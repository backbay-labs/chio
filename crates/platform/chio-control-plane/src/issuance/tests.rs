use super::*;
use chio_test_support::prelude::*;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    runtime_attestation::{RuntimeAssuranceTier, RuntimeAttestationEvidence},
    scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant},
    token::CapabilityToken,
};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    metadata::ReceiptAttributionMetadata,
};
use chio_kernel::{KernelError, ReceiptStore};
use chio_store_sqlite::SqliteReceiptStore;

use crate::policy::{
    ReputationIssuancePolicy, ReputationTierPolicy, RuntimeAssuranceIssuancePolicy,
    RuntimeAssuranceTierPolicy, TierScopeCeiling,
};

fn unique_path(prefix: &str, extension: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}{extension}"))
}

fn test_policy() -> ReputationIssuancePolicy {
    ReputationIssuancePolicy {
        scoring: chio_reputation::ReputationConfig {
            history_receipt_target: 10,
            history_day_target: 10,
            ..Default::default()
        },
        probationary_receipt_count: 10,
        probationary_min_days: 10,
        probationary_score_ceiling: 0.60,
        tiers: vec![
            ReputationTierPolicy {
                name: "probationary".to_string(),
                score_range: [0.0, 0.50],
                max_scope: TierScopeCeiling {
                    operations: vec![Operation::Read, Operation::Get],
                    max_invocations: Some(50),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 1_000,
                        currency: "USD".to_string(),
                    }),
                    max_delegation_depth: Some(0),
                    ttl_seconds: 60,
                    constraints_required: true,
                },
            },
            ReputationTierPolicy {
                name: "trusted".to_string(),
                score_range: [0.50, 1.0],
                max_scope: TierScopeCeiling {
                    operations: vec![
                        Operation::Read,
                        Operation::Get,
                        Operation::Invoke,
                        Operation::ReadResult,
                        Operation::Delegate,
                    ],
                    max_invocations: Some(500),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 1_000,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 10_000,
                        currency: "USD".to_string(),
                    }),
                    max_delegation_depth: Some(3),
                    ttl_seconds: 300,
                    constraints_required: false,
                },
            },
        ],
    }
}

fn test_runtime_assurance_policy() -> RuntimeAssuranceIssuancePolicy {
    RuntimeAssuranceIssuancePolicy {
        tiers: vec![
            RuntimeAssuranceTierPolicy {
                name: "baseline".to_string(),
                minimum_attestation_tier: RuntimeAssuranceTier::None,
                max_scope: TierScopeCeiling {
                    operations: vec![Operation::Invoke],
                    max_invocations: Some(5),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 50,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    }),
                    max_delegation_depth: Some(0),
                    ttl_seconds: 30,
                    constraints_required: false,
                },
            },
            RuntimeAssuranceTierPolicy {
                name: "attested".to_string(),
                minimum_attestation_tier: RuntimeAssuranceTier::Attested,
                max_scope: TierScopeCeiling {
                    operations: vec![Operation::Invoke],
                    max_invocations: Some(20),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 250,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 1_000,
                        currency: "USD".to_string(),
                    }),
                    max_delegation_depth: Some(0),
                    ttl_seconds: 300,
                    constraints_required: false,
                },
            },
        ],
        attestation_trust_policy: None,
    }
}

fn test_trusted_runtime_assurance_policy() -> RuntimeAssuranceIssuancePolicy {
    let mut policy = test_runtime_assurance_policy();
    policy.attestation_trust_policy = Some(
        chio_core::capability::trust_policy::AttestationTrustPolicy {
            rules: vec![
                chio_core::capability::trust_policy::AttestationTrustRule {
                    name: "azure-contoso".to_string(),
                    schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                    verifier: "https://maa.contoso.test".to_string(),
                    effective_tier: RuntimeAssuranceTier::Verified,
                    verifier_family: Some(
                        chio_core::appraisal::AttestationVerifierFamily::AzureMaa,
                    ),
                    max_evidence_age_seconds: Some(120),
                    allowed_attestation_types: vec!["sgx".to_string()],
                    required_assertions: std::collections::BTreeMap::new(),
                },
                chio_core::capability::trust_policy::AttestationTrustRule {
                    name: "google-confidential".to_string(),
                    schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
                    verifier: "https://confidentialcomputing.googleapis.com".to_string(),
                    effective_tier: RuntimeAssuranceTier::Verified,
                    verifier_family: Some(
                        chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
                    ),
                    max_evidence_age_seconds: Some(120),
                    allowed_attestation_types: vec!["confidential_vm".to_string()],
                    required_assertions: std::collections::BTreeMap::from([
                        ("hardwareModel".to_string(), "GCP_AMD_SEV".to_string()),
                        ("secureBoot".to_string(), "enabled".to_string()),
                    ]),
                },
            ],
        },
    );
    policy.tiers.push(RuntimeAssuranceTierPolicy {
        name: "verified".to_string(),
        minimum_attestation_tier: RuntimeAssuranceTier::Verified,
        max_scope: TierScopeCeiling {
            operations: vec![Operation::Invoke],
            max_invocations: Some(50),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 5_000,
                currency: "USD".to_string(),
            }),
            max_delegation_depth: Some(0),
            ttl_seconds: 600,
            constraints_required: false,
        },
    });
    policy
}

fn test_azure_runtime_attestation() -> RuntimeAttestationEvidence {
    let now = unix_now();
    RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.contoso.test/".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "attestation-digest-azure".to_string(),
        runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {
                "attestationType": "sgx"
            }
        })),
    }
}

fn test_google_runtime_attestation() -> RuntimeAttestationEvidence {
    let now = unix_now();
    RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
        verifier: "https://confidentialcomputing.googleapis.com".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "attestation-digest-google".to_string(),
        runtime_identity: Some(
            "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1".to_string(),
        ),
        workload_identity: None,
        claims: Some(serde_json::json!({
            "googleAttestation": {
                "attestationType": "confidential_vm",
                "hardwareModel": "GCP_AMD_SEV",
                "secureBoot": "enabled"
            }
        })),
    }
}

fn make_receipt(
    id: &str,
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    timestamp: u64,
    kernel_kp: &Keypair,
) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "path": "/workspace/safe/data.txt"
            }))
            .test_expect("action"),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_key.to_string(),
                    issuer_key: issuer_key.to_string(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                }
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kernel_kp.public_key(),
            bbs_projection_version: None,
        },
        kernel_kp,
    )
    .test_expect("sign receipt")
}

fn make_subject_capability(
    capability_id: &str,
    subject_kp: &Keypair,
    issuer_kp: &Keypair,
    issued_at: u64,
    max_invocations: Option<u32>,
) -> CapabilityToken {
    let body = chio_core::capability::token::CapabilityTokenBody {
        id: capability_id.to_string(),
        issuer: issuer_kp.public_key(),
        subject: subject_kp.public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "filesystem".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::PathPrefix("/workspace/safe".to_string())],
                max_invocations,
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 250,
                    currency: "USD".to_string(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: 2_500,
                    currency: "USD".to_string(),
                }),
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        },
        issued_at,
        expires_at: issued_at + 3_600,
        delegation_chain: Vec::new(),
    };
    CapabilityToken::sign(body, issuer_kp).test_expect("sign capability")
}

#[test]
fn probationary_subject_requires_constrained_read_scope_and_persists_snapshot() {
    let receipt_db_path = unique_path("issuance-policy-receipts", ".sqlite3");
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        Some(test_policy()),
        None,
        Some(&receipt_db_path),
        None,
    );
    let subject_kp = Keypair::generate();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Read],
            constraints: vec![Constraint::PathPrefix("/workspace/safe".to_string())],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 50,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let capability = authority
        .issue_capability(&subject_kp.public_key(), scope, 30)
        .test_expect("probationary read capability should issue");

    let store = SqliteReceiptStore::open(&receipt_db_path).test_expect("open receipt store");
    let stored = store
        .get_lineage(&capability.id)
        .test_expect("lineage query")
        .test_expect("snapshot present");
    assert_eq!(stored.subject_key, subject_kp.public_key().to_hex());

    let _ = fs::remove_file(receipt_db_path);
}

#[test]
fn probationary_subject_denied_broad_issue_request() {
    let receipt_db_path = unique_path("issuance-policy-deny", ".sqlite3");
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        Some(test_policy()),
        None,
        Some(&receipt_db_path),
        None,
    );
    let subject_kp = Keypair::generate();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let error = authority
        .issue_capability(&subject_kp.public_key(), scope, 300)
        .test_expect_err("broad probationary issuance should be denied");
    assert!(
        matches!(error, KernelError::CapabilityIssuanceDenied(_)),
        "expected denial, got {error:?}"
    );

    let _ = fs::remove_file(receipt_db_path);
}

#[test]
fn strong_local_history_allows_trusted_invoke_scope() {
    let receipt_db_path = unique_path("issuance-policy-history", ".sqlite3");
    let receipt_store = SqliteReceiptStore::open(&receipt_db_path).test_expect("receipt store");
    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    // The history receipts must be signed by a kernel key the issuing
    // authority trusts; otherwise reputation scoring fails them closed as
    // unsigned (see chio-reputation::receipt_integrity_valid) and the
    // subject never accumulates history. Sign every receipt with the same
    // keypair that backs the local authority below so its public key is in
    // the trusted set.
    let kernel_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();
    let now = unix_now();
    let subject_capability = make_subject_capability(
        "cap-history-001",
        &subject_kp,
        &issuer_kp,
        now - 20 * 86_400,
        Some(200),
    );
    receipt_store
        .record_capability_snapshot(&subject_capability, None)
        .test_expect("record subject capability");
    for day in 0..12 {
        let receipt = make_receipt(
            &format!("rcpt-{day}"),
            &subject_capability.id,
            &subject_hex,
            &issuer_hex,
            now - (11 - day) * 86_400,
            &kernel_kp,
        );
        receipt_store
            .append_chio_receipt(&receipt)
            .test_expect("append receipt");
    }
    drop(receipt_store);

    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(kernel_kp)),
        Some(test_policy()),
        None,
        Some(&receipt_db_path),
        None,
    );
    let requested_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: Vec::new(),
            max_invocations: Some(250),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 5_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let capability = authority
        .issue_capability(&subject_kp.public_key(), requested_scope, 300)
        .test_expect("trusted issuance should succeed");
    assert_eq!(capability.subject, subject_kp.public_key());

    let _ = fs::remove_file(receipt_db_path);
}

#[test]
fn runtime_assurance_policy_denies_high_budget_without_attestation() {
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        None,
        Some(test_runtime_assurance_policy()),
        None,
        None,
    );
    let subject_kp = Keypair::generate();
    let requested_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 250,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let error = authority
        .issue_capability(&subject_kp.public_key(), requested_scope, 120)
        .test_expect_err("baseline runtime tier should not allow the higher monetary ceiling");
    assert!(
        matches!(error, KernelError::CapabilityIssuanceDenied(_)),
        "expected runtime-assurance issuance denial, got {error:?}"
    );
}

#[test]
fn runtime_assurance_policy_denies_raw_attestation_without_local_trust_boundary() {
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        None,
        Some(test_runtime_assurance_policy()),
        None,
        None,
    );
    let subject_kp = Keypair::generate();
    let requested_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 250,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let error = authority
        .issue_capability_with_attestation(
            &subject_kp.public_key(),
            requested_scope,
            120,
            Some(test_azure_runtime_attestation()),
        )
        .test_expect_err("raw attestation must not unlock attested scope without local trust");

    assert!(
        error
            .to_string()
            .contains("policy tier 'baseline'"),
        "expected local verification boundary to keep raw attestation on the baseline tier, got {error}"
    );
}

#[test]
fn issuance_verification_returns_canonical_subject_and_provenance() {
    let policy = test_trusted_runtime_assurance_policy();
    let verified = verify_runtime_attestation_for_issuance(
        Some(&test_azure_runtime_attestation()),
        Some(&policy),
        unix_now(),
    )
    .test_expect("trusted attestation should verify")
    .test_expect("verified record should be returned when runtime policy is present");

    assert!(verified.is_locally_accepted());
    assert_eq!(verified.effective_tier(), RuntimeAssuranceTier::Verified);
    assert_eq!(
        verified.provenance.canonical_verifier,
        "https://maa.contoso.test"
    );
    assert_eq!(verified.matched_trust_rule(), Some("azure-contoso"));
    assert_eq!(
        verified
            .workload_identity()
            .test_expect("trusted attestation should bind a workload identity")
            .trust_domain,
        "chio"
    );
}

#[test]
fn issuance_verification_returns_verified_record_without_runtime_policy() {
    let evidence = test_azure_runtime_attestation();
    let verified = verify_runtime_attestation_for_issuance(Some(&evidence), None, unix_now())
        .test_expect("attestation should pass local binding validation")
        .test_expect("verified record should still be returned without runtime policy");

    assert!(!verified.policy_outcome.trust_policy_configured);
    assert!(!verified.is_locally_accepted());
    assert_eq!(verified.effective_tier(), RuntimeAssuranceTier::None);
    assert_eq!(
        verified.evidence_schema(),
        "chio.runtime-attestation.azure-maa.jwt.v1"
    );
    assert_eq!(verified.evidence_sha256(), "attestation-digest-azure");
    assert_eq!(verified.canonical_verifier(), "https://maa.contoso.test");
    assert_eq!(
        verified.verifier_family(),
        chio_core::appraisal::AttestationVerifierFamily::AzureMaa
    );
    assert!(verified.matches_evidence(&evidence));
}

#[test]
fn workload_identity_validation_denies_conflicting_attestation_without_policy() {
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        None,
        None,
        None,
        None,
    );
    let subject_kp = Keypair::generate();
    let now = unix_now();
    let requested_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(1),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };
    let runtime_attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.v1".to_string(),
        verifier: "verifier.chio".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "attestation-digest".to_string(),
        runtime_identity: Some("spiffe://prod.chio/payments/worker".to_string()),
        workload_identity: Some(chio_core::capability::workload_identity::WorkloadIdentity {
            scheme: chio_core::capability::workload_identity::WorkloadIdentityScheme::Spiffe,
            credential_kind:
                chio_core::capability::workload_identity::WorkloadCredentialKind::X509Svid,
            uri: "spiffe://dev.chio/payments/worker".to_string(),
            trust_domain: "dev.chio".to_string(),
            path: "/payments/worker".to_string(),
        }),
        claims: None,
    };

    let error = authority
        .issue_capability_with_attestation(
            &subject_kp.public_key(),
            requested_scope,
            120,
            Some(runtime_attestation),
        )
        .test_expect_err("conflicting workload identity should fail closed");
    assert!(
        matches!(error, KernelError::CapabilityIssuanceDenied(_)),
        "expected issuance denial, got {error:?}"
    );
    assert!(
        error.to_string().contains("workload identity"),
        "expected workload-identity denial, got {error}"
    );
}

#[test]
fn runtime_assurance_policy_rebinds_trusted_attestation_to_verified_tier() {
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        None,
        Some(test_trusted_runtime_assurance_policy()),
        None,
        None,
    );
    let subject_kp = Keypair::generate();
    let requested_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 5_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let capability = authority
        .issue_capability_with_attestation(
            &subject_kp.public_key(),
            requested_scope,
            120,
            Some(test_azure_runtime_attestation()),
        )
        .test_expect("trusted attestation should unlock verified tier");

    assert!(
        capability.scope.grants[0]
            .constraints
            .contains(&Constraint::MinimumRuntimeAssurance(
                RuntimeAssuranceTier::Verified
            )),
        "issued capability should bind the verified runtime assurance tier"
    );
}

#[test]
fn runtime_assurance_policy_denies_untrusted_attestation_when_verifier_rules_exist() {
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        None,
        Some(test_trusted_runtime_assurance_policy()),
        None,
        None,
    );
    let subject_kp = Keypair::generate();
    let requested_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 250,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };
    let mut untrusted = test_azure_runtime_attestation();
    untrusted.verifier = "https://maa.untrusted.test".to_string();

    let error = authority
        .issue_capability_with_attestation(
            &subject_kp.public_key(),
            requested_scope,
            120,
            Some(untrusted),
        )
        .test_expect_err("untrusted verifier should fail closed");
    assert!(
        error.to_string().contains("trust policy"),
        "expected trust policy denial, got {error}"
    );
}

#[test]
fn runtime_assurance_policy_rebinds_google_attestation_to_verified_tier() {
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        None,
        Some(test_trusted_runtime_assurance_policy()),
        None,
        None,
    );
    let subject_kp = Keypair::generate();
    let requested_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 250,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let capability = authority
        .issue_capability_with_attestation(
            &subject_kp.public_key(),
            requested_scope,
            120,
            Some(test_google_runtime_attestation()),
        )
        .test_expect("trusted google appraisal should unlock verified tier");

    assert!(
        capability.scope.grants[0]
            .constraints
            .contains(&Constraint::MinimumRuntimeAssurance(
                RuntimeAssuranceTier::Verified
            )),
        "issued capability should bind the verified runtime assurance tier"
    );
}
