use chio_test_support::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|core_dir| core_dir.parent())
        .and_then(|crates_dir| crates_dir.parent())
        .test_expect("workspace root is parent of crates/core/chio-core-types")
        .to_path_buf()
}

#[test]
fn enforced_claims_reference_live_proof_manifests() {
    let root = workspace_root();
    let claim_registry = read_json(&root.join("spec/registries/claim-registry.v1.json"));
    let proof_manifest = read_json(&root.join("spec/registries/proof-manifest.v1.json"));

    let live_manifests = proof_manifest["manifests"]
        .as_array()
        .test_expect("proof manifest has manifests array")
        .iter()
        .filter_map(|entry| {
            let id = entry.get("id").and_then(serde_json::Value::as_str)?;
            let claim_ref = entry.get("claim_ref").and_then(serde_json::Value::as_str)?;
            Some((id, claim_ref))
        })
        .collect::<BTreeMap<_, _>>();
    let proposed_manifest_ids = proof_manifest["proposed_manifests"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("id").and_then(serde_json::Value::as_str))
        .collect::<BTreeSet<_>>();

    for claim in claim_registry["claims"]
        .as_array()
        .test_expect("claim registry has claims array")
    {
        let status = claim
            .get("status")
            .and_then(serde_json::Value::as_str)
            .test_expect("claim status is present");
        if status != "enforced" {
            continue;
        }

        let claim_id = claim
            .get("id")
            .and_then(serde_json::Value::as_str)
            .test_expect("claim id is present");
        let proof_manifest_ref = claim
            .get("proof_manifest_ref")
            .and_then(serde_json::Value::as_str)
            .test_expect("enforced claim has proof_manifest_ref");
        let Some(manifest_claim_ref) = live_manifests.get(proof_manifest_ref) else {
            assert!(
                !proposed_manifest_ids.contains(proof_manifest_ref),
                "enforced claim references proposed proof manifest: {claim_id} -> {proof_manifest_ref}"
            );
            panic!(
                "enforced claim missing live proof manifest: {claim_id} -> {proof_manifest_ref}"
            );
        };
        assert_eq!(
            *manifest_claim_ref, claim_id,
            "proof manifest claim_ref mismatch for {proof_manifest_ref}"
        );
    }
}

#[test]
fn proof_manifest_rust_test_refs_point_to_live_files() {
    let root = workspace_root();
    let proof_manifest = read_json(&root.join("spec/registries/proof-manifest.v1.json"));
    let mut missing_refs = Vec::new();

    for manifest in proof_manifest["manifests"]
        .as_array()
        .test_expect("proof manifest has manifests array")
    {
        let manifest_id = manifest
            .get("id")
            .and_then(serde_json::Value::as_str)
            .test_expect("manifest id is present");
        for evidence in manifest["evidence"]
            .as_array()
            .test_expect("manifest evidence is present")
        {
            if evidence.get("kind").and_then(serde_json::Value::as_str) != Some("rust_test") {
                continue;
            }
            let reference = evidence
                .get("ref")
                .and_then(serde_json::Value::as_str)
                .test_expect("rust_test ref is present");
            let (file_ref, test_name) = reference
                .rsplit_once("::")
                .test_expect("rust_test ref includes test name");
            let test_file = root.join(file_ref);
            if !test_file.is_file() {
                missing_refs.push(format!("{manifest_id}: {reference}"));
                continue;
            }
            let test_source =
                std::fs::read_to_string(&test_file).test_expect("rust_test ref file is readable");
            let fn_ref = format!("fn {test_name}(");
            if !test_source.contains(&fn_ref) {
                missing_refs.push(format!("{manifest_id}: {reference}"));
            }
        }
    }

    assert!(
        missing_refs.is_empty(),
        "proof manifest rust_test refs point to missing tests: {}",
        missing_refs.join(", ")
    );
}

#[test]
fn transaction_passport_required_claim_rows_are_registered() {
    let root = workspace_root();
    let claim_registry = read_json(&root.join("spec/registries/claim-registry.v1.json"));
    let proof_manifest = read_json(&root.join("spec/registries/proof-manifest.v1.json"));
    let claim_ids = claim_registry["claims"]
        .as_array()
        .test_expect("claim registry has claims array")
        .iter()
        .filter_map(|claim| claim.get("id").and_then(serde_json::Value::as_str))
        .collect::<BTreeSet<_>>();
    let manifest_claim_refs = proof_manifest["manifests"]
        .as_array()
        .test_expect("proof manifest has manifests array")
        .iter()
        .filter_map(|manifest| {
            manifest
                .get("claim_ref")
                .and_then(serde_json::Value::as_str)
        })
        .collect::<BTreeSet<_>>();
    let required_claims = [
        "claim.transaction.passport_root_verified",
        "claim.transaction.evidence_graph_digest_bound",
        "claim.transaction.evidence_graph_structure_verified",
        "claim.transaction.claim_set_digest_bound",
        "claim.transaction.policy_digest_bound",
        "claim.transaction.omission_policy_bound",
    ];

    for claim in required_claims {
        assert!(
            claim_ids.contains(claim),
            "missing claim registry row: {claim}"
        );
        assert!(
            manifest_claim_refs.contains(claim),
            "missing proof manifest row for claim: {claim}"
        );
    }
}

#[test]
fn financial_credential_required_claim_rows_are_registered() {
    let root = workspace_root();
    let claim_registry = read_json(&root.join("spec/registries/claim-registry.v1.json"));
    let proof_manifest = read_json(&root.join("spec/registries/proof-manifest.v1.json"));
    let claim_ids = claim_registry["claims"]
        .as_array()
        .test_expect("claim registry has claims array")
        .iter()
        .filter_map(|claim| claim.get("id").and_then(serde_json::Value::as_str))
        .collect::<BTreeSet<_>>();
    let manifest_claim_refs = proof_manifest["manifests"]
        .as_array()
        .test_expect("proof manifest has manifests array")
        .iter()
        .filter_map(|manifest| {
            manifest
                .get("claim_ref")
                .and_then(serde_json::Value::as_str)
        })
        .collect::<BTreeSet<_>>();
    let required_claims = [
        "claim.fincred.credit_scorecard.verified_projection_bound",
        "claim.fincred.exposure_history.complete_window_bound",
        "claim.fincred.premium_history.complete_window_bound",
        "claim.fincred.loss_history.complete_window_bound",
        "claim.fincred.settlement_reliability.fail_closed",
        "claim.fincred.source_manifest.credential_set_bound",
        "claim.fincred.presentation_challenge.signed_exact",
    ];

    for claim in required_claims {
        assert!(
            claim_ids.contains(claim),
            "missing claim registry row: {claim}"
        );
        assert!(
            manifest_claim_refs.contains(claim),
            "missing proof manifest row for claim: {claim}"
        );
    }
}

#[test]
fn commerce_order_emitted_claim_rows_are_registered() {
    let root = workspace_root();
    let claim_registry = read_json(&root.join("spec/registries/claim-registry.v1.json"));
    let proof_manifest = read_json(&root.join("spec/registries/proof-manifest.v1.json"));
    let claim_ids = claim_registry["claims"]
        .as_array()
        .test_expect("claim registry has claims array")
        .iter()
        .filter_map(|claim| claim.get("id").and_then(serde_json::Value::as_str))
        .collect::<BTreeSet<_>>();
    let manifest_claim_refs = proof_manifest["manifests"]
        .as_array()
        .test_expect("proof manifest has manifests array")
        .iter()
        .filter_map(|manifest| {
            manifest
                .get("claim_ref")
                .and_then(serde_json::Value::as_str)
        })
        .collect::<BTreeSet<_>>();
    let source =
        std::fs::read_to_string(root.join("crates/platform/chio-commerce-order/src/lib.rs"))
            .test_expect("commerce verifier source is readable");
    let emitted_claims = source
        .split('"')
        .filter(|part| part.starts_with("claim."))
        .collect::<BTreeSet<_>>();

    assert!(
        !emitted_claims.is_empty(),
        "commerce verifier should emit registered claims"
    );
    for claim in emitted_claims {
        assert!(
            claim_ids.contains(claim),
            "commerce verifier emits unregistered claim: {claim}"
        );
        assert!(
            manifest_claim_refs.contains(claim),
            "commerce verifier emits claim without proof manifest: {claim}"
        );
    }
}

#[test]
fn public_settlement_claims_reference_positive_fixture() {
    assert_proof_manifests_reference_positive_fixture(
        "public-settlement-v1",
        "fixtures/proof-room/public-settlement/",
        "public settlement",
    );
}

#[test]
fn swarm_authority_claims_reference_positive_fixture() {
    assert_proof_manifests_reference_positive_fixture(
        "swarm-authority-v1",
        "fixtures/proof-room/swarm-authority/",
        "swarm authority",
    );
}

#[test]
fn launch_schema_boundary_matches_registry_owner_acceptance() {
    let root = workspace_root();
    let schema_registry = read_json(&root.join("spec/schemas/registry.json"));
    let registered_schemas = schema_registry["artifacts"]
        .as_array()
        .test_expect("schema registry has artifacts array")
        .iter()
        .filter_map(|entry| entry.get("schema").and_then(serde_json::Value::as_str))
        .collect::<BTreeSet<_>>();
    let known_signed_schemas = chio_core_types::KNOWN_SIGNED_ARTIFACT_SCHEMAS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();

    let accepted_schemas = [
        "chio.commerce.payment-lifecycle.v1",
        "chio.commerce.mandate-allowance-ledger.v1",
        "chio.workflow.preflight-plan.v1",
        "chio.workflow.preflight-report.v1",
        "chio.enterprise.telemetry-projection.v1",
        "chio.enterprise.data-governance-report.v1",
        "chio.enterprise.approval-case.v1",
        "chio.enterprise.evidence-export-bundle.v1",
        "chio.enterprise.control-evidence-map.v1",
    ];
    let candidate_schemas = [
        "chio.commerce.dispute-recovery-ledger.v1",
        "chio.commerce.fraud-assessment.v1",
        "chio.commerce.currency-liquidity-ledger.v1",
        "chio.commerce.recurring-agent-commerce.v1",
        "chio.workflow.what-if-delta.v1",
        "chio.workflow.rehearsal-run.v1",
        "chio.workflow.replay-capsule.v1",
        "chio.workflow.model-provider-conformance.v1",
        "chio.workflow.approval-gate.v1",
        "chio.enterprise.policy-pack-manifest.v1",
        "chio.enterprise.access-decision-report.v1",
        "chio.enterprise.incident-review-case.v1",
        "chio.enterprise.regulator-review-bundle.v1",
    ];

    for schema in accepted_schemas {
        assert!(
            registered_schemas.contains(schema),
            "accepted launch schema is not registered: {schema}"
        );
        assert!(
            known_signed_schemas.contains(schema),
            "accepted launch schema is not a known signed artifact: {schema}"
        );
    }

    for schema in candidate_schemas {
        assert!(
            !registered_schemas.contains(schema),
            "candidate launch schema registered without registry-owner promotion: {schema}"
        );
        assert!(
            !known_signed_schemas.contains(schema),
            "candidate launch schema signed without registry-owner promotion: {schema}"
        );
    }
}

#[test]
fn agent_web_positive_fixture_refs_cover_valid_projection_artifacts() {
    let root = workspace_root();
    let proof_manifest = read_json(&root.join("spec/registries/proof-manifest.v1.json"));
    let evidence_graph = read_json(
        &root.join("fixtures/proof-room/agent-web/valid-webhook-cloudevents/evidence-graph.json"),
    );
    let envelope_refs = positive_fixture_refs_for_claim(
        &proof_manifest,
        "claim.agent_web.external_subject_digest_bound",
    );
    let sidecar_refs = positive_fixture_refs_for_claim(
        &proof_manifest,
        "claim.agent_web.sidecar_not_native_authority",
    );
    let projection_manifest_refs = positive_fixture_refs_for_claim(
        &proof_manifest,
        "claim.agent_web.projection_manifest_bound",
    );
    let unsupported_claim_refs = positive_fixture_refs_for_claim(
        &proof_manifest,
        "claim.agent_web.unsupported_claims_limited",
    );
    let mut missing_refs = Vec::new();

    for node in evidence_graph["nodes"]
        .as_array()
        .test_expect("Agent Web evidence graph has nodes")
    {
        let role = node
            .get("role")
            .and_then(serde_json::Value::as_str)
            .test_expect("Agent Web evidence graph node has role");
        if role != "agent-web-proof-envelope" && role != "external-projection-manifest" {
            continue;
        }
        let path = node
            .get("path")
            .and_then(serde_json::Value::as_str)
            .test_expect("Agent Web evidence graph node has path");
        let expected_ref =
            format!("fixtures/proof-room/agent-web/valid-webhook-cloudevents/{path}");
        let required_claims = match role {
            "agent-web-proof-envelope" => [
                (
                    "claim.agent_web.external_subject_digest_bound",
                    &envelope_refs,
                ),
                (
                    "claim.agent_web.sidecar_not_native_authority",
                    &sidecar_refs,
                ),
            ],
            "external-projection-manifest" => [
                (
                    "claim.agent_web.projection_manifest_bound",
                    &projection_manifest_refs,
                ),
                (
                    "claim.agent_web.unsupported_claims_limited",
                    &unsupported_claim_refs,
                ),
            ],
            _ => unreachable!("role filtered above"),
        };
        for (claim_ref, refs) in required_claims {
            if !refs.contains(&expected_ref) {
                missing_refs.push(format!("{claim_ref}: {expected_ref}"));
            }
        }
    }

    assert!(
        missing_refs.is_empty(),
        "Agent Web proof manifests missing valid projection positive fixtures: {}",
        missing_refs.join(", ")
    );
}

struct ExpectedEvidenceRef {
    claim_ref: &'static str,
    kind: &'static str,
    expected_ref: &'static str,
}

const EXPECTED_REFS: &[ExpectedEvidenceRef] = &[
    ExpectedEvidenceRef {
        claim_ref: "claim.transaction.passport_root_verified",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/minimal-passport/unknown-passport-schema/transaction-passport.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.transaction.evidence_graph_digest_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/minimal-passport/evidence-graph-digest-mismatch/transaction-passport.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.transaction.policy_digest_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/minimal-passport/invalid-policy-digest-mismatch/verifier-policy.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.proof_room.verifier_report_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/negatives/report-hash-mismatch.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.proof_room.allow_and_deny_visible",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/negatives/missing-denial-receipt.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.proof_room.receipt_coverage_matrix_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/negatives/receipt-coverage-status-mismatch.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.runtime.execution_lease_valid",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/runtime-security/missing-execution-lease/transaction-passport.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.runtime.execution_lease_valid",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/runtime-security/negatives/expired-execution-lease.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.runtime.nonce_fresh",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/runtime-security/negatives/reused-nonce.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.runtime.revocation_fresh_at_dispatch",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/runtime-security/negatives/stale-revocation.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.runtime.sandbox_attestation_matched",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/runtime-security/negatives/sandbox-mismatch.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.runtime.tool_server_ack_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/runtime-security/negatives/ack-outside-lease.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.runtime.receipt_totality_complete",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/runtime-security/negatives/missing-terminal-receipt.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.runtime.advisory_not_used_as_authorization",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/runtime-security/advisory-used-as-authorization/evidence-graph.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.enterprise.data_governance_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/enterprise-export/negatives/pii-overdisclosure.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.enterprise.evidence_export_digest_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/enterprise-export/negatives/export-bundle-digest-mismatch.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.enterprise.telemetry_projection_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/enterprise-export/negatives/telemetry-digest-mismatch.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.enterprise.export_approval_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/enterprise-export/negatives/missing-approval-case.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.enterprise.control_map_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/enterprise-export/negatives/control-map-missing-gate.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.risk.comptroller_report_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/enterprise-export/coverage-subject-mismatch/risk-comptroller-report.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.risk.comptroller_report_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/enterprise-export/negatives/double-consumed-reserve.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.risk.comptroller_report_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/enterprise-export/negatives/market-slash-facility-reserve.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.risk.comptroller_report_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/enterprise-export/negatives/reverse-slash-without-prior-penalty.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.external_subject_digest_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/agent-web/negatives/external-digest-mismatch.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.external_subject_digest_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/agent-web/negatives/acp-client-unsupported-bridge-allowed.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.external_subject_digest_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/agent-web/negatives/email-send-missing-message-digest.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.external_subject_digest_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/agent-web/negatives/calendar-time-range-mismatch.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.external_subject_digest_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/agent-web/negatives/slack-failed-provider-response.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.external_subject_digest_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/agent-web/negatives/kubernetes-admission-uid-mismatch.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.external_subject_digest_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/agent-web/negatives/oci-tag-only-ref.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.external_subject_digest_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/agent-web/negatives/slsa-unverified-provenance.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.projection_manifest_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/agent-web/negatives/cloudevents-specversion-mismatch.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.projection_manifest_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/agent-web/negatives/graphql-http-draft-version-missing.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.projection_manifest_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/agent-web/negatives/graphql-errors-projected-as-success.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.unsupported_claims_limited",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/agent-web/negatives/unsupported-claim-not-limited.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.unsupported_claims_limited",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/agent-web/negatives/mcp-authority-claim-not-limited.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.unsupported_claims_limited",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/agent-web/negatives/a2a-authority-claim-not-limited.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.agent_web.sidecar_not_native_authority",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/agent-web/negatives/sidecar-claim-marked-native.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.trust_market.provider_discovery_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/trust-market/negatives/stale-discovery.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.trust_market.provider_selection_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/trust-market/negatives/selected-provider-absent.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.trust_market.local_scorecard_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/trust-market/negatives/score-recompute-mismatch.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.trust_market.reputation_import_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/trust-market/negatives/reputation-import-overweight.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.trust_market.sla_commitment_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/trust-market/negatives/sla-wrong-order.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.trust_market.collateral_guarantee_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/trust-market/negatives/guarantee-without-backing.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.trust_market.collateral_guarantee_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/trust-market/negatives/unsupported-collateral-source.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.trust_market.jurisdiction_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/trust-market/negatives/slash-authority-outside-jurisdiction.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.trust_market.unsupported_market_claims_limited",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/trust-market/negatives/required-unsupported-market-claim.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.public_settlement.order_binding_verified",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/public-settlement/negatives/missing-commerce-order-binding.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.public_settlement.chain_context_verified",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/public-settlement/negatives/wrong-chain-id.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.public_settlement.finality_verified",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/public-settlement/negatives/finality-below-threshold.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.public_settlement.oracle_conversion_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/public-settlement/negatives/missing-oracle-evidence.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.public_settlement.dispute_posture_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/public-settlement/negatives/refunded-posture-without-reversal.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.swarm.task_graph_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/swarm-authority/negatives/graph-cycle.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.swarm.continuation_fresh",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/swarm-authority/negatives/stale-continuation.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.swarm.continuation_fresh",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/swarm-authority/negatives/replayed-continuation-nonce.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.swarm.attenuation_witness_chain_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/swarm-authority/negatives/witness-child-scope-mismatch.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.swarm.route_plan_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/swarm-authority/negatives/stale-route-plan.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.swarm.join_receipt_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/swarm-authority/negatives/join-parent-set-mismatch.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.swarm.budget_pool_bound",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/swarm-authority/negatives/budget-allocations-exceed-pool.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.swarm.revocation_epoch_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/swarm-authority/negatives/revoked-task.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.runtime.advisory_not_used_as_authorization",
        kind: "positive_fixture",
        expected_ref:
            "fixtures/proof-room/runtime-security/valid-side-effecting-call/evidence-graph.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.workflow.preflight_planning_only",
        kind: "positive_fixture",
        expected_ref: "fixtures/proof-room/workflow-preflight/valid-child-scope/preflight-plan.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.workflow.preflight_planning_only",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/workflow-preflight/planning-artifact-claims-authority/preflight-plan.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.disclosure.lineage_subgraph_bound",
        kind: "positive_fixture",
        expected_ref:
            "fixtures/proof-room/disclosure-lineage/valid-lineage-ledger/signed-lineage-subgraph.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.disclosure.leakage_ledger_complete",
        kind: "positive_fixture",
        expected_ref:
            "fixtures/proof-room/disclosure-lineage/valid-lineage-ledger/leakage-ledger.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.disclosure.lineage_subgraph_bound",
        kind: "negative_fixture",
        expected_ref: "fixtures/proof-room/disclosure-lineage/negatives/unknown-lineage-root.json",
    },
    ExpectedEvidenceRef {
        claim_ref: "claim.disclosure.leakage_ledger_complete",
        kind: "negative_fixture",
        expected_ref:
            "fixtures/proof-room/disclosure-lineage/missing-ledger-entry/leakage-ledger.json",
    },
];

#[test]
fn expected_claim_evidence_refs_are_manifested() {
    for expected in EXPECTED_REFS {
        assert_manifest_references_evidence(
            expected.claim_ref,
            expected.kind,
            expected.expected_ref,
        );
    }
}

fn assert_proof_manifests_reference_positive_fixture(
    introduced_by: &str,
    fixture_prefix: &str,
    label: &str,
) {
    let root = workspace_root();
    let proof_manifest = read_json(&root.join("spec/registries/proof-manifest.v1.json"));
    let mut missing_fixture = Vec::new();

    for manifest in proof_manifest["manifests"]
        .as_array()
        .test_expect("proof manifest has manifests array")
        .iter()
        .filter(|manifest| {
            manifest
                .get("introduced_by")
                .and_then(serde_json::Value::as_str)
                == Some(introduced_by)
        })
    {
        let claim_ref = manifest
            .get("claim_ref")
            .and_then(serde_json::Value::as_str)
            .test_expect("manifest claim_ref is present");
        let has_public_settlement_fixture = manifest["evidence"]
            .as_array()
            .test_expect("manifest evidence is present")
            .iter()
            .any(|evidence| {
                evidence.get("kind").and_then(serde_json::Value::as_str) == Some("positive_fixture")
                    && evidence
                        .get("ref")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|reference| reference.starts_with(fixture_prefix))
            });
        if !has_public_settlement_fixture {
            missing_fixture.push(claim_ref.to_string());
        }
    }

    assert!(
        missing_fixture.is_empty(),
        "{label} claim manifests missing positive fixture evidence: {}",
        missing_fixture.join(", ")
    );
}

fn assert_manifest_references_evidence(claim_ref: &str, kind: &str, expected_ref: &str) {
    let root = workspace_root();
    let proof_manifest = read_json(&root.join("spec/registries/proof-manifest.v1.json"));
    let manifest = proof_manifest["manifests"]
        .as_array()
        .test_expect("proof manifest has manifests array")
        .iter()
        .find(|manifest| {
            manifest
                .get("claim_ref")
                .and_then(serde_json::Value::as_str)
                == Some(claim_ref)
        })
        .test_expect("claim has live proof manifest");

    let has_expected_ref = manifest["evidence"]
        .as_array()
        .test_expect("manifest evidence is present")
        .iter()
        .any(|evidence| {
            evidence.get("kind").and_then(serde_json::Value::as_str) == Some(kind)
                && evidence.get("ref").and_then(serde_json::Value::as_str) == Some(expected_ref)
        });

    assert!(
        has_expected_ref,
        "{claim_ref} missing {kind} evidence ref {expected_ref}"
    );
}

fn positive_fixture_refs_for_claim(
    proof_manifest: &serde_json::Value,
    claim_ref: &str,
) -> BTreeSet<String> {
    proof_manifest["manifests"]
        .as_array()
        .test_expect("proof manifest has manifests array")
        .iter()
        .find(|manifest| {
            manifest
                .get("claim_ref")
                .and_then(serde_json::Value::as_str)
                == Some(claim_ref)
        })
        .test_expect("claim has live proof manifest")["evidence"]
        .as_array()
        .test_expect("manifest evidence is present")
        .iter()
        .filter(|evidence| {
            evidence.get("kind").and_then(serde_json::Value::as_str) == Some("positive_fixture")
        })
        .filter_map(|evidence| {
            evidence
                .get("ref")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

fn read_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).test_expect("json file reads");
    serde_json::from_slice(&bytes).test_expect("json file parses")
}
