use super::*;

const STANDALONE_TRANSACTION_VERIFIED_CLAIMS: [&str; 6] = [
    "claim.transaction.passport_root_verified",
    "claim.transaction.evidence_graph_digest_bound",
    "claim.transaction.evidence_graph_structure_verified",
    "claim.transaction.claim_set_digest_bound",
    "claim.transaction.policy_digest_bound",
    "claim.transaction.omission_policy_bound",
];

pub(crate) fn verify_source_verifier_report(
    bundle_root: &Path,
    transaction_passport_artifact: &VerifiedManifestArtifact,
    actual_report: &serde_json::Value,
    verify_transaction_passport_signature: bool,
) -> Result<(), String> {
    if source_report_requires_family_verification(actual_report) {
        verify_family_source_verifier_report(
            bundle_root,
            transaction_passport_artifact,
            actual_report,
            verify_transaction_passport_signature,
        )?;
        return Ok(());
    }
    match verify_transaction_passport_file_with_options(
        bundle_root,
        &transaction_passport_artifact.path,
        verify_transaction_passport_signature,
    ) {
        Ok(expected_report) => {
            if normalized_source_verifier_report(actual_report)
                != normalized_source_verifier_report(&expected_report)
            {
                return Err(
                    "proof-room.report.mismatch: verifier report does not match transaction passport"
                        .to_string(),
                );
            }
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

pub(crate) fn source_report_has_family_reports(report: &serde_json::Value) -> bool {
    report
        .get("family_reports")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|reports| !reports.is_empty())
}

pub(crate) fn source_report_requires_family_verification(report: &serde_json::Value) -> bool {
    source_report_has_family_reports(report)
        || source_report_verified_claims(report)
            .iter()
            .any(|claim| !claim.starts_with(CLAIM_PREFIX_TRANSACTION))
}

pub(crate) fn verify_family_source_verifier_report(
    bundle_root: &Path,
    transaction_passport_artifact: &VerifiedManifestArtifact,
    actual_report: &serde_json::Value,
    verify_transaction_passport_signature: bool,
) -> Result<(), String> {
    let expected_report = verify_transaction_passport_family_report_with_options(
        bundle_root,
        &transaction_passport_artifact.path,
        verify_transaction_passport_signature,
    )?;
    if normalized_source_verifier_report(actual_report)
        != normalized_source_verifier_report(&expected_report)
        && !source_report_matches_unwrapped_single_family(actual_report, &expected_report)
    {
        return Err(
            "proof-room.report.mismatch: verifier report does not match transaction passport"
                .to_string(),
        );
    }
    Ok(())
}

pub(crate) fn normalized_source_verifier_report(report: &serde_json::Value) -> serde_json::Value {
    let mut normalized = report.clone();
    let Some(object) = normalized.as_object_mut() else {
        return normalized;
    };
    if object.get("schema").and_then(serde_json::Value::as_str)
        == Some("chio.transaction.verifier-report.v1")
        && object.get("verdict").and_then(serde_json::Value::as_str) == Some("verified")
    {
        object
            .entry("accepted".to_string())
            .or_insert(serde_json::Value::Bool(true));
        object
            .entry("state".to_string())
            .or_insert(serde_json::Value::String("verified".to_string()));
        let verified_claims = object
            .get("verified_claims")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        object
            .entry("claimResults".to_string())
            .or_insert_with(|| serde_json::Value::Array(source_claim_results(&verified_claims)));
        object
            .entry("checker_provenance".to_string())
            .or_insert_with(|| {
                serde_json::Value::Array(source_claim_checker_provenance(&verified_claims))
            });
        normalize_claim_order(object);
    }
    if let Some(family_reports) = object
        .get_mut("family_reports")
        .and_then(serde_json::Value::as_array_mut)
    {
        for family_report in family_reports {
            *family_report = normalized_source_verifier_report(family_report);
        }
    }
    normalized
}

fn normalize_claim_order(object: &mut serde_json::Map<String, serde_json::Value>) {
    if let Some(verified_claims) = object
        .get_mut("verified_claims")
        .and_then(serde_json::Value::as_array_mut)
    {
        verified_claims.sort_by(|left, right| {
            left.as_str()
                .unwrap_or_default()
                .cmp(right.as_str().unwrap_or_default())
        });
    }
    sort_claim_object_array(object, "claimResults");
    sort_claim_object_array(object, "checker_provenance");
}

fn sort_claim_object_array(object: &mut serde_json::Map<String, serde_json::Value>, field: &str) {
    if let Some(values) = object
        .get_mut(field)
        .and_then(serde_json::Value::as_array_mut)
    {
        values.sort_by(|left, right| {
            claim_sort_key(left)
                .cmp(claim_sort_key(right))
                .then_with(|| left.to_string().cmp(&right.to_string()))
        });
    }
}

fn claim_sort_key(value: &serde_json::Value) -> &str {
    value
        .get("claim_id")
        .or_else(|| value.get("claimId"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
}

pub(crate) fn source_report_matches_unwrapped_single_family(
    actual_report: &serde_json::Value,
    expected_report: &serde_json::Value,
) -> bool {
    expected_report
        .get("family_reports")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|reports| {
            reports.len() == 1
                && reports.first().is_some_and(|report| {
                    normalized_source_verifier_report(report)
                        == normalized_source_verifier_report(actual_report)
                })
        })
}

pub(crate) struct SourceVerifierContext {
    pub(crate) passport: chio_transaction_passport::TransactionPassport,
    pub(crate) passport_report_path: String,
    pub(crate) evidence_graph_bytes: Vec<u8>,
    pub(crate) claim_set_bytes: Vec<u8>,
    pub(crate) verifier_policy_bytes: Vec<u8>,
    pub(crate) artifacts: BTreeMap<String, Vec<u8>>,
}

#[derive(Default)]
pub(crate) struct SourceVerifierClaimRequirements {
    required_claims: Vec<String>,
    prefixes: BTreeSet<&'static str>,
}

impl SourceVerifierClaimRequirements {
    pub(crate) fn requires(&self, prefix: &'static str) -> bool {
        self.prefixes.contains(prefix)
    }
}

#[derive(Default)]
pub(crate) struct SourceRiskRoute {
    through_enterprise: bool,
    through_trust_market: bool,
    standalone: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct SourceLocalFamilyRoute {
    prefix: &'static str,
    route: ProofRoomFixtureReportRoute,
    label: &'static str,
}

pub(crate) const SOURCE_LOCAL_FAMILY_ROUTES: &[SourceLocalFamilyRoute] = &[
    SourceLocalFamilyRoute {
        prefix: CLAIM_PREFIX_COMMERCE,
        route: ProofRoomFixtureReportRoute::Commerce,
        label: "commerce",
    },
    SourceLocalFamilyRoute {
        prefix: CLAIM_PREFIX_DISCLOSURE,
        route: ProofRoomFixtureReportRoute::DisclosureLineage,
        label: "disclosure",
    },
    SourceLocalFamilyRoute {
        prefix: CLAIM_PREFIX_SWARM,
        route: ProofRoomFixtureReportRoute::Swarm,
        label: "swarm",
    },
    SourceLocalFamilyRoute {
        prefix: CLAIM_PREFIX_PUBLIC_SETTLEMENT,
        route: ProofRoomFixtureReportRoute::PublicSettlement,
        label: "public settlement",
    },
];

#[cfg(test)]
pub(crate) fn verify_transaction_passport_family_report(
    bundle_root: &Path,
    path: &Path,
) -> Result<serde_json::Value, String> {
    verify_transaction_passport_family_report_with_options(bundle_root, path, true)
}

pub(crate) fn verify_transaction_passport_family_report_with_options(
    bundle_root: &Path,
    path: &Path,
    verify_transaction_passport_signature: bool,
) -> Result<serde_json::Value, String> {
    let context = source_verifier_context_with_options(
        bundle_root,
        path,
        verify_transaction_passport_signature,
    )?;
    verify_source_passport_artifact_digests(&context)?;
    let requirements = source_verifier_claim_requirements(&context.verifier_policy_bytes)?;
    let risk_route = source_risk_route(
        &context.evidence_graph_bytes,
        requirements.requires(CLAIM_PREFIX_RISK),
    )?;
    let settlement_requires_trust_market_context =
        if requirements.required_claims.iter().any(|claim| {
            claim == chio_web3::settlement_proof::CLAIM_PUBLIC_SETTLEMENT_TRUST_MARKET_REFS_BOUND
        }) {
            embedded_public_settlement_proof_bundle(
                &context.evidence_graph_bytes,
                &context.artifacts,
            )
            .map(|bundle| bundle.has_trust_market_refs())
            .map_err(|error| format!("proof-room.public-settlement-invalid: {error}"))?
        } else {
            false
        };
    let routes_trust_market = requirements.requires(CLAIM_PREFIX_TRUST_MARKET)
        || risk_route.through_trust_market
        || settlement_requires_trust_market_context;
    reject_unrouted_source_claims(&requirements.required_claims, routes_trust_market)?;
    let mut family_reports = Vec::new();
    let mut expected_public_settlement_trust_market_context = None;
    let mut expected_commerce_trust_market_context = None;
    if routes_trust_market {
        let evidence_graph_bytes = source_scoped_evidence_graph_bytes(
            &context.evidence_graph_bytes,
            is_trust_market_evidence_graph_node,
        )?;
        let passport = source_passport_for_evidence_graph(&context.passport, &evidence_graph_bytes);
        let trusted_passport_signer_keys = crate::transaction_trusted_root_keys_from_env()
            .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        let trusted_market_authority_keys =
            crate::trust_market_trusted_authority_keys_from_env()
                .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        let report = chio_trust_market_context::verify_trust_market_context(
            &chio_trust_market_context::TrustMarketBundle {
                passport,
                evidence_graph_bytes,
                root_evidence_graph_bytes: Some(context.evidence_graph_bytes.clone()),
                verifier_policy_bytes: context.verifier_policy_bytes.clone(),
                artifacts: context.artifacts.clone(),
                trusted_passport_signer_keys,
                trusted_market_authority_keys,
            },
        )
        .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        expected_public_settlement_trust_market_context =
            Some(public_settlement_trust_market_context_from_trust_market_report(&report));
        expected_commerce_trust_market_context = Some(
            commerce_trust_market_context_from_trust_market_report(&report),
        );
        push_source_family_report(&mut family_reports, report)?;
    }

    for route in SOURCE_LOCAL_FAMILY_ROUTES {
        if requirements.requires(route.prefix) {
            push_source_local_family_report(
                &mut family_reports,
                &context,
                &requirements.required_claims,
                route,
                expected_public_settlement_trust_market_context.as_ref(),
                expected_commerce_trust_market_context.as_ref(),
            )?;
        }
    }
    if risk_route.standalone {
        family_reports.push(verify_source_standalone_risk_report(
            &context,
            &requirements.required_claims,
        )?);
    }
    if requirements.requires(CLAIM_PREFIX_AGENT_WEB) {
        let trusted_passport_signer_keys = crate::transaction_trusted_root_keys_from_env()
            .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        let agent_web_trust = agent_web_verifier_trust_from_env()
            .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?
            .with_trusted_passport_signer_keys(trusted_passport_signer_keys);
        let evidence_graph_bytes = source_scoped_evidence_graph_bytes(
            &context.evidence_graph_bytes,
            is_agent_web_evidence_graph_node,
        )?;
        let passport = source_passport_for_evidence_graph(&context.passport, &evidence_graph_bytes);
        let report = chio_agent_web_interop::verify_agent_web_interop_with_trust(
            &chio_agent_web_interop::AgentWebInteropBundle {
                passport,
                evidence_graph_bytes,
                root_evidence_graph_bytes: Some(context.evidence_graph_bytes.clone()),
                verifier_policy_bytes: context.verifier_policy_bytes.clone(),
                artifacts: context.artifacts.clone(),
            },
            &agent_web_trust,
        )
        .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        push_source_family_report(&mut family_reports, report)?;
    }
    if requirements.requires(CLAIM_PREFIX_ENTERPRISE) || risk_route.through_enterprise {
        let evidence_graph_bytes = source_scoped_evidence_graph_bytes(
            &context.evidence_graph_bytes,
            is_enterprise_evidence_graph_node,
        )?;
        let passport = source_passport_for_evidence_graph(&context.passport, &evidence_graph_bytes);
        let trusted_passport_signer_keys = crate::transaction_trusted_root_keys_from_env()
            .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        let trusted_approval_signer_keys =
            crate::enterprise_trusted_approval_signer_keys_from_env()
                .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        let trusted_risk_comptroller_signer_keys =
            crate::enterprise_trusted_risk_comptroller_signer_keys_from_env()
                .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        let trusted_receipt_kernel_keys = crate::enterprise_trusted_receipt_kernel_keys_from_env()
            .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        let report = chio_enterprise_export::verify_enterprise_export(
            &chio_enterprise_export::EnterpriseExportBundle {
                passport,
                evidence_graph_bytes,
                root_evidence_graph_bytes: Some(context.evidence_graph_bytes.clone()),
                verifier_policy_bytes: context.verifier_policy_bytes.clone(),
                artifacts: context.artifacts.clone(),
                trusted_passport_signer_keys,
                trusted_receipt_kernel_keys,
                trusted_approval_signer_keys,
                trusted_risk_comptroller_signer_keys,
            },
        )
        .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        push_source_family_report(&mut family_reports, report)?;
    }
    if requirements.requires(CLAIM_PREFIX_RUNTIME) {
        let evidence_graph_bytes = source_scoped_evidence_graph_bytes(
            &context.evidence_graph_bytes,
            is_runtime_source_node,
        )?;
        let artifacts = embedded_runtime_artifacts(&evidence_graph_bytes, &context.artifacts)
            .map_err(|error| format!("proof-room.runtime-invalid: {error}"))?;
        let runtime_trust = crate::runtime_trust_from_env()
            .map_err(|error| format!("proof-room.runtime-invalid: {error}"))?;
        let report = chio_transaction_passport::verify_runtime_security_claims_with_trust(
            &chio_transaction_passport::RuntimeSecurityBundle {
                passport: context.passport.clone(),
                evidence_graph_bytes,
                root_evidence_graph_bytes: Some(context.evidence_graph_bytes.clone()),
                verifier_policy_bytes: context.verifier_policy_bytes.clone(),
                artifacts,
            },
            &runtime_trust,
        )
        .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        push_source_family_report(&mut family_reports, report)?;
    }

    let mut report = if family_reports.is_empty() {
        verify_transaction_passport_file_with_options(
            bundle_root,
            path,
            verify_transaction_passport_signature,
        )?
    } else {
        verify_source_root_claim_set_artifacts(
            &context,
            &family_reports,
            verify_transaction_passport_signature,
        )?;
        merge_source_family_verifier_reports(
            &context,
            family_reports,
            verify_transaction_passport_signature,
        )?
    };
    ensure_source_policy_required_claims_verified(&requirements.required_claims, &report)?;
    attach_source_runtime_proof_parity_report(&context, &mut report)?;
    Ok(report)
}

fn reject_unrouted_source_claims(
    required_claims: &[String],
    routes_trust_market: bool,
) -> Result<(), String> {
    for required_claim in required_claims {
        if required_claim.starts_with(CLAIM_PREFIX_MARKET) && !routes_trust_market {
            return Err(format!(
                "proof-room.source-verifier.failed: required proof claim not verified: {required_claim}"
            ));
        }
    }
    Ok(())
}

fn public_settlement_trust_market_context_from_trust_market_report(
    report: &chio_trust_market_context::TrustMarketVerifierReport,
) -> chio_web3::settlement_proof::PublicSettlementTrustMarketContext {
    chio_web3::settlement_proof::PublicSettlementTrustMarketContext {
        collateral_position_ref: report.trust_market_sections.collateral_position_ref.clone(),
        guarantee_decision_ref: report.trust_market_sections.guarantee_decision_ref.clone(),
        sla_remedy_ref: report.trust_market_sections.sla_remedy_ref.clone(),
        slash_authority_ref: report.trust_market_sections.slash_authority_ref.clone(),
    }
}

fn commerce_trust_market_context_from_trust_market_report(
    report: &chio_trust_market_context::TrustMarketVerifierReport,
) -> chio_commerce_order::CommerceVerifiedTrustMarketContext {
    chio_commerce_order::CommerceVerifiedTrustMarketContext {
        provider_discovery_snapshot_ref: report
            .trust_market_sections
            .provider_discovery_snapshot_ref
            .clone(),
        provider_selection_report_ref: report
            .trust_market_sections
            .provider_selection_report_ref
            .clone(),
        trust_scorecard_ref: report.trust_market_sections.trust_scorecard_ref.clone(),
        reputation_import_ref: report.trust_market_sections.reputation_import_ref.clone(),
        sla_commitment_ref: report.trust_market_sections.sla_commitment_ref.clone(),
        risk_comptroller_report_ref: report
            .trust_market_sections
            .risk_comptroller_report_ref
            .clone(),
        collateral_position_ref: report.trust_market_sections.collateral_position_ref.clone(),
        guarantee_decision_ref: report.trust_market_sections.guarantee_decision_ref.clone(),
        adjudication_jurisdiction_ref: report
            .trust_market_sections
            .adjudication_jurisdiction_ref
            .clone(),
        selected_provider_subject: report
            .trust_market_sections
            .selected_provider_subject
            .clone(),
    }
}

pub(crate) fn push_source_local_family_report(
    family_reports: &mut Vec<serde_json::Value>,
    context: &SourceVerifierContext,
    required_claims: &[String],
    route: &SourceLocalFamilyRoute,
    expected_public_settlement_trust_market_context: Option<
        &chio_web3::settlement_proof::PublicSettlementTrustMarketContext,
    >,
    expected_commerce_trust_market_context: Option<
        &chio_commerce_order::CommerceVerifiedTrustMarketContext,
    >,
) -> Result<(), String> {
    match route.route {
        ProofRoomFixtureReportRoute::Commerce => {
            let bundle = embedded_commerce_order_bundle(
                &context.evidence_graph_bytes,
                &context.artifacts,
                expected_commerce_trust_market_context,
            )
            .map_err(|error| format!("proof-room.commerce-invalid: {error}"))?;
            push_source_local_family_result(
                family_reports,
                required_claims,
                route,
                chio_commerce_order::verify_commerce_order(&bundle),
            )
        }
        ProofRoomFixtureReportRoute::DisclosureLineage => {
            let bundle = embedded_disclosure_lineage_bundle(
                &context.evidence_graph_bytes,
                &context.artifacts,
            )
            .map_err(|error| format!("proof-room.disclosure-lineage-invalid: {error}"))?;
            let trust = crate::disclosure_lineage_verifier_trust_from_env()
                .map_err(|error| format!("proof-room.disclosure-lineage-invalid: {error}"))?;
            push_source_local_family_result(
                family_reports,
                required_claims,
                route,
                chio_disclosure_lineage::verify_disclosure_lineage_bundle_with_trust(
                    &bundle, &trust,
                ),
            )
        }
        ProofRoomFixtureReportRoute::Swarm => {
            let bundle =
                embedded_swarm_authority_bundle(&context.evidence_graph_bytes, &context.artifacts)
                    .map_err(|error| format!("proof-room.swarm-invalid: {error}"))?;
            let trusted_witness_keys = crate::swarm_trusted_witness_keys_for_bundle(&bundle)
                .map_err(|error| format!("proof-room.swarm-invalid: {error}"))?;
            push_source_local_family_result(
                family_reports,
                required_claims,
                route,
                chio_swarm_authority::verify_swarm_authority_bundle(&bundle, &trusted_witness_keys),
            )
        }
        ProofRoomFixtureReportRoute::PublicSettlement => {
            let proof_bundle = embedded_public_settlement_proof_bundle(
                &context.evidence_graph_bytes,
                &context.artifacts,
            )
            .map_err(|error| format!("proof-room.public-settlement-invalid: {error}"))?;
            if proof_bundle.transaction_passport_id != context.passport.id {
                return Err(format!(
                    "proof-room.public-settlement-invalid: passport mismatch: expected {}, got {}",
                    context.passport.id, proof_bundle.transaction_passport_id
                ));
            }
            let mut trust = crate::public_settlement_verifier_trust_from_env(&proof_bundle)
                .map_err(|error| format!("proof-room.public-settlement-invalid: {error}"))?;
            trust.expected_trust_market_context =
                expected_public_settlement_trust_market_context.cloned();
            push_source_local_family_result(
                family_reports,
                required_claims,
                route,
                chio_web3::settlement_proof::verify_public_settlement_proof(&proof_bundle, &trust),
            )
        }
        ProofRoomFixtureReportRoute::StandaloneRisk
        | ProofRoomFixtureReportRoute::TrustMarket
        | ProofRoomFixtureReportRoute::Enterprise
        | ProofRoomFixtureReportRoute::AgentWeb
        | ProofRoomFixtureReportRoute::Runtime
        | ProofRoomFixtureReportRoute::MinimalPassport => {
            Err("proof-room.source-verifier.route-invalid".to_string())
        }
    }
}

pub(crate) fn push_source_local_family_result<T, E>(
    family_reports: &mut Vec<serde_json::Value>,
    required_claims: &[String],
    route: &SourceLocalFamilyRoute,
    result: Result<T, E>,
) -> Result<(), String>
where
    T: serde::Serialize,
    E: std::fmt::Display,
{
    let report = result.map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
    push_verified_source_family_report(family_reports, required_claims, route, report)
}

pub(crate) fn push_verified_source_family_report<T: serde::Serialize>(
    family_reports: &mut Vec<serde_json::Value>,
    required_claims: &[String],
    route: &SourceLocalFamilyRoute,
    report: T,
) -> Result<(), String> {
    let report = source_verifier_report_value(report)?;
    ensure_source_required_claims_verified(required_claims, &report, route.prefix, route.label)?;
    family_reports.push(report);
    Ok(())
}

pub(crate) fn push_source_family_report<T: serde::Serialize>(
    family_reports: &mut Vec<serde_json::Value>,
    report: T,
) -> Result<(), String> {
    let report = source_verifier_report_value(report)?;
    family_reports.push(report);
    Ok(())
}

pub(crate) fn source_verifier_report_value<T: serde::Serialize>(
    report: T,
) -> Result<serde_json::Value, String> {
    serde_json::to_value(report)
        .map_err(|error| format!("proof-room.source-verifier.report-encode: {error}"))
}

pub(crate) fn source_verifier_context_with_options(
    bundle_root: &Path,
    path: &Path,
    verify_transaction_passport_signature: bool,
) -> Result<SourceVerifierContext, String> {
    let passport_bytes =
        fs::read(path).map_err(|error| format!("proof-room.passport.unreadable: {error}"))?;
    let passport: chio_transaction_passport::TransactionPassport =
        serde_json::from_slice(&passport_bytes)
            .map_err(|error| format!("proof-room.passport.invalid-json: {error}"))?;
    chio_transaction_passport::verify_minimal_passport_schema(&passport)
        .map_err(|error| format!("proof-room.passport.invalid: {error}"))?;
    if verify_transaction_passport_signature {
        let trusted_root_signer_keys = crate::transaction_trusted_root_keys_from_env()
            .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        chio_transaction_passport::verify_transaction_passport_signature(
            &passport,
            &trusted_root_signer_keys,
        )
        .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
    }
    let passport_dir = path
        .parent()
        .ok_or_else(|| "proof-room.passport.path-invalid".to_string())?;
    let evidence_graph_path =
        resolve_nested_bundle_path(bundle_root, passport_dir, &passport.evidence_graph_path)?;
    let claim_set_path =
        resolve_nested_bundle_path(bundle_root, passport_dir, &passport.claim_set_path)?;
    let verifier_policy_path =
        resolve_nested_bundle_path(bundle_root, passport_dir, &passport.verifier_policy_path)?;
    let evidence_graph_bytes = fs::read(&evidence_graph_path)
        .map_err(|error| format!("proof-room.evidence-graph.unreadable: {error}"))?;
    let claim_set_bytes = fs::read(&claim_set_path)
        .map_err(|error| format!("proof-room.claim-set.unreadable: {error}"))?;
    let verifier_policy_bytes = fs::read(&verifier_policy_path)
        .map_err(|error| format!("proof-room.verifier-policy.unreadable: {error}"))?;
    chio_transaction_passport::validate_verifier_policy_artifact(&verifier_policy_bytes)
        .map_err(|error| format!("proof-room.verifier-policy.invalid: {error}"))?;
    let artifacts =
        load_standalone_evidence_graph_artifacts(bundle_root, passport_dir, &evidence_graph_bytes)?;
    let passport_report_path = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    Ok(SourceVerifierContext {
        passport,
        passport_report_path,
        evidence_graph_bytes,
        claim_set_bytes,
        verifier_policy_bytes,
        artifacts,
    })
}

pub(crate) fn verify_source_passport_artifact_digests(
    context: &SourceVerifierContext,
) -> Result<(), String> {
    let evidence_graph_sha256 = sha256_hex(&context.evidence_graph_bytes);
    if evidence_graph_sha256 != context.passport.evidence_graph_sha256 {
        return Err(format!(
            "proof-room.source-verifier.failed: evidence graph digest mismatch: expected {}, got {}",
            context.passport.evidence_graph_sha256, evidence_graph_sha256
        ));
    }
    let verifier_policy_sha256 = sha256_hex(&context.verifier_policy_bytes);
    if verifier_policy_sha256 != context.passport.verifier_policy_sha256 {
        return Err(format!(
            "proof-room.source-verifier.failed: verifier policy digest mismatch: expected {}, got {}",
            context.passport.verifier_policy_sha256, verifier_policy_sha256
        ));
    }

    let claim_set_sha256 = sha256_hex(&context.claim_set_bytes);
    if claim_set_sha256 != context.passport.claim_set_sha256 {
        return Err(format!(
            "proof-room.source-verifier.failed: evidence graph artifact digest mismatch for {}: expected {}, got {}",
            context.passport.claim_set_path, context.passport.claim_set_sha256, claim_set_sha256
        ));
    }
    Ok(())
}

pub(crate) fn source_verifier_claim_requirements(
    policy_bytes: &[u8],
) -> Result<SourceVerifierClaimRequirements, String> {
    let policy: serde_json::Value = serde_json::from_slice(policy_bytes)
        .map_err(|error| format!("proof-room.verifier-policy.invalid-json: {error}"))?;
    let mut requirements = SourceVerifierClaimRequirements::default();
    if let Some(claims) = policy
        .get("required_claims")
        .and_then(serde_json::Value::as_array)
    {
        for claim in claims {
            let Some(claim) = claim.as_str() else {
                return Err("proof-room.verifier-policy.required-claim-invalid".to_string());
            };
            requirements.required_claims.push(claim.to_string());
            let mut supported = false;
            for prefix in SOURCE_VERIFIER_CLAIM_PREFIXES {
                if claim.starts_with(prefix) {
                    requirements.prefixes.insert(prefix);
                    supported = true;
                }
            }
            if !supported {
                return Err(format!("unsupported required proof claim: {claim}"));
            }
        }
    }
    Ok(requirements)
}

pub(crate) fn source_risk_route(
    evidence_graph_bytes: &[u8],
    requires_risk: bool,
) -> Result<SourceRiskRoute, String> {
    if !requires_risk {
        return Ok(SourceRiskRoute::default());
    }
    let through_enterprise =
        embedded_evidence_graph_has_role(evidence_graph_bytes, is_enterprise_risk_context_role)?;
    let through_trust_market =
        embedded_evidence_graph_has_role(evidence_graph_bytes, is_trust_market_risk_context_role)?;
    Ok(SourceRiskRoute {
        through_enterprise,
        through_trust_market,
        standalone: !through_enterprise && !through_trust_market,
    })
}

pub(crate) fn source_scoped_evidence_graph_bytes(
    evidence_graph_bytes: &[u8],
    include_node: fn(&serde_json::Value) -> bool,
) -> Result<Vec<u8>, String> {
    let mut graph: serde_json::Value = serde_json::from_slice(evidence_graph_bytes)
        .map_err(|error| format!("proof-room.evidence-graph.invalid-json: {error}"))?;
    let nodes = graph
        .get_mut("nodes")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| "proof-room.evidence-graph.nodes-invalid".to_string())?;

    let mut retained_ids = BTreeSet::new();
    nodes.retain(|node| {
        if !include_node(node) {
            return false;
        }
        let Some(id) = node.get("id").and_then(serde_json::Value::as_str) else {
            return false;
        };
        retained_ids.insert(id.to_string());
        true
    });

    if let Some(edges) = graph
        .get_mut("edges")
        .and_then(serde_json::Value::as_array_mut)
    {
        edges.retain(|edge| {
            let Some(from) = edge.get("from").and_then(serde_json::Value::as_str) else {
                return false;
            };
            let Some(to) = edge.get("to").and_then(serde_json::Value::as_str) else {
                return false;
            };
            retained_ids.contains(from) && retained_ids.contains(to)
        });
    }

    serde_json::to_vec(&graph)
        .map_err(|error| format!("proof-room.evidence-graph.encode-failed: {error}"))
}

pub(crate) fn source_passport_for_evidence_graph(
    passport: &chio_transaction_passport::TransactionPassport,
    evidence_graph_bytes: &[u8],
) -> chio_transaction_passport::TransactionPassport {
    let mut passport = passport.clone();
    passport.evidence_graph_sha256 = sha256_hex(evidence_graph_bytes);
    passport
}

pub(crate) fn is_trust_market_evidence_graph_node(node: &serde_json::Value) -> bool {
    let Some(role) = node.get("role").and_then(serde_json::Value::as_str) else {
        return false;
    };
    matches!(role, "claim-set" | "receipt" | "verifier-policy" | "report")
        || is_trust_market_artifact_role(role)
}

pub(crate) fn is_trust_market_artifact_role(role: &str) -> bool {
    matches!(
        role,
        "provider-discovery-snapshot"
            | "receipt"
            | "provider-selection-report"
            | "trust-scorecard-snapshot"
            | "reputation-import-report"
            | "sla-commitment"
            | "sla-performance-report"
            | "risk-comptroller-report"
            | "collateral-position-report"
            | "guarantee-decision"
            | "adjudication-jurisdiction-receipt"
    )
}

pub(crate) fn is_agent_web_evidence_graph_node(node: &serde_json::Value) -> bool {
    let Some(role) = node.get("role").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let schema = node.get("schema").and_then(serde_json::Value::as_str);
    if role == "receipt" {
        return schema == Some(CHIO_RECEIPT_SCHEMA);
    }
    matches!(
        role,
        "agent-web-proof-envelope"
            | "claim-set"
            | "external-projection-manifest"
            | "external-subject"
            | "commerce-provider-passport"
            | "commerce-reputation-snapshot"
            | "commerce-federation-trust-bundle"
            | "verifier-policy"
            | "report"
    )
}

pub(crate) fn is_enterprise_evidence_graph_node(node: &serde_json::Value) -> bool {
    let Some(role) = node.get("role").and_then(serde_json::Value::as_str) else {
        return false;
    };
    matches!(
        role,
        "risk-comptroller-report"
            | "claim-set"
            | "data-governance-report"
            | "evidence-export-bundle"
            | "telemetry-projection"
            | "approval-case"
            | "control-evidence-map"
            | "adjudication-jurisdiction-receipt"
            | "verifier-policy"
            | "report"
    )
}

fn is_runtime_source_node(node: &serde_json::Value) -> bool {
    let Some(role) = node.get("role").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let schema = node.get("schema").and_then(serde_json::Value::as_str);
    if role == "receipt" {
        return schema == Some("chio.runtime.terminal-receipt.v1");
    }
    matches!(
        role,
        "advisory-observation"
            | "claim-set"
            | "request"
            | "verifier-policy"
            | "policy-activation-receipt"
            | "execution-lease"
            | "trust-root"
            | "tool-server-ack"
            | "trusted-time-proof"
            | "revocation-freshness-proof"
            | "sandbox-attestation"
            | "swarm-task-graph"
            | "swarm-budget-pool"
            | "swarm-join-receipt"
            | "swarm-route-plan-receipt"
            | "runtime-attack-simulation-report"
            | "runtime-chaos-run-report"
    )
}

pub(crate) fn verify_source_standalone_risk_report(
    context: &SourceVerifierContext,
    required_claims: &[String],
) -> Result<serde_json::Value, String> {
    let trusted_risk_comptroller_signer_keys =
        crate::enterprise_trusted_risk_comptroller_signer_keys_from_env()
            .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
    verify_source_standalone_risk_report_with_keys(
        context,
        required_claims,
        &trusted_risk_comptroller_signer_keys,
    )
}

pub(crate) fn verify_source_standalone_risk_report_with_keys(
    context: &SourceVerifierContext,
    required_claims: &[String],
    trusted_risk_comptroller_signer_keys: &[chio_core_types::PublicKey],
) -> Result<serde_json::Value, String> {
    let risk_report_value =
        embedded_risk_comptroller_report_value(&context.evidence_graph_bytes, &context.artifacts)
            .map_err(|error| format!("proof-room.risk-invalid: {error}"))?;
    let risk_report = chio_risk_comptroller::validate_signed_risk_report(
        &context.passport,
        &risk_report_value,
        trusted_risk_comptroller_signer_keys,
    )
    .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
    let risk_evidence_graph =
        parse_embedded_evidence_graph(&context.evidence_graph_bytes, "evidence graph")
            .map_err(|error| format!("proof-room.evidence-graph-invalid: {error}"))?;
    chio_risk_comptroller::validate_risk_evidence_refs(&risk_report, |evidence_ref, kind| {
        embedded_risk_evidence_ref_matches(
            &risk_evidence_graph.nodes,
            &context.artifacts,
            evidence_ref,
            kind,
        )
    })
    .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
    let verified_claims = vec![CLAIM_RISK_COMPTROLLER_REPORT_BOUND.to_string()];
    let report = serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": format!("verifier-report-{}", context.passport.id),
        "issued_at": context.passport.issued_at.clone(),
        "verdict": "verified",
        "passport_id": context.passport.id.clone(),
        "passport_path": context.passport_report_path,
        "evidence_graph_sha256": context.passport.evidence_graph_sha256.clone(),
        "evidence_graph_path": context.passport.evidence_graph_path.clone(),
        "verifier_policy_sha256": context.passport.verifier_policy_sha256.clone(),
        "verifier_policy_path": context.passport.verifier_policy_path.clone(),
        "risk_comptroller_report_ref": risk_report.id,
        "order_id": risk_report.order_id,
        "subject": risk_report.subject,
        "verified_claims": verified_claims,
    });
    ensure_source_required_claims_verified(required_claims, &report, CLAIM_PREFIX_RISK, "risk")?;
    Ok(report)
}

pub(crate) fn merge_source_family_verifier_reports(
    context: &SourceVerifierContext,
    family_reports: Vec<serde_json::Value>,
    verify_transaction_passport_signature: bool,
) -> Result<serde_json::Value, String> {
    let verified_claim_ids = source_family_verified_claims(&family_reports);
    let verified_claims = verified_claim_ids
        .iter()
        .cloned()
        .map(serde_json::Value::String)
        .collect::<Vec<_>>();
    let claim_results = source_claim_results(&verified_claims);
    let trusted_checkpoint_signer_keys = if verify_transaction_passport_signature {
        crate::transaction_trusted_checkpoint_keys_from_env()
            .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?
    } else {
        Vec::new()
    };
    let transparency_state =
        chio_transaction_passport::transaction_evidence_graph_transparency_state_with_anchors(
            &context.evidence_graph_bytes,
            &context.artifacts,
            &trusted_checkpoint_signer_keys,
        )
        .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;

    // Fail closed: derive the merged verdict from the family reports rather
    // than hardcoding "verified". Correctness must not rely solely on every
    // family verifier returning Err on failure; an Ok-but-rejected family
    // report must downgrade the merge. Mirrors xtask launch_acceptance
    // overall_verdict (derive, do not assume).
    let all_families_verified = family_reports.iter().all(source_family_report_is_verified);
    let (verdict, accepted, state) = if all_families_verified {
        ("verified", true, "verified")
    } else {
        ("rejected", false, "rejected")
    };

    Ok(serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": format!("verifier-report-{}", context.passport.id),
        "issued_at": context.passport.issued_at.clone(),
        "verdict": verdict,
        "accepted": accepted,
        "state": state,
        "passport_id": context.passport.id.clone(),
        "passport_path": context.passport_report_path,
        "evidence_graph_sha256": context.passport.evidence_graph_sha256.clone(),
        "evidence_graph_path": context.passport.evidence_graph_path.clone(),
        "claim_set_sha256": context.passport.claim_set_sha256.clone(),
        "claim_set_path": context.passport.claim_set_path.clone(),
        "verifier_policy_sha256": context.passport.verifier_policy_sha256.clone(),
        "verifier_policy_path": context.passport.verifier_policy_path.clone(),
        "transparencyState": transparency_state,
        "verified_claims": verified_claims,
        "claimResults": claim_results,
        "family_reports": family_reports,
        "checker_provenance": source_claim_checker_provenance(&verified_claims),
    }))
}

/// A family report counts as verified only when its own verdict is "verified"
/// and any accepted/state fields it carries are affirmative. Some family
/// reports (for example standalone risk) omit accepted/state, so those are
/// treated as satisfied when absent but must be positive when present. Fail
/// closed: anything short of an affirmative family verdict is not verified.
fn source_family_report_is_verified(report: &serde_json::Value) -> bool {
    let verdict_verified =
        report.get("verdict").and_then(serde_json::Value::as_str) == Some("verified");
    let accepted_ok = match report.get("accepted") {
        Some(value) => value.as_bool() == Some(true),
        None => true,
    };
    let state_ok = match report.get("state") {
        Some(value) => value.as_str() == Some("verified"),
        None => true,
    };
    verdict_verified && accepted_ok && state_ok
}

pub(crate) fn verify_source_root_claim_set_artifacts(
    context: &SourceVerifierContext,
    family_reports: &[serde_json::Value],
    verify_transaction_passport_signature: bool,
) -> Result<(), String> {
    let externally_verified_claims = source_family_verified_claims(family_reports);
    if verify_transaction_passport_signature {
        let trusted_root_signer_keys = crate::transaction_trusted_root_keys_from_env()
            .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        let trusted_checkpoint_signer_keys =
            crate::transaction_trusted_checkpoint_keys_from_env()
                .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        let mut root_artifacts = context.artifacts.clone();
        root_artifacts.insert(
            context.passport.claim_set_path.clone(),
            context.claim_set_bytes.clone(),
        );
        chio_transaction_passport::verify_passport_root_and_claim_set_artifacts_with_transparency_anchors(
            &context.passport,
            context.passport_report_path.clone(),
            &context.evidence_graph_bytes,
            &context.verifier_policy_bytes,
            &root_artifacts,
            chio_transaction_passport::TransactionTrustAnchors {
                passport_root_signers: &trusted_root_signer_keys,
                checkpoint_signers: &trusted_checkpoint_signer_keys,
            },
            &externally_verified_claims,
        )
    } else {
        let mut root_artifacts = BTreeMap::new();
        root_artifacts.insert(
            context.passport.claim_set_path.clone(),
            context.claim_set_bytes.clone(),
        );
        chio_transaction_passport::verify_passport_root_and_claim_set_artifacts_unchecked_signature_with_external_claims(
            &context.passport,
            context.passport_report_path.clone(),
            &context.evidence_graph_bytes,
            &context.verifier_policy_bytes,
            &root_artifacts,
            &externally_verified_claims,
        )
    }
    .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
    Ok(())
}

pub(crate) fn source_family_verified_claims(family_reports: &[serde_json::Value]) -> Vec<String> {
    let mut seen_claims = BTreeSet::new();
    let mut verified_claims = Vec::new();
    for report in family_reports {
        for claim in source_report_verified_claims(report) {
            if seen_claims.insert(claim.clone()) {
                verified_claims.push(claim);
            }
        }
    }
    verified_claims
}

pub(crate) fn source_claim_results(
    verified_claims: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    verified_claims
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(|claim_id| {
            serde_json::json!({
                "claim_id": claim_id,
                "status": "verified",
                "verifier_module": source_checker_for_claim(claim_id)
            })
        })
        .collect()
}

pub(crate) fn source_claim_checker_provenance(
    verified_claims: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    verified_claims
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(|claim_id| {
            serde_json::json!({
                "claim_id": claim_id,
                "checker": source_checker_for_claim(claim_id)
            })
        })
        .collect()
}

pub(crate) fn source_checker_for_claim(claim_id: &str) -> &'static str {
    if claim_id.starts_with("claim.agent_web.") {
        "chio proof verify --require external-envelope"
    } else if claim_id.starts_with("claim.commerce.") {
        "chio proof verify --require commerce"
    } else if claim_id.starts_with("claim.disclosure.") {
        "chio proof verify --require disclosure"
    } else if claim_id.starts_with("claim.enterprise.") {
        "chio proof verify --require enterprise"
    } else if claim_id.starts_with("claim.public_settlement.") {
        "chio proof verify --require settlement"
    } else if claim_id.starts_with("claim.risk.") {
        "chio proof verify --require risk"
    } else if claim_id.starts_with("claim.runtime.") {
        "chio proof verify --require runtime"
    } else if claim_id.starts_with("claim.swarm.") {
        "chio proof verify --require delegation"
    } else if claim_id.starts_with("claim.trust_market.") {
        "chio proof verify --require trust-market"
    } else {
        "chio proof verify"
    }
}

pub(crate) fn ensure_source_required_claims_verified(
    required_claims: &[String],
    report: &serde_json::Value,
    claim_prefix: &str,
    label: &str,
) -> Result<(), String> {
    let verified_claims = source_report_verified_claims(report);
    for required_claim in required_claims {
        if required_claim.starts_with(claim_prefix)
            && !verified_claims.iter().any(|claim| claim == required_claim)
        {
            return Err(format!(
                "proof-room.source-verifier.failed: required {label} claim not verified: {required_claim}"
            ));
        }
    }
    Ok(())
}

pub(crate) fn ensure_source_policy_required_claims_verified(
    required_claims: &[String],
    report: &serde_json::Value,
) -> Result<(), String> {
    for required_claim in required_claims {
        if !source_report_verifies_required_claim(report, required_claim) {
            return Err(format!(
                "proof-room.source-verifier.failed: required proof claim not verified: {required_claim}"
            ));
        }
    }
    Ok(())
}

pub(crate) fn source_report_verifies_required_claim(
    report: &serde_json::Value,
    required_claim: &str,
) -> bool {
    source_report_verified_claims(report)
        .iter()
        .any(|claim| claim == required_claim)
        || source_transaction_report_verifies_claim(report, required_claim)
}

fn source_transaction_report_verifies_claim(
    report: &serde_json::Value,
    required_claim: &str,
) -> bool {
    STANDALONE_TRANSACTION_VERIFIED_CLAIMS.contains(&required_claim)
        && report
            .get("schema")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|schema| schema == "chio.transaction.verifier-report.v1")
        && report
            .get("verdict")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|verdict| verdict == "verified")
}

pub(crate) fn source_report_verified_claims(report: &serde_json::Value) -> Vec<String> {
    report
        .get("verified_claims")
        .or_else(|| report.get("verifiedClaims"))
        .and_then(serde_json::Value::as_array)
        .map(|claims| {
            claims
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn verify_transaction_passport_file_with_options(
    bundle_root: &Path,
    path: &Path,
    verify_transaction_passport_signature: bool,
) -> Result<serde_json::Value, String> {
    let passport_bytes =
        fs::read(path).map_err(|error| format!("proof-room.passport.unreadable: {error}"))?;
    let passport: chio_transaction_passport::TransactionPassport =
        serde_json::from_slice(&passport_bytes)
            .map_err(|error| format!("proof-room.passport.invalid-json: {error}"))?;
    let trusted_root_signer_keys = crate::transaction_trusted_root_keys_from_env()
        .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
    if verify_transaction_passport_signature {
        chio_transaction_passport::verify_transaction_passport_signature(
            &passport,
            &trusted_root_signer_keys,
        )
        .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
    }
    let passport_dir = path
        .parent()
        .ok_or_else(|| "proof-room.passport.path-invalid".to_string())?;
    let evidence_graph_path =
        resolve_nested_bundle_path(bundle_root, passport_dir, &passport.evidence_graph_path)?;
    let claim_set_path =
        resolve_nested_bundle_path(bundle_root, passport_dir, &passport.claim_set_path)?;
    let verifier_policy_path =
        resolve_nested_bundle_path(bundle_root, passport_dir, &passport.verifier_policy_path)?;
    let evidence_graph_bytes = fs::read(&evidence_graph_path)
        .map_err(|error| format!("proof-room.evidence-graph.unreadable: {error}"))?;
    let claim_set_bytes = fs::read(&claim_set_path)
        .map_err(|error| format!("proof-room.claim-set.unreadable: {error}"))?;
    let verifier_policy_bytes = fs::read(&verifier_policy_path)
        .map_err(|error| format!("proof-room.verifier-policy.unreadable: {error}"))?;
    let artifacts =
        load_standalone_evidence_graph_artifacts(bundle_root, passport_dir, &evidence_graph_bytes)?;
    let passport_report_path = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    let report = if verify_transaction_passport_signature {
        let trusted_checkpoint_signer_keys = crate::transaction_trusted_checkpoint_keys_from_env()
            .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        chio_transaction_passport::
            verify_standalone_minimal_passport_artifacts_with_transparency_anchors(
            &passport,
            passport_report_path.clone(),
            &evidence_graph_bytes,
            &verifier_policy_bytes,
            &artifacts,
            chio_transaction_passport::TransactionTrustAnchors {
                passport_root_signers: &trusted_root_signer_keys,
                checkpoint_signers: &trusted_checkpoint_signer_keys,
            },
        )
    } else {
        chio_transaction_passport::verify_standalone_minimal_passport_artifacts_unchecked_signature(
            &passport,
            passport_report_path.clone(),
            &evidence_graph_bytes,
            &verifier_policy_bytes,
            &artifacts,
            &trusted_root_signer_keys,
        )
    }
    .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
    let mut report = serde_json::to_value(report)
        .map_err(|error| format!("proof-room.source-verifier.report-encode: {error}"))?;
    let context = SourceVerifierContext {
        passport,
        passport_report_path,
        evidence_graph_bytes,
        claim_set_bytes,
        verifier_policy_bytes,
        artifacts,
    };
    attach_source_runtime_proof_parity_report(&context, &mut report)?;
    Ok(report)
}

#[derive(serde::Deserialize)]
pub(crate) struct StandaloneEvidenceGraphArtifactIndex {
    nodes: Vec<StandaloneEvidenceGraphArtifactNode>,
}

#[derive(serde::Deserialize)]
pub(crate) struct StandaloneEvidenceGraphArtifactNode {
    path: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct SourceRuntimeParityEvidenceGraph {
    nodes: Vec<SourceRuntimeParityEvidenceNode>,
}

#[derive(serde::Deserialize)]
pub(crate) struct SourceRuntimeParityEvidenceNode {
    path: String,
    schema: String,
    sha256: String,
    #[serde(default)]
    role: String,
}

pub(crate) fn attach_source_runtime_proof_parity_report(
    context: &SourceVerifierContext,
    report: &mut serde_json::Value,
) -> Result<(), String> {
    let Some(parity_report) = source_runtime_proof_parity_report(context)? else {
        return Ok(());
    };
    let regeneration_hashes = validate_source_runtime_proof_regeneration_artifacts(context)?;
    ensure_source_runtime_parity_report_binds_regenerated_artifacts(
        &parity_report,
        &regeneration_hashes,
    )?;
    let report_object = report
        .as_object_mut()
        .ok_or_else(|| "proof-room.source-verifier.report-not-object".to_string())?;
    report_object.insert("runtime_proof_parity_report".to_string(), parity_report);
    Ok(())
}

pub(crate) fn source_runtime_proof_parity_report(
    context: &SourceVerifierContext,
) -> Result<Option<serde_json::Value>, String> {
    let graph: SourceRuntimeParityEvidenceGraph =
        serde_json::from_slice(&context.evidence_graph_bytes)
            .map_err(|error| format!("proof-room.evidence-graph.invalid-json: {error}"))?;
    let parity_nodes = graph
        .nodes
        .into_iter()
        .filter(|node| {
            node.role == "runtime-proof-parity-report"
                || node.schema == chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA
        })
        .collect::<Vec<_>>();
    let node = match parity_nodes.as_slice() {
        [] => return Ok(None),
        [node] => node,
        _ => return Err("proof-room.runtime-parity.multiple-reports".to_string()),
    };
    if node.schema != chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA {
        return Err(format!(
            "proof-room.runtime-parity.schema-unsupported: {}",
            node.schema
        ));
    }
    let bytes = context
        .artifacts
        .get(&node.path)
        .ok_or_else(|| format!("proof-room.runtime-parity.artifact-missing: {}", node.path))?;
    let actual_sha256 = sha256_hex(bytes);
    if actual_sha256 != node.sha256 {
        return Err(format!(
            "proof-room.runtime-parity.hash-mismatch: expected {}, got {}",
            node.sha256, actual_sha256
        ));
    }
    let report: chio_runtime_proof_parity::RuntimeProofParityReport = serde_json::from_slice(bytes)
        .map_err(|error| format!("proof-room.runtime-parity.invalid-json: {error}"))?;
    chio_runtime_proof_parity::validate_runtime_proof_parity_report(&report)
        .map_err(|error| format!("proof-room.runtime-parity.invalid: {error}"))?;
    if !report.accepted {
        return Err(format!(
            "proof-room.runtime-parity.failed: {}",
            report
                .failure_code
                .as_deref()
                .unwrap_or("runtime proof parity report rejected")
        ));
    }
    serde_json::to_value(report)
        .map(Some)
        .map_err(|error| format!("proof-room.runtime-parity.report-encode: {error}"))
}

pub(crate) fn validate_source_runtime_proof_regeneration_artifacts(
    context: &SourceVerifierContext,
) -> Result<SourceRuntimeProofRegenerationHashes, String> {
    let graph: SourceRuntimeParityEvidenceGraph =
        serde_json::from_slice(&context.evidence_graph_bytes)
            .map_err(|error| format!("proof-room.evidence-graph.invalid-json: {error}"))?;
    let proof_regeneration_report = source_runtime_graph_artifact_bytes(
        context,
        &graph.nodes,
        "runtime-proof-regeneration-report",
        Some(chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA),
    )?;
    let proof_regeneration_input = source_runtime_graph_artifact_bytes(
        context,
        &graph.nodes,
        "runtime-proof-regeneration-input",
        Some(chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA),
    )?;
    let evidence_manifest = source_runtime_graph_artifact_bytes(
        context,
        &graph.nodes,
        "runtime-evidence-manifest",
        Some(chio_runtime_proof_parity::CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA),
    )?;
    let workflow_run_report = source_runtime_graph_artifact_bytes(
        context,
        &graph.nodes,
        "runtime-workflow-run-report",
        Some(chio_runtime_proof_parity::CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA),
    )?;
    let proof_package =
        source_runtime_graph_artifact_bytes(context, &graph.nodes, "runtime-proof-package", None)?;
    let verifier_report = source_runtime_graph_artifact_bytes(
        context,
        &graph.nodes,
        "runtime-verifier-report",
        None,
    )?;
    let workflow_receipt = source_runtime_graph_artifact_bytes(
        context,
        &graph.nodes,
        "runtime-workflow-receipt",
        None,
    )?;

    chio_runtime_proof_parity::validate_runtime_proof_regeneration_artifacts(
        chio_runtime_proof_parity::RuntimeProofRegenerationArtifacts {
            proof_regeneration_report,
            proof_regeneration_input,
            evidence_manifest,
            workflow_run_report,
            proof_package,
            verifier_report,
            workflow_receipt,
        },
    )
    .map_err(source_runtime_regeneration_error)?;
    ensure_source_runtime_regeneration_records_bind_workflow_steps(
        proof_regeneration_report,
        workflow_run_report,
    )?;
    Ok(SourceRuntimeProofRegenerationHashes {
        proof_package_sha256: source_runtime_artifact_canonical_sha256(proof_package)?,
        verifier_report_sha256: source_runtime_artifact_canonical_sha256(verifier_report)?,
    })
}

fn source_runtime_regeneration_error(
    error: chio_runtime_proof_parity::RuntimeProofParityError,
) -> String {
    if error.code() == "runtime_proof_regeneration_workflow_step_evidence_mismatch" {
        return format!(
            "proof-room.runtime-regeneration.source-record-workflow-step-mismatch: {}",
            error.detail()
        );
    }
    format!("proof-room.runtime-regeneration.invalid: {error}")
}

fn ensure_source_runtime_regeneration_records_bind_workflow_steps(
    proof_regeneration_report: &[u8],
    workflow_run_report: &[u8],
) -> Result<(), String> {
    let proof_report: serde_json::Value = serde_json::from_slice(proof_regeneration_report)
        .map_err(|error| format!("proof-room.runtime-regeneration.invalid-json: {error}"))?;
    let workflow_report: serde_json::Value = serde_json::from_slice(workflow_run_report)
        .map_err(|error| format!("proof-room.runtime-regeneration.invalid-json: {error}"))?;
    let source_records = proof_report
        .get("sourceRecords")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "proof-room.runtime-regeneration.source-records-missing".to_string())?;
    let workflow_steps = workflow_report
        .get("stepEvidence")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "proof-room.runtime-regeneration.workflow-steps-missing".to_string())?;

    for source_record in source_records {
        let step_index = source_record
            .get("stepIndex")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                "proof-room.runtime-regeneration.source-record-step-missing".to_string()
            })?;
        let workflow_step = workflow_steps
            .iter()
            .find(|step| {
                step.get("stepIndex").and_then(serde_json::Value::as_u64) == Some(step_index)
            })
            .ok_or_else(|| {
                format!("proof-room.runtime-regeneration.source-record-step-unbound: {step_index}")
            })?;
        for field in [
            "admissionReportSha256",
            "toolReceiptSha256",
            "bilateralDsseSha256",
            "workflowStepSha256",
        ] {
            let source_value = source_runtime_required_str(source_record, field)?;
            let workflow_value = source_runtime_required_str(workflow_step, field)?;
            if source_value != workflow_value {
                return Err(format!(
                    "proof-room.runtime-regeneration.source-record-workflow-step-mismatch: step {step_index} {field}"
                ));
            }
        }
    }
    Ok(())
}

fn source_runtime_required_str<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!("proof-room.runtime-regeneration.source-record-field-missing: {field}")
        })
}

pub(crate) struct SourceRuntimeProofRegenerationHashes {
    proof_package_sha256: String,
    verifier_report_sha256: String,
}

fn ensure_source_runtime_parity_report_binds_regenerated_artifacts(
    parity_report: &serde_json::Value,
    regeneration_hashes: &SourceRuntimeProofRegenerationHashes,
) -> Result<(), String> {
    ensure_source_runtime_parity_hash_matches(
        parity_report,
        "runtimeProofPackageSha256",
        &regeneration_hashes.proof_package_sha256,
        "proof-room.runtime-parity.package-hash-mismatch",
    )?;
    ensure_source_runtime_parity_hash_matches(
        parity_report,
        "runtimeVerifierReportSha256",
        &regeneration_hashes.verifier_report_sha256,
        "proof-room.runtime-parity.verifier-report-hash-mismatch",
    )
}

fn ensure_source_runtime_parity_hash_matches(
    parity_report: &serde_json::Value,
    field: &str,
    expected: &str,
    label: &'static str,
) -> Result<(), String> {
    let actual = parity_report
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("proof-room.runtime-parity.missing-field: {field}"))?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label}: expected {expected}, got {actual}"))
    }
}

fn source_runtime_artifact_canonical_sha256(bytes: &[u8]) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("proof-room.runtime-regeneration.invalid-json: {error}"))?;
    let canonical_bytes = chio_core_types::canonical_json_bytes(&value)
        .map_err(|error| format!("proof-room.runtime-regeneration.canonical-json: {error}"))?;
    Ok(sha256_hex(&canonical_bytes))
}

pub(crate) fn source_runtime_graph_artifact_bytes<'a>(
    context: &'a SourceVerifierContext,
    nodes: &[SourceRuntimeParityEvidenceNode],
    role: &str,
    schema: Option<&str>,
) -> Result<&'a [u8], String> {
    let matching_nodes = nodes
        .iter()
        .filter(|node| {
            node.role == role
                || schema.is_some_and(|expected_schema| node.schema.as_str() == expected_schema)
        })
        .collect::<Vec<_>>();
    let node = match matching_nodes.as_slice() {
        [node] => *node,
        [] => {
            return Err(format!(
                "proof-room.runtime-regeneration.artifact-missing: {role}"
            ));
        }
        _ => {
            return Err(format!(
                "proof-room.runtime-regeneration.artifact-duplicate: {role}"
            ));
        }
    };
    if let Some(expected_schema) = schema {
        if node.schema != expected_schema {
            return Err(format!(
                "proof-room.runtime-regeneration.schema-unsupported: {role}: {}",
                node.schema
            ));
        }
    }
    let bytes = context.artifacts.get(&node.path).ok_or_else(|| {
        format!(
            "proof-room.runtime-regeneration.artifact-missing: {}",
            node.path
        )
    })?;
    let actual_sha256 = sha256_hex(bytes);
    if actual_sha256 != node.sha256 {
        return Err(format!(
            "proof-room.runtime-regeneration.hash-mismatch: {role}: expected {}, got {}",
            node.sha256, actual_sha256
        ));
    }
    Ok(bytes)
}

pub(crate) fn load_standalone_evidence_graph_artifacts(
    bundle_root: &Path,
    passport_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let graph: StandaloneEvidenceGraphArtifactIndex = serde_json::from_slice(evidence_graph_bytes)
        .map_err(|error| format!("proof-room.evidence-graph.invalid-json: {error}"))?;
    let mut artifacts = BTreeMap::new();
    for node in graph.nodes {
        validate_bundle_relative_path(&node.path)?;
        let artifact_path = if bundle_root.join(&node.path).exists() {
            resolve_nested_bundle_path(bundle_root, bundle_root, &node.path)?
        } else if passport_dir.join(&node.path).exists() {
            resolve_nested_bundle_path(bundle_root, passport_dir, &node.path)?
        } else {
            continue;
        };
        let bytes = fs::read(&artifact_path)
            .map_err(|error| format!("proof-room.artifact.unreadable: {}: {error}", node.path))?;
        artifacts.insert(node.path, bytes);
    }
    load_enterprise_export_sidecar_artifacts(bundle_root, passport_dir, &mut artifacts)?;
    Ok(artifacts)
}

pub(crate) fn load_enterprise_export_sidecar_artifacts(
    bundle_root: &Path,
    passport_dir: &Path,
    artifacts: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    let export_bundle_paths = artifacts
        .iter()
        .filter_map(|(path, bytes)| {
            let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
            (value.get("schema").and_then(serde_json::Value::as_str)
                == Some(ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA))
            .then(|| path.clone())
        })
        .collect::<Vec<_>>();

    for export_bundle_path in export_bundle_paths {
        let export_bundle_bytes = artifacts
            .get(&export_bundle_path)
            .ok_or_else(|| format!("proof-room.enterprise-export.missing: {export_bundle_path}"))?;
        let sidecar_paths = enterprise_export_sidecar_paths(export_bundle_bytes)?;
        for sidecar_path in sidecar_paths {
            if artifacts.contains_key(&sidecar_path) {
                continue;
            }
            validate_bundle_relative_path(&sidecar_path)?;
            let artifact_path = if bundle_root.join(&sidecar_path).exists() {
                resolve_nested_bundle_path(bundle_root, bundle_root, &sidecar_path)?
            } else {
                resolve_nested_bundle_path(bundle_root, passport_dir, &sidecar_path)?
            };
            let bytes = fs::read(&artifact_path).map_err(|error| {
                format!("proof-room.artifact.unreadable: {sidecar_path}: {error}")
            })?;
            artifacts.insert(sidecar_path, bytes);
        }
    }
    Ok(())
}

pub(crate) fn enterprise_export_sidecar_paths(
    export_bundle_bytes: &[u8],
) -> Result<Vec<String>, String> {
    #[derive(serde::Deserialize)]
    struct ExportBundlePaths {
        artifacts: Vec<ExportArtifactPath>,
    }

    #[derive(serde::Deserialize)]
    struct ExportArtifactPath {
        path: String,
    }

    let export_bundle: ExportBundlePaths = serde_json::from_slice(export_bundle_bytes)
        .map_err(|error| format!("proof-room.enterprise-export.invalid-json: {error}"))?;
    Ok(export_bundle
        .artifacts
        .into_iter()
        .map(|artifact| artifact.path)
        .collect())
}
