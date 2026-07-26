use std::path::Path;

use crate::admission_loop::RuntimeLoopbackAdmissionOutput;
use crate::buyer_closure::build_runtime_loopback_buyer_closure;
use crate::evidence_io::{
    canonical_sha256_json, write_json_string, write_runtime_json_artifact,
    write_runtime_json_artifact_string,
};
use crate::proof_parity::{
    materialize_final_runtime_proof_parity_report, ExpectedBuyerClosureParity,
};
use crate::scenario::RuntimeLoopbackStep;
use crate::RuntimeLoopbackError;

pub(crate) struct StaticProofBaseline {
    pub(crate) package: chio_attest_buyer_core::proof_package::ChioProofPackage,
    pub(crate) report: chio_attest_buyer_core::report::VerifierReport,
}

pub(crate) struct StepAdmissionBinding {
    pub(crate) admission_report_sha256: String,
    pub(crate) admission_id: String,
}

pub(crate) fn validate_step_admission_binding_counts(
    workflow_step_count: usize,
    admission_hash_count: usize,
    admission_id_count: usize,
) -> Result<(), RuntimeLoopbackError> {
    if workflow_step_count != admission_hash_count {
        return Err(RuntimeLoopbackError::message(format!(
            "Chio runtime proof generation workflow step count {workflow_step_count} did not match admission report hash count {admission_hash_count}"
        )));
    }
    if workflow_step_count != admission_id_count {
        return Err(RuntimeLoopbackError::message(format!(
            "Chio runtime proof generation workflow step count {workflow_step_count} did not match admission id count {admission_id_count}"
        )));
    }
    Ok(())
}

pub(crate) fn step_admission_binding(
    index: usize,
    admission_hashes: &[String],
    admission_ids: &[String],
) -> Result<StepAdmissionBinding, RuntimeLoopbackError> {
    let admission_report_sha256 = admission_hashes.get(index).cloned().ok_or_else(|| {
        RuntimeLoopbackError::message(format!(
            "Chio runtime proof generation missing admission report hash for workflow step {index}"
        ))
    })?;
    let admission_id = admission_ids.get(index).cloned().ok_or_else(|| {
        RuntimeLoopbackError::message(format!(
            "Chio runtime proof generation missing admission id for workflow step {index}"
        ))
    })?;

    Ok(StepAdmissionBinding {
        admission_report_sha256,
        admission_id,
    })
}

pub(crate) fn runtime_admission_report_sha256_for_workflow(
    principal_admission_report_sha256: Option<&str>,
    admission_hashes: &[String],
    terminal_admission_report_sha256: Option<&str>,
) -> Result<String, RuntimeLoopbackError> {
    if let Some(principal_admission_report_sha256) = principal_admission_report_sha256 {
        return Ok(principal_admission_report_sha256.to_string());
    }
    if let Some(admission_report_sha256) = admission_hashes.first() {
        return Ok(admission_report_sha256.clone());
    }
    if let Some(terminal_admission_report_sha256) = terminal_admission_report_sha256 {
        return Ok(terminal_admission_report_sha256.to_string());
    }
    Err(RuntimeLoopbackError::message(
        "Chio runtime proof generation missing admission report hash".to_string(),
    ))
}

pub(crate) fn assemble_runtime_loopback_outputs(
    run_id: &str,
    steps: &[RuntimeLoopbackStep],
    out_dir: &Path,
    now_unix_ms: u64,
    admission: RuntimeLoopbackAdmissionOutput,
    static_baseline: StaticProofBaseline,
) -> Result<(), RuntimeLoopbackError> {
    let RuntimeLoopbackAdmissionOutput {
        mut accepted,
        mut failure_code,
        mut evidence_paths,
        admission_hashes,
        terminal_admission_report_sha256,
        mut evidence_manifest_entries,
        live_tool_receipts,
        live_treaty_contexts,
    } = admission;
    let mut step_evidence = Vec::new();
    let mut source_records = Vec::new();
    let mut proof_package_sha256 = None;
    let mut verifier_report_sha256 = None;
    let mut workflow_receipt_sha256 = None;
    let mut trust_bundle_sha256 = None;
    let mut verification_context_sha256 = None;
    let mut parity_report: Option<chio_runtime_core::RuntimeProofParityReport> = None;
    let mut principal_admission_report_sha256 = None;
    let mut proof_checks = vec!["runtime_source_records.bound".to_string()];

    if accepted {
        if live_tool_receipts.len() != steps.len() {
            return Err(RuntimeLoopbackError::message(format!(
                "Chio runtime captured {} live receipts for {} accepted steps",
                live_tool_receipts.len(),
                steps.len()
            )));
        }
        let captured_receipt_hashes = live_tool_receipts
            .iter()
            .map(|receipt| {
                canonical_sha256_json(receipt, "Chio runtime captured receipt canonical hash")
            })
            .collect::<Result<Vec<_>, _>>()?;
        proof_checks.push("runtime_kernel_receipts.captured".to_string());
        let baseline_package =
            chio_attest_loopback::proof_package_from_runtime_receipts(live_tool_receipts.clone())
                .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime proof package build from live receipts: {error}"
                ))
            })?;
        let baseline_receipt_hashes = baseline_package
            .tool_receipts
            .iter()
            .map(|receipt| {
                canonical_sha256_json(receipt, "Chio runtime package receipt canonical hash")
            })
            .collect::<Result<Vec<_>, _>>()?;
        if baseline_receipt_hashes != captured_receipt_hashes {
            return Err(RuntimeLoopbackError::message(
                "Chio runtime proof package did not preserve captured live receipts".to_string(),
            ));
        }
        proof_checks.push("runtime_live_receipts.bound_to_proof_package".to_string());
        let buyer_closure_index = steps
            .iter()
            .enumerate()
            .find(|(index, step)| {
                step.admission_bundle.destructive
                    && step.admission_bundle.governance_receipt_id.is_some()
                    && live_treaty_contexts
                        .get(*index)
                        .and_then(Option::as_ref)
                        .is_some()
            })
            .map(|(index, _)| index);
        let (mut package, buyer_closure) = if let Some(index) = buyer_closure_index {
            let treaty_context = live_treaty_contexts
                .get(index)
                .and_then(Option::as_ref)
                .ok_or_else(|| {
                    RuntimeLoopbackError::message(format!(
                        "Chio runtime buyer closure missing treaty context for step {index}"
                    ))
                })?;
            let (package, closure) = build_runtime_loopback_buyer_closure(
                index,
                &steps[index],
                treaty_context,
                &baseline_package,
                now_unix_ms,
            )?;
            proof_checks.push("runtime_treaty_buyer_closure.bound".to_string());
            (package, Some(closure))
        } else {
            (baseline_package, None)
        };
        if package.selective_disclosure_proof.subject_sha256_hex
            == static_baseline
                .package
                .selective_disclosure_proof
                .subject_sha256_hex
        {
            package.selective_disclosure_proof =
                static_baseline.package.selective_disclosure_proof.clone();
        }
        let package_receipt_hashes = package
            .tool_receipts
            .iter()
            .map(|receipt| {
                canonical_sha256_json(receipt, "Chio runtime final package receipt hash")
            })
            .collect::<Result<Vec<_>, _>>()?;
        if package_receipt_hashes != captured_receipt_hashes {
            return Err(RuntimeLoopbackError::message(
                "Chio runtime final proof package did not preserve captured live receipts"
                    .to_string(),
            ));
        }
        let context = chio_attest_loopback::verification_context();
        let trust_bundle_document =
            chio_attest_loopback::verifier_trust_bundle_document_for_package(&package).map_err(
                |error| {
                    RuntimeLoopbackError::message(format!(
                        "Chio runtime verifier trust bundle build: {error}"
                    ))
                },
            )?;
        let trust_bundle =
            chio_attest_buyer_core::trust_bundle::ChioVerifierTrustBundle::from_document(
                trust_bundle_document.clone(),
            )
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime verifier trust bundle parse: {error}"
                ))
            })?;
        let verifier_report = chio_attest_buyer_core::report::verify_package_report(
            &package,
            &trust_bundle,
            &context,
        );

        let package_json =
            chio_attest_buyer_core::proof_package::package_json(&package).map_err(|error| {
                RuntimeLoopbackError::message(format!("Chio runtime proof package JSON: {error}"))
            })?;
        let package_json_value: serde_json::Value =
            serde_json::from_str(&package_json).map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime proof package JSON value: {error}"
                ))
            })?;
        let trust_bundle_json = chio_attest_buyer_core::trust_bundle::verifier_trust_bundle_json(
            &trust_bundle_document,
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime verifier trust bundle JSON: {error}"
            ))
        })?;
        write_runtime_json_artifact_string(
            out_dir,
            "verifier_trust_bundle",
            "verifier-trust-bundle.json",
            &trust_bundle_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        let context_json = chio_attest_buyer_core::context::verification_context_json(&context)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime verification context JSON: {error}"
                ))
            })?;
        write_runtime_json_artifact_string(
            out_dir,
            "verification_context",
            "verification-context.json",
            &context_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        let verifier_report_json = chio_attest_buyer_core::report::report_json(&verifier_report)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!("Chio runtime verifier report JSON: {error}"))
            })?;
        let verifier_report_artifact_sha256 = write_runtime_json_artifact_string(
            out_dir,
            "verifier_report",
            "verifier-report.json",
            &verifier_report_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        if verifier_report_artifact_sha256.is_empty() {
            return Err(RuntimeLoopbackError::message(
                "Chio runtime verifier report artifact hash was empty".to_string(),
            ));
        }
        write_runtime_json_artifact(
            out_dir,
            "workflow_receipt",
            "workflow-receipt.json",
            &package.workflow_receipt,
            "Chio runtime workflow receipt JSON",
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;

        let verifier_report_canonical_sha256 = canonical_sha256_json(
            &verifier_report,
            "Chio runtime verifier report canonical hash",
        )?;
        if verifier_report_canonical_sha256.is_empty() {
            return Err(RuntimeLoopbackError::message(
                "Chio runtime verifier report canonical hash was empty".to_string(),
            ));
        }
        verifier_report_sha256 = Some(verifier_report_canonical_sha256);
        workflow_receipt_sha256 = Some(canonical_sha256_json(
            &package.workflow_receipt,
            "Chio runtime workflow receipt canonical hash",
        )?);
        trust_bundle_sha256 = Some(trust_bundle.document_sha256().to_string());
        verification_context_sha256 = Some(
            chio_attest_buyer_core::context::verification_context_sha256(&context).map_err(
                |error| {
                    RuntimeLoopbackError::message(format!(
                        "Chio runtime verification context hash: {error}"
                    ))
                },
            )?,
        );
        proof_checks.push("runtime_verifier_report.canonical_hash_recorded".to_string());

        let admission_ids = steps
            .iter()
            .map(|step| step.admission_bundle.admission_id.clone())
            .collect::<Vec<_>>();
        validate_step_admission_binding_counts(
            package.workflow_receipt.steps.len(),
            admission_hashes.len(),
            admission_ids.len(),
        )?;
        for (index, step) in package.workflow_receipt.steps.iter().enumerate() {
            let tool_receipt_id = step.tool_receipt_id.as_ref().ok_or_else(|| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime workflow step {} missing tool receipt id",
                    step.step_index
                ))
            })?;
            let receipt = package
                .tool_receipts
                .iter()
                .find(|receipt| receipt.id == *tool_receipt_id)
                .ok_or_else(|| {
                    RuntimeLoopbackError::message(format!(
                        "Chio runtime package missing tool receipt {}",
                        tool_receipt_id
                    ))
                })?;
            let envelope = package.bilateral_envelopes.get(index).ok_or_else(|| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime package missing DSSE envelope for step {}",
                    step.step_index
                ))
            })?;
            let receipt_name = format!("tool-receipt-{}.json", index + 1);
            let dsse_name = format!("bilateral-dsse-{}.json", index + 1);
            let workflow_step_name = format!("workflow-step-{}.json", index + 1);
            let tool_receipt_sha256 =
                canonical_sha256_json(receipt, "Chio runtime tool receipt canonical hash")?;
            let bilateral_dsse_sha256 =
                canonical_sha256_json(envelope, "Chio runtime bilateral DSSE canonical hash")?;
            let workflow_step_sha256 =
                canonical_sha256_json(step, "Chio runtime workflow step canonical hash")?;
            write_runtime_json_artifact(
                out_dir,
                "tool_receipt",
                &receipt_name,
                receipt,
                "Chio runtime tool receipt JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "bilateral_dsse",
                &dsse_name,
                envelope,
                "Chio runtime bilateral DSSE JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "workflow_step",
                &workflow_step_name,
                step,
                "Chio runtime workflow step JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            let admission_binding =
                step_admission_binding(index, &admission_hashes, &admission_ids)?;
            step_evidence.push(chio_runtime_core::RuntimeStepEvidence {
                schema: chio_runtime_core::CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA.to_string(),
                step_index: u64::try_from(step.step_index).map_err(|error| {
                    RuntimeLoopbackError::message(format!(
                        "Chio runtime step index conversion failed: {error}"
                    ))
                })?,
                admission_id: admission_binding.admission_id.clone(),
                admission_report_sha256: admission_binding.admission_report_sha256.clone(),
                tool_receipt_id: tool_receipt_id.clone(),
                tool_receipt_sha256: tool_receipt_sha256.clone(),
                output_sha256: step.output_hash.clone().ok_or_else(|| {
                    RuntimeLoopbackError::message(format!(
                        "Chio runtime workflow step {} missing output hash",
                        step.step_index
                    ))
                })?,
                bilateral_dsse_sha256: bilateral_dsse_sha256.clone(),
                workflow_step_sha256: workflow_step_sha256.clone(),
                parent_receipt_sha256: step.parent_receipt_sha256.clone(),
                consistency_anchor: step.consistency_anchor.clone().ok_or_else(|| {
                    RuntimeLoopbackError::message(format!(
                        "Chio runtime workflow step {} missing consistency anchor",
                        step.step_index
                    ))
                })?,
                destructive: step.destructive.unwrap_or(false),
                lease_id: package
                    .capability_leases
                    .get(index)
                    .map(|lease| lease.body.lease_id.clone()),
                governance_receipt_id: step.governance_receipt_id.clone(),
            });
            source_records.push(chio_runtime_core::RuntimeProofSourceRecord {
                step_index: u64::try_from(step.step_index).map_err(|error| {
                    RuntimeLoopbackError::message(format!(
                        "Chio runtime source step conversion failed: {error}"
                    ))
                })?,
                admission_report_sha256: admission_binding.admission_report_sha256,
                tool_receipt_sha256,
                bilateral_dsse_sha256,
                workflow_step_sha256,
            });
        }

        if let Some(closure) = buyer_closure.as_ref() {
            let step = step_evidence.get_mut(closure.step_index).ok_or_else(|| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime buyer closure missing step evidence {}",
                    closure.step_index
                ))
            })?;
            step.admission_report_sha256 = closure.admission_report_sha256.clone();
            let source_record = source_records.get_mut(closure.step_index).ok_or_else(|| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime buyer closure missing source record {}",
                    closure.step_index
                ))
            })?;
            source_record.admission_report_sha256 = closure.admission_report_sha256.clone();
            principal_admission_report_sha256 = Some(closure.admission_report_sha256.clone());
            write_runtime_json_artifact(
                out_dir,
                "cross_boundary_admission_report",
                "cross-boundary-admission-report.json",
                &closure.admission_report,
                "Chio runtime buyer closure admission report JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "cross_kernel_continuation",
                "cross-kernel-continuation.json",
                &closure.continuation,
                "Chio runtime buyer closure continuation JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "receipt_lineage_statement",
                "receipt-lineage-statement.json",
                &closure.lineage_statement,
                "Chio runtime buyer closure lineage statement JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "receipt_lineage_bundle",
                "receipt-lineage-bundle.json",
                &closure.lineage_bundle,
                "Chio runtime buyer closure lineage bundle JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "bilateral_invocation",
                "bilateral-invocation.json",
                &closure.bilateral_invocation,
                "Chio runtime buyer closure bilateral invocation JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "bilateral_dsse_envelope",
                "bilateral-dsse-envelope.json",
                &closure.bilateral_dsse,
                "Chio runtime buyer closure bilateral DSSE JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
        }

        let proof_package_canonical_sha256 = canonical_sha256_json(
            &package_json_value,
            "Chio runtime proof package canonical hash",
        )?;
        proof_package_sha256 = Some(proof_package_canonical_sha256.clone());
        write_runtime_json_artifact_string(
            out_dir,
            "proof_package",
            "proof-package.json",
            &package_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        write_json_string(
            &out_dir.join("buyer-auditor-proof-package.json"),
            &format!("{package_json}\n"),
        )?;
        if let Some(closure) = buyer_closure.as_ref() {
            let workflow_sha256 = workflow_receipt_sha256.clone().ok_or_else(|| {
                RuntimeLoopbackError::message(
                    "Chio runtime buyer packet missing workflow receipt hash".to_string(),
                )
            })?;
            let verifier_sha256 = verifier_report_sha256.clone().ok_or_else(|| {
                RuntimeLoopbackError::message(
                    "Chio runtime buyer packet missing verifier report hash".to_string(),
                )
            })?;
            let packet = chio_runtime_core::BuyerAttestationPacket {
                schema: chio_runtime_core::CHIO_ATTEST_BUYER_ATTESTATION_PACKET_SCHEMA.to_string(),
                packet_id: format!("buyer-packet:{}", run_id),
                buyer_id: closure.continuation.source_kernel_id.clone(),
                capability_id: closure.bilateral_invocation.capability_id.clone(),
                treaty_scope_sha256: closure.admission_report.treaty_scope_sha256.clone(),
                ladder_intersection_sha256: closure
                    .admission_report
                    .ladder_intersection_sha256
                    .clone(),
                cross_boundary_admission_report_sha256: closure.admission_report_sha256.clone(),
                continuation_sha256: closure.bilateral_invocation.continuation_sha256.clone(),
                receipt_lineage_statement_sha256: closure.lineage_statement_sha256.clone(),
                bilateral_invocation_sha256: closure.bilateral_invocation_binding_sha256.clone(),
                bilateral_dsse_sha256: closure.bilateral_dsse_sha256.clone(),
                workflow_receipt_sha256: workflow_sha256,
                proof_package_sha256: proof_package_canonical_sha256.clone(),
                verifier_report_sha256: verifier_sha256,
                budget_refs: vec![format!(
                    "budget.reserve:{}",
                    closure.bilateral_invocation.capability_id
                )],
                settlement_claimed: false,
            };
            write_runtime_json_artifact(
                out_dir,
                "buyer_attestation_packet",
                "buyer-attestation-packet.json",
                &packet,
                "Chio runtime buyer attestation packet JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
        }

        let expected_buyer_closure_parity = buyer_closure
            .as_ref()
            .map(|closure| {
                chio_runtime_core::bilateral_dsse_consistency_model(
                    &closure.admission_report.consistency_model,
                )
                .map(|consistency_model| ExpectedBuyerClosureParity {
                    step_index: closure.step_index,
                    consistency_model: consistency_model.to_string(),
                })
                .map_err(|error| {
                    RuntimeLoopbackError::message(format!(
                        "Chio runtime proof parity DSSE consistency model: {error}"
                    ))
                })
            })
            .transpose()?;
        let final_parity_report = materialize_final_runtime_proof_parity_report(
            run_id,
            now_unix_ms,
            &static_baseline.package,
            &static_baseline.report,
            &package,
            &context,
            expected_buyer_closure_parity.as_ref(),
        )?;
        let parity_accepted = final_parity_report.accepted;
        parity_report = Some(final_parity_report);

        if verifier_report.accepted && parity_accepted {
            proof_checks.push("runtime_semantic_proof_regeneration.verified".to_string());
        } else {
            accepted = false;
            failure_code = if verifier_report.accepted {
                Some("runtime_proof_semantic_parity_mismatch".to_string())
            } else {
                verifier_report
                    .failure
                    .as_ref()
                    .map(|failure| failure.code.clone())
                    .or_else(|| Some("runtime_proof_semantic_verifier_rejected".to_string()))
            };
        }
    } else {
        proof_checks.push("runtime_admission.denied".to_string());
    }

    let proof_regeneration_report = chio_runtime_core::RuntimeProofRegenerationReport {
        schema: chio_runtime_core::CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
        run_id: run_id.to_string(),
        accepted,
        failure_code: if accepted { None } else { failure_code.clone() },
        generated_at_unix_ms: now_unix_ms,
        proof_package_sha256,
        verifier_report_sha256,
        workflow_receipt_sha256,
        source_records: source_records.clone(),
        checks: proof_checks,
    };
    let proof_regeneration_json =
        chio_runtime_core::runtime_proof_regeneration_report_json(&proof_regeneration_report)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime proof regeneration report: {error}"
                ))
            })?;
    write_runtime_json_artifact_string(
        out_dir,
        "proof_regeneration_report",
        "proof-regeneration-report.json",
        &proof_regeneration_json,
        &mut evidence_manifest_entries,
        &mut evidence_paths,
    )?;
    let proof_regeneration_report_sha256 = canonical_sha256_json(
        &proof_regeneration_report,
        "Chio runtime proof regeneration report canonical hash",
    )?;
    if let Some(parity_report) = parity_report.as_ref() {
        let parity_json = chio_runtime_core::runtime_proof_parity_report_json(parity_report)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!("Chio runtime proof parity report: {error}"))
            })?;
        write_runtime_json_artifact_string(
            out_dir,
            "proof_parity_report",
            "runtime-proof-parity-report.json",
            &parity_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
    }
    let runtime_admission_report_sha256 = runtime_admission_report_sha256_for_workflow(
        principal_admission_report_sha256.as_deref(),
        &admission_hashes,
        terminal_admission_report_sha256.as_deref(),
    )?;
    let workflow_report = chio_runtime_core::RuntimeWorkflowRunReport {
        schema: chio_runtime_core::CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA.to_string(),
        run_id: run_id.to_string(),
        accepted,
        failure_code,
        generated_at_unix_ms: now_unix_ms,
        admission_report_sha256: runtime_admission_report_sha256.clone(),
        evidence_paths: evidence_paths.clone(),
        step_evidence,
        proof_regeneration_report_sha256: Some(proof_regeneration_report_sha256.clone()),
    };
    let workflow_report_json =
        chio_runtime_core::runtime_workflow_run_report_json(&workflow_report).map_err(|error| {
            RuntimeLoopbackError::message(format!("Chio runtime workflow run report: {error}"))
        })?;
    write_runtime_json_artifact_string(
        out_dir,
        "runtime_run_report",
        "runtime-run-report.json",
        &workflow_report_json,
        &mut evidence_manifest_entries,
        &mut evidence_paths,
    )?;
    write_runtime_json_artifact_string(
        out_dir,
        "workflow_run_report",
        "workflow-run-report.json",
        &workflow_report_json,
        &mut evidence_manifest_entries,
        &mut evidence_paths,
    )?;
    let workflow_run_report_sha256 = canonical_sha256_json(
        &workflow_report,
        "Chio runtime workflow run report canonical hash",
    )?;
    let manifest = chio_runtime_core::RuntimeEvidenceManifest {
        schema: chio_runtime_core::CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
        run_id: run_id.to_string(),
        generated_at_unix_ms: now_unix_ms,
        workflow_run_report_sha256: workflow_run_report_sha256.clone(),
        proof_regeneration_report_sha256: proof_regeneration_report_sha256.clone(),
        entries: evidence_manifest_entries.clone(),
    };
    let manifest_json =
        chio_runtime_core::runtime_evidence_manifest_json(&manifest).map_err(|error| {
            RuntimeLoopbackError::message(format!("Chio runtime evidence manifest: {error}"))
        })?;
    write_runtime_json_artifact_string(
        out_dir,
        "runtime_evidence_manifest",
        "runtime-evidence-manifest.json",
        &manifest_json,
        &mut evidence_manifest_entries,
        &mut evidence_paths,
    )?;
    let evidence_manifest_sha256 =
        canonical_sha256_json(&manifest, "Chio runtime evidence manifest canonical hash")?;
    if accepted {
        let regeneration_input = chio_runtime_core::RuntimeProofRegenerationInput {
            schema: chio_runtime_core::CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            evidence_manifest_sha256,
            workflow_run_report_sha256,
            admission_report_sha256: runtime_admission_report_sha256,
            trust_bundle_sha256: trust_bundle_sha256.ok_or_else(|| {
                RuntimeLoopbackError::message(
                    "Chio runtime proof input missing trust bundle hash".to_string(),
                )
            })?,
            verification_context_sha256: verification_context_sha256.ok_or_else(|| {
                RuntimeLoopbackError::message(
                    "Chio runtime proof input missing context hash".to_string(),
                )
            })?,
            source_records,
        };
        let input_json = chio_runtime_core::runtime_proof_regeneration_input_json(
            &regeneration_input,
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!("Chio runtime proof regeneration input: {error}"))
        })?;
        write_runtime_json_artifact_string(
            out_dir,
            "proof_regeneration_input",
            "runtime-proof-regeneration-input.json",
            &input_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
    }
    if workflow_report.accepted {
        Ok(())
    } else {
        let parity_detail = parity_report
            .as_ref()
            .filter(|report| !report.accepted)
            .map(|report| {
                let fields = report
                    .mismatches
                    .iter()
                    .map(|mismatch| mismatch.field.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "; mismatched fields: [{}]; proof package hash match: {}; verifier report hash match: {}",
                    fields,
                    report.static_proof_package_sha256 == report.runtime_proof_package_sha256,
                    report.static_verifier_report_sha256 == report.runtime_verifier_report_sha256,
                )
            })
            .unwrap_or_default();
        Err(RuntimeLoopbackError::message(format!(
            "Chio runtime loopback rejected request: {}{}",
            workflow_report
                .failure_code
                .as_deref()
                .unwrap_or("unknown_runtime_loopback_failure"),
            parity_detail,
        )))
    }
}
