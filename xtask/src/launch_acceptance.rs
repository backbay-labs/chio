//! Public Proof Room launch acceptance package assembly.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::cli::LaunchAcceptanceArgs;
use crate::XtaskError;

const ACCEPTANCE_SCHEMA: &str = "chio.proof-room.launch-acceptance.v1";
const ACCEPTANCE_REPORT_SCHEMA: &str = "chio.proof-room.launch-acceptance-report.v1";
const HOMEPAGE_COPY_MAP_SCHEMA: &str = "chio.proof-room.homepage-copy-map.v1";
const NON_CLAIMS_SCHEMA: &str = "chio.proof-room.non-claims.v1";
const NEGATIVE_CATALOG_SCHEMA: &str = "chio.proof-room.negative-catalog.v1";
const AGENT_WEB_STAGE_ID: &str = "disclosure-and-agent-web-envelope";
const AGENT_WEB_SOURCE_LOG_PATH: &str =
    "docs/superpowers/research/chio-launch/indices/external-standards-source-log.md";
const AGENT_WEB_SOURCE_LOG_STATUS: &str = "Status: refreshed source log";
const AGENT_WEB_PROJECTION_MANIFEST_SCHEMA: &str = "chio.agent-web.external-projection-manifest.v1";
const REQUIRED_AGENT_WEB_PROTOCOLS: [&str; 30] = [
    "a2a",
    "acp-client",
    "acp-commerce",
    "ag-ui",
    "ap2",
    "asyncapi",
    "bbs",
    "browser-automation",
    "gmail-api",
    "cloudevents",
    "dsse",
    "google-calendar-api",
    "graphql-http",
    "in-toto",
    "kubernetes-admission",
    "mcp",
    "oauth2",
    "oci",
    "openapi",
    "openid-connect",
    "rpa",
    "scim",
    "sd-jwt-vc",
    "sigstore",
    "slack",
    "slsa-provenance",
    "spiffe",
    "standard-webhooks",
    "vc",
    "x402",
];
const REQUIRED_AGENT_WEB_NEGATIVE_IDS: [&str; 8] = [
    "agent-web-external-digest-mismatch",
    "agent-web-missing-required-signature",
    "agent-web-unsupported-claim-not-limited",
    "agent-web-sidecar-claim-marked-native",
    "agent-web-x402-detached-from-order",
    "agent-web-ap2-detached-from-order",
    "agent-web-oci-tag-only-ref",
    "agent-web-slsa-unverified-provenance",
];

const STAGES: [StageSpec; 4] = [
    StageSpec {
        fixture_id: "single-call-authority",
        source: "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle",
    },
    StageSpec {
        fixture_id: "commerce-transaction-passport",
        source: "fixtures/proof-room/public-stages/commerce-transaction-passport/proof-room-bundle",
    },
    StageSpec {
        fixture_id: "recursive-runtime-swarm",
        source: "fixtures/proof-room/public-stages/recursive-runtime-swarm/proof-room-bundle",
    },
    StageSpec {
        fixture_id: "disclosure-and-agent-web-envelope",
        source:
            "fixtures/proof-room/public-stages/disclosure-and-agent-web-envelope/proof-room-bundle",
    },
];

struct StageSpec {
    fixture_id: &'static str,
    source: &'static str,
}

struct StageEvidence {
    fixture_id: &'static str,
    output_path: String,
    source_path: String,
    manifest_sha256: String,
    verifier_report_sha256: String,
    transaction_passport_sha256: String,
    evidence_graph_sha256: String,
    negative_cases: Vec<Value>,
    agent_web_exit_gate: Option<Value>,
}

struct CommandRecord {
    command: String,
    exit_code: i32,
    stdout: String,
    stderr: String,
}

pub(crate) fn run(args: &LaunchAcceptanceArgs) -> Result<(), XtaskError> {
    let root = crate::workspace_root()?;
    let out = resolve_output_path(&root, &args.out);
    let archive = archive_path(&out)?;
    let mut transcript = Vec::new();

    if !args.schema_only {
        transcript.push(run_fixture_verifier_gate(&root)?);
    }

    reset_output_dir(&root, &out)?;
    fs::create_dir_all(out.join("claims"))
        .map_err(|err| XtaskError::Io(crate::display_path(&out.join("claims")), err))?;
    fs::create_dir_all(out.join("roots"))
        .map_err(|err| XtaskError::Io(crate::display_path(&out.join("roots")), err))?;
    fs::create_dir_all(out.join("verifier"))
        .map_err(|err| XtaskError::Io(crate::display_path(&out.join("verifier")), err))?;
    fs::create_dir_all(out.join("negatives"))
        .map_err(|err| XtaskError::Io(crate::display_path(&out.join("negatives")), err))?;
    fs::create_dir_all(out.join("ui"))
        .map_err(|err| XtaskError::Io(crate::display_path(&out.join("ui")), err))?;

    let stages = copy_and_validate_stages(&root, &out)?;
    copy_roots_from_stage_zero(&root, &out)?;
    copy_claim_registry(&root, &out)?;
    write_homepage_copy_map(&out)?;
    write_non_claims(&out)?;
    write_negative_catalog(&out, &stages)?;
    copy_static_ui(&root, &out)?;

    let git_commit = required_stdout(&root, "git", &["rev-parse", "HEAD"])?;
    let tool_versions = tool_versions(&root, &git_commit)?;
    write_json(&out.join("verifier/tool-versions.json"), &tool_versions)?;

    transcript.push(CommandRecord {
        command: std::env::args().collect::<Vec<_>>().join(" "),
        exit_code: 0,
        stdout: if args.schema_only {
            "schema-only package assembly".to_string()
        } else {
            "launch acceptance package assembly".to_string()
        },
        stderr: String::new(),
    });
    write_command_transcript(&out, &transcript)?;

    let report = acceptance_report(args.schema_only, &git_commit, &stages);
    write_json(&out.join("verifier/report.json"), &report)?;
    let report_sha256 = sha256_file(&out.join("verifier/report.json"))?;
    write_unsigned_dsse(
        &out.join("verifier/report.dsse.json"),
        "application/vnd.chio.proof-room.launch-acceptance-report.v1+json",
        &report_sha256,
    )?;

    let manifest = acceptance_manifest(&git_commit, &stages, &report_sha256);
    write_json(&out.join("manifest.json"), &manifest)?;
    let manifest_sha256 = sha256_file(&out.join("manifest.json"))?;
    write_unsigned_dsse(
        &out.join("bundle-signature.dsse.json"),
        "application/vnd.chio.proof-room.launch-acceptance.v1+json",
        &manifest_sha256,
    )?;

    create_archive(&out, &archive)?;
    println!(
        "verify launch-acceptance: wrote {} and {}",
        crate::display_path(&out),
        crate::display_path(&archive)
    );
    Ok(())
}

fn copy_and_validate_stages(root: &Path, out: &Path) -> Result<Vec<StageEvidence>, XtaskError> {
    let mut stages = Vec::new();
    for spec in STAGES {
        let source = root.join(spec.source);
        if !source.is_dir() {
            return Err(XtaskError::Validation(format!(
                "public Proof Room stage is missing: {}",
                spec.source
            )));
        }
        let manifest_path = source.join("manifest.json");
        let verifier_report_path = source.join("verifier/report.json");
        let transaction_passport_path = source.join("roots/transaction-passport.json");
        let evidence_graph_path = source.join("roots/evidence-graph.json");
        require_file(&manifest_path)?;
        require_file(&verifier_report_path)?;
        require_file(&transaction_passport_path)?;
        require_file(&evidence_graph_path)?;

        let manifest = read_json(&manifest_path)?;
        let report = read_json(&verifier_report_path)?;
        let fixture_id = manifest
            .get("fixture_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                XtaskError::Validation(format!(
                    "{}: fixture_id is missing",
                    crate::display_path(&manifest_path)
                ))
            })?;
        if fixture_id != spec.fixture_id {
            return Err(XtaskError::Validation(format!(
                "{}: fixture_id {fixture_id} does not match expected {}",
                crate::display_path(&manifest_path),
                spec.fixture_id
            )));
        }
        if manifest.get("schema").and_then(Value::as_str) != Some("chio.proof-room.bundle.v1") {
            return Err(XtaskError::Validation(format!(
                "{}: schema is not chio.proof-room.bundle.v1",
                crate::display_path(&manifest_path)
            )));
        }
        if report.get("verdict").and_then(Value::as_str) != Some("verified") {
            return Err(XtaskError::Validation(format!(
                "{}: verifier report did not verify",
                crate::display_path(&verifier_report_path)
            )));
        }

        let negative_cases = manifest
            .get("negative_cases")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                XtaskError::Validation(format!(
                    "{}: negative_cases is missing",
                    crate::display_path(&manifest_path)
                ))
            })?;
        if negative_cases.is_empty() {
            return Err(XtaskError::Validation(format!(
                "{}: negative_cases is empty",
                crate::display_path(&manifest_path)
            )));
        }

        let stage_out = out.join("stages").join(spec.fixture_id);
        crate::copy_dir_recursive(&source, &stage_out.join("proof-room-bundle"))?;
        if let Some(stage_root) = source.parent() {
            let report = stage_root.join("verifier-report.json");
            if report.is_file() {
                copy_file(&report, &stage_out.join("verifier-report.json"))?;
            }
        }

        let agent_web_exit_gate = if spec.fixture_id == AGENT_WEB_STAGE_ID {
            Some(validate_agent_web_exit_gate(root, &source, negative_cases)?)
        } else {
            None
        };

        stages.push(StageEvidence {
            fixture_id: spec.fixture_id,
            output_path: format!("stages/{}/proof-room-bundle", spec.fixture_id),
            source_path: spec.source.to_string(),
            manifest_sha256: sha256_file(&manifest_path)?,
            verifier_report_sha256: sha256_file(&verifier_report_path)?,
            transaction_passport_sha256: sha256_file(&transaction_passport_path)?,
            evidence_graph_sha256: sha256_file(&evidence_graph_path)?,
            negative_cases: negative_cases.clone(),
            agent_web_exit_gate,
        });
    }
    Ok(stages)
}

fn validate_agent_web_exit_gate(
    root: &Path,
    source: &Path,
    negative_cases: &[Value],
) -> Result<Value, XtaskError> {
    let source_log_path = root.join(AGENT_WEB_SOURCE_LOG_PATH);
    require_file(&source_log_path)?;
    let source_log = fs::read_to_string(&source_log_path)
        .map_err(|err| XtaskError::Io(crate::display_path(&source_log_path), err))?;
    if !source_log.contains(AGENT_WEB_SOURCE_LOG_STATUS) {
        return Err(XtaskError::Validation(format!(
            "{}: Agent Web source log is not marked refreshed",
            crate::display_path(&source_log_path)
        )));
    }

    let mut source_protocols = BTreeSet::new();
    let mut manifest_count = 0usize;
    for entry in
        fs::read_dir(source).map_err(|err| XtaskError::Io(crate::display_path(source), err))?
    {
        let entry = entry.map_err(|err| XtaskError::Io(crate::display_path(source), err))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(envelope_stem) = file_name.strip_suffix("-manifest.json") else {
            continue;
        };
        let manifest = read_json(&path)?;
        if manifest.get("schema").and_then(Value::as_str)
            != Some(AGENT_WEB_PROJECTION_MANIFEST_SCHEMA)
        {
            continue;
        }
        let source_protocol = required_json_string(&manifest, "source_protocol", &path)?;
        required_json_string(&manifest, "source_version", &path)?;
        require_non_empty_json_array(&manifest, "claim_mapping", &path)?;
        require_non_empty_json_array(&manifest, "unsupported_claims", &path)?;
        require_non_empty_json_array(&manifest, "copy_limitations", &path)?;

        let envelope_path = source.join(format!("{envelope_stem}-envelope.json"));
        require_file(&envelope_path)?;
        source_protocols.insert(source_protocol.to_string());
        manifest_count += 1;
    }

    for protocol in REQUIRED_AGENT_WEB_PROTOCOLS {
        if !source_protocols.contains(protocol) {
            return Err(XtaskError::Validation(format!(
                "Agent Web exit gate missing projection manifest for {protocol}"
            )));
        }
    }

    let negative_ids = negative_cases
        .iter()
        .filter_map(|case| case.get("id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    for case_id in REQUIRED_AGENT_WEB_NEGATIVE_IDS {
        if !negative_ids.contains(case_id) {
            return Err(XtaskError::Validation(format!(
                "Agent Web exit gate missing negative fixture {case_id}"
            )));
        }
    }

    Ok(json!({
        "verdict": "verified",
        "source_log_path": AGENT_WEB_SOURCE_LOG_PATH,
        "source_log_status": "refreshed source log",
        "projection_manifest_schema": AGENT_WEB_PROJECTION_MANIFEST_SCHEMA,
        "manifest_count": manifest_count,
        "source_protocols": source_protocols.into_iter().collect::<Vec<_>>(),
        "negative_case_ids": negative_ids.into_iter().collect::<Vec<_>>(),
    }))
}

fn copy_roots_from_stage_zero(root: &Path, out: &Path) -> Result<(), XtaskError> {
    let roots = root.join(STAGES[0].source).join("roots");
    crate::copy_dir_recursive(&roots, &out.join("roots"))
}

fn copy_claim_registry(root: &Path, out: &Path) -> Result<(), XtaskError> {
    copy_file(
        &root.join("spec/registries/claim-registry.v1.json"),
        &out.join("claims/claim-registry.json"),
    )
}

fn write_homepage_copy_map(out: &Path) -> Result<(), XtaskError> {
    let copy_map = json!({
        "schema": HOMEPAGE_COPY_MAP_SCHEMA,
        "copy_claims": [
            {
                "copy_claim": "The trust network for autonomous commerce",
                "claim_ids": [
                    "claim.commerce.order_replay_consistent",
                    "claim.commerce.payment_lifecycle_bound",
                    "claim.commerce.mandate_allowance_bound",
                    "claim.commerce.admission_gates_bound",
                    "claim.commerce.settlement_lifecycle_bound",
                    "claim.public_settlement.order_binding_verified"
                ],
                "fixture_ids": ["commerce-transaction-passport"]
            },
            {
                "copy_claim": "Proof layer",
                "claim_ids": [
                    "claim.transaction.passport_root_verified",
                    "claim.transaction.evidence_graph_digest_bound",
                    "claim.transaction.policy_digest_bound",
                    "claim.proof_room.verifier_report_bound"
                ],
                "fixture_ids": ["single-call-authority"]
            },
            {
                "copy_claim": "Emerging agent web",
                "claim_ids": [
                    "claim.agent_web.external_subject_digest_bound",
                    "claim.agent_web.projection_manifest_bound",
                    "claim.agent_web.unsupported_claims_limited",
                    "claim.agent_web.sidecar_not_native_authority"
                ],
                "fixture_ids": ["disclosure-and-agent-web-envelope"]
            },
            {
                "copy_claim": "Every action",
                "claim_ids": [
                    "claim.proof_room.receipt_coverage_matrix_bound"
                ],
                "fixture_ids": ["single-call-authority"]
            },
            {
                "copy_claim": "Single agent call",
                "claim_ids": [
                    "claim.transaction.passport_root_verified",
                    "claim.transaction.evidence_graph_digest_bound",
                    "claim.transaction.policy_digest_bound"
                ],
                "fixture_ids": ["single-call-authority"]
            },
            {
                "copy_claim": "Multi-swarm coordination",
                "claim_ids": [
                    "claim.swarm.task_graph_bound",
                    "claim.swarm.continuation_fresh",
                    "claim.swarm.attenuation_witness_chain_bound",
                    "claim.swarm.route_plan_bound",
                    "claim.swarm.join_receipt_bound",
                    "claim.swarm.budget_pool_bound",
                    "claim.swarm.revocation_epoch_bound"
                ],
                "fixture_ids": ["recursive-runtime-swarm"]
            },
            {
                "copy_claim": "Verifiable authority",
                "claim_ids": [
                    "claim.transaction.passport_root_verified",
                    "claim.transaction.policy_digest_bound",
                    "claim.proof_room.authority_evidence_bound"
                ],
                "fixture_ids": ["single-call-authority"]
            },
            {
                "copy_claim": "Recursive delegation",
                "claim_ids": [
                    "claim.swarm.continuation_fresh",
                    "claim.swarm.attenuation_witness_chain_bound",
                    "claim.swarm.join_receipt_bound",
                    "claim.swarm.revocation_epoch_bound"
                ],
                "fixture_ids": ["recursive-runtime-swarm"]
            },
            {
                "copy_claim": "Lineage",
                "claim_ids": [
                    "claim.disclosure.lineage_subgraph_bound",
                    "claim.disclosure.leakage_ledger_complete"
                ],
                "fixture_ids": ["disclosure-and-agent-web-envelope"]
            },
            {
                "copy_claim": "Selective disclosure",
                "claim_ids": [
                    "claim.disclosure.crypto_context_bound",
                    "claim.disclosure.profile_context_policy_enforced",
                    "claim.disclosure.lineage_subgraph_bound",
                    "claim.disclosure.leakage_ledger_complete"
                ],
                "fixture_ids": ["disclosure-and-agent-web-envelope"]
            },
            {
                "copy_claim": "Settlement context",
                "claim_ids": [
                    "claim.public_settlement.order_binding_verified",
                    "claim.public_settlement.chain_context_verified",
                    "claim.public_settlement.finality_verified",
                    "claim.public_settlement.oracle_conversion_bound",
                    "claim.public_settlement.dispute_posture_bound"
                ],
                "fixture_ids": ["commerce-transaction-passport"]
            },
            {
                "copy_claim": "Across trust boundaries",
                "claim_ids": [
                    "claim.agent_web.external_subject_digest_bound",
                    "claim.agent_web.projection_manifest_bound",
                    "claim.agent_web.unsupported_claims_limited",
                    "claim.agent_web.sidecar_not_native_authority"
                ],
                "fixture_ids": ["disclosure-and-agent-web-envelope"]
            },
            {
                "copy_claim": "Autonomous commerce",
                "claim_ids": [
                    "claim.commerce.order_replay_consistent",
                    "claim.commerce.payment_lifecycle_bound",
                    "claim.commerce.mandate_allowance_bound",
                    "claim.commerce.settlement_lifecycle_bound",
                    "claim.public_settlement.order_binding_verified",
                    "claim.public_settlement.dispute_posture_bound"
                ],
                "fixture_ids": ["commerce-transaction-passport"]
            }
        ]
    });
    write_json(&out.join("claims/homepage-copy-map.json"), &copy_map)
}

fn write_non_claims(out: &Path) -> Result<(), XtaskError> {
    let non_claims = json!({
        "schema": NON_CLAIMS_SCHEMA,
        "non_claims": [
            {
                "id": "no-hosted-demo-claim",
                "statement": "This package does not claim a hosted public demo."
            },
            {
                "id": "no-live-network-finality-claim",
                "statement": "Network-dependent settlement claims are absent or represented by offline verifier evidence."
            },
            {
                "id": "aggregate-package-not-production-release",
                "statement": "This package is launch acceptance evidence, not a GA release artifact."
            },
            {
                "id": "aggregate-signature-not-external-attestation",
                "statement": "The aggregate DSSE sidecars record local assembly hashes; stage verifier roots remain the authority."
            }
        ]
    });
    write_json(&out.join("claims/non-claims.json"), &non_claims)
}

fn write_negative_catalog(out: &Path, stages: &[StageEvidence]) -> Result<(), XtaskError> {
    let mut cases = Vec::new();
    for stage in stages {
        for case in &stage.negative_cases {
            let mut enriched = case.clone();
            if let Some(obj) = enriched.as_object_mut() {
                obj.insert(
                    "stage".to_string(),
                    Value::String(stage.fixture_id.to_string()),
                );
            }
            cases.push(enriched);
        }
    }
    let catalog = json!({
        "schema": NEGATIVE_CATALOG_SCHEMA,
        "cases": cases,
    });
    write_json(&out.join("negatives/catalog.json"), &catalog)
}

fn copy_static_ui(root: &Path, out: &Path) -> Result<(), XtaskError> {
    let dist = root.join("crates/products/chio-cli/dashboard/dist");
    if !dist.is_dir() {
        return Err(XtaskError::Validation(format!(
            "Proof Room static UI export is missing: {}",
            crate::display_path(&dist)
        )));
    }
    crate::copy_dir_recursive(&dist, &out.join("ui/proof-room-static"))
}

fn acceptance_report(schema_only: bool, git_commit: &str, stages: &[StageEvidence]) -> Value {
    let agent_web_exit_gate = stages
        .iter()
        .find_map(|stage| stage.agent_web_exit_gate.clone())
        .unwrap_or_else(|| {
            json!({
                "verdict": "missing",
            })
        });
    json!({
        "schema": ACCEPTANCE_REPORT_SCHEMA,
        "verdict": "verified",
        "mode": if schema_only { "schema-only" } else { "full" },
        "git_commit": git_commit,
        "stages": stages.iter().map(stage_json).collect::<Vec<_>>(),
        "agent_web_exit_gate": agent_web_exit_gate,
        "negative_case_count": stages
            .iter()
            .map(|stage| stage.negative_cases.len())
            .sum::<usize>(),
        "required_stage_count": STAGES.len(),
    })
}

fn acceptance_manifest(git_commit: &str, stages: &[StageEvidence], report_sha256: &str) -> Value {
    json!({
        "schema": ACCEPTANCE_SCHEMA,
        "id": "chio-proof-room-public-bundle",
        "generated_by": "cargo xtask verify launch-acceptance",
        "git_commit": git_commit,
        "claims": {
            "claim_registry": {
                "path": "claims/claim-registry.json",
            },
            "homepage_copy_map": {
                "path": "claims/homepage-copy-map.json",
            },
            "non_claims": {
                "path": "claims/non-claims.json",
            }
        },
        "roots": {
            "transaction_passport": {
                "path": "roots/transaction-passport.json",
            },
            "evidence_graph": {
                "path": "roots/evidence-graph.json",
            }
        },
        "verifier": {
            "report": {
                "path": "verifier/report.json",
                "sha256": report_sha256,
            },
            "report_dsse": {
                "path": "verifier/report.dsse.json",
            },
            "tool_versions": {
                "path": "verifier/tool-versions.json",
            },
            "command_transcript": {
                "path": "verifier/command-transcript.json",
            }
        },
        "stages": stages.iter().map(stage_json).collect::<Vec<_>>(),
        "negative_catalog": {
            "path": "negatives/catalog.json",
        },
        "ui": {
            "path": "ui/proof-room-static",
        }
    })
}

fn stage_json(stage: &StageEvidence) -> Value {
    json!({
        "fixture_id": stage.fixture_id,
        "source_path": stage.source_path,
        "output_path": stage.output_path,
        "manifest_sha256": stage.manifest_sha256,
        "verifier_report_sha256": stage.verifier_report_sha256,
        "transaction_passport_sha256": stage.transaction_passport_sha256,
        "evidence_graph_sha256": stage.evidence_graph_sha256,
        "negative_case_count": stage.negative_cases.len(),
    })
}

fn tool_versions(root: &Path, git_commit: &str) -> Result<Value, XtaskError> {
    Ok(json!({
        "git_commit": git_commit,
        "cargo": required_stdout(root, "cargo", &["--version"])?,
        "rustc": required_stdout(root, "rustc", &["--version"])?,
        "zstd": required_stdout(root, "zstd", &["--version"])?,
    }))
}

fn write_command_transcript(out: &Path, records: &[CommandRecord]) -> Result<(), XtaskError> {
    let transcript = json!({
        "schema": "chio.proof-room.command-transcript.v1",
        "commands": records.iter().map(|record| {
            json!({
                "command": record.command,
                "exit_code": record.exit_code,
                "stdout": record.stdout,
                "stderr": record.stderr,
            })
        }).collect::<Vec<_>>(),
    });
    write_json(&out.join("verifier/command-transcript.json"), &transcript)
}

fn write_unsigned_dsse(
    path: &Path,
    payload_type: &str,
    payload_sha256: &str,
) -> Result<(), XtaskError> {
    let value = json!({
        "payloadType": payload_type,
        "payloadSha256": payload_sha256,
        "signatures": [],
        "signatureStatus": "unsigned-local-assembly",
    });
    write_json(path, &value)
}

fn run_fixture_verifier_gate(root: &Path) -> Result<CommandRecord, XtaskError> {
    let script = root.join("scripts/check-chio-transaction-passport.sh");
    let output = Command::new("bash")
        .arg(&script)
        .current_dir(root)
        .env("CARGO_INCREMENTAL", "0")
        .output()
        .map_err(|err| XtaskError::Io(crate::display_path(&script), err))?;
    let record = CommandRecord {
        command: crate::display_path(&script),
        exit_code: output.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    };
    if !output.status.success() {
        return Err(XtaskError::ToolFailed(format!(
            "launch acceptance verifier gate failed: {}\nstdout: {}\nstderr: {}",
            record.command, record.stdout, record.stderr
        )));
    }
    Ok(record)
}

fn create_archive(out: &Path, archive: &Path) -> Result<(), XtaskError> {
    if archive.exists() {
        fs::remove_file(archive)
            .map_err(|err| XtaskError::Io(crate::display_path(archive), err))?;
    }
    let parent = out.parent().ok_or_else(|| {
        XtaskError::Usage(format!(
            "output path has no parent: {}",
            crate::display_path(out)
        ))
    })?;
    let name = out
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            XtaskError::Usage(format!(
                "output path has no UTF-8 file name: {}",
                crate::display_path(out)
            ))
        })?;
    let tar_path = parent.join(format!("{name}.tar"));
    if tar_path.exists() {
        fs::remove_file(&tar_path)
            .map_err(|err| XtaskError::Io(crate::display_path(&tar_path), err))?;
    }

    let tar_output = Command::new("tar")
        .arg("-cf")
        .arg(&tar_path)
        .arg("-C")
        .arg(parent)
        .arg(name)
        .output()
        .map_err(|err| XtaskError::Io("tar".to_string(), err))?;
    if !tar_output.status.success() {
        return Err(XtaskError::ToolFailed(format!(
            "tar exited {}\nstdout: {}\nstderr: {}",
            tar_output.status,
            String::from_utf8_lossy(&tar_output.stdout).trim(),
            String::from_utf8_lossy(&tar_output.stderr).trim()
        )));
    }

    let zstd_output = Command::new("zstd")
        .arg("-q")
        .arg("-f")
        .arg("-o")
        .arg(archive)
        .arg(&tar_path)
        .output()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                XtaskError::ToolMissing("zstd not found on PATH".to_string())
            } else {
                XtaskError::Io("zstd".to_string(), err)
            }
        })?;
    let _ = fs::remove_file(&tar_path);
    if !zstd_output.status.success() {
        return Err(XtaskError::ToolFailed(format!(
            "zstd exited {}\nstdout: {}\nstderr: {}",
            zstd_output.status,
            String::from_utf8_lossy(&zstd_output.stdout).trim(),
            String::from_utf8_lossy(&zstd_output.stderr).trim()
        )));
    }
    Ok(())
}

fn resolve_output_path(root: &Path, out: &Path) -> PathBuf {
    if out.is_absolute() {
        out.to_path_buf()
    } else {
        root.join(out)
    }
}

fn archive_path(out: &Path) -> Result<PathBuf, XtaskError> {
    let name = out
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            XtaskError::Usage(format!(
                "output path has no UTF-8 file name: {}",
                crate::display_path(out)
            ))
        })?;
    Ok(out.with_file_name(format!("{name}.tar.zst")))
}

fn reset_output_dir(root: &Path, out: &Path) -> Result<(), XtaskError> {
    assert_safe_output_path(root, out)?;
    if out.exists() {
        if out.is_dir() {
            fs::remove_dir_all(out).map_err(|err| XtaskError::Io(crate::display_path(out), err))?;
        } else {
            fs::remove_file(out).map_err(|err| XtaskError::Io(crate::display_path(out), err))?;
        }
    }
    fs::create_dir_all(out).map_err(|err| XtaskError::Io(crate::display_path(out), err))
}

fn assert_safe_output_path(root: &Path, out: &Path) -> Result<(), XtaskError> {
    if out.parent().is_none() {
        return Err(unsafe_output_error(out));
    }
    if out.exists() {
        let canonical_root = root
            .canonicalize()
            .map_err(|err| XtaskError::Io(crate::display_path(root), err))?;
        let canonical_out = out
            .canonicalize()
            .map_err(|err| XtaskError::Io(crate::display_path(out), err))?;
        if canonical_out == canonical_root || canonical_root.starts_with(&canonical_out) {
            return Err(unsafe_output_error(out));
        }
    }
    Ok(())
}

fn unsafe_output_error(out: &Path) -> XtaskError {
    XtaskError::Usage(format!(
        "refusing to replace unsafe launch acceptance output: {}",
        crate::display_path(out)
    ))
}

fn read_json(path: &Path) -> Result<Value, XtaskError> {
    let raw =
        fs::read_to_string(path).map_err(|err| XtaskError::Io(crate::display_path(path), err))?;
    serde_json::from_str(&raw).map_err(|err| XtaskError::Json(crate::display_path(path), err))
}

fn required_json_string<'a>(
    value: &'a Value,
    field: &str,
    path: &Path,
) -> Result<&'a str, XtaskError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            XtaskError::Validation(format!(
                "{}: required string field is missing: {field}",
                crate::display_path(path)
            ))
        })
}

fn require_non_empty_json_array(value: &Value, field: &str, path: &Path) -> Result<(), XtaskError> {
    match value.get(field).and_then(Value::as_array) {
        Some(values) if !values.is_empty() => Ok(()),
        _ => Err(XtaskError::Validation(format!(
            "{}: required non-empty array field is missing: {field}",
            crate::display_path(path)
        ))),
    }
}

fn write_json(path: &Path, value: &Value) -> Result<(), XtaskError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| XtaskError::Io(crate::display_path(parent), err))?;
    }
    let body = serde_json::to_vec_pretty(value)
        .map_err(|err| XtaskError::Process(format!("json render failed: {err}")))?;
    fs::write(path, [&body[..], b"\n"].concat())
        .map_err(|err| XtaskError::Io(crate::display_path(path), err))
}

fn require_file(path: &Path) -> Result<(), XtaskError> {
    if path.is_file() {
        Ok(())
    } else {
        Err(XtaskError::Validation(format!(
            "required launch acceptance input is missing: {}",
            crate::display_path(path)
        )))
    }
}

fn copy_file(src: &Path, dst: &Path) -> Result<(), XtaskError> {
    require_file(src)?;
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| XtaskError::Io(crate::display_path(parent), err))?;
    }
    fs::copy(src, dst)
        .map(|_| ())
        .map_err(|err| XtaskError::Io(crate::display_path(dst), err))
}

fn sha256_file(path: &Path) -> Result<String, XtaskError> {
    let bytes = fs::read(path).map_err(|err| XtaskError::Io(crate::display_path(path), err))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn required_stdout(root: &Path, program: &str, args: &[&str]) -> Result<String, XtaskError> {
    let output = Command::new(program)
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                XtaskError::ToolMissing(format!("{program} not found on PATH"))
            } else {
                XtaskError::Io(program.to_string(), err)
            }
        })?;
    if !output.status.success() {
        return Err(XtaskError::ToolFailed(format!(
            "{} {} exited {}\nstdout: {}\nstderr: {}",
            program,
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Err(XtaskError::ToolFailed(format!(
            "{} {} produced empty stdout",
            program,
            args.join(" ")
        )));
    }
    Ok(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_output_dir_rejects_workspace_root() {
        let root = crate::workspace_root().unwrap_or_else(|err| panic!("workspace root: {err}"));
        match reset_output_dir(&root, &root) {
            Err(XtaskError::Usage(message)) => {
                assert!(
                    message.contains("refusing to replace unsafe launch acceptance output"),
                    "{message}"
                );
            }
            Ok(()) => panic!("workspace root accepted as output"),
            Err(other) => panic!("expected Usage, got {other}"),
        }
    }
}
