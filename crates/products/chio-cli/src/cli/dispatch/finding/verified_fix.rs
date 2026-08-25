use super::super::*;

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chio_control_plane::trust_control::finding_challenge_coordinator::FindingAuthorityStatusResolver;
use chio_control_plane::trust_control::finding_operator_profile::{
    FindingOperatorBuyerClientProfile, FindingOperatorClientProfile, FindingOperatorProfile,
    FindingOperatorSellerClientProfile, FINDING_OPERATOR_BUYER_CLIENT_SCHEMA,
    FINDING_OPERATOR_CLIENT_PROFILE_SCHEMA, FINDING_OPERATOR_PROFILE_SCHEMA,
    FINDING_OPERATOR_SELLER_CLIENT_SCHEMA,
};
use chio_control_plane::trust_control::finding_operator_status::FindingOperatorAuthorityStatusResolver;
use chio_control_plane::trust_control::finding_purchase_routes::{
    FindingPurchaseRequest, FindingPurchaseResult, FINDING_PURCHASE_MAX_RESULT_BYTES,
};
use chio_control_plane::trust_control::finding_verified_fix::{
    FindingOperatorProofBundle, FindingVerifiedFixDraft, VerifiedFixAuthoringInput,
    VerifiedFixCommandResult,
};
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_finding::{
    FindingAuthorityStatus, FINDING_AUTHORITY_STATUS_SCHEMA_V1,
    FINDING_SELLER_AUTHORIZATION_KEY_EPOCH_V1,
};
use chio_store_sqlite::{
    SqliteFindingOperatorBundleStore, SqliteFindingPayloadStore, TenantId, TenantKey,
};

use super::finding_operator::{load_profile, ResolvedOperatorPaths};

#[path = "verified_fix_admission_lock.rs"]
mod admission_lock;
use admission_lock::FindingAdmissionJobLock;
#[path = "verified_fix_sandbox.rs"]
mod sandbox;
use sandbox::{
    require_sandbox, run_test_commands, runtime_fingerprint, PACKAGE_WORK_TIMEOUT,
};
#[path = "verified_fix_repository_sandbox.rs"]
mod repository_sandbox;
use repository_sandbox::{
    approved_repository, isolated_git_stdout_bounded, isolated_repository_identity,
    stage_repository_isolated,
};
#[cfg(test)]
use sandbox::{
    add_runtime_mounts, run_test_command_with_limits, run_test_command_with_timeout,
    TestSandboxLimits,
};

const MAX_DRAFT_BYTES: usize = 32 * 1024 * 1024;
const MAX_PROOF_BYTES: usize = 24 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const MAX_GIT_ERROR_BYTES: usize = 64 * 1024;
const MAX_REPOSITORY_IDENTITY_BYTES: usize = 8 * 1024;
#[cfg(test)]
const REPOSITORY_STAGE_TIMEOUT: Duration = Duration::from_secs(300);
pub(super) const REPOSITORY_STAGE_MAX_BYTES: u64 = 1024 * 1024 * 1024;
pub(super) const REPOSITORY_STAGE_MAX_ENTRIES: u64 = 75_000;
const PAYLOAD_TENANT: &str = "cognition-market-pilot";
const ADMISSION_JOB_SCHEMA: &str = "chio.finding.admission-job.v1";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FindingAdmissionJob {
    schema: String,
    finding_id: String,
    package_path: String,
    package_sha256: String,
    accepted_at: Option<u64>,
    evaluation_time: Option<u64>,
    activation: Option<serde_json::Value>,
    completed: bool,
}

struct FindingAdmissionRunResult {
    finding_id: String,
    activation: serde_json::Value,
    proof_path: PathBuf,
}

pub(super) struct VerifiedFixPackageRequest<'a> {
    pub profile_path: &'a Path,
    pub repository: &'a Path,
    pub base: &'a str,
    pub candidate: &'a str,
    pub tests: &'a [String],
    pub topic: &'a str,
    pub seller: &'a str,
    pub price: u64,
    pub output: Option<&'a Path>,
}

pub(super) fn cmd_finding_package_verified_fix(
    request: &VerifiedFixPackageRequest<'_>,
    json_output: bool,
) -> Result<(), CliError> {
    let (profile, root) = load_profile(request.profile_path)?;
    let paths = ResolvedOperatorPaths::new(&root, &profile.paths);
    let package_deadline = Instant::now()
        .checked_add(PACKAGE_WORK_TIMEOUT)
        .ok_or_else(|| CliError::cli_other_error("package work deadline overflowed".to_owned()))?;
    let (approved_root, repository) =
        approved_repository(&profile.seller_repository_root, request.repository)?;
    require_sandbox()?;
    require_isolated_git_repository(
        &approved_root,
        &repository,
        remaining_package_time(package_deadline)?,
    )?;
    let base_revision = format!("{}^{{commit}}", request.base);
    let base = isolated_git_stdout_bounded(
        &approved_root,
        &repository,
        &["rev-parse", "--verify", &base_revision],
        128,
        remaining_package_time(package_deadline)?,
        "resolve verified-fix base revision",
    )?;
    let candidate_revision = format!("{}^{{commit}}", request.candidate);
    let candidate = isolated_git_stdout_bounded(
        &approved_root,
        &repository,
        &["rev-parse", "--verify", &candidate_revision],
        128,
        remaining_package_time(package_deadline)?,
        "resolve verified-fix candidate revision",
    )?;
    if base == candidate {
        return Err(CliError::cli_other_error(
            "base and candidate resolve to the same commit".to_owned(),
        ));
    }
    if request.tests.is_empty() || request.tests.iter().any(|test| test.trim().is_empty()) {
        return Err(CliError::cli_other_error(
            "at least one non-empty --test command is required".to_owned(),
        ));
    }
    let repository_identity = isolated_repository_identity(
        &approved_root,
        &repository,
        remaining_package_time(package_deadline)?,
    )?;
    let work_root = paths
        .packages_directory
        .join(format!(".verified-fix-work-{}", uuid::Uuid::new_v4()));
    create_private_directory(&work_root)?;
    // Install the cleanup guard before clone staging. Any partial clone or
    // checkout is therefore removed on every ordinary error path.
    let worktrees = StagedRepositorySet::new(work_root);
    worktrees.stage(&repository, &approved_root, package_deadline)?;
    let staged_repository = worktrees.repository.clone();
    let baseline_path = worktrees.add("baseline", &base, package_deadline)?;
    let candidate_path = worktrees.add("candidate", &candidate, package_deadline)?;
    let baseline = run_test_commands(&baseline_path, request.tests, package_deadline)?;
    let candidate_results = run_test_commands(&candidate_path, request.tests, package_deadline)?;
    if !baseline.iter().any(|result| result.exit_code != 0) {
        return Err(CliError::cli_other_error(
            "verified-fix baseline unexpectedly passed every test".to_owned(),
        ));
    }
    if let Some(failure) = candidate_results.iter().find(|result| result.exit_code != 0) {
        return Err(CliError::cli_other_error(format!(
            "verified-fix candidate failed `{}` with exit code {}",
            terminal_safe(&failure.command),
            failure.exit_code
        )));
    }
    let patch = git_stdout_bytes_bounded(
        &staged_repository,
        &["diff", "--binary", "--full-index", &base, &candidate, "--"],
        MAX_DRAFT_BYTES,
        remaining_package_time(package_deadline)?,
    )?;
    let patch = String::from_utf8(patch).map_err(|_| {
        CliError::cli_other_error("git emitted a non-UTF-8 binary patch".to_owned())
    })?;
    let issued_at = unix_time()?;
    let runner_manifest = canonical_json_bytes(&serde_json::json!({
        "aggregatePackageDeadlineMillis": PACKAGE_WORK_TIMEOUT.as_millis(),
        "isolation": "bubblewrap-cgroup-v2-rlimit-bounded-tmpfs-v1",
        "runner": "chio finding package verified-fix",
        "tests": request.tests,
        "version": env!("CARGO_PKG_VERSION"),
    }))?;
    let runtime_fingerprint = runtime_fingerprint()?;
    let draft = FindingVerifiedFixDraft::author(
        &profile,
        VerifiedFixAuthoringInput {
            seller_principal: request.seller.to_owned(),
            repository: repository_identity,
            base_revision: base,
            candidate_revision: candidate,
            topic: request.topic.to_owned(),
            patch,
            baseline,
            candidate: candidate_results,
            runner_manifest,
            runtime_fingerprint,
            price_units: request.price,
            issued_at,
        },
    )
    .map_err(CliError::cli_other_error)?;
    draft
        .verify_static(&profile)
        .map_err(CliError::cli_other_error)?;
    decode_canonical_b64(&draft.payload_b64, MAX_PAYLOAD_BYTES, "payload")?;
    let bytes = canonical_json_bytes(&draft)?;
    if bytes.len() > MAX_DRAFT_BYTES {
        return Err(CliError::cli_other_error(
            "verified-fix draft exceeds the local size bound".to_owned(),
        ));
    }
    let output = request.output.map_or_else(
        || {
            paths
                .packages_directory
                .join(format!("{}.draft.json", draft.finding.finding_id))
        },
        Path::to_path_buf,
    );
    write_private_new_atomic(&output, &bytes)?;
    let report = serde_json::json!({
        "candidatePassed": true,
        "draft": output,
        "findingId": draft.finding.finding_id,
        "baselineFailed": true,
        "payloadSha256": draft.finding.payload_sha256,
        "schema": "chio.finding.verified-fix-package-result.v1",
        "testCount": request.tests.len(),
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("finding_id:       {}", draft.finding.finding_id);
        println!("draft:            {}", output.display());
        println!("baseline_failed:  true");
        println!("candidate_passed: true");
        println!("tests:            {}", request.tests.len());
    }
    Ok(())
}

pub(super) fn cmd_finding_admit(
    profile_path: &Path,
    package_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let result = run_finding_admission(profile_path, package_path)?;
    let output = serde_json::json!({
        "activation": result.activation,
        "findingId": result.finding_id,
        "proofBundle": result.proof_path,
        "schema": "chio.finding.admission-result.v1",
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("finding_id:  {}", output["findingId"]);
        println!("activation:  {}", output["activation"]["outcome"]);
        println!("proof_bundle: {}", result.proof_path.display());
    }
    Ok(())
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FindingAdmissionReconciliationFailure {
    finding_id: String,
    error: String,
}

pub(super) struct FindingAdmissionReconciliation {
    pub(super) reconciled_jobs: u64,
    pub(super) failed_jobs: Vec<FindingAdmissionReconciliationFailure>,
}

pub(super) fn reconcile_admission_jobs(
    profile_path: &Path,
) -> Result<FindingAdmissionReconciliation, CliError> {
    let (profile, root) = load_profile(profile_path)?;
    let paths = ResolvedOperatorPaths::new(&root, &profile.paths);
    let mut pending = Vec::new();
    for entry in fs::read_dir(&paths.reports_directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || !entry
                .file_name()
                .to_string_lossy()
                .ends_with(".admission-job.json")
        {
            continue;
        }
        let job: FindingAdmissionJob = read_canonical_file(&entry.path(), MAX_DRAFT_BYTES)?;
        validate_admission_job(&job)?;
        if !job.completed {
            pending.push((job.finding_id, PathBuf::from(job.package_path)));
        }
    }
    pending.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(reconcile_pending_admissions(pending, |package| {
        run_finding_admission(profile_path, package).map(|_| ())
    }))
}

fn reconcile_pending_admissions(
    pending: Vec<(String, PathBuf)>,
    mut reconcile: impl FnMut(&Path) -> Result<(), CliError>,
) -> FindingAdmissionReconciliation {
    let mut reconciled_jobs = 0u64;
    let mut failed_jobs = Vec::new();
    for (finding_id, package) in pending {
        match reconcile(&package) {
            Ok(()) => reconciled_jobs = reconciled_jobs.saturating_add(1),
            Err(error) => failed_jobs.push(FindingAdmissionReconciliationFailure {
                finding_id,
                error: terminal_safe(reconciliation_error_message(&error)),
            }),
        }
    }
    FindingAdmissionReconciliation {
        reconciled_jobs,
        failed_jobs,
    }
}

fn reconciliation_error_message(error: &CliError) -> &str {
    match error {
        CliError::Chio(error) => error.message(),
        CliError::Other(message) => message,
        _ => "admission reconciliation failed",
    }
}

fn run_finding_admission(
    profile_path: &Path,
    package_path: &Path,
) -> Result<FindingAdmissionRunResult, CliError> {
    let (profile, root) = load_profile(profile_path)?;
    let paths = ResolvedOperatorPaths::new(&root, &profile.paths);
    let package_path = fs::canonicalize(package_path)?;
    let package_bytes = read_file_bounded(&package_path, MAX_DRAFT_BYTES)?;
    let draft: FindingVerifiedFixDraft = parse_canonical(&package_bytes, "verified-fix package")?;
    draft
        .verify_static(&profile)
        .map_err(CliError::cli_other_error)?;
    let job_path = paths.reports_directory.join(format!(
        "{}.admission-job.json",
        draft.finding.finding_id
    ));
    let _job_lock = FindingAdmissionJobLock::acquire(&root)?;
    let mut job = load_or_create_admission_job(
        &job_path,
        &draft.finding.finding_id,
        &package_path,
        &sha256_hex(&package_bytes),
    )?;
    let proof_path = paths
        .reports_directory
        .join(format!("{}.proof.json", draft.finding.finding_id));
    if job.completed {
        let activation = job.activation.clone().ok_or_else(|| {
            CliError::cli_other_error("completed admission job omitted activation".to_owned())
        })?;
        if !proof_path.is_file() {
            return Err(CliError::cli_other_error(
                "completed admission job omitted its proof bundle".to_owned(),
            ));
        }
        return Ok(FindingAdmissionRunResult {
            finding_id: draft.finding.finding_id,
            activation,
            proof_path,
        });
    }
    let base_url = format!("http://{}", profile.listen);
    let resolver = FindingOperatorAuthorityStatusResolver::new(
        profile.market.authority_status.clone(),
        profile
            .authority_status_key()
            .map_err(CliError::cli_other_error)?,
    )
    .map_err(CliError::cli_other_error)?;

    let now = unix_time()?;
    let governance_status = resolver
        .resolve(&profile.market.governance_root, now)
        .map_err(CliError::cli_other_error)?;
    post_json(
        &base_url,
        "/v1/findings/profiles",
        &profile.service_token,
        &serde_json::json!({
            "governanceAuthorityStatus": governance_status,
            "profile": draft.verifier_profile,
        }),
    )?;
    let recipe = decode_canonical_b64(&draft.replay_recipe_b64, 1024 * 1024, "replay recipe")?;
    post_bytes(
        &base_url,
        "/v1/findings/recipes",
        &profile.service_token,
        &recipe,
    )?;
    for blob in &draft.recipe_blobs {
        let bytes = decode_canonical_b64(&blob.bytes_b64, 4 * 1024 * 1024, "recipe blob")?;
        if sha256_hex(&bytes) != blob.sha256 {
            return Err(CliError::cli_other_error(
                "recipe blob digest mismatch".to_owned(),
            ));
        }
        post_bytes(
            &base_url,
            "/v1/findings/recipes",
            &profile.service_token,
            &bytes,
        )?;
    }
    post_bytes(
        &base_url,
        "/v1/findings/publish",
        &profile.service_token,
        &canonical_json_bytes(&draft.finding)?,
    )?;
    let collateral_now = unix_time()?;
    let collateral_status = resolver
        .resolve(&profile.market.collateral, collateral_now)
        .map_err(CliError::cli_other_error)?;
    let collateral_response = post_json(
        &base_url,
        "/v1/findings/collateral",
        &profile.service_token,
        &serde_json::json!({
            "backing": draft.bond_backing,
            "collateralAuthorityStatus": collateral_status,
        }),
    )?;
    let accepted_at = collateral_response
        .get("acceptedAt")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            CliError::transport_shape_error(
                "collateral response omitted its acceptedAt timestamp".to_owned(),
            )
        })?;
    if job.accepted_at.is_some_and(|stored| stored != accepted_at) {
        return Err(CliError::cli_other_error(
            "admission retry returned a different collateral acceptance time".to_owned(),
        ));
    }
    job.accepted_at = Some(accepted_at);
    let evaluation_time = job
        .evaluation_time
        .unwrap_or(unix_time()?.max(accepted_at.saturating_add(1)));
    if evaluation_time <= accepted_at {
        return Err(CliError::cli_other_error(
            "admission job evaluation time does not follow collateral acceptance".to_owned(),
        ));
    }
    job.evaluation_time = Some(evaluation_time);
    write_private_atomic(&job_path, &canonical_json_bytes(&job)?)?;
    wait_until(evaluation_time)?;
    let finalization = draft
        .finalize(&profile, accepted_at, evaluation_time)
        .map_err(CliError::cli_other_error)?;
    // Persist every byte needed by the purchase and proof paths before the
    // listing can become active. A crash can therefore leave a retained but
    // inactive package, never an active listing whose reveal is unavailable.
    let bundle_bytes = canonical_json_bytes(&finalization.bundle)?;
    let bundle_store = SqliteFindingOperatorBundleStore::open(&paths.operator_database)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    bundle_store
        .put(&draft.finding.finding_id, &bundle_bytes)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let payload = decode_canonical_b64(&draft.payload_b64, MAX_PAYLOAD_BYTES, "payload")?;
    SqliteFindingPayloadStore::open(&paths.operator_database)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
        .put(
            &TenantId::new(PAYLOAD_TENANT),
            &TenantKey::from_bytes(
                profile
                    .payload_key_bytes()
                    .map_err(CliError::cli_other_error)?,
            ),
            &draft.finding.finding_id,
            &draft.finding.payload_media_type,
            &draft.finding.payload_sha256,
            &payload,
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let proof_bytes = canonical_json_bytes(&finalization.proof)?;
    bundle_store
        .put_proof(&draft.finding.finding_id, &proof_bytes)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    write_private_exact_or_new(&proof_path, &proof_bytes)?;

    post_bytes(
        &base_url,
        &format!(
            "/v1/findings/{}/operator/live-status",
            draft.finding.finding_id
        ),
        &profile.service_token,
        b"",
    )?;
    let activation_now = unix_time()?;
    let status = |pin| {
        resolver
            .resolve(pin, activation_now)
            .map_err(CliError::cli_other_error)
    };
    let seller_status = seller_authorization_status(&profile, &draft, activation_now)?;
    let activation = serde_json::json!({
        "admission": finalization.bundle.admission,
        "backing": finalization.bundle.bond_backing,
        "collateralAuthorityStatus": status(&profile.market.collateral)?,
        "feeSchedule": finalization.bundle.fee_schedule,
        "listing": finalization.bundle.listing.listing,
        "listingAuthorityStatus": status(&profile.market.listing)?,
        "pricingHint": finalization.bundle.listing.pricing,
        "profileGovernanceAuthorityStatus": status(&profile.market.governance_root)?,
        "sellerAuthorization": finalization.bundle.seller_authorization,
        "sellerAuthorizationStatus": seller_status,
        "statusOperatorAuthorityStatus": status(&profile.market.status_feed_operator.authority)?,
        "terms": finalization.bundle.market_terms,
        "venueAuthorityStatus": status(&profile.market.venue)?,
        "verifierAuthorityStatus": status(&profile.market.verifier_report)?,
        "verifierReport": finalization.bundle.verifier_report,
    });
    let mut activation_response = post_json(
        &base_url,
        &format!("/v1/findings/{}/activate", draft.finding.finding_id),
        &profile.service_token,
        &activation,
    )?;
    if let Some(stored) = job.activation.as_ref() {
        if !same_activation(stored, &activation_response) {
            return Err(CliError::cli_other_error(
                "admission retry returned a different activation result".to_owned(),
            ));
        }
        activation_response = stored.clone();
    } else {
        job.activation = Some(activation_response.clone());
    }
    write_private_atomic(&job_path, &canonical_json_bytes(&job)?)?;

    job.completed = true;
    write_private_atomic(&job_path, &canonical_json_bytes(&job)?)?;
    Ok(FindingAdmissionRunResult {
        finding_id: draft.finding.finding_id,
        activation: activation_response,
        proof_path,
    })
}

pub(super) fn cmd_finding_verify_bundle(
    profile_path: &Path,
    input: &Path,
    purchase_request_path: Option<&Path>,
    purchase_result_path: Option<&Path>,
    json_output: bool,
) -> Result<(), CliError> {
    let market = load_verification_market(profile_path)?;
    let bytes = if input == Path::new("-") {
        read_stdin_bounded(MAX_PROOF_BYTES)?
    } else {
        read_file_bounded(input, MAX_PROOF_BYTES)?
    };
    let proof: FindingOperatorProofBundle = parse_canonical(&bytes, "proof bundle")?;
    let authorized_terminal = match (purchase_request_path, purchase_result_path) {
        (Some(request_path), Some(result_path)) => {
            let request: FindingPurchaseRequest =
                read_canonical_file(request_path, 64 * 1024)?;
            request.validate().map_err(CliError::transport_shape_error)?;
            if request.max_price.units > i64::MAX as u64 {
                return Err(CliError::transport_shape_error(
                    "purchase request exceeds the durable payment range".to_owned(),
                ));
            }
            let result: FindingPurchaseResult =
                read_canonical_file(result_path, FINDING_PURCHASE_MAX_RESULT_BYTES)?;
            result
                .validate_authorized(
                    &request,
                    &proof.bundle.finding,
                    &proof.bundle.admission,
                )
                .map_err(CliError::transport_shape_error)?;
            let terminal_time = result
                .purchase_record
                .as_ref()
                .map(|record| record.body.recorded_at)
                .or_else(|| {
                    result
                        .failed_delivery
                        .as_ref()
                        .map(|failed| failed.body.recorded_at)
                })
                .ok_or_else(|| {
                    CliError::transport_shape_error(
                        "purchase terminal omitted its authenticated time".to_owned(),
                    )
                })?;
            Some((result, terminal_time))
        }
        (None, None) => None,
        _ => {
            return Err(CliError::cli_other_error(
                "purchase request and result must be supplied together".to_owned(),
            ));
        }
    };
    // A paid terminal remains deliverable after the listing or admission
    // expires. Its purchase authority signature authenticates the historical
    // record time, so verify proof liveness at that terminal rather than at
    // the retrying client's wall clock. Pre-purchase verification stays live.
    let verification_time = proof_verification_time(
        authorized_terminal
            .as_ref()
            .map(|(_, terminal_time)| *terminal_time),
    )?;
    proof
        .verify(&market, verification_time)
        .map_err(CliError::cli_other_error)?;
    if let Some((result, _)) = authorized_terminal.as_ref() {
        super::verify_purchased_output(&proof.bundle.finding, result)?;
    }
    let purchase_verified = authorized_terminal.is_some();
    let result = serde_json::json!({
        "evaluationTime": proof.bundle.verifier_report.body.evaluation_time,
        "findingId": proof.bundle.finding.finding_id,
        "purchaseTerminalVerified": purchase_verified,
        "requiredFacetsVerified": true,
        "schema": "chio.finding.verify-bundle-result.v1",
        "verifierReportId": proof.bundle.verifier_report.body.report_id,
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("finding_id:              {}", proof.bundle.finding.finding_id);
        println!("required_facets_verified: true");
        println!("purchase_terminal_verified: {purchase_verified}");
        println!(
            "verifier_report_id:       {}",
            proof.bundle.verifier_report.body.report_id
        );
    }
    Ok(())
}

fn proof_verification_time(authenticated_terminal_time: Option<u64>) -> Result<u64, CliError> {
    match authenticated_terminal_time {
        Some(terminal_time) => Ok(terminal_time),
        None => unix_time(),
    }
}

struct StagedRepositorySet {
    repository: PathBuf,
    root: PathBuf,
}

impl StagedRepositorySet {
    fn new(root: PathBuf) -> Self {
        Self {
            repository: root.join("repository"),
            root,
        }
    }

    fn stage(
        &self,
        source: &Path,
        approved_root: &Path,
        deadline: Instant,
    ) -> Result<(), CliError> {
        stage_repository_isolated(
            source,
            approved_root,
            &self.root,
            remaining_package_time(deadline)?,
        )
    }

    fn add(&self, name: &str, revision: &str, deadline: Instant) -> Result<PathBuf, CliError> {
        let path = self.root.join(name);
        let template = self.root.join(format!("{name}-git-template"));
        fs::create_dir(&template)?;
        let mut clone = hardened_git_command();
        clone
            .args(["clone", "--no-local", "--no-checkout"])
            .arg(format!("--template={}", template.display()))
            .arg(&self.repository)
            .arg(&path);
        run_repository_staging_command(
            clone,
            &self.root,
            &format!("create isolated {name} repository"),
            remaining_package_time(deadline)?,
            REPOSITORY_STAGE_MAX_BYTES,
        )?;
        let mut checkout = hardened_git_command();
        checkout
            .arg("-C")
            .arg(&path)
            .args(["checkout", "--detach"])
            .arg(revision);
        run_repository_staging_command(
            checkout,
            &self.root,
            &format!("check out isolated {name} repository"),
            remaining_package_time(deadline)?,
            REPOSITORY_STAGE_MAX_BYTES,
        )?;
        Ok(path)
    }
}

impl Drop for StagedRepositorySet {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn run_repository_staging_command(
    mut command: Command,
    staging_root: &Path,
    operation: &str,
    timeout: Duration,
    maximum_bytes: u64,
) -> Result<(), CliError> {
    command.stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
        // SAFETY: setrlimit is async-signal-safe and touches only the child
        // between fork and exec. It bounds any one file in addition to the
        // aggregate staging-root accounting below.
        unsafe {
            command.pre_exec(move || {
                let limit = libc::rlimit {
                    rlim_cur: maximum_bytes,
                    rlim_max: maximum_bytes,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }
    let started = Instant::now();
    let mut child = command.spawn()?;
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(CliError::cli_other_error(format!(
                    "failed to {operation} within the repository staging limits"
                )));
            }
            if !staging_root_within_bound(staging_root, maximum_bytes)? {
                return Err(CliError::cli_other_error(
                    "repository staging exceeded its storage bound".to_owned(),
                ));
            }
            return Ok(());
        }
        if started.elapsed() >= timeout {
            terminate_process_group(&mut child);
            let _ = child.wait();
            return Err(CliError::cli_other_error(format!(
                "repository staging exceeded its {} millisecond deadline",
                timeout.as_millis()
            )));
        }
        match staging_root_within_bound(staging_root, maximum_bytes) {
            Ok(true) => {}
            Ok(false) => {
                terminate_process_group(&mut child);
                let _ = child.wait();
                return Err(CliError::cli_other_error(
                    "repository staging exceeded its storage bound".to_owned(),
                ));
            }
            Err(error) => {
                terminate_process_group(&mut child);
                let _ = child.wait();
                return Err(error);
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn terminate_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        if let Ok(pid) = i32::try_from(child.id()) {
            // SAFETY: the child is created as its own process group above, so
            // the negative PID targets only that group.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    let _ = child.kill();
}

fn staging_root_within_bound(root: &Path, maximum_bytes: u64) -> Result<bool, CliError> {
    let mut pending = vec![root.to_path_buf()];
    let mut bytes = 0u64;
    let mut entries = 0u64;
    while let Some(directory) = pending.pop() {
        let directory_entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(CliError::from(error)),
        };
        for entry in directory_entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(CliError::from(error)),
            };
            entries = entries.saturating_add(1);
            if entries > REPOSITORY_STAGE_MAX_ENTRIES {
                return Ok(false);
            }
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(CliError::from(error)),
            };
            if metadata.file_type().is_symlink() {
                bytes = bytes.saturating_add(metadata.len());
            } else if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                bytes = bytes.saturating_add(metadata.len());
            }
            if bytes > maximum_bytes {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn hardened_git_command() -> Command {
    let mut command = Command::new("git");
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PAGER", "cat")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "credential.helper=",
            "-c",
            "protocol.ext.allow=never",
        ]);
    command
}

fn require_isolated_git_repository(
    approved_root: &Path,
    repository: &Path,
    timeout: Duration,
) -> Result<(), CliError> {
    let inside = isolated_git_stdout_bounded(
        approved_root,
        repository,
        &["rev-parse", "--is-inside-work-tree"],
        16,
        timeout,
        "verify seller repository",
    )?;
    if inside != "true" {
        return Err(CliError::cli_other_error(
            "--repository is not a git worktree".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn git_stdout_bounded(
    repository: &Path,
    args: &[&str],
    max_bytes: usize,
    timeout: Duration,
    label: &str,
) -> Result<String, CliError> {
    let mut command = hardened_git_command();
    command.arg("-C").arg(repository).args(args);
    let bytes = run_bounded_output_command(command, max_bytes, timeout, label)?;
    let value = String::from_utf8(bytes)
        .map_err(|_| CliError::cli_other_error("git output is not UTF-8".to_owned()))?;
    Ok(value.trim().to_owned())
}

#[cfg(test)]
fn git_optional_stdout_bounded(
    repository: &Path,
    args: &[&str],
    max_bytes: usize,
    timeout: Duration,
    label: &str,
) -> Result<Option<String>, CliError> {
    let mut command = hardened_git_command();
    command.arg("-C").arg(repository).args(args);
    let output = run_bounded_output_command_capture(command, max_bytes, timeout, label)?;
    if !output.status.success() {
        return Ok(None);
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| CliError::cli_other_error("git output is not UTF-8".to_owned()))?;
    Ok((!value.trim().is_empty()).then(|| value.trim().to_owned()))
}

#[cfg(test)]
fn repository_identity(repository: &Path) -> Result<String, CliError> {
    Ok(git_optional_stdout_bounded(
        repository,
        &["remote", "get-url", "origin"],
        MAX_REPOSITORY_IDENTITY_BYTES,
        REPOSITORY_STAGE_TIMEOUT,
        "resolve seller repository identity",
    )?
        .and_then(|remote| credential_free_repository_url(&remote))
        .unwrap_or_else(|| repository.display().to_string()))
}

fn credential_free_repository_url(remote: &str) -> Option<String> {
    if let Ok(mut parsed) = url::Url::parse(remote) {
        parsed.set_username("").ok()?;
        parsed.set_password(None).ok()?;
        parsed.set_query(None);
        parsed.set_fragment(None);
        return Some(parsed.to_string());
    }
    if remote.contains("://") {
        return None;
    }
    let without_suffix = remote
        .split(['?', '#'])
        .next()
        .filter(|value| !value.is_empty())?;
    let identity = without_suffix
        .rsplit_once('@')
        .filter(|(_, location)| location.contains(':'))
        .map_or(without_suffix, |(_, location)| location);
    Some(identity.to_owned())
}

fn git_stdout_bytes_bounded(
    repository: &Path,
    args: &[&str],
    max_bytes: usize,
    timeout: Duration,
) -> Result<Vec<u8>, CliError> {
    let mut command = hardened_git_command();
    command.arg("-C").arg(repository).args(args);
    run_bounded_output_command(command, max_bytes, timeout, "git command")
}

fn remaining_package_time(deadline: Instant) -> Result<Duration, CliError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(CliError::cli_other_error(format!(
            "verified-fix packaging exceeded the {} millisecond aggregate deadline",
            PACKAGE_WORK_TIMEOUT.as_millis()
        )));
    }
    Ok(remaining)
}

fn run_bounded_output_command(
    command: Command,
    max_bytes: usize,
    timeout: Duration,
    label: &str,
) -> Result<Vec<u8>, CliError> {
    let output = run_bounded_output_command_capture(command, max_bytes, timeout, label)?;
    if !output.status.success() {
        return Err(CliError::cli_other_error(format!(
            "{label} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

struct BoundedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_bounded_output_command_capture(
    mut command: Command,
    max_bytes: usize,
    timeout: Duration,
    label: &str,
) -> Result<BoundedCommandOutput, CliError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let started = Instant::now();
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::cli_other_error("git stdout pipe is unavailable".to_owned()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| CliError::cli_other_error("git stderr pipe is unavailable".to_owned()))?;
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout_overflow = Arc::clone(&overflow);
    let stdout_reader = thread::spawn(move || {
        read_output_prefix(stdout, max_bytes, Some(&stdout_overflow))
    });
    let stderr_reader =
        thread::spawn(move || read_output_prefix(stderr, MAX_GIT_ERROR_BYTES, None));
    let outcome = loop {
        if let Some(status) = child.try_wait()? {
            break Ok(status);
        }
        if overflow.load(Ordering::Acquire) {
            terminate_process_group(&mut child);
            let _ = child.wait();
            break Err(CliError::cli_other_error(format!(
                "{label} output exceeded the {max_bytes} byte bound"
            )));
        }
        if started.elapsed() >= timeout {
            terminate_process_group(&mut child);
            let _ = child.wait();
            break Err(CliError::cli_other_error(format!(
                "{label} exceeded the {} millisecond deadline",
                timeout.as_millis()
            )));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let bytes = stdout_reader
        .join()
        .map_err(|_| CliError::cli_other_error("git stdout reader panicked".to_owned()))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| CliError::cli_other_error("git stderr reader panicked".to_owned()))??;
    if overflow.load(Ordering::Acquire) {
        return Err(CliError::cli_other_error(format!(
            "{label} output exceeded the {max_bytes} byte bound"
        )));
    }
    let status = outcome?;
    Ok(BoundedCommandOutput {
        status,
        stdout: bytes,
        stderr,
    })
}

fn read_output_prefix(
    mut reader: impl Read,
    maximum: usize,
    overflow: Option<&AtomicBool>,
) -> Result<Vec<u8>, std::io::Error> {
    let mut prefix = Vec::new();
    let mut total = 0usize;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        let retained = maximum.saturating_sub(prefix.len()).min(read);
        prefix.extend_from_slice(&buffer[..retained]);
        if total > maximum {
            if let Some(overflow) = overflow {
                overflow.store(true, Ordering::Release);
            }
        }
    }
    Ok(prefix)
}

fn seller_authorization_status(
    profile: &FindingOperatorProfile,
    draft: &FindingVerifiedFixDraft,
    observed_at: u64,
) -> Result<SignedExportEnvelope<FindingAuthorityStatus>, CliError> {
    let key = profile
        .authority_status_key()
        .map_err(CliError::cli_other_error)?;
    SignedExportEnvelope::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_owned(),
            status_ref: draft
                .seller_authorization
                .body
                .revocation_status_ref
                .clone(),
            authority_id: draft
                .seller_authorization
                .body
                .authorization_id
                .clone(),
            key: draft.seller_authorization.body.issuer.clone(),
            key_epoch: FINDING_SELLER_AUTHORIZATION_KEY_EPOCH_V1,
            revoked_from: None,
            observed_at,
        },
        &key,
    )
    .map_err(|error| CliError::cli_other_error(error.to_string()))
}

fn post_json(
    base_url: &str,
    path: &str,
    token: &str,
    value: &serde_json::Value,
) -> Result<serde_json::Value, CliError> {
    post_bytes(base_url, path, token, &canonical_json_bytes(value)?)
}

fn post_bytes(
    base_url: &str,
    path: &str,
    token: &str,
    bytes: &[u8],
) -> Result<serde_json::Value, CliError> {
    let endpoint = format!("{}{path}", base_url.trim_end_matches('/'));
    let response = match ureq::post(&endpoint)
        .set("authorization", &format!("Bearer {token}"))
        .set("content-type", "application/json")
        .send_bytes(bytes)
    {
        Ok(response) => response,
        Err(ureq::Error::Status(status, response)) => {
            let body = response.into_string().unwrap_or_default();
            return Err(CliError::transport_error(format!(
                "operator request to {path} failed with HTTP {status}: {body}"
            )));
        }
        Err(ureq::Error::Transport(error)) => {
            return Err(CliError::transport_error(format!(
                "operator request to {path} failed: {error}"
            )));
        }
    };
    let mut body = Vec::new();
    response
        .into_reader()
        .take(1024 * 1024)
        .read_to_end(&mut body)?;
    if body.is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_slice(&body).map_err(CliError::from)
}

fn load_verification_market(
    path: &Path,
) -> Result<chio_control_plane::trust_control::FindingMarketConfig, CliError> {
    let bytes = read_file_bounded(path, 1024 * 1024)?;
    let value: serde_json::Value = parse_canonical(&bytes, "verification profile")?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CliError::cli_other_error("verification profile has no schema".to_owned()))?;
    let market = match schema {
        FINDING_OPERATOR_PROFILE_SCHEMA => load_profile(path)?.0.market,
        FINDING_OPERATOR_CLIENT_PROFILE_SCHEMA => {
            let profile: FindingOperatorClientProfile =
                parse_canonical(&bytes, "operator client profile")?;
            profile
                .validate()
                .map_err(CliError::cli_other_error)?;
            profile.market
        }
        FINDING_OPERATOR_BUYER_CLIENT_SCHEMA => {
            let profile: FindingOperatorBuyerClientProfile =
                parse_canonical(&bytes, "buyer client profile")?;
            profile.market
        }
        FINDING_OPERATOR_SELLER_CLIENT_SCHEMA => {
            let profile: FindingOperatorSellerClientProfile =
                parse_canonical(&bytes, "seller client profile")?;
            profile.market
        }
        _ => {
            return Err(CliError::cli_other_error(
                "unsupported verification profile schema".to_owned(),
            ));
        }
    };
    market
        .validate()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(market)
}

pub(super) fn read_canonical_file<T: serde::de::DeserializeOwned + serde::Serialize>(
    path: &Path,
    max_bytes: usize,
) -> Result<T, CliError> {
    let bytes = read_file_bounded(path, max_bytes)?;
    parse_canonical(&bytes, &path.display().to_string())
}

fn parse_canonical<T: serde::de::DeserializeOwned + serde::Serialize>(
    bytes: &[u8],
    label: &str,
) -> Result<T, CliError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CliError::cli_other_error(format!("{label} is not UTF-8")))?;
    let strict = chio_core::canonical::canonical_json_bytes_from_str(text)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if strict != bytes {
        return Err(CliError::cli_other_error(format!(
            "{label} is not strict canonical JSON"
        )));
    }
    let value: T = serde_json::from_slice(bytes)?;
    if canonical_json_bytes(&value)? != bytes {
        return Err(CliError::cli_other_error(format!(
            "{label} typed serialization is not byte-stable"
        )));
    }
    Ok(value)
}

fn load_or_create_admission_job(
    path: &Path,
    finding_id: &str,
    package_path: &Path,
    package_sha256: &str,
) -> Result<FindingAdmissionJob, CliError> {
    let package_path = package_path.to_str().ok_or_else(|| {
        CliError::cli_other_error("verified-fix package path is not UTF-8".to_owned())
    })?;
    if path.exists() {
        let job: FindingAdmissionJob = read_canonical_file(path, MAX_DRAFT_BYTES)?;
        validate_admission_job(&job)?;
        if job.finding_id != finding_id
            || job.package_path != package_path
            || job.package_sha256 != package_sha256
        {
            return Err(CliError::cli_other_error(
                "admission job is bound to different package input".to_owned(),
            ));
        }
        return Ok(job);
    }
    let job = FindingAdmissionJob {
        schema: ADMISSION_JOB_SCHEMA.to_owned(),
        finding_id: finding_id.to_owned(),
        package_path: package_path.to_owned(),
        package_sha256: package_sha256.to_owned(),
        accepted_at: None,
        evaluation_time: None,
        activation: None,
        completed: false,
    };
    validate_admission_job(&job)?;
    write_private_atomic(path, &canonical_json_bytes(&job)?)?;
    Ok(job)
}

fn validate_admission_job(job: &FindingAdmissionJob) -> Result<(), CliError> {
    let hex64 = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if job.schema != ADMISSION_JOB_SCHEMA
        || !hex64(&job.finding_id)
        || !hex64(&job.package_sha256)
        || job.package_path.is_empty()
        || !Path::new(&job.package_path).is_absolute()
        || job.evaluation_time.is_some() != job.accepted_at.is_some()
        || job.activation.is_some() && job.evaluation_time.is_none()
        || job.completed && job.activation.is_none()
    {
        return Err(CliError::cli_other_error(
            "admission job failed its state invariants".to_owned(),
        ));
    }
    if let (Some(accepted_at), Some(evaluation_time)) = (job.accepted_at, job.evaluation_time) {
        if evaluation_time <= accepted_at {
            return Err(CliError::cli_other_error(
                "admission job evaluation time is invalid".to_owned(),
            ));
        }
    }
    Ok(())
}

fn same_activation(stored: &serde_json::Value, replay: &serde_json::Value) -> bool {
    let accepted_outcome = |value: &serde_json::Value| {
        matches!(
            value.get("outcome").and_then(serde_json::Value::as_str),
            Some("Activated" | "ExactReplay")
        )
    };
    accepted_outcome(stored)
        && accepted_outcome(replay)
        && stored.get("admissionId") == replay.get("admissionId")
}

fn read_file_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, CliError> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return Err(CliError::cli_other_error(format!(
            "{} exceeds its size bound",
            path.display()
        )));
    }
    fs::read(path).map_err(CliError::from)
}

fn read_stdin_bounded(max_bytes: usize) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(u64::try_from(max_bytes.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(CliError::cli_other_error(
            "standard input exceeds the proof-bundle size bound".to_owned(),
        ));
    }
    Ok(bytes)
}

fn decode_canonical_b64(
    encoded: &str,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, CliError> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| CliError::cli_other_error(format!("{label} is not base64")))?;
    if bytes.len() > max_bytes || STANDARD.encode(&bytes) != encoded {
        return Err(CliError::cli_other_error(format!(
            "{label} is oversized or noncanonical base64"
        )));
    }
    Ok(bytes)
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let parent = path.parent().ok_or_else(|| {
        CliError::cli_other_error("output path has no parent directory".to_owned())
    })?;
    if !parent.is_dir() {
        return Err(CliError::cli_other_error(format!(
            "output parent does not exist: {}",
            parent.display()
        )));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_private_new_atomic(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let parent = path.parent().ok_or_else(|| {
        CliError::cli_other_error("output path has no parent directory".to_owned())
    })?;
    let file_name = path.file_name().and_then(|name| name.to_str()).ok_or_else(|| {
        CliError::cli_other_error("output path has no portable file name".to_owned())
    })?;
    let temporary = parent.join(format!(".{file_name}.tmp"));
    if temporary.exists() {
        let metadata = fs::symlink_metadata(&temporary)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(CliError::cli_other_error(format!(
                "{} is not a regular temporary output file",
                temporary.display()
            )));
        }
        fs::remove_file(&temporary)?;
    }
    write_private_new(&temporary, bytes)?;
    if let Err(error) = fs::hard_link(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(CliError::from(error));
    }
    fs::remove_file(&temporary)?;
    let directory = OpenOptions::new().read(true).open(parent)?;
    directory.sync_all()?;
    Ok(())
}

fn write_private_exact_or_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    match write_private_new_atomic(path, bytes) {
        Ok(()) => Ok(()),
        Err(_) if path.is_file() => {
            let existing = fs::read(path)?;
            if existing == bytes {
                Ok(())
            } else {
                Err(CliError::cli_other_error(format!(
                    "{} already contains a different proof bundle",
                    path.display()
                )))
            }
        }
        Err(error) => Err(error),
    }
}

pub(super) fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let parent = path.parent().ok_or_else(|| {
        CliError::cli_other_error("private output path has no parent directory".to_owned())
    })?;
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(CliError::cli_other_error(format!(
                "{} is not a regular admission job file",
                path.display()
            )));
        }
    }
    let temporary = parent.join(format!(".admission-job-{}.tmp", uuid::Uuid::new_v4()));
    write_private_new(&temporary, bytes)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(CliError::from(error));
    }
    let directory = OpenOptions::new().read(true).open(parent)?;
    directory.sync_all()?;
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), CliError> {
    fs::create_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn wait_until(timestamp: u64) -> Result<(), CliError> {
    loop {
        let now = unix_time()?;
        if now >= timestamp {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "verified_fix_tests.rs"]
mod tests;

fn unix_time() -> Result<u64, CliError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}
