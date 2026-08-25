use super::super::*;

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
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

const MAX_DRAFT_BYTES: usize = 32 * 1024 * 1024;
const MAX_PROOF_BYTES: usize = 24 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
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
    let repository = fs::canonicalize(request.repository)?;
    require_git_repository(&repository)?;
    let base = git_stdout(&repository, &["rev-parse", "--verify", &format!("{}^{{commit}}", request.base)])?;
    let candidate = git_stdout(
        &repository,
        &["rev-parse", "--verify", &format!("{}^{{commit}}", request.candidate)],
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
    require_bwrap()?;

    let work_root = paths
        .packages_directory
        .join(format!(".verified-fix-work-{}", uuid::Uuid::new_v4()));
    create_private_directory(&work_root)?;
    let mut worktrees = WorktreeSet::new(repository.clone(), work_root);
    let baseline_path = worktrees.add("baseline", &base)?;
    let candidate_path = worktrees.add("candidate", &candidate)?;
    let baseline = run_test_commands(&baseline_path, request.tests)?;
    let candidate_results = run_test_commands(&candidate_path, request.tests)?;
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
    let patch = git_stdout_bytes(
        &repository,
        &["diff", "--binary", "--full-index", &base, &candidate, "--"],
    )?;
    let patch = String::from_utf8(patch).map_err(|_| {
        CliError::cli_other_error("git emitted a non-UTF-8 binary patch".to_owned())
    })?;
    let repository_identity = git_optional_stdout(&repository, &["remote", "get-url", "origin"])
        .unwrap_or_else(|| repository.display().to_string());
    let issued_at = unix_time()?;
    let runner_manifest = canonical_json_bytes(&serde_json::json!({
        "isolation": "bubblewrap-unshare-net-v1",
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
    write_private_new(&output, &bytes)?;
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

pub(super) fn reconcile_admission_jobs(profile_path: &Path) -> Result<u64, CliError> {
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
            pending.push(PathBuf::from(job.package_path));
        }
    }
    let mut reconciled = 0u64;
    for package in pending {
        run_finding_admission(profile_path, &package)?;
        reconciled = reconciled
            .checked_add(1)
            .ok_or_else(|| CliError::cli_other_error("admission job count overflowed".to_owned()))?;
    }
    Ok(reconciled)
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
    let mut job = load_or_create_admission_job(
        &job_path,
        &draft.finding.finding_id,
        &package_path,
        &sha256_hex(&package_bytes),
    )?;
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

    let bundle_bytes = canonical_json_bytes(&finalization.bundle)?;
    let bundle_store = SqliteFindingOperatorBundleStore::open(&paths.operator_database)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    bundle_store
        .put(&draft.finding.finding_id, &bundle_bytes)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let payload = decode_canonical_b64(&draft.payload_b64, 8 * 1024 * 1024, "payload")?;
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
    let proof_path = paths
        .reports_directory
        .join(format!("{}.proof.json", draft.finding.finding_id));
    let proof_bytes = canonical_json_bytes(&finalization.proof)?;
    bundle_store
        .put_proof(&draft.finding.finding_id, &proof_bytes)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    write_private_exact_or_new(&proof_path, &proof_bytes)?;
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
    json_output: bool,
) -> Result<(), CliError> {
    let market = load_verification_market(profile_path)?;
    let bytes = if input == Path::new("-") {
        read_stdin_bounded(MAX_PROOF_BYTES)?
    } else {
        read_file_bounded(input, MAX_PROOF_BYTES)?
    };
    let proof: FindingOperatorProofBundle = parse_canonical(&bytes, "proof bundle")?;
    let now = unix_time()?;
    proof
        .verify(&market, now)
        .map_err(CliError::cli_other_error)?;
    let result = serde_json::json!({
        "evaluationTime": proof.bundle.verifier_report.body.evaluation_time,
        "findingId": proof.bundle.finding.finding_id,
        "requiredFacetsVerified": true,
        "schema": "chio.finding.verify-bundle-result.v1",
        "verifierReportId": proof.bundle.verifier_report.body.report_id,
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("finding_id:              {}", proof.bundle.finding.finding_id);
        println!("required_facets_verified: true");
        println!(
            "verifier_report_id:       {}",
            proof.bundle.verifier_report.body.report_id
        );
    }
    Ok(())
}

struct WorktreeSet {
    repository: PathBuf,
    root: PathBuf,
    paths: Vec<PathBuf>,
}

impl WorktreeSet {
    fn new(repository: PathBuf, root: PathBuf) -> Self {
        Self {
            repository,
            root,
            paths: Vec::new(),
        }
    }

    fn add(&mut self, name: &str, revision: &str) -> Result<PathBuf, CliError> {
        let path = self.root.join(name);
        let status = Command::new("git")
            .arg("-C")
            .arg(&self.repository)
            .args(["worktree", "add", "--detach"])
            .arg(&path)
            .arg(revision)
            .status()?;
        if !status.success() {
            return Err(CliError::cli_other_error(format!(
                "failed to create isolated {name} worktree"
            )));
        }
        self.paths.push(path.clone());
        Ok(path)
    }
}

impl Drop for WorktreeSet {
    fn drop(&mut self) {
        for path in self.paths.iter().rev() {
            let _ = Command::new("git")
                .arg("-C")
                .arg(&self.repository)
                .args(["worktree", "remove", "--force"])
                .arg(path)
                .status();
        }
        let _ = fs::remove_dir(&self.root);
    }
}

fn run_test_commands(
    worktree: &Path,
    commands: &[String],
) -> Result<Vec<VerifiedFixCommandResult>, CliError> {
    commands
        .iter()
        .map(|command| run_test_command(worktree, command))
        .collect()
}

fn run_test_command(
    worktree: &Path,
    command: &str,
) -> Result<VerifiedFixCommandResult, CliError> {
    let started = Instant::now();
    let mut child = Command::new("bwrap")
        .args([
            "--die-with-parent",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/tmp/chio-home",
        ])
        .arg("--bind")
        .arg(worktree)
        .arg(worktree)
        .arg("--chdir")
        .arg(worktree)
        .args([
            "--setenv",
            "HOME",
            "/tmp/chio-home",
            "--setenv",
            "LANG",
            "C",
            "--setenv",
            "LC_ALL",
            "C",
            "--setenv",
            "TZ",
            "UTC",
            "--",
            "sh",
            "-lc",
        ])
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            CliError::cli_other_error(format!("failed to start isolated test command: {error}"))
        })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::cli_other_error("test stdout pipe is unavailable".to_owned()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| CliError::cli_other_error("test stderr pipe is unavailable".to_owned()))?;
    let stdout_reader = thread::spawn(move || read_and_digest(stdout));
    let stderr_reader = thread::spawn(move || read_and_digest(stderr));
    let status = child.wait()?;
    let (stdout_sha256, stdout_overflow) = join_digest(stdout_reader, "stdout")?;
    let (stderr_sha256, stderr_overflow) = join_digest(stderr_reader, "stderr")?;
    if stdout_overflow || stderr_overflow {
        return Err(CliError::cli_other_error(
            "test command output exceeded the 4 MiB evidence bound".to_owned(),
        ));
    }
    Ok(VerifiedFixCommandResult {
        command: command.to_owned(),
        exit_code: exit_code(status),
        stdout_sha256,
        stderr_sha256,
        duration_millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

fn read_and_digest(mut reader: impl Read) -> Result<(String, bool), std::io::Error> {
    use sha2::Digest as _;
    let mut digest = sha2::Sha256::new();
    let mut total = 0usize;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        digest.update(&buffer[..read]);
    }
    Ok((hex::encode(digest.finalize()), total > MAX_COMMAND_OUTPUT_BYTES))
}

fn join_digest(
    worker: thread::JoinHandle<Result<(String, bool), std::io::Error>>,
    label: &str,
) -> Result<(String, bool), CliError> {
    worker
        .join()
        .map_err(|_| CliError::cli_other_error(format!("{label} reader panicked")))?
        .map_err(CliError::from)
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(255)
}

fn require_git_repository(path: &Path) -> Result<(), CliError> {
    let inside = git_stdout(path, &["rev-parse", "--is-inside-work-tree"])?;
    if inside != "true" {
        return Err(CliError::cli_other_error(
            "--repository is not a git worktree".to_owned(),
        ));
    }
    Ok(())
}

fn require_bwrap() -> Result<(), CliError> {
    let output = Command::new("bwrap").arg("--version").output().map_err(|_| {
        CliError::cli_other_error(
            "verified-fix packaging requires bubblewrap for network isolation".to_owned(),
        )
    })?;
    if !output.status.success() {
        return Err(CliError::cli_other_error(
            "bubblewrap is unavailable for verified-fix isolation".to_owned(),
        ));
    }
    Ok(())
}

fn runtime_fingerprint() -> Result<Vec<u8>, CliError> {
    let os_release = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let git = command_version("git", &["--version"])?;
    let bwrap = command_version("bwrap", &["--version"])?;
    let shell = command_version("sh", &["--version"]).unwrap_or_else(|_| "sh".to_owned());
    canonical_json_bytes(&serde_json::json!({
        "arch": std::env::consts::ARCH,
        "bubblewrap": bwrap,
        "git": git,
        "os": std::env::consts::OS,
        "osReleaseSha256": sha256_hex(os_release.as_bytes()),
        "shell": shell,
    }))
    .map_err(CliError::from)
}

fn command_version(command: &str, args: &[&str]) -> Result<String, CliError> {
    let output = Command::new(command).args(args).output()?;
    if !output.status.success() {
        return Err(CliError::cli_other_error(format!(
            "failed to query {command} version"
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn git_stdout(repository: &Path, args: &[&str]) -> Result<String, CliError> {
    let bytes = git_stdout_bytes(repository, args)?;
    let value = String::from_utf8(bytes)
        .map_err(|_| CliError::cli_other_error("git output is not UTF-8".to_owned()))?;
    Ok(value.trim().to_owned())
}

fn git_optional_stdout(repository: &Path, args: &[&str]) -> Option<String> {
    git_stdout(repository, args).ok().filter(|value| !value.is_empty())
}

fn git_stdout_bytes(repository: &Path, args: &[&str]) -> Result<Vec<u8>, CliError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(CliError::cli_other_error(format!(
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
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

fn write_private_exact_or_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    match write_private_new(path, bytes) {
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

fn unix_time() -> Result<u64, CliError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}
