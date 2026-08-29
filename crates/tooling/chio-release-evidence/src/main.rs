//! Produce the signed, exact-candidate release qualification manifest.

#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::{
    canonical_json_bytes, canonical_json_bytes_from_str, receipt::lineage::SignedExportEnvelope,
    Keypair, SigningAlgorithm,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MANIFEST_SCHEMA: &str = "chio.release-qualification-manifest.v1";
const QUALIFICATION_SCOPE: &str =
    "self-signed internal release qualification; not external assurance or underwriting evidence";
const MAX_ARTIFACTS: usize = 100_000;
const HASH_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CLOCK_SKEW_SECS: u64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationArtifact {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseQualificationManifest {
    schema: String,
    candidate_git_commit: String,
    candidate_git_tree: String,
    cargo_lock_sha256: String,
    generated_at_unix_secs: u64,
    source: String,
    workflow_run_id: Option<String>,
    workflow_run_attempt: Option<String>,
    qualification_scope: String,
    artifacts: Vec<QualificationArtifact>,
}

struct Args {
    repo_root: PathBuf,
    artifact_root: PathBuf,
    signing_seed: Option<PathBuf>,
    output: PathBuf,
    checksums: PathBuf,
    expected_candidate: Option<String>,
    verify: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("release qualification manifest: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = parse_args(env::args_os().collect())?;
    if args.verify {
        verify(args)
    } else {
        qualify(args)
    }
}

fn qualify(args: Args) -> Result<(), String> {
    let repo_root = canonical_directory(&args.repo_root, "repository root")?;
    let artifact_root = canonical_directory(&args.artifact_root, "artifact root")?;
    if !artifact_root.starts_with(&repo_root) {
        return Err("artifact root must be inside the repository".to_owned());
    }
    let signing_seed_path = args
        .signing_seed
        .as_ref()
        .ok_or_else(|| "missing --signing-seed".to_owned())?;
    let signing_seed = fs::canonicalize(signing_seed_path)
        .map_err(|error| format!("resolve signing seed: {error}"))?;
    if signing_seed.starts_with(&artifact_root) {
        return Err("signing seed must be outside the release artifact root".to_owned());
    }
    let output = absolute_under(&repo_root, &args.output, "manifest output")?;
    let checksums = absolute_under(&repo_root, &args.checksums, "checksum output")?;
    if !output.starts_with(&artifact_root) || !checksums.starts_with(&artifact_root) {
        return Err("manifest and checksum outputs must be inside the artifact root".to_owned());
    }
    if output == checksums {
        return Err("manifest and checksum outputs must be distinct".to_owned());
    }

    let status = git_output(
        &repo_root,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        return Err(
            "source tree is dirty; release evidence requires an exact clean commit".to_owned(),
        );
    }
    let candidate = git_output(&repo_root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    require_git_object_id(&candidate, "candidate commit")?;
    if args
        .expected_candidate
        .as_deref()
        .is_some_and(|expected| expected != candidate)
    {
        return Err("expected candidate does not match the checked-out commit".to_owned());
    }
    let tree = git_output(&repo_root, &["rev-parse", "--verify", "HEAD^{tree}"])?;
    require_git_object_id(&tree, "candidate tree")?;

    let cargo_lock_sha256 = hash_file(&repo_root.join("Cargo.lock"))?.0;
    let mut artifacts = collect_artifacts(&artifact_root, &output, &checksums)?;
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    if artifacts.is_empty() {
        return Err("release qualification produced no artifacts".to_owned());
    }

    let seed_text =
        fs::read_to_string(&signing_seed).map_err(|error| format!("read signing seed: {error}"))?;
    let signer = Keypair::from_seed_hex(seed_text.trim())
        .map_err(|_| "release qualification signing seed is invalid".to_owned())?;
    let github_actions = env::var("GITHUB_ACTIONS").is_ok_and(|value| value == "true");
    let manifest = ReleaseQualificationManifest {
        schema: MANIFEST_SCHEMA.to_owned(),
        candidate_git_commit: candidate.clone(),
        candidate_git_tree: tree,
        cargo_lock_sha256,
        generated_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock predates the Unix epoch".to_owned())?
            .as_secs(),
        source: if github_actions {
            "github-actions".to_owned()
        } else {
            "local".to_owned()
        },
        workflow_run_id: github_actions
            .then(|| env::var("GITHUB_RUN_ID"))
            .transpose()
            .map_err(|_| "GitHub Actions release evidence requires GITHUB_RUN_ID".to_owned())?,
        workflow_run_attempt: github_actions
            .then(|| env::var("GITHUB_RUN_ATTEMPT"))
            .transpose()
            .map_err(|_| {
                "GitHub Actions release evidence requires GITHUB_RUN_ATTEMPT".to_owned()
            })?,
        qualification_scope: QUALIFICATION_SCOPE.to_owned(),
        artifacts,
    };
    let signed = SignedExportEnvelope::sign(manifest, &signer)
        .map_err(|_| "release qualification manifest signing failed".to_owned())?;

    let commit_after = git_output(&repo_root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let status_after = git_output(
        &repo_root,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if commit_after != candidate || !status_after.is_empty() {
        return Err("source candidate changed before qualification signing".to_owned());
    }
    let mut artifacts_after = collect_artifacts(&artifact_root, &output, &checksums)?;
    artifacts_after.sort_by(|left, right| left.path.cmp(&right.path));
    if artifacts_after != signed.body.artifacts {
        return Err("release artifacts changed before qualification signing".to_owned());
    }

    let manifest_bytes = canonical_json_bytes(&signed)
        .map_err(|_| "release qualification manifest canonicalization failed".to_owned())?;
    write_new_or_replace(&output, &manifest_bytes)?;
    let checksum_bytes = checksum_bytes(&signed.body.artifacts);
    write_new_or_replace(&checksums, &checksum_bytes)?;
    Ok(())
}

fn verify(args: Args) -> Result<(), String> {
    if args.signing_seed.is_some() {
        return Err("--signing-seed is not accepted with --verify".to_owned());
    }
    let repo_root = canonical_directory(&args.repo_root, "repository root")?;
    let artifact_root = canonical_directory(&args.artifact_root, "artifact root")?;
    if !artifact_root.starts_with(&repo_root) {
        return Err("artifact root must be inside the repository".to_owned());
    }
    let output = absolute_under(&repo_root, &args.output, "manifest input")?;
    let checksums = absolute_under(&repo_root, &args.checksums, "checksum input")?;
    if !output.starts_with(&artifact_root) || !checksums.starts_with(&artifact_root) {
        return Err("manifest and checksum inputs must be inside the artifact root".to_owned());
    }
    if output == checksums {
        return Err("manifest and checksum inputs must be distinct".to_owned());
    }

    let status = git_output(
        &repo_root,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        return Err(
            "source tree is dirty; release evidence requires an exact clean commit".to_owned(),
        );
    }
    let candidate = git_output(&repo_root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    require_git_object_id(&candidate, "candidate commit")?;
    if args
        .expected_candidate
        .as_deref()
        .is_some_and(|expected| expected != candidate)
    {
        return Err("expected candidate does not match the checked-out commit".to_owned());
    }
    let tree = git_output(&repo_root, &["rev-parse", "--verify", "HEAD^{tree}"])?;
    require_git_object_id(&tree, "candidate tree")?;

    let manifest_bytes = read_bounded_regular_file(&output, MAX_MANIFEST_BYTES, "manifest")?;
    let manifest_text = std::str::from_utf8(&manifest_bytes)
        .map_err(|_| "release qualification manifest is not UTF-8".to_owned())?;
    let canonical = canonical_json_bytes_from_str(manifest_text)
        .map_err(|_| "release qualification manifest is not strict JSON".to_owned())?;
    if canonical != manifest_bytes {
        return Err("release qualification manifest is not canonical JSON".to_owned());
    }
    let signed: SignedExportEnvelope<ReleaseQualificationManifest> =
        serde_json::from_slice(&manifest_bytes)
            .map_err(|_| "release qualification manifest schema is invalid".to_owned())?;
    validate_signed_manifest(&signed, &candidate, &tree, &repo_root)?;

    let mut artifacts = collect_artifacts(&artifact_root, &output, &checksums)?;
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    if artifacts != signed.body.artifacts {
        return Err("release artifacts do not match the signed manifest".to_owned());
    }
    let checksum_file = read_bounded_regular_file(
        &checksums,
        MAX_CHECKSUM_BYTES,
        "release qualification checksums",
    )?;
    if checksum_file != checksum_bytes(&signed.body.artifacts) {
        return Err("release qualification checksums do not match the signed manifest".to_owned());
    }

    let mut artifacts_after = collect_artifacts(&artifact_root, &output, &checksums)?;
    artifacts_after.sort_by(|left, right| left.path.cmp(&right.path));
    let commit_after = git_output(&repo_root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let status_after = git_output(
        &repo_root,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if commit_after != candidate || !status_after.is_empty() {
        return Err("source candidate changed during qualification verification".to_owned());
    }
    if artifacts_after != artifacts {
        return Err("release artifacts changed during qualification verification".to_owned());
    }
    Ok(())
}

fn validate_signed_manifest(
    signed: &SignedExportEnvelope<ReleaseQualificationManifest>,
    candidate: &str,
    tree: &str,
    repo_root: &Path,
) -> Result<(), String> {
    let manifest = &signed.body;
    if signed.signer_key.algorithm() != SigningAlgorithm::Ed25519
        || signed.signer_key.is_weak_ed25519()
        || !signed
            .verify_signature()
            .map_err(|_| "release qualification signature verification failed".to_owned())?
    {
        return Err("release qualification signature is invalid".to_owned());
    }
    if manifest.schema != MANIFEST_SCHEMA
        || manifest.qualification_scope != QUALIFICATION_SCOPE
        || manifest.candidate_git_commit != candidate
        || manifest.candidate_git_tree != tree
        || manifest.cargo_lock_sha256 != hash_file(&repo_root.join("Cargo.lock"))?.0
    {
        return Err("release qualification candidate binding is invalid".to_owned());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock predates the Unix epoch".to_owned())?
        .as_secs();
    if manifest.generated_at_unix_secs == 0
        || manifest.generated_at_unix_secs > now.saturating_add(MAX_CLOCK_SKEW_SECS)
    {
        return Err("release qualification generation time is invalid".to_owned());
    }
    validate_source_metadata(manifest)?;
    validate_manifest_artifacts(&manifest.artifacts)
}

fn validate_source_metadata(manifest: &ReleaseQualificationManifest) -> Result<(), String> {
    let valid_optional_number = |value: &Option<String>| {
        value.as_ref().is_none_or(|value| {
            !value.is_empty()
                && value.len() <= 32
                && value.bytes().all(|byte| byte.is_ascii_digit())
        })
    };
    if !matches!(manifest.source.as_str(), "local" | "github-actions")
        || !valid_optional_number(&manifest.workflow_run_id)
        || !valid_optional_number(&manifest.workflow_run_attempt)
        || (manifest.workflow_run_id.is_some() != manifest.workflow_run_attempt.is_some())
        || (manifest.source == "github-actions" && manifest.workflow_run_id.is_none())
    {
        return Err("release qualification source metadata is invalid".to_owned());
    }
    Ok(())
}

fn validate_manifest_artifacts(artifacts: &[QualificationArtifact]) -> Result<(), String> {
    if artifacts.is_empty() || artifacts.len() > MAX_ARTIFACTS {
        return Err("release qualification artifact count is invalid".to_owned());
    }
    let mut previous = None;
    for artifact in artifacts {
        let path = Path::new(&artifact.path);
        let path_is_portable = !artifact.path.is_empty()
            && !artifact.path.contains('\\')
            && !artifact.path.chars().any(char::is_control)
            && !path.is_absolute()
            && path
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)));
        let digest_is_canonical = artifact.sha256.len() == 64
            && artifact
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !path_is_portable || !digest_is_canonical {
            return Err("release qualification artifact metadata is invalid".to_owned());
        }
        if previous.is_some_and(|value: &str| value >= artifact.path.as_str()) {
            return Err("release qualification artifact paths are not strictly sorted".to_owned());
        }
        previous = Some(artifact.path.as_str());
    }
    Ok(())
}

fn read_bounded_regular_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label} is not a regular file"));
    }
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err(format!("{label} exceeds its byte bound"));
    }
    fs::read(path).map_err(|error| format!("read {label} {}: {error}", path.display()))
}

fn collect_artifacts(
    artifact_root: &Path,
    output: &Path,
    checksums: &Path,
) -> Result<Vec<QualificationArtifact>, String> {
    let mut pending = vec![artifact_root.to_path_buf()];
    let mut artifacts = Vec::new();
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| format!("read artifact directory {}: {error}", directory.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("read artifact entry: {error}"))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|error| format!("inspect artifact {}: {error}", path.display()))?;
            if kind.is_symlink() {
                return Err(format!(
                    "release artifact is a symbolic link: {}",
                    path.display()
                ));
            }
            if kind.is_dir() {
                pending.push(path);
                continue;
            }
            if !kind.is_file() {
                return Err(format!(
                    "release artifact is not a regular file: {}",
                    path.display()
                ));
            }
            if path == output || path == checksums {
                continue;
            }
            let relative = path
                .strip_prefix(artifact_root)
                .map_err(|_| "artifact escaped its root".to_owned())?
                .to_str()
                .ok_or_else(|| "release artifact path is not UTF-8".to_owned())?
                .replace('\\', "/");
            if relative.is_empty() || relative.chars().any(char::is_control) {
                return Err("release artifact path is not portable".to_owned());
            }
            let normalized = relative.to_ascii_lowercase();
            if normalized.ends_with(".seed")
                || normalized.contains("private-key")
                || normalized.contains("private_key")
                || normalized.ends_with("/.env")
                || normalized == ".env"
            {
                return Err(format!(
                    "secret-like file is present in release artifacts: {relative}"
                ));
            }
            let (sha256, bytes) = hash_file(&path)?;
            artifacts.push(QualificationArtifact {
                path: relative,
                sha256,
                bytes,
            });
            if artifacts.len() > MAX_ARTIFACTS {
                return Err("release artifact count exceeds its bound".to_owned());
            }
        }
    }
    Ok(artifacts)
}

fn hash_file(path: &Path) -> Result<(String, u64), String> {
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut reader = BufReader::with_capacity(HASH_BUFFER_BYTES, file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    let mut bytes = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(u64::try_from(read).map_err(|_| "artifact size overflow".to_owned())?)
            .ok_or_else(|| "artifact size overflow".to_owned())?;
        hasher.update(&buffer[..read]);
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}

fn checksum_bytes(artifacts: &[QualificationArtifact]) -> Vec<u8> {
    let mut output = String::new();
    for artifact in artifacts {
        output.push_str(&artifact.sha256);
        output.push_str("  ");
        output.push_str(&artifact.path);
        output.push('\n');
    }
    output.into_bytes()
}

fn write_new_or_replace(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("output has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create output directory {}: {error}", parent.display()))?;
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("create {}: {error}", temporary.display()))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("write {}: {error}", temporary.display()));
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("install {}: {error}", path.display()));
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync output directory {}: {error}", parent.display()))?;
    Ok(())
}

fn parse_args(raw: Vec<OsString>) -> Result<Args, String> {
    let mut values = raw.into_iter().skip(1);
    let mut repo_root = None;
    let mut artifact_root = None;
    let mut signing_seed = None;
    let mut output = None;
    let mut checksums = None;
    let mut expected_candidate = None;
    let mut verify = false;
    while let Some(flag) = values.next() {
        match flag.to_string_lossy().as_ref() {
            "--repo-root" => repo_root = Some(next_path(&mut values, "--repo-root")?),
            "--artifact-root" => artifact_root = Some(next_path(&mut values, "--artifact-root")?),
            "--signing-seed" => signing_seed = Some(next_path(&mut values, "--signing-seed")?),
            "--output" => output = Some(next_path(&mut values, "--output")?),
            "--checksums" => checksums = Some(next_path(&mut values, "--checksums")?),
            "--expected-candidate" => {
                expected_candidate = Some(next_string(&mut values, "--expected-candidate")?)
            }
            "--verify" => verify = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        repo_root: repo_root.ok_or("missing --repo-root")?,
        artifact_root: artifact_root.ok_or("missing --artifact-root")?,
        signing_seed,
        output: output.ok_or("missing --output")?,
        checksums: checksums.ok_or("missing --checksums")?,
        expected_candidate,
        verify,
    })
}

fn next_path(values: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<PathBuf, String> {
    values
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn next_string(values: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<String, String> {
    values
        .next()
        .and_then(|value| value.into_string().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing or invalid value for {flag}"))
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let resolved = fs::canonicalize(path).map_err(|error| format!("resolve {label}: {error}"))?;
    if !resolved.is_dir() {
        return Err(format!("{label} is not a directory"));
    }
    Ok(resolved)
}

fn absolute_under(repo_root: &Path, path: &Path, label: &str) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root.join(path)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| format!("{label} has no parent"))?;
    let parent =
        fs::canonicalize(parent).map_err(|error| format!("resolve {label} parent: {error}"))?;
    let file_name = absolute
        .file_name()
        .ok_or_else(|| format!("{label} has no file name"))?;
    Ok(parent.join(file_name))
}

fn git_output(repo_root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_root)
        .output()
        .map_err(|error| format!("run git: {error}"))?;
    if !output.status.success() {
        return Err("git command failed".to_owned());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "git output is not UTF-8".to_owned())
}

fn require_git_object_id(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        checksum_bytes, collect_artifacts, qualify, verify, write_new_or_replace, Args,
        ReleaseQualificationManifest,
    };
    use chio_core_types::receipt::lineage::SignedExportEnvelope;
    use std::fs;
    use std::process::Command;

    #[test]
    fn artifacts_are_hashed_and_checksums_are_deterministic() -> Result<(), String> {
        let directory = tempfile::tempdir().map_err(|error| error.to_string())?;
        let root = directory.path();
        fs::create_dir(root.join("nested")).map_err(|error| error.to_string())?;
        fs::write(root.join("nested/report.json"), b"abc").map_err(|error| error.to_string())?;
        let manifest = root.join("artifact-manifest.signed.json");
        let checksums = root.join("SHA256SUMS");

        let artifacts = collect_artifacts(root, &manifest, &checksums)?;

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].path, "nested/report.json");
        assert_eq!(artifacts[0].bytes, 3);
        assert_eq!(
            artifacts[0].sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            checksum_bytes(&artifacts),
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  nested/report.json\n"
        );
        Ok(())
    }

    #[test]
    fn secret_like_artifacts_fail_closed() -> Result<(), String> {
        let directory = tempfile::tempdir().map_err(|error| error.to_string())?;
        let root = directory.path();
        fs::write(root.join("release.seed"), b"secret").map_err(|error| error.to_string())?;

        let error = collect_artifacts(
            root,
            &root.join("artifact-manifest.signed.json"),
            &root.join("SHA256SUMS"),
        )
        .err()
        .ok_or_else(|| "secret-like artifact was accepted".to_owned())?;

        assert!(error.contains("secret-like file"));
        Ok(())
    }

    #[test]
    fn non_portable_artifact_paths_fail_closed() -> Result<(), String> {
        let directory = tempfile::tempdir().map_err(|error| error.to_string())?;
        let root = directory.path();
        fs::write(root.join("line\nbreak.json"), b"{}").map_err(|error| error.to_string())?;

        let error = collect_artifacts(
            root,
            &root.join("artifact-manifest.signed.json"),
            &root.join("SHA256SUMS"),
        )
        .err()
        .ok_or_else(|| "non-portable artifact path was accepted".to_owned())?;

        assert!(error.contains("not portable"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_artifacts_fail_closed() -> Result<(), String> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().map_err(|error| error.to_string())?;
        let root = directory.path();
        fs::write(root.join("report.json"), b"{}").map_err(|error| error.to_string())?;
        symlink(root.join("report.json"), root.join("report-link.json"))
            .map_err(|error| error.to_string())?;

        let error = collect_artifacts(
            root,
            &root.join("artifact-manifest.signed.json"),
            &root.join("SHA256SUMS"),
        )
        .err()
        .ok_or_else(|| "symbolic-link artifact was accepted".to_owned())?;

        assert!(error.contains("symbolic link"));
        Ok(())
    }

    #[test]
    fn output_replacement_does_not_leave_partial_files() -> Result<(), String> {
        let directory = tempfile::tempdir().map_err(|error| error.to_string())?;
        let output = directory.path().join("manifest.json");

        write_new_or_replace(&output, b"first")?;
        write_new_or_replace(&output, b"second")?;

        assert_eq!(
            fs::read(&output).map_err(|error| error.to_string())?,
            b"second"
        );
        assert!(!output
            .with_extension(format!("tmp.{}", std::process::id()))
            .exists());
        Ok(())
    }

    #[test]
    fn qualification_binds_and_signs_one_clean_git_candidate() -> Result<(), String> {
        let repository = tempfile::tempdir().map_err(|error| error.to_string())?;
        let root = repository.path();
        fs::write(root.join(".gitignore"), b"target/\n").map_err(|error| error.to_string())?;
        fs::write(root.join("Cargo.lock"), b"version = 4\n").map_err(|error| error.to_string())?;
        run_git(root, &["init", "--quiet"])?;
        run_git(root, &["add", ".gitignore", "Cargo.lock"])?;
        run_git(
            root,
            &[
                "-c",
                "user.name=Chio Test",
                "-c",
                "user.email=chio-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "test candidate",
            ],
        )?;

        let artifact_root = root.join("target/release-qualification");
        fs::create_dir_all(&artifact_root).map_err(|error| error.to_string())?;
        fs::write(artifact_root.join("gate.log"), b"passed\n")
            .map_err(|error| error.to_string())?;
        let secret_root = root.join("target/secrets");
        fs::create_dir_all(&secret_root).map_err(|error| error.to_string())?;
        let seed = secret_root.join("release.seed");
        fs::write(&seed, "11".repeat(32)).map_err(|error| error.to_string())?;
        let manifest_path = artifact_root.join("artifact-manifest.signed.json");
        let checksum_path = artifact_root.join("SHA256SUMS");
        let candidate = git_value(root, &["rev-parse", "HEAD^{commit}"])?;

        qualify(Args {
            repo_root: root.to_path_buf(),
            artifact_root: artifact_root.clone(),
            signing_seed: Some(seed),
            output: manifest_path.clone(),
            checksums: checksum_path.clone(),
            expected_candidate: Some(candidate.clone()),
            verify: false,
        })?;

        let bytes = fs::read(&manifest_path).map_err(|error| error.to_string())?;
        let signed: SignedExportEnvelope<ReleaseQualificationManifest> =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        assert_eq!(signed.body.candidate_git_commit, candidate);
        assert_eq!(signed.body.artifacts.len(), 1);
        assert_eq!(signed.body.artifacts[0].path, "gate.log");
        assert!(signed
            .verify_signature()
            .map_err(|error| error.to_string())?);
        assert_eq!(
            fs::read_to_string(&checksum_path).map_err(|error| error.to_string())?,
            format!("{}  gate.log\n", signed.body.artifacts[0].sha256)
        );

        verify(Args {
            repo_root: root.to_path_buf(),
            artifact_root: artifact_root.clone(),
            signing_seed: None,
            output: manifest_path.clone(),
            checksums: checksum_path.clone(),
            expected_candidate: Some(candidate),
            verify: true,
        })?;
        fs::write(artifact_root.join("gate.log"), b"tampered\n")
            .map_err(|error| error.to_string())?;
        let error = verify(Args {
            repo_root: root.to_path_buf(),
            artifact_root,
            signing_seed: None,
            output: manifest_path,
            checksums: checksum_path,
            expected_candidate: None,
            verify: true,
        })
        .err()
        .ok_or_else(|| "tampered release artifact was accepted".to_owned())?;
        assert!(error.contains("do not match the signed manifest"));
        Ok(())
    }

    fn run_git(root: &std::path::Path, args: &[&str]) -> Result<(), String> {
        let status = Command::new("git")
            .args(args)
            .current_dir(root)
            .status()
            .map_err(|error| error.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("git command failed with {status}"))
        }
    }

    fn git_value(root: &std::path::Path, args: &[&str]) -> Result<String, String> {
        let output = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(format!("git command failed with {}", output.status));
        }
        String::from_utf8(output.stdout)
            .map(|value| value.trim().to_owned())
            .map_err(|error| error.to_string())
    }
}
