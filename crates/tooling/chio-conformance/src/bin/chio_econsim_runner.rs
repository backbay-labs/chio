use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use chio_conformance::econsim::{
    sign_econsim_qualification_matrix, validate_econsim_qualification_matrix, EconsimDisposition,
    EconsimFindingSeverity, EconsimHarnessProvenance, EconsimOutcome, EconsimQualificationMatrix,
    EconsimScenarioResult, EconsimTargetStatus, ECONSIM_QUALIFICATION_MATRIX_SCHEMA,
    ECONSIM_SCENARIO_CLASSES, ECONSIM_SCENARIO_RESULT_SCHEMA,
};
use chio_core::{sha256, Keypair};
use serde::Deserialize;

const INTERNAL_QUALIFICATION_SCOPE: &str =
    "self-signed internal qualification only; not external evidence, underwriting input, or insurance fact";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EconsimManifest {
    profile_id: String,
    advisory: bool,
    corpus_manifest: PathBuf,
    scenario: Vec<EconsimScenario>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EconsimScenario {
    class: String,
    seed: u64,
    requirement_ids: Vec<String>,
    assertion_scope: String,
    explicit_limits: Vec<String>,
    finding_severity: EconsimFindingSeverity,
    cargo_tests: Vec<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CorpusManifest {
    schema: String,
    scenarios: Vec<CorpusScenario>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CorpusScenario {
    class: String,
    seed: u64,
    steps: Vec<String>,
}

struct RunnerArgs {
    repo_root: PathBuf,
    manifest: PathBuf,
    output_dir: PathBuf,
    signing_seed: PathBuf,
    allow_dirty: bool,
    command: Vec<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("econsim: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = parse_args(env::args_os().collect())?;
    let manifest_path = args.repo_root.join(&args.manifest);
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("read {}: {error}", manifest_path.display()))?;
    let manifest: EconsimManifest = toml::from_str(
        std::str::from_utf8(&manifest_bytes)
            .map_err(|error| format!("manifest is not UTF-8: {error}"))?,
    )
    .map_err(|error| format!("parse {}: {error}", manifest_path.display()))?;
    validate_manifest(&manifest)?;

    let corpus_path = args.repo_root.join(&manifest.corpus_manifest);
    let corpus_bytes = fs::read(&corpus_path)
        .map_err(|error| format!("read {}: {error}", corpus_path.display()))?;
    let corpus: CorpusManifest = serde_json::from_slice(&corpus_bytes)
        .map_err(|error| format!("parse {}: {error}", corpus_path.display()))?;
    validate_corpus(&manifest, &corpus)?;

    let corpus_digest = digest(&corpus_bytes);
    let mut results = Vec::with_capacity(manifest.scenario.len());
    for scenario in &manifest.scenario {
        let held = scenario
            .cargo_tests
            .iter()
            .all(|test| run_cargo_target(&args.repo_root, test));
        results.push(EconsimScenarioResult {
            schema: ECONSIM_SCENARIO_RESULT_SCHEMA.to_owned(),
            scenario_id: format!("{}-seed-{}", scenario.class, scenario.seed),
            scenario_class: scenario.class.clone(),
            seed: scenario.seed,
            corpus_manifest_digest: corpus_digest.clone(),
            requirement_ids: scenario.requirement_ids.clone(),
            expected_disposition: EconsimDisposition::FailClosed,
            observed_disposition: Some(if held {
                EconsimDisposition::FailClosed
            } else {
                EconsimDisposition::Breach
            }),
            target_status: EconsimTargetStatus::Bound,
            outcome: if held {
                EconsimOutcome::Held
            } else {
                EconsimOutcome::Finding
            },
            finding_severity: (!held).then_some(scenario.finding_severity),
            assertion_scope: scenario.assertion_scope.clone(),
            explicit_limits: scenario.explicit_limits.clone(),
        });
    }

    let output_dir = args.repo_root.join(&args.output_dir);
    fs::create_dir_all(&output_dir)
        .map_err(|error| format!("create {}: {error}", output_dir.display()))?;
    for result in &results {
        write_json(
            &output_dir.join(format!("{}.json", result.scenario_id)),
            result,
        )?;
    }
    if results.iter().any(|result| {
        result.outcome == EconsimOutcome::TargetMissing
            || result.finding_severity >= Some(EconsimFindingSeverity::High)
    }) {
        return Err("high or critical findings prevent qualification signing".to_owned());
    }

    let source_tree_state = git_output(&args.repo_root, &["status", "--porcelain"])?;
    let dirty = !source_tree_state.trim().is_empty();
    if dirty && !args.allow_dirty {
        return Err(
            "source tree is dirty; pass --allow-dirty to bind that state explicitly".to_owned(),
        );
    }
    let seed_text = fs::read_to_string(args.repo_root.join(&args.signing_seed))
        .map_err(|error| format!("read signing seed: {error}"))?;
    let signer = Keypair::from_seed_hex(seed_text.trim())
        .map_err(|error| format!("parse signing seed: {error}"))?;
    let provenance = EconsimHarnessProvenance {
        git_commit: git_output(&args.repo_root, &["rev-parse", "HEAD"])?
            .trim()
            .to_owned(),
        source_tree_state: if dirty { "dirty" } else { "clean" }.to_owned(),
        source_tree_digest: source_tree_digest(&args.repo_root)?,
        executable_digest: digest(
            &fs::read(env::current_exe().map_err(|error| error.to_string())?)
                .map_err(|error| format!("read runner executable: {error}"))?,
        ),
        cargo_lock_digest: digest(
            &fs::read(args.repo_root.join("Cargo.lock"))
                .map_err(|error| format!("read Cargo.lock: {error}"))?,
        ),
        enabled_features: Vec::new(),
        target_triple: rustc_host()?,
        rustc_version: tool_version("rustc")?,
        cargo_version: tool_version("cargo")?,
        command: args.command,
        scenario_manifest_digest: digest(&manifest_bytes),
        corpus_manifest_digest: corpus_digest,
        runner_key_id: signer.public_key().to_hex(),
        qualification_scope: INTERNAL_QUALIFICATION_SCOPE.to_owned(),
    };
    let matrix = EconsimQualificationMatrix {
        schema: ECONSIM_QUALIFICATION_MATRIX_SCHEMA.to_owned(),
        profile_id: manifest.profile_id,
        harness_provenance: provenance,
        cases: results,
    };
    validate_econsim_qualification_matrix(&matrix).map_err(|error| error.to_string())?;

    let manifest_digest_before_signing = digest(
        &fs::read(&manifest_path)
            .map_err(|error| format!("re-read {}: {error}", manifest_path.display()))?,
    );
    let corpus_digest_before_signing = digest(
        &fs::read(&corpus_path)
            .map_err(|error| format!("re-read {}: {error}", corpus_path.display()))?,
    );
    let executable_digest_before_signing = digest(
        &fs::read(env::current_exe().map_err(|error| error.to_string())?)
            .map_err(|error| format!("re-read runner executable: {error}"))?,
    );
    let lock_digest_before_signing = digest(
        &fs::read(args.repo_root.join("Cargo.lock"))
            .map_err(|error| format!("re-read Cargo.lock: {error}"))?,
    );
    let source_digest_before_signing = source_tree_digest(&args.repo_root)?;
    if manifest_digest_before_signing != matrix.harness_provenance.scenario_manifest_digest
        || corpus_digest_before_signing != matrix.harness_provenance.corpus_manifest_digest
        || executable_digest_before_signing != matrix.harness_provenance.executable_digest
        || lock_digest_before_signing != matrix.harness_provenance.cargo_lock_digest
        || source_digest_before_signing != matrix.harness_provenance.source_tree_digest
    {
        return Err("bound provenance changed before signing".to_owned());
    }
    let signed =
        sign_econsim_qualification_matrix(matrix, &signer).map_err(|error| error.to_string())?;
    write_json(
        &output_dir.join("qualification-matrix.signed.json"),
        &signed,
    )?;
    if manifest.advisory {
        eprintln!("econsim: advisory facet held for all six scenario classes");
    }
    Ok(())
}

fn parse_args(raw: Vec<OsString>) -> Result<RunnerArgs, String> {
    let command = raw
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect();
    let mut values = raw.into_iter().skip(1);
    let mut repo_root = None;
    let mut manifest = None;
    let mut output_dir = None;
    let mut signing_seed = None;
    let mut allow_dirty = false;
    while let Some(flag) = values.next() {
        match flag.to_string_lossy().as_ref() {
            "--repo-root" => repo_root = Some(next_path(&mut values, "--repo-root")?),
            "--manifest" => manifest = Some(next_path(&mut values, "--manifest")?),
            "--output-dir" => output_dir = Some(next_path(&mut values, "--output-dir")?),
            "--signing-seed" => signing_seed = Some(next_path(&mut values, "--signing-seed")?),
            "--allow-dirty" => allow_dirty = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(RunnerArgs {
        repo_root: repo_root.ok_or("missing --repo-root")?,
        manifest: manifest.ok_or("missing --manifest")?,
        output_dir: output_dir.ok_or("missing --output-dir")?,
        signing_seed: signing_seed.ok_or("missing --signing-seed")?,
        allow_dirty,
        command,
    })
}

fn next_path(values: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<PathBuf, String> {
    values
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn validate_manifest(manifest: &EconsimManifest) -> Result<(), String> {
    if manifest.profile_id.trim().is_empty() {
        return Err("profile_id must not be empty".to_owned());
    }
    let mut classes = BTreeSet::new();
    for scenario in &manifest.scenario {
        if !ECONSIM_SCENARIO_CLASSES.contains(&scenario.class.as_str()) {
            return Err(format!("unknown scenario class: {}", scenario.class));
        }
        if !classes.insert(scenario.class.as_str()) {
            return Err(format!("duplicate scenario class: {}", scenario.class));
        }
        if scenario.seed == 0
            || scenario.requirement_ids.is_empty()
            || scenario.assertion_scope.trim().is_empty()
            || scenario.explicit_limits.is_empty()
            || scenario.cargo_tests.is_empty()
            || scenario.cargo_tests.iter().any(Vec::is_empty)
            || scenario
                .cargo_tests
                .iter()
                .flatten()
                .any(|argument| argument == "--")
        {
            return Err(format!("scenario {} is incomplete", scenario.class));
        }
    }
    for class in ECONSIM_SCENARIO_CLASSES {
        if !classes.contains(class) {
            return Err(format!("manifest is missing scenario class: {class}"));
        }
    }
    Ok(())
}

fn validate_corpus(manifest: &EconsimManifest, corpus: &CorpusManifest) -> Result<(), String> {
    if corpus.schema != "chio.econsim.corpus-manifest.v1" {
        return Err(format!("unsupported corpus schema: {}", corpus.schema));
    }
    let entries: BTreeMap<&str, &CorpusScenario> = corpus
        .scenarios
        .iter()
        .map(|scenario| (scenario.class.as_str(), scenario))
        .collect();
    if entries.len() != ECONSIM_SCENARIO_CLASSES.len() || entries.len() != corpus.scenarios.len() {
        return Err("corpus must enumerate each scenario class exactly once".to_owned());
    }
    for scenario in &manifest.scenario {
        let corpus_scenario = entries
            .get(scenario.class.as_str())
            .ok_or_else(|| format!("corpus is missing scenario class: {}", scenario.class))?;
        if corpus_scenario.seed != scenario.seed || corpus_scenario.steps.is_empty() {
            return Err(format!("corpus does not bind scenario: {}", scenario.class));
        }
    }
    Ok(())
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize {}: {error}", path.display()))?;
    fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

fn run_cargo_target(repo_root: &Path, args: &[String]) -> bool {
    let listed = Command::new("cargo")
        .arg("test")
        .args(args)
        .args(["--", "--list"])
        .current_dir(repo_root)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_PROFILE_DEV_DEBUG", "0")
        .env("CARGO_PROFILE_TEST_DEBUG", "0")
        .output();
    let Ok(listed) = listed else {
        return false;
    };
    if !listed.status.success()
        || !String::from_utf8_lossy(&listed.stdout)
            .lines()
            .any(|line| line.ends_with(": test"))
    {
        return false;
    }
    Command::new("cargo")
        .arg("test")
        .args(args)
        .current_dir(repo_root)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_PROFILE_DEV_DEBUG", "0")
        .env("CARGO_PROFILE_TEST_DEBUG", "0")
        .status()
        .is_ok_and(|status| status.success())
}

fn digest(bytes: &[u8]) -> String {
    sha256(bytes).to_hex()
}

fn git_output(repo_root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_root)
        .output()
        .map_err(|error| format!("run git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| format!("git output is not UTF-8: {error}"))
}

fn source_tree_digest(repo_root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(repo_root)
        .output()
        .map_err(|error| format!("enumerate source tree: {error}"))?;
    if !output.status.success() {
        return Err("git ls-files failed".to_owned());
    }
    let mut material = Vec::new();
    for raw_path in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let path = std::str::from_utf8(raw_path)
            .map_err(|error| format!("source path is not UTF-8: {error}"))?;
        material.extend_from_slice(raw_path);
        material.push(0);
        let source_path = repo_root.join(path);
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|error| format!("inspect source path {path}: {error}"))?;
        if metadata.file_type().is_symlink() {
            material.extend_from_slice(
                fs::read_link(&source_path)
                    .map_err(|error| format!("read source symlink {path}: {error}"))?
                    .to_string_lossy()
                    .as_bytes(),
            );
        } else if metadata.is_file() {
            material.extend_from_slice(
                &fs::read(&source_path)
                    .map_err(|error| format!("read source path {path}: {error}"))?,
            );
        } else {
            return Err(format!("source inventory path is not a file: {path}"));
        }
        material.push(0);
    }
    Ok(digest(&material))
}

fn tool_version(tool: &str) -> Result<String, String> {
    let output = Command::new(tool)
        .arg("--version")
        .output()
        .map_err(|error| format!("run {tool} --version: {error}"))?;
    if !output.status.success() {
        return Err(format!("{tool} --version failed"));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("{tool} version is not UTF-8: {error}"))
}

fn rustc_host() -> Result<String, String> {
    let output = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|error| format!("run rustc -vV: {error}"))?;
    if !output.status.success() {
        return Err("rustc -vV failed".to_owned());
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| format!("rustc -vV output is not UTF-8: {error}"))?;
    text.lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(ToOwned::to_owned)
        .ok_or_else(|| "rustc -vV omitted host triple".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> EconsimManifest {
        EconsimManifest {
            profile_id: "econsim-v1".to_owned(),
            advisory: true,
            corpus_manifest: "fixtures/econsim/corpus-manifest.json".into(),
            scenario: ECONSIM_SCENARIO_CLASSES
                .into_iter()
                .map(|class| EconsimScenario {
                    class: class.to_owned(),
                    seed: 7,
                    requirement_ids: vec!["AE-TEST".to_owned()],
                    assertion_scope: "bounded production behavior".to_owned(),
                    explicit_limits: vec!["internal qualification".to_owned()],
                    finding_severity: EconsimFindingSeverity::High,
                    cargo_tests: vec![vec!["-p".to_owned(), "chio-test".to_owned()]],
                })
                .collect(),
        }
    }

    #[test]
    fn manifest_rejects_short_and_unknown_class_sets() {
        let mut short = manifest();
        short.scenario.pop();
        assert!(validate_manifest(&short).is_err());

        let mut unknown = manifest();
        unknown.scenario[0].class = "unknown".to_owned();
        assert!(validate_manifest(&unknown).is_err());
    }
}
