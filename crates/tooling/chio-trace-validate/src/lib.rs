mod apalache;
mod capture;
mod decode;
mod intern;
mod itf;
pub mod map;
mod observation;
mod report;

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub use apalache::{ApalacheOracle, PrefixReachability, ReachabilityOracle};
pub use capture::{RuntimeTraceMutation, RuntimeTraceRecorder};
pub use decode::{decode_observations, encode_observations, ValidatedTrace};
pub use map::revocation::{
    project_revocation_trace, ActionCoverage, InvariantWitnessCoverage, ProjectedAction,
    ProjectedEvent, RevocationProjection,
};
pub use observation::{
    ObservationBody, ObservationEvent, SignedObservation, TRACE_OBSERVATION_SCHEMA,
};
pub use report::{
    Divergence, TraceValidationReport, ValidationStatus, REVOCATION_INVARIANTS,
    TRACE_VALIDATION_REPORT_SCHEMA,
};

use chio_core_types::crypto::PublicKey;

const TRIAGE_TEMPLATE: &str = "formal/issue-templates/property-counterexample.md";

#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    #[error("invalid trace input: {0}")]
    InvalidInput(String),

    #[error("trace I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("trace JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("trace cryptography error: {0}")]
    Crypto(#[from] chio_core_types::Error),

    #[error("Apalache validation error: {0}")]
    Apalache(String),
}

#[derive(Debug, Clone)]
pub struct ValidationOptions {
    pub log_path: PathBuf,
    pub trusted_observer_keys: Vec<PublicKey>,
    pub apalache_bin: PathBuf,
    pub timeout_secs: u64,
    pub itf_output: Option<PathBuf>,
    pub witness_output: Option<PathBuf>,
    pub minimum_revoke: u64,
    pub minimum_post_revocation_evaluate: u64,
}

pub fn validate_file(options: &ValidationOptions) -> Result<TraceValidationReport, TraceError> {
    let bytes = read_stable_trace_file(&options.log_path)?;
    let observations = decode_observations(&bytes, &options.trusted_observer_keys)?;
    let projection = project_revocation_trace(&observations)?;
    enforce_action_floor(&projection.action_coverage, options)?;
    enforce_invariant_witnesses(projection.invariant_witnesses())?;
    if let Some(path) = &options.itf_output {
        write_trace_artifact(path, &projection.itf_json)?;
    }

    let oracle = ApalacheOracle::new(&options.apalache_bin, options.timeout_secs)?;
    let evaluation = oracle.evaluate_itf_invariants(&projection)?;
    if let Some(path) = &options.witness_output {
        write_trace_artifact(path, &evaluation.witness_json)?;
    }
    if let Some(failure) = evaluation.failure.clone() {
        return TraceValidationReport::failed_invariant(
            &projection,
            failure,
            &evaluation,
            TRIAGE_TEMPLATE,
            oracle.checker_name(),
        );
    }
    let mut report = validate_projection_with(&projection, &oracle)?;
    report.bind_invariant_evaluation(&evaluation);
    Ok(report)
}

pub fn validate_projection_with(
    projection: &RevocationProjection,
    oracle: &impl ReachabilityOracle,
) -> Result<TraceValidationReport, TraceError> {
    let trace_length = projection.events.len();
    if trace_length == 0 {
        return Err(TraceError::InvalidInput(
            "observation trace must contain at least one event".to_string(),
        ));
    }

    if oracle.prefix_reachability(projection, trace_length)? == PrefixReachability::Reachable {
        return Ok(TraceValidationReport::passed(
            projection,
            oracle.checker_name(),
        ));
    }

    let mut low = 1_usize;
    let mut high = trace_length;
    while low < high {
        let midpoint = low + (high - low) / 2;
        if oracle.prefix_reachability(projection, midpoint)? == PrefixReachability::Reachable {
            low = midpoint + 1;
        } else {
            high = midpoint;
        }
    }

    TraceValidationReport::failed(
        projection,
        low,
        "TraceReachability",
        TRIAGE_TEMPLATE,
        oracle.checker_name(),
    )
}

pub fn write_report(path: &Path, report: &TraceValidationReport) -> Result<(), TraceError> {
    let mut bytes = serde_json::to_vec_pretty(report)?;
    bytes.push(b'\n');
    write_trace_artifact(path, &bytes)
}

fn enforce_action_floor(
    coverage: &ActionCoverage,
    options: &ValidationOptions,
) -> Result<(), TraceError> {
    if coverage.revoke < options.minimum_revoke {
        return Err(TraceError::InvalidInput(format!(
            "trace has {} revoke events, requires at least {}",
            coverage.revoke, options.minimum_revoke
        )));
    }
    if coverage.post_revocation_evaluate < options.minimum_post_revocation_evaluate {
        return Err(TraceError::InvalidInput(format!(
            "trace has {} post-revocation evaluations, requires at least {}",
            coverage.post_revocation_evaluate, options.minimum_post_revocation_evaluate
        )));
    }
    Ok(())
}

fn enforce_invariant_witnesses(witnesses: InvariantWitnessCoverage) -> Result<(), TraceError> {
    let missing = [
        ("NoAllowAfterRevoke", witnesses.allow_receipt),
        ("MonotoneLog", witnesses.ordered_receipt_pair),
        ("AttenuationPreserving", witnesses.attenuated_admission),
        ("RevocationFreshness", witnesses.nonzero_revocation_epoch),
    ]
    .into_iter()
    .filter_map(|(name, count)| (count == 0).then_some(name))
    .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(TraceError::InvalidInput(format!(
            "trace does not exercise invariant witnesses: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

pub fn write_trace_artifact(path: &Path, bytes: &[u8]) -> Result<(), TraceError> {
    reject_symlink_components(path)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(TraceError::InvalidInput(format!(
                "output must be a regular non-symlink file: {}",
                path.display()
            )));
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    reject_symlink_components(path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), TraceError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(TraceError::InvalidInput(format!(
                    "path contains a symlink component: {}",
                    current.display()
                )))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_stable_trace_file(path: &Path) -> Result<Vec<u8>, TraceError> {
    reject_symlink_components(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(TraceError::InvalidInput(format!(
            "trace log must be a regular non-symlink file: {}",
            path.display()
        )));
    }
    let max_trace_bytes = u64::try_from(decode::MAX_TRACE_BYTES)
        .map_err(|_| TraceError::InvalidInput("trace byte limit exceeds u64".to_string()))?;
    let read_limit = max_trace_bytes
        .checked_add(1)
        .ok_or_else(|| TraceError::InvalidInput("trace read limit overflow".to_string()))?;
    let oversized_metadata = before.len() > max_trace_bytes;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    if path_after.file_type().is_symlink()
        || !path_after.is_file()
        || !same_file_identity(&before, &after)
        || !same_file_identity(&before, &path_after)
    {
        return Err(TraceError::InvalidInput(format!(
            "trace log changed while it was read: {}",
            path.display()
        )));
    }
    reject_symlink_components(path)?;
    if oversized_metadata || bytes.len() > decode::MAX_TRACE_BYTES {
        return Err(TraceError::InvalidInput(format!(
            "observation log exceeds {} bytes",
            decode::MAX_TRACE_BYTES
        )));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_trace_read_is_bounded_by_the_decoder_limit() -> Result<(), TraceError> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("oversized.ndjson");
        let file = fs::File::create(&path)?;
        file.set_len(
            u64::try_from(decode::MAX_TRACE_BYTES).map_err(|_| {
                TraceError::InvalidInput("trace byte limit exceeds u64".to_string())
            })? + 1,
        )?;

        let error = read_stable_trace_file(&path)
            .err()
            .ok_or_else(|| TraceError::InvalidInput("oversized trace was accepted".to_string()))?;
        assert!(error.to_string().contains("observation log exceeds"));
        Ok(())
    }
}
