use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::{RevocationProjection, TraceError};

pub(crate) const REVOCATION_MODEL: &str =
    include_str!("../../../../formal/tla/RevocationPropagation.tla");
pub(crate) const TRACE_CHECK_MODEL: &str =
    include_str!("../../../../formal/tla/trace/TraceCheckRevocationPropagation.tla");
pub(crate) const TRACE_EVALUATE_MODEL: &str =
    include_str!("../../../../formal/tla/trace/TraceEvaluateRevocationPropagation.tla");
const REQUIRED_APALACHE_VERSION: &str = "0.50.1";

const INVARIANT_EXPRESSIONS: [&str; 4] = [
    "NoAllowAfterRevoke",
    "MonotoneLog",
    "AttenuationPreserving",
    "RevocationFreshness",
];
const WITNESS_EXPRESSIONS: [&str; 4] = [
    "WitnessAllowReceipt",
    "WitnessOrderedReceiptPair",
    "WitnessAttenuatedAdmission",
    "WitnessNonzeroRevocationEpoch",
];
const MODEL_VARIABLES: [&str; 6] = [
    "clock",
    "depth",
    "pending",
    "receipt_log",
    "rev_epoch",
    "state",
];
const MODEL_VARIABLE_TYPES: [(&str, &str); 6] = [
    ("clock", "Int"),
    ("depth", "(Int -> (Int -> Int))"),
    (
        "pending",
        "Set({ from: Int, to: Int, cap: Int, epoch: Int })",
    ),
    (
        "receipt_log",
        "(Int -> Seq({ cap: Int, verdict: Str, t: Int, seen_epoch: Int }))",
    ),
    ("rev_epoch", "(Int -> (Int -> Int))"),
    ("state", "(Int -> (Int -> Str))"),
];
const APALACHE_MODEL_VARIABLE_TYPES: [(&str, &str); 6] = [
    ("clock", "Int"),
    ("depth", "(Int -> (Int -> Int))"),
    (
        "pending",
        "Set({ cap: Int, epoch: Int, from: Int, to: Int })",
    ),
    (
        "receipt_log",
        "(Int -> Seq({ cap: Int, seen_epoch: Int, t: Int, verdict: Str }))",
    ),
    ("rev_epoch", "(Int -> (Int -> Int))"),
    ("state", "(Int -> (Int -> Str))"),
];
const EVALUATED_VARIABLES: [(&str, &str); 8] = [
    ("eval_no_allow_after_revoke", "NoAllowAfterRevoke"),
    ("eval_monotone_log", "MonotoneLog"),
    ("eval_attenuation_preserving", "AttenuationPreserving"),
    ("eval_revocation_freshness", "RevocationFreshness"),
    ("eval_witness_allow_receipt", "WitnessAllowReceipt"),
    (
        "eval_witness_ordered_receipt_pair",
        "WitnessOrderedReceiptPair",
    ),
    (
        "eval_witness_attenuated_admission",
        "WitnessAttenuatedAdmission",
    ),
    (
        "eval_witness_nonzero_revocation_epoch",
        "WitnessNonzeroRevocationEpoch",
    ),
];
const TRACE_EVALUATION_EXPORT_INVARIANT: &str = "TraceEvaluationIncomplete";

#[derive(Debug, Clone)]
pub(crate) struct ItfInvariantFailure {
    pub state_index: usize,
    pub visible_step: usize,
    pub invariant: String,
    pub input_predecessor: serde_json::Value,
    pub evaluated_state: serde_json::Value,
}

#[derive(Debug, Clone)]
pub(crate) struct ItfInvariantEvaluation {
    pub witness_sha256: String,
    pub witness_json: Vec<u8>,
    pub checker_binary_sha256: String,
    pub timeout_binary_sha256: String,
    pub failure: Option<ItfInvariantFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixReachability {
    Reachable,
    Unreachable,
}

pub trait ReachabilityOracle {
    fn checker_name(&self) -> &str;

    fn prefix_reachability(
        &self,
        projection: &RevocationProjection,
        prefix_len: usize,
    ) -> Result<PrefixReachability, TraceError>;
}

pub struct ApalacheOracle {
    apalache_bin: PathBuf,
    apalache_sha256: String,
    timeout_bin: PathBuf,
    timeout_sha256: String,
    timeout_secs: u64,
}

impl ApalacheOracle {
    pub fn new(apalache_bin: impl AsRef<Path>, timeout_secs: u64) -> Result<Self, TraceError> {
        if timeout_secs == 0 {
            return Err(TraceError::InvalidInput(
                "Apalache timeout must be positive".to_string(),
            ));
        }
        let timeout_bin = find_timeout_binary()?;
        let timeout_sha256 = chio_core_types::sha256_hex(&fs::read(&timeout_bin)?);
        let apalache_bin = resolve_executable(apalache_bin.as_ref())?;
        let apalache_sha256 = chio_core_types::sha256_hex(&fs::read(&apalache_bin)?);
        let oracle = Self {
            apalache_bin,
            apalache_sha256,
            timeout_bin,
            timeout_sha256,
            timeout_secs,
        };
        let output = oracle.run_timeout_command(["version"])?;
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !output.status.success() || version != REQUIRED_APALACHE_VERSION {
            return Err(TraceError::Apalache(format!(
                "Apalache {REQUIRED_APALACHE_VERSION} is required; run tools/install-apalache.sh"
            )));
        }
        Ok(oracle)
    }

    fn run_timeout_command<I, S>(&self, args: I) -> Result<Output, TraceError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.ensure_checker_unchanged()?;
        let output = Command::new(&self.timeout_bin)
            .arg(self.timeout_secs.to_string())
            .arg(&self.apalache_bin)
            .args(args)
            .output()
            .map_err(|error| {
                TraceError::Apalache(format!(
                    "failed to execute {}: {error}; run tools/install-apalache.sh",
                    self.apalache_bin.display()
                ))
            })?;
        self.ensure_checker_unchanged()?;
        Ok(output)
    }

    fn ensure_checker_unchanged(&self) -> Result<(), TraceError> {
        let current = chio_core_types::sha256_hex(&fs::read(&self.apalache_bin)?);
        if current != self.apalache_sha256 {
            return Err(TraceError::Apalache(
                "Apalache executable changed during trace validation".to_string(),
            ));
        }
        let timeout_current = chio_core_types::sha256_hex(&fs::read(&self.timeout_bin)?);
        if timeout_current != self.timeout_sha256 {
            return Err(TraceError::Apalache(
                "timeout executable changed during trace validation".to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn evaluate_itf_invariants(
        &self,
        projection: &RevocationProjection,
    ) -> Result<ItfInvariantEvaluation, TraceError> {
        let work = tempfile::Builder::new()
            .prefix("chio-trace-evaluate-")
            .tempdir()?;
        let input_dir = work.path().join("input");
        let out_dir = work.path().join("out");
        let run_dir = work.path().join("run");
        fs::create_dir_all(&input_dir)?;
        fs::create_dir_all(&out_dir)?;
        fs::create_dir_all(&run_dir)?;
        fs::write(
            input_dir.join("RevocationPropagation.tla"),
            REVOCATION_MODEL,
        )?;
        fs::write(
            input_dir.join("TraceEvaluateRevocationPropagation.tla"),
            TRACE_EVALUATE_MODEL,
        )?;
        let itf_path = input_dir.join("projected.itf.json");
        fs::write(&itf_path, &projection.itf_json)?;
        fs::write(
            input_dir.join("TraceEvaluationInput.tla"),
            trace_evaluation_input_module(&projection.itf_json)?,
        )?;
        let config_path = input_dir.join("MCTraceEvaluateRevocationPropagation.cfg");
        fs::write(&config_path, trace_evaluation_config(projection))?;
        let length = projection
            .states
            .len()
            .checked_sub(1)
            .and_then(|value| value.checked_mul(2))
            .ok_or_else(|| {
                TraceError::InvalidInput("projected ITF evaluation length overflow".to_string())
            })?;
        let args = vec![
            format!("--out-dir={}", out_dir.display()),
            format!("--run-dir={}", run_dir.display()),
            "check".to_string(),
            "--output-traces".to_string(),
            format!("--length={length}"),
            format!("--config={}", config_path.display()),
            input_dir
                .join("TraceEvaluateRevocationPropagation.tla")
                .display()
                .to_string(),
        ];
        let output = self.run_timeout_command(args)?;
        classify_trace_evaluation(
            &output,
            &run_dir,
            projection,
            &self.apalache_sha256,
            &self.timeout_sha256,
        )
    }
}

fn classify_trace_evaluation(
    output: &Output,
    run_dir: &Path,
    projection: &RevocationProjection,
    checker_binary_sha256: &str,
    timeout_binary_sha256: &str,
) -> Result<ItfInvariantEvaluation, TraceError> {
    let code = output.status.code().unwrap_or(-1);
    if code == 124 {
        return Err(TraceError::Apalache(
            "ITF invariant evaluation timed out".to_string(),
        ));
    }
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let outcomes = collect_apalache_markers(&combined, "The outcome is:", "outcome")?;
    let invariants = collect_apalache_markers(&combined, "> Set an invariant to", "invariant")?;
    if code != 12 || outcomes != ["Error"] || invariants != [TRACE_EVALUATION_EXPORT_INVARIANT] {
        return Err(TraceError::Apalache(format!(
            "unexpected ITF invariant evaluation exit={code} outcomes={outcomes:?} invariants={invariants:?}: {}",
            combined.trim()
        )));
    }
    let mut traces = Vec::new();
    collect_named_itf_traces(run_dir, "violation", &mut traces)?;
    if traces.len() != 1 {
        return Err(TraceError::Apalache(format!(
            "ITF invariant evaluation must produce exactly one witness, found {}",
            traces.len()
        )));
    }
    let witness_bytes = fs::read(&traces[0])?;
    let witness = parse_strict_json(&witness_bytes, "invariant evaluation witness")?;
    let witness_object = witness.as_object().ok_or_else(|| {
        TraceError::Apalache("invariant evaluation witness is not an object".to_string())
    })?;
    let expected_root_keys = ["#meta", "params", "states", "vars"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let actual_root_keys = witness_object
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_root_keys != expected_root_keys {
        return Err(TraceError::Apalache(format!(
            "invariant evaluation witness root keys are invalid: {actual_root_keys:?}"
        )));
    }
    if witness
        .get("#meta")
        .and_then(serde_json::Value::as_object)
        .and_then(|metadata| metadata.get("format"))
        .and_then(serde_json::Value::as_str)
        != Some("ITF")
    {
        return Err(TraceError::Apalache(
            "invariant evaluation witness has invalid ITF metadata".to_string(),
        ));
    }
    let params = witness
        .get("params")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| TraceError::Apalache("evaluation witness has no params".to_string()))?;
    let parameter_names = itf_names(params, "evaluation parameter")?;
    let expected_parameter_names = ["CAPS", "DEPTH_MAX", "PROCS"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if parameter_names != expected_parameter_names {
        return Err(TraceError::Apalache(format!(
            "evaluation witness parameter set is invalid: {parameter_names:?}"
        )));
    }
    let expected_names = MODEL_VARIABLES
        .into_iter()
        .chain(std::iter::once("trace_index"))
        .chain(std::iter::once("evaluated"))
        .chain(
            EVALUATED_VARIABLES
                .into_iter()
                .map(|(variable, _)| variable),
        )
        .collect::<BTreeSet<_>>();
    let variables = witness
        .get("vars")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| TraceError::Apalache("evaluation witness has no vars".to_string()))?;
    let actual_names = itf_names(variables, "evaluation variable")?;
    if actual_names != expected_names {
        return Err(TraceError::Apalache(format!(
            "evaluation witness variable set is invalid: {actual_names:?}"
        )));
    }
    let var_types = witness
        .get("#meta")
        .and_then(serde_json::Value::as_object)
        .and_then(|metadata| metadata.get("varTypes"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| TraceError::Apalache("evaluation witness has no varTypes".to_string()))?;
    let typed_names = var_types
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if typed_names != expected_names
        || APALACHE_MODEL_VARIABLE_TYPES
            .iter()
            .any(|(name, expected)| {
                var_types.get(*name).and_then(serde_json::Value::as_str) != Some(*expected)
            })
        || var_types
            .get("trace_index")
            .and_then(serde_json::Value::as_str)
            != Some("Int")
        || var_types
            .get("evaluated")
            .and_then(serde_json::Value::as_str)
            != Some("Bool")
        || EVALUATED_VARIABLES.iter().any(|(name, _)| {
            var_types.get(*name).and_then(serde_json::Value::as_str) != Some("Bool")
        })
    {
        return Err(TraceError::Apalache(format!(
            "evaluation witness varTypes are not exact: {var_types:?}"
        )));
    }
    let states = witness
        .get("states")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| TraceError::Apalache("evaluation witness has no states".to_string()))?;
    let expected_state_count = projection
        .states
        .len()
        .checked_mul(2)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| TraceError::InvalidInput("evaluation state count overflow".to_string()))?;
    if states.len() != expected_state_count || states.is_empty() {
        return Err(TraceError::Apalache(format!(
            "evaluation witness has {} states, expected {}",
            states.len(),
            expected_state_count
        )));
    }
    let mut evaluated_states = Vec::with_capacity(projection.states.len());
    for (index, state) in states.iter().enumerate() {
        let state = state.as_object().ok_or_else(|| {
            TraceError::Apalache(format!("evaluation witness state {index} is not an object"))
        })?;
        let recorded_index = state
            .get("#meta")
            .and_then(serde_json::Value::as_object)
            .and_then(|metadata| metadata.get("index"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| usize::try_from(value).ok());
        if recorded_index != Some(index)
            || state.keys().any(|name| {
                name != "#meta"
                    && !expected_names.contains(name.as_str())
                    && !expected_parameter_names.contains(name.as_str())
            })
            || expected_names.iter().any(|name| !state.contains_key(*name))
        {
            return Err(TraceError::Apalache(format!(
                "evaluation witness state {index} has an invalid shape"
            )));
        }
        for (parameter, expected) in [
            ("CAPS", u64::try_from(projection.capability_count).ok()),
            ("DEPTH_MAX", Some(u64::from(projection.depth_max))),
            ("PROCS", u64::try_from(projection.authority_count).ok()),
        ] {
            let value = state.get(parameter).and_then(itf_u64);
            if (index == 0 || value.is_some()) && value != expected {
                return Err(TraceError::Apalache(format!(
                    "evaluation witness state {index} has the wrong {parameter} parameter: actual={:?} expected={expected:?}",
                    state.get(parameter)
                )));
            }
        }
        let projected_index = index
            .checked_add(1)
            .map(|value| value / 2)
            .ok_or_else(|| TraceError::InvalidInput("ITF state index overflow".to_string()))?;
        let expected_trace_index = u64::try_from(projected_index + 1)
            .map_err(|_| TraceError::InvalidInput("ITF state index exceeds u64".to_string()))?;
        if state.get("trace_index").and_then(itf_u64) != Some(expected_trace_index) {
            return Err(TraceError::Apalache(format!(
                "evaluation witness state {index} has the wrong trace index"
            )));
        }
        let expected_evaluated = index % 2 == 0;
        if state.get("evaluated").and_then(serde_json::Value::as_bool) != Some(expected_evaluated) {
            return Err(TraceError::Apalache(format!(
                "evaluation witness state {index} breaks the load/evaluate alternation"
            )));
        }
        let input_state = projection.states.get(projected_index).ok_or_else(|| {
            TraceError::Apalache(format!("projected ITF lacks state {projected_index}"))
        })?;
        for variable in MODEL_VARIABLES {
            if !state
                .get(variable)
                .zip(input_state.get(variable))
                .is_some_and(|(actual, expected)| itf_values_equal(actual, expected))
            {
                return Err(TraceError::Apalache(format!(
                    "evaluation witness state {index} differs from ITF variable {variable}"
                )));
            }
        }
        let mut evaluated = serde_json::Map::new();
        for (variable, expression) in EVALUATED_VARIABLES {
            let value = state
                .get(variable)
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| {
                    TraceError::Apalache(format!(
                        "evaluation witness state {index} lacks Boolean {variable}"
                    ))
                })?;
            evaluated.insert(expression.to_string(), serde_json::Value::Bool(value));
        }
        if expected_evaluated {
            evaluated_states.push(serde_json::Value::Object(evaluated));
        } else if let Some(previous) = states.get(index.saturating_sub(1)) {
            for (variable, _) in EVALUATED_VARIABLES {
                if state.get(variable) != previous.get(variable) {
                    return Err(TraceError::Apalache(format!(
                        "evaluation witness load state {index} changed {variable}"
                    )));
                }
            }
        }
    }
    if evaluated_states.len() != projection.states.len() {
        return Err(TraceError::Apalache(
            "evaluation witness has the wrong evaluated-state count".to_string(),
        ));
    }
    for witness_name in WITNESS_EXPRESSIONS {
        if !evaluated_states
            .iter()
            .any(|state| state.get(witness_name).and_then(serde_json::Value::as_bool) == Some(true))
        {
            return Err(TraceError::InvalidInput(format!(
                "ITF does not contain a non-vacuous witness for {witness_name}"
            )));
        }
    }

    let failure = evaluated_states
        .iter()
        .enumerate()
        .find_map(|(state_index, state)| {
            let state_object = state.as_object()?;
            let invariant = INVARIANT_EXPRESSIONS.into_iter().find(|name| {
                state_object.get(*name).and_then(serde_json::Value::as_bool) == Some(false)
            })?;
            let input_state = projection.states.get(state_index)?;
            let visible_step = input_state
                .get("#meta")
                .and_then(serde_json::Value::as_object)
                .and_then(|metadata| metadata.get("visibleSequence"))
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or_else(|| {
                    projection.states[..=state_index]
                        .iter()
                        .filter(|input| {
                            input
                                .get("#meta")
                                .and_then(serde_json::Value::as_object)
                                .and_then(|metadata| metadata.get("visibleSequence"))
                                .is_some()
                        })
                        .count()
                });
            Some(ItfInvariantFailure {
                state_index,
                visible_step,
                invariant: invariant.to_string(),
                input_predecessor: projection
                    .states
                    .get(state_index.saturating_sub(1))?
                    .clone(),
                evaluated_state: state.clone(),
            })
        });
    Ok(ItfInvariantEvaluation {
        witness_sha256: chio_core_types::sha256_hex(&witness_bytes),
        witness_json: witness_bytes,
        checker_binary_sha256: checker_binary_sha256.to_string(),
        timeout_binary_sha256: timeout_binary_sha256.to_string(),
        failure,
    })
}

fn collect_named_itf_traces(
    root: &Path,
    prefix: &str,
    traces: &mut Vec<PathBuf>,
) -> Result<(), TraceError> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(TraceError::Apalache(format!(
                "Apalache output contains a symlink: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            collect_named_itf_traces(&path, prefix, traces)?;
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(number) = name
            .strip_prefix(prefix)
            .and_then(|name| name.strip_suffix(".itf.json"))
        else {
            continue;
        };
        if !number.is_empty()
            && number.bytes().all(|byte| byte.is_ascii_digit())
            && metadata.len() > 0
        {
            traces.push(path);
        }
    }
    traces.sort();
    Ok(())
}

fn trace_evaluation_config(projection: &RevocationProjection) -> String {
    format!(
        "INIT TraceEvaluationInit\nNEXT TraceEvaluationNext\nINVARIANT {TRACE_EVALUATION_EXPORT_INVARIANT}\n\nCONSTANTS\n    PROCS = {}\n    CAPS = {}\n    DEPTH_MAX = {}\n",
        projection.authority_count, projection.capability_count, projection.depth_max
    )
}

fn trace_evaluation_input_module(itf_json: &[u8]) -> Result<String, TraceError> {
    let root = parse_strict_json(itf_json, "projected invariant-evaluation ITF")?;
    let object = root.as_object().ok_or_else(|| {
        TraceError::InvalidInput("projected ITF root is not an object".to_string())
    })?;
    let metadata = object
        .get("#meta")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| TraceError::InvalidInput("projected ITF has no metadata".to_string()))?;
    if metadata.get("format").and_then(serde_json::Value::as_str) != Some("ITF") {
        return Err(TraceError::InvalidInput(
            "projected ITF metadata is invalid".to_string(),
        ));
    }
    let params = object
        .get("params")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| TraceError::InvalidInput("projected ITF has no params".to_string()))?;
    if !params.is_empty() {
        return Err(TraceError::InvalidInput(
            "projected ITF unexpectedly contains parameters".to_string(),
        ));
    }
    let variables = object
        .get("vars")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| TraceError::InvalidInput("projected ITF has no vars".to_string()))?;
    let variable_names = itf_names(variables, "projected variable")?;
    let expected_names = MODEL_VARIABLES.into_iter().collect::<BTreeSet<_>>();
    if variable_names != expected_names {
        return Err(TraceError::InvalidInput(format!(
            "projected ITF variable set is invalid: {variable_names:?}"
        )));
    }
    let var_types = metadata
        .get("varTypes")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| TraceError::InvalidInput("projected ITF has no varTypes".to_string()))?;
    let typed_names = var_types
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if typed_names != expected_names
        || MODEL_VARIABLE_TYPES.iter().any(|(name, expected)| {
            var_types.get(*name).and_then(serde_json::Value::as_str) != Some(*expected)
        })
    {
        return Err(TraceError::InvalidInput(
            "projected ITF varTypes are not exact".to_string(),
        ));
    }
    let states = object
        .get("states")
        .and_then(serde_json::Value::as_array)
        .filter(|states| !states.is_empty())
        .ok_or_else(|| TraceError::InvalidInput("projected ITF has no states".to_string()))?;
    let mut next_binder = 0_u64;
    let entries = states
        .iter()
        .enumerate()
        .map(|(index, state)| {
            let state = state.as_object().ok_or_else(|| {
                TraceError::InvalidInput(format!("projected ITF state {index} is not an object"))
            })?;
            let recorded_index = state
                .get("#meta")
                .and_then(serde_json::Value::as_object)
                .and_then(|metadata| metadata.get("index"))
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| usize::try_from(value).ok());
            if recorded_index != Some(index)
                || state
                    .keys()
                    .any(|name| name != "#meta" && !expected_names.contains(name.as_str()))
                || expected_names.iter().any(|name| !state.contains_key(*name))
            {
                return Err(TraceError::InvalidInput(format!(
                    "projected ITF state {index} has an invalid shape"
                )));
            }
            let fields = MODEL_VARIABLES
                .into_iter()
                .map(|name| {
                    let value = state.get(name).ok_or_else(|| {
                        TraceError::InvalidInput(format!(
                            "projected ITF state {index} lacks {name}"
                        ))
                    })?;
                    Ok(format!(
                        "{name} |-> {}",
                        itf_value_to_tla(value, &mut next_binder)?
                    ))
                })
                .collect::<Result<Vec<_>, TraceError>>()?;
            Ok(format!("[{}]", fields.join(", ")))
        })
        .collect::<Result<Vec<_>, TraceError>>()?;
    let observed_states = entries.iter().fold("<<>>".to_string(), |sequence, state| {
        format!("Append({sequence}, {state})")
    });
    Ok(format!(
        "----------------------- MODULE TraceEvaluationInput -----------------------\nEXTENDS Naturals, Sequences\n\nReceiptIndexSet == 1..{}\n\n\\* @type: Seq({{ {} }});\nObservedStates ==\n    {}\n\n================================================================================\n",
        states.len(),
        MODEL_VARIABLE_TYPES
            .into_iter()
            .map(|(name, value_type)| format!("{name}: {value_type}"))
            .collect::<Vec<_>>()
            .join(", "),
        observed_states
    ))
}

fn itf_value_to_tla(
    value: &serde_json::Value,
    next_binder: &mut u64,
) -> Result<String, TraceError> {
    match value {
        serde_json::Value::Null => Err(TraceError::InvalidInput(
            "projected ITF contains null".to_string(),
        )),
        serde_json::Value::Bool(value) => Ok(if *value { "TRUE" } else { "FALSE" }.to_string()),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(value.to_string())
            } else if let Some(value) = value.as_u64() {
                Ok(value.to_string())
            } else {
                Err(TraceError::InvalidInput(
                    "projected ITF contains a non-integer number".to_string(),
                ))
            }
        }
        serde_json::Value::String(value) => {
            if value.is_empty()
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
            {
                return Err(TraceError::InvalidInput(
                    "projected ITF contains an unsupported string".to_string(),
                ));
            }
            Ok(format!("\"{value}\""))
        }
        serde_json::Value::Array(values) => {
            if values.is_empty() {
                return Ok(
                    "Tail(<<[cap |-> 0, seen_epoch |-> 0, t |-> 0, verdict |-> \"deny\"]>>)"
                        .to_string(),
                );
            }
            values
                .iter()
                .try_fold("<<>>".to_string(), |sequence, value| {
                    Ok(format!(
                        "Append({sequence}, {})",
                        itf_value_to_tla(value, next_binder)?
                    ))
                })
        }
        serde_json::Value::Object(object) => {
            if let Some(map) = object.get("#map") {
                if object.len() != 1 {
                    return Err(TraceError::InvalidInput(
                        "projected ITF map has extra fields".to_string(),
                    ));
                }
                let pairs = map.as_array().ok_or_else(|| {
                    TraceError::InvalidInput("projected ITF map is not an array".to_string())
                })?;
                let mut entries = std::collections::BTreeMap::new();
                for pair in pairs {
                    let pair = pair
                        .as_array()
                        .filter(|pair| pair.len() == 2)
                        .ok_or_else(|| {
                            TraceError::InvalidInput(
                                "projected ITF map entry is malformed".to_string(),
                            )
                        })?;
                    let key = pair[0].as_u64().filter(|key| *key > 0).ok_or_else(|| {
                        TraceError::InvalidInput(
                            "projected ITF map key is not a positive integer".to_string(),
                        )
                    })?;
                    if entries.insert(key, &pair[1]).is_some() {
                        return Err(TraceError::InvalidInput(
                            "projected ITF map repeats a key".to_string(),
                        ));
                    }
                }
                if entries.is_empty() {
                    return Err(TraceError::InvalidInput(
                        "projected ITF map is empty".to_string(),
                    ));
                }
                let expected_len = u64::try_from(entries.len()).map_err(|_| {
                    TraceError::InvalidInput("projected ITF map is too large".to_string())
                })?;
                if entries.keys().copied().ne(1..=expected_len) {
                    return Err(TraceError::InvalidInput(
                        "projected ITF map domain is not contiguous from one".to_string(),
                    ));
                }
                let values = entries
                    .values()
                    .map(|entry| itf_value_to_tla(entry, next_binder))
                    .collect::<Result<Vec<_>, TraceError>>()?;
                let binder = format!("i{next_binder}");
                *next_binder = next_binder.checked_add(1).ok_or_else(|| {
                    TraceError::InvalidInput("generated TLA binder overflow".to_string())
                })?;
                let domain = values.len();
                if domain == 1 {
                    return Ok(format!("[{binder} \\in 1..1 |-> {}]", values[0]));
                }
                let branches = values[..domain - 1]
                    .iter()
                    .enumerate()
                    .map(|(index, value)| format!("{binder} = {} -> {value}", index + 1))
                    .chain(std::iter::once(format!("OTHER -> {}", values[domain - 1])))
                    .collect::<Vec<_>>()
                    .join(" [] ");
                return Ok(format!("[{binder} \\in 1..{domain} |-> CASE {branches}]"));
            }
            if let Some(set) = object.get("#set") {
                if object.len() != 1 {
                    return Err(TraceError::InvalidInput(
                        "projected ITF set has extra fields".to_string(),
                    ));
                }
                let entries = set.as_array().ok_or_else(|| {
                    TraceError::InvalidInput("projected ITF set is not an array".to_string())
                })?;
                return Ok(format!(
                    "{{{}}}",
                    entries
                        .iter()
                        .map(|entry| itf_value_to_tla(entry, next_binder))
                        .collect::<Result<Vec<_>, TraceError>>()?
                        .join(", ")
                ));
            }
            if object.is_empty() {
                return Err(TraceError::InvalidInput(
                    "projected ITF contains an empty record".to_string(),
                ));
            }
            let fields = object
                .iter()
                .map(|(name, value)| {
                    if !is_tla_identifier(name) {
                        return Err(TraceError::InvalidInput(format!(
                            "projected ITF record field is invalid: {name}"
                        )));
                    }
                    Ok(format!(
                        "{name} |-> {}",
                        itf_value_to_tla(value, next_binder)?
                    ))
                })
                .collect::<Result<Vec<_>, TraceError>>()?;
            Ok(format!("[{}]", fields.join(", ")))
        }
    }
}

fn is_tla_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

impl ReachabilityOracle for ApalacheOracle {
    fn checker_name(&self) -> &str {
        "Apalache 0.50.1"
    }

    fn prefix_reachability(
        &self,
        projection: &RevocationProjection,
        prefix_len: usize,
    ) -> Result<PrefixReachability, TraceError> {
        if prefix_len == 0 || prefix_len > projection.events.len() {
            return Err(TraceError::InvalidInput(format!(
                "trace prefix length {prefix_len} is outside 1..={}",
                projection.events.len()
            )));
        }
        let work = tempfile::Builder::new()
            .prefix("chio-trace-check-")
            .tempdir()?;
        let input_dir = work.path().join("input");
        let out_dir = work.path().join("out");
        let run_dir = work.path().join("run");
        fs::create_dir_all(&input_dir)?;
        fs::create_dir_all(&out_dir)?;
        fs::create_dir_all(&run_dir)?;
        fs::write(
            input_dir.join("RevocationPropagation.tla"),
            REVOCATION_MODEL,
        )?;
        fs::write(
            input_dir.join("TraceCheckRevocationPropagation.tla"),
            TRACE_CHECK_MODEL,
        )?;
        fs::write(
            input_dir.join("TraceInput.tla"),
            trace_input_module(&projection.itf_json, prefix_len)?,
        )?;
        fs::write(
            input_dir.join("MCTraceCheckRevocationPropagation.cfg"),
            trace_config(projection),
        )?;

        let hidden_bound = prefix_len
            .checked_mul(projection.authority_count.saturating_sub(1))
            .and_then(|value| value.checked_add(projection.depth_max as usize))
            .ok_or_else(|| TraceError::InvalidInput("trace length bound overflow".to_string()))?;
        let length = prefix_len
            .checked_add(hidden_bound)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| TraceError::InvalidInput("trace length bound overflow".to_string()))?;
        let args = vec![
            format!("--out-dir={}", out_dir.display()),
            format!("--run-dir={}", run_dir.display()),
            "check".to_string(),
            "--output-traces".to_string(),
            format!("--length={length}"),
            format!(
                "--config={}",
                input_dir
                    .join("MCTraceCheckRevocationPropagation.cfg")
                    .display()
            ),
            input_dir
                .join("TraceCheckRevocationPropagation.tla")
                .display()
                .to_string(),
        ];
        let output = self.run_timeout_command(args)?;
        classify_apalache_output(&output, &run_dir, prefix_len)
    }
}

fn classify_apalache_output(
    output: &Output,
    run_dir: &Path,
    prefix_len: usize,
) -> Result<PrefixReachability, TraceError> {
    let code = output.status.code().unwrap_or(-1);
    if code == 124 {
        return Err(TraceError::Apalache(
            "trace reachability check timed out".to_string(),
        ));
    }
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let outcomes = collect_apalache_markers(&combined, "The outcome is:", "outcome")?;
    let invariants = collect_apalache_markers(&combined, "> Set an invariant to", "invariant")?;
    if invariants != ["TraceNotAccepted"] {
        return Err(TraceError::Apalache(format!(
            "expected exactly invariant TraceNotAccepted, found {invariants:?}: {}",
            combined.trim()
        )));
    }
    match (code, outcomes.as_slice()) {
        (12, [outcome]) if outcome == "Error" => {
            let mut traces = Vec::new();
            collect_violation_traces(run_dir, &mut traces)?;
            if traces.len() != 1 {
                return Err(TraceError::Apalache(format!(
                    "reachable prefix must produce exactly one ITF witness, found {}",
                    traces.len()
                )));
            }
            validate_itf_witness(&traces[0], prefix_len)?;
            Ok(PrefixReachability::Reachable)
        }
        (0, [outcome]) if outcome == "NoError" => Ok(PrefixReachability::Unreachable),
        _ => Err(TraceError::Apalache(format!(
            "unexpected Apalache result exit={code} outcomes={outcomes:?}: {}",
            combined.trim()
        ))),
    }
}

fn collect_violation_traces(root: &Path, traces: &mut Vec<PathBuf>) -> Result<(), TraceError> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(TraceError::Apalache(format!(
                "Apalache output contains a symlink: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            collect_violation_traces(&path, traces)?;
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(number) = name
            .strip_prefix("violation")
            .and_then(|name| name.strip_suffix(".itf.json"))
        else {
            continue;
        };
        if !number.is_empty()
            && number.bytes().all(|byte| byte.is_ascii_digit())
            && metadata.len() > 0
        {
            traces.push(path);
        }
    }
    Ok(())
}

fn validate_itf_witness(path: &Path, prefix_len: usize) -> Result<(), TraceError> {
    let witness = parse_strict_json(&fs::read(path)?, "reachability witness")?;
    let object = witness.as_object().ok_or_else(|| {
        TraceError::Apalache("reachable prefix produced a non-object ITF witness".to_string())
    })?;
    let expected_root_keys = ["#meta", "params", "states", "vars"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let actual_root_keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual_root_keys != expected_root_keys {
        return Err(TraceError::Apalache(format!(
            "reachability witness root keys are invalid: {actual_root_keys:?}"
        )));
    }
    if object
        .get("#meta")
        .and_then(serde_json::Value::as_object)
        .and_then(|metadata| metadata.get("format"))
        .and_then(serde_json::Value::as_str)
        != Some("ITF")
    {
        return Err(TraceError::Apalache(
            "reachable prefix produced an invalid ITF metadata block".to_string(),
        ));
    }
    let params = object
        .get("params")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| TraceError::Apalache("ITF witness is missing params".to_string()))?;
    let variables = object
        .get("vars")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| TraceError::Apalache("ITF witness is missing vars".to_string()))?;
    if variables.is_empty() {
        return Err(TraceError::Apalache(
            "ITF witness has no variables".to_string(),
        ));
    }
    let parameter_names = itf_names(params, "parameter")?;
    let variable_names = itf_names(variables, "variable")?;
    if !parameter_names.is_disjoint(&variable_names) {
        return Err(TraceError::Apalache(
            "ITF params and vars overlap".to_string(),
        ));
    }
    let var_types = object
        .get("#meta")
        .and_then(serde_json::Value::as_object)
        .and_then(|metadata| metadata.get("varTypes"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| TraceError::Apalache("ITF witness is missing varTypes".to_string()))?;
    let typed_names = var_types
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if typed_names != variable_names
        || var_types
            .values()
            .any(|value| value.as_str().is_none_or(str::is_empty))
    {
        return Err(TraceError::Apalache(
            "ITF varTypes must define every variable exactly".to_string(),
        ));
    }
    let states = object
        .get("states")
        .and_then(serde_json::Value::as_array)
        .filter(|states| !states.is_empty())
        .ok_or_else(|| TraceError::Apalache("ITF witness has no states".to_string()))?;
    let initial = states[0].as_object().ok_or_else(|| {
        TraceError::Apalache("ITF witness initial state is not an object".to_string())
    })?;
    if parameter_names
        .iter()
        .any(|parameter| !initial.contains_key(*parameter))
    {
        return Err(TraceError::Apalache(
            "ITF witness initial state is missing a parameter".to_string(),
        ));
    }
    for (index, state) in states.iter().enumerate() {
        let state = state.as_object().ok_or_else(|| {
            TraceError::Apalache("ITF witness state is not an object".to_string())
        })?;
        let recorded_index = state
            .get("#meta")
            .and_then(serde_json::Value::as_object)
            .and_then(|metadata| metadata.get("index"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| usize::try_from(value).ok());
        if recorded_index != Some(index)
            || variable_names
                .iter()
                .any(|variable| !state.contains_key(*variable))
            || state.keys().any(|name| {
                name != "#meta"
                    && !variable_names.contains(name.as_str())
                    && !parameter_names.contains(name.as_str())
            })
            || parameter_names.iter().any(|parameter| {
                state
                    .get(*parameter)
                    .is_some_and(|value| initial.get(*parameter) != Some(value))
            })
        {
            return Err(TraceError::Apalache(
                "ITF witness state shape is invalid".to_string(),
            ));
        }
    }
    let final_state = states
        .last()
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| TraceError::Apalache("ITF witness has no final state".to_string()))?;
    let expected_index = u64::try_from(prefix_len)
        .map_err(|_| TraceError::InvalidInput("trace prefix exceeds u64".to_string()))?;
    if final_state
        .get("accepted")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
        || final_state.get("trace_index").and_then(itf_u64) != Some(expected_index)
    {
        return Err(TraceError::Apalache(
            "ITF witness does not end at the accepted trace prefix".to_string(),
        ));
    }
    Ok(())
}

fn collect_apalache_markers(
    output: &str,
    prefix: &str,
    label: &str,
) -> Result<Vec<String>, TraceError> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix(prefix).map(|rest| {
                if !rest.starts_with(' ') {
                    return Err(TraceError::Apalache(format!(
                        "malformed Apalache {label} line: {line}"
                    )));
                }
                let fields = rest.split_ascii_whitespace().collect::<Vec<_>>();
                match fields.as_slice() {
                    [value] if !value.is_empty() => Ok((*value).to_string()),
                    [value, timestamp] if !value.is_empty() && is_apalache_timestamp(timestamp) => {
                        Ok((*value).to_string())
                    }
                    _ => Err(TraceError::Apalache(format!(
                        "malformed Apalache {label} line: {line}"
                    ))),
                }
            })
        })
        .collect()
}

fn is_apalache_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 14
        && &bytes[..2] == b"I@"
        && bytes[2..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b':'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b':'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[10] == b'.'
        && bytes[11..14].iter().all(u8::is_ascii_digit)
}

fn parse_strict_json(bytes: &[u8], label: &str) -> Result<serde_json::Value, TraceError> {
    let input = std::str::from_utf8(bytes)
        .map_err(|error| TraceError::Apalache(format!("{label} is not UTF-8 JSON: {error}")))?;
    let canonical = chio_core_types::canonical::canonical_json_bytes_from_str(input)
        .map_err(|error| TraceError::Apalache(format!("{label} is not strict JSON: {error}")))?;
    Ok(serde_json::from_slice(&canonical)?)
}

fn itf_u64(value: &serde_json::Value) -> Option<u64> {
    itf_integer(value)?.parse().ok()
}

fn itf_integer(value: &serde_json::Value) -> Option<String> {
    if let Some(value) = value.as_i64() {
        return Some(value.to_string());
    }
    if let Some(value) = value.as_u64() {
        return Some(value.to_string());
    }
    let object = value.as_object()?;
    if object.len() != 1 {
        return None;
    }
    let tagged = object.get("#bigint")?.as_str()?;
    let digits = tagged.strip_prefix('-').unwrap_or(tagged);
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
        || tagged == "-0"
    {
        return None;
    }
    Some(tagged.to_string())
}

fn itf_values_equal(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    if let (Some(left), Some(right)) = (itf_integer(left), itf_integer(right)) {
        return left == right;
    }
    match (left, right) {
        (serde_json::Value::Array(left), serde_json::Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| itf_values_equal(left, right))
        }
        (serde_json::Value::Object(left), serde_json::Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(name, left)| {
                    right
                        .get(name)
                        .is_some_and(|right| itf_values_equal(left, right))
                })
        }
        _ => left == right,
    }
}

fn itf_names<'a>(
    values: &'a [serde_json::Value],
    label: &str,
) -> Result<BTreeSet<&'a str>, TraceError> {
    let mut names = BTreeSet::new();
    for value in values {
        let name = value
            .as_str()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                TraceError::Apalache(format!("ITF {label} name is not a non-empty string"))
            })?;
        if !names.insert(name) {
            return Err(TraceError::Apalache(format!(
                "ITF witness repeats {label} {name}"
            )));
        }
    }
    Ok(names)
}

fn trace_input_module(itf_json: &[u8], prefix_len: usize) -> Result<String, TraceError> {
    let root = parse_strict_json(itf_json, "projected reachability ITF")?;
    if root
        .get("#meta")
        .and_then(serde_json::Value::as_object)
        .and_then(|metadata| metadata.get("format"))
        .and_then(serde_json::Value::as_str)
        != Some("ITF")
    {
        return Err(TraceError::InvalidInput(
            "projected ITF metadata is invalid".to_string(),
        ));
    }
    let visible = root
        .get("states")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| TraceError::InvalidInput("projected ITF has no states".to_string()))?
        .iter()
        .filter_map(|state| {
            let metadata = state.get("#meta")?.as_object()?;
            matches!(
                metadata.get("action").and_then(serde_json::Value::as_str),
                Some("revoke" | "evaluate")
            )
            .then_some(metadata)
        })
        .collect::<Vec<_>>();
    if prefix_len == 0 || prefix_len > visible.len() {
        return Err(TraceError::InvalidInput(format!(
            "ITF visible prefix {prefix_len} is outside 1..={}",
            visible.len()
        )));
    }
    let entries = visible[..prefix_len]
        .iter()
        .map(|metadata| {
            let kind = required_meta_str(metadata, "action")?;
            let authority = required_meta_u64(metadata, "authority")?;
            let capability = required_meta_u64(metadata, "capability")?;
            let sequence = required_meta_u64(metadata, "visibleSequence")?;
            let (epoch, receipt_time, seen_epoch, verdict) = match kind {
                "revoke" => (required_meta_u64(metadata, "epoch")?, 0, 0, "none"),
                "evaluate" => (
                    0,
                    required_meta_u64(metadata, "receiptTime")?,
                    required_meta_u64(metadata, "seenEpoch")?,
                    required_meta_str(metadata, "verdict")?,
                ),
                _ => {
                    return Err(TraceError::InvalidInput(format!(
                        "ITF contains unsupported visible action {kind}"
                    )))
                }
            };
            Ok(format!(
                "[kind |-> \"{kind}\", authority |-> {authority}, cap |-> {capability}, sequence |-> {sequence}, epoch |-> {epoch}, receipt_time |-> {receipt_time}, seen_epoch |-> {seen_epoch}, verdict |-> \"{verdict}\"]"
            ))
        })
        .collect::<Result<Vec<_>, TraceError>>()?;
    let observed_trace = entries.iter().fold("<<>>".to_string(), |sequence, event| {
        format!("Append({sequence}, {event})")
    });
    Ok(format!(
        "------------------------------ MODULE TraceInput ------------------------------\nEXTENDS Sequences\n\n\\* @type: Seq({{ authority: Int, cap: Int, epoch: Int, kind: Str, receipt_time: Int, seen_epoch: Int, sequence: Int, verdict: Str }});\nObservedTrace ==\n    {observed_trace}\n\n================================================================================\n"
    ))
}

fn required_meta_str<'a>(
    metadata: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a str, TraceError> {
    metadata
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TraceError::InvalidInput(format!("ITF action metadata lacks {field}")))
}

fn required_meta_u64(
    metadata: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<u64, TraceError> {
    metadata
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| TraceError::InvalidInput(format!("ITF action metadata lacks {field}")))
}

fn trace_config(projection: &RevocationProjection) -> String {
    format!(
        "CONSTANTS\n    PROCS = {}\n    CAPS = {}\n    DEPTH_MAX = {}\n\nINIT\n    TraceInit\n\nNEXT\n    TraceNext\n\nINVARIANT\n    TraceNotAccepted\n",
        projection.authority_count, projection.capability_count, projection.depth_max
    )
}

fn find_timeout_binary() -> Result<PathBuf, TraceError> {
    for candidate in ["timeout", "gtimeout"] {
        let Ok(path) = resolve_executable(Path::new(candidate)) else {
            continue;
        };
        if Command::new(&path)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return Ok(path);
        }
    }
    Err(TraceError::Apalache(
        "timeout or gtimeout is required to bound Apalache".to_string(),
    ))
}

fn resolve_executable(path: &Path) -> Result<PathBuf, TraceError> {
    if path.components().count() > 1 || path.is_absolute() {
        return fs::canonicalize(path).map_err(|error| {
            TraceError::Apalache(format!(
                "cannot resolve Apalache executable {}: {error}",
                path.display()
            ))
        });
    }
    let search_path = std::env::var_os("PATH")
        .ok_or_else(|| TraceError::Apalache("PATH is unavailable".to_string()))?;
    for directory in std::env::split_paths(&search_path) {
        let candidate = directory.join(path);
        if candidate.is_file() {
            return fs::canonicalize(candidate).map_err(TraceError::Io);
        }
    }
    Err(TraceError::Apalache(format!(
        "Apalache executable is not on PATH: {}",
        path.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_apalache_marker_grammar_is_exact() -> Result<(), TraceError> {
        assert_eq!(
            collect_apalache_markers(
                "The outcome is: Error I@12:34:56.789\n",
                "The outcome is:",
                "outcome",
            )?,
            ["Error"]
        );
        assert_eq!(
            collect_apalache_markers(
                "> Set an invariant to TraceNotAccepted\n",
                "> Set an invariant to",
                "invariant",
            )?,
            ["TraceNotAccepted"]
        );
        for malformed in [
            "The outcome is: Error trailing",
            "The outcome is: Error I@1:34:56.789",
            "The outcome is: Error I@12:34:56.789 trailing",
            "The outcome is:Error",
        ] {
            assert!(
                collect_apalache_markers(malformed, "The outcome is:", "outcome").is_err(),
                "accepted malformed marker: {malformed}"
            );
        }
        Ok(())
    }

    #[test]
    fn strict_itf_parser_rejects_duplicate_keys() {
        assert!(parse_strict_json(br#"{"vars":[],"vars":[]}"#, "test ITF").is_err());
        assert!(parse_strict_json(br#"{"outer":{"key":1,"key":2}}"#, "test ITF").is_err());
    }
}
