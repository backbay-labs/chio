#![cfg(unix)]

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use chio_trace_validate::{
    decode_observations, project_revocation_trace, validate_projection_with, ApalacheOracle,
    TraceError, ValidationStatus,
};

#[test]
fn apalache_protocol_distinguishes_reachable_and_unreachable_prefixes() -> Result<(), TraceError> {
    let temp = tempfile::tempdir()?;
    let checker = temp.path().join("apalache-mc");
    fs::write(
        &checker,
        r##"#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "version" ]]; then
  printf '%s\n' '0.50.1'
  exit 0
fi

run_dir=''
input=''
for arg in "$@"; do
  case "${arg}" in
    --run-dir=*) run_dir="${arg#--run-dir=}" ;;
    */TraceCheckRevocationPropagation.tla) input="$(dirname "${arg}")/TraceInput.tla" ;;
  esac
done

if grep -Fq 'seen_epoch |-> 2, verdict |-> "allow"' "${input}"; then
  printf '%s\n' '> Set an invariant to TraceNotAccepted'
  printf '%s\n' 'The outcome is: NoError'
  exit 0
fi

mkdir -p "${run_dir}"
prefix="$(grep -oF 'Append(' "${input}" | wc -l | tr -d ' ')"
printf '%s\n' "{\"#meta\":{\"format\":\"ITF\",\"varTypes\":{\"accepted\":\"Bool\",\"trace_index\":\"Int\"}},\"params\":[],\"vars\":[\"accepted\",\"trace_index\"],\"states\":[{\"#meta\":{\"index\":0},\"accepted\":true,\"trace_index\":${prefix}}]}" >"${run_dir}/violation1.itf.json"
printf '%s\n' '> Set an invariant to TraceNotAccepted'
printf '%s\n' 'The outcome is: Error'
exit 12
"##,
    )?;
    let mut permissions = fs::metadata(&checker)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&checker, permissions)?;
    let oracle = ApalacheOracle::new(&checker, 10)?;

    let good = support::good_trace()?;
    let observations = decode_observations(&good.ndjson, &[good.observer_key])?;
    let projection = project_revocation_trace(&observations)?;
    let report = validate_projection_with(&projection, &oracle)?;
    assert_eq!(report.status, ValidationStatus::Passed);
    assert_eq!(report.checker, "Apalache 0.50.1");

    let bad = support::bad_trace()?;
    let observations = decode_observations(&bad.ndjson, &[bad.observer_key])?;
    let projection = project_revocation_trace(&observations)?;
    let report = validate_projection_with(&projection, &oracle)?;
    assert_eq!(report.status, ValidationStatus::Failed);
    assert_eq!(report.divergence.map(|value| value.step), Some(3));
    Ok(())
}

#[test]
fn apalache_protocol_rejects_an_incomplete_itf_witness() -> Result<(), TraceError> {
    let temp = tempfile::tempdir()?;
    let checker = temp.path().join("apalache-mc");
    fs::write(
        &checker,
        r##"#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "version" ]]; then
  printf '%s\n' '0.50.1'
  exit 0
fi

run_dir=''
for arg in "$@"; do
  case "${arg}" in
    --run-dir=*) run_dir="${arg#--run-dir=}" ;;
  esac
done
mkdir -p "${run_dir}"
printf '%s\n' '{"#meta":{"format":"ITF"},"params":[],"vars":["accepted"],"states":[{"#meta":{"index":0},"accepted":true}]}' >"${run_dir}/violation1.itf.json"
printf '%s\n' '> Set an invariant to TraceNotAccepted'
printf '%s\n' 'The outcome is: Error'
exit 12
"##,
    )?;
    let mut permissions = fs::metadata(&checker)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&checker, permissions)?;
    let oracle = ApalacheOracle::new(&checker, 10)?;

    let fixture = support::good_trace()?;
    let observations = decode_observations(&fixture.ndjson, &[fixture.observer_key])?;
    let projection = project_revocation_trace(&observations)?;
    let error = validate_projection_with(&projection, &oracle)
        .err()
        .ok_or_else(|| TraceError::Apalache("incomplete ITF witness was accepted".to_string()))?;
    assert!(error.to_string().contains("varTypes"));
    Ok(())
}
