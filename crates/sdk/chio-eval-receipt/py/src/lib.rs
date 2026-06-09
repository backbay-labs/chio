#![allow(clippy::useless_conversion)]

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Verify a bundle JSON string and return a compact summary.
#[allow(clippy::useless_conversion)]
#[pyfunction]
fn verify_bundle_json(bundle_json: &str) -> PyResult<String> {
    let verified = chio_eval_receipt::verify_bundle(bundle_json)
        .map_err(|err| PyValueError::new_err(err.to_string()))?;
    Ok(format!(
        "bundle_id={} receipts={} signatures={} corpus_sha256={}",
        verified.bundle_id,
        verified.receipt_count,
        verified.signature_count,
        verified.corpus_sha256
    ))
}

/// Python module exposing the Chio eval-report receipt bundle verifier.
#[pymodule]
fn chio_eval_receipt_py(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(verify_bundle_json, module)?)?;
    Ok(())
}
