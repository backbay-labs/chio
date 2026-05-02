use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Return whether the Rust verifier surface is ready.
#[pyfunction]
fn verifier_ready() -> bool {
    chio_eval_receipt::surface().verifier_ready()
}

/// Verify a bundle JSON string and return a compact summary.
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

/// Python module for METR ingest smoke tests.
#[pymodule]
fn chio_eval_receipt_py(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(verifier_ready, module)?)?;
    module.add_function(wrap_pyfunction!(verify_bundle_json, module)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn rust_binding_surface_reports_ready() {
        assert!(chio_eval_receipt::surface().verifier_ready());
    }
}
