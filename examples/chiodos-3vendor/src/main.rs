use std::env;
use std::fs;
use std::path::PathBuf;

use chiodos_three_vendor_example::{
    fresh_proof_package, package_json, report_json, verifier_trust_bundle_document_for_package,
    verifier_trust_bundle_json, verify_package, ChiodosPackageError, ChiodosVerifierTrustBundle,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ChiodosPackageError> {
    let package = fresh_proof_package()?;
    let trust_bundle_document = verifier_trust_bundle_document_for_package(&package)?;
    let trust_bundle = ChiodosVerifierTrustBundle::from_document(trust_bundle_document.clone())?;
    let report = verify_package(&package, &trust_bundle)?;
    let args = env::args().collect::<Vec<_>>();
    match args.as_slice() {
        [_] => {
            println!("{}", package_json(&package)?);
        }
        [_, flag] if flag == "--report" => {
            println!("{}", report_json(&report)?);
        }
        [_, flag, dir] if flag == "--out-dir" => {
            let dir = PathBuf::from(dir);
            fs::create_dir_all(&dir)
                .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("buyer-auditor-proof-package.json"),
                package_json(&package)?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("selective-disclosure-proof.json"),
                serde_json::to_string_pretty(&package.selective_disclosure_proof)
                    .map_err(|error| ChiodosPackageError::Json(error.to_string()))?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("verifier-trust-bundle.json"),
                verifier_trust_bundle_json(&trust_bundle_document)?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(dir.join("verifier-report.json"), report_json(&report)?)
                .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
        }
        _ => {
            return Err(ChiodosPackageError::Json(
                "usage: generate-chiodos-proof-package [--report|--out-dir DIR]".to_string(),
            ));
        }
    }
    Ok(())
}
