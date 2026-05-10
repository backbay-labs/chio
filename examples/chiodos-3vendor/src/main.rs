use std::env;
use std::fs;
use std::path::PathBuf;

use chiodos_three_vendor_example::{
    authority_issuance_request, authority_profile_document, authority_profile_json,
    authority_signing_keys_document, disclosure_policy, fresh_proof_package, issuance_request_json,
    package_json, peer_pins_document_for_package, peer_pins_json, report_json,
    revocation_publication_request, revocation_publication_request_json, signing_keys_json,
    verification_context, verification_context_json, verifier_trust_bundle_document_for_package,
    verifier_trust_bundle_json, verify_package, write_signed_negative_case_inputs,
    ChiodosPackageError, ChiodosVerifierTrustBundle,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ChiodosPackageError> {
    let package = fresh_proof_package()?;
    let context = verification_context();
    let trust_bundle_document = verifier_trust_bundle_document_for_package(&package)?;
    let trust_bundle = ChiodosVerifierTrustBundle::from_document(trust_bundle_document.clone())?;
    let report = verify_package(&package, &trust_bundle, &context)?;
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
            fs::write(
                dir.join("verification-context.json"),
                verification_context_json(&context)?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(dir.join("verifier-report.json"), report_json(&report)?)
                .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
        }
        [_, flag, dir] if flag == "--signed-negative-dir" => {
            write_signed_negative_case_inputs(&PathBuf::from(dir))?;
        }
        [_, flag, dir] if flag == "--authority-input-dir" => {
            let dir = PathBuf::from(dir);
            fs::create_dir_all(&dir)
                .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("authority-profile.json"),
                authority_profile_json(&authority_profile_document()?)?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("issuance-request.json"),
                issuance_request_json(&authority_issuance_request()?)?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("local-signing-keys.json"),
                signing_keys_json(&authority_signing_keys_document())?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("peer-pins.json"),
                peer_pins_json(&peer_pins_document_for_package(&package))?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("workflow-intersection.json"),
                serde_json::to_string_pretty(&package.workflow_intersection)
                    .map_err(|error| ChiodosPackageError::Json(error.to_string()))?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("disclosure-policy.json"),
                serde_json::to_string_pretty(&disclosure_policy())
                    .map_err(|error| ChiodosPackageError::Json(error.to_string()))?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("revocation-publication-request.json"),
                revocation_publication_request_json(&revocation_publication_request(Vec::new()))?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
        }
        _ => {
            return Err(ChiodosPackageError::Json(
                "usage: generate-chiodos-proof-package [--report|--out-dir DIR|--signed-negative-dir DIR|--authority-input-dir DIR]"
                    .to_string(),
            ));
        }
    }
    Ok(())
}
