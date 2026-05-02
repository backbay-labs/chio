use std::env;
use std::fs;
use std::process::ExitCode;

use chio_eval_receipt::verify_bundle;

fn main() -> ExitCode {
    match run() {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 2 || args[0] != "verify" {
        return Err("usage: chio-eval-receipt verify <bundle-path>".to_owned());
    }

    let bundle_path = &args[1];
    let bundle_json = fs::read_to_string(bundle_path)
        .map_err(|err| format!("failed to read {bundle_path}: {err}"))?;
    let verified = verify_bundle(&bundle_json)
        .map_err(|err| format!("failed to verify {bundle_path}: {err}"))?;
    Ok(format!(
        "verified {} receipts={} signatures={} corpus_sha256={}",
        verified.bundle_id, verified.receipt_count, verified.signature_count, verified.corpus_sha256
    ))
}
