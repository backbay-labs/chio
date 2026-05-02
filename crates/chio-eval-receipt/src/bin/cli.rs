use std::env;
use std::fs;
use std::process::ExitCode;

use chio_eval_receipt::verify_bundle;
use sha2::{Digest, Sha256};

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
    match args.as_slice() {
        [command, bundle_path] if command == "verify" => verify_bundle_path(bundle_path),
        [command, memo_path, sig_path] if command == "verify-memo" => {
            verify_memo_path(memo_path, sig_path)
        }
        _ => Err(
            "usage: chio-eval-receipt verify <bundle-path> | verify-memo <memo-path> <sig-path>"
                .to_owned(),
        ),
    }
}

fn verify_bundle_path(bundle_path: &str) -> Result<String, String> {
    let bundle_json = fs::read_to_string(bundle_path)
        .map_err(|err| format!("failed to read {bundle_path}: {err}"))?;
    let verified = verify_bundle(&bundle_json)
        .map_err(|err| format!("failed to verify {bundle_path}: {err}"))?;
    Ok(format!(
        "verified {} receipts={} signatures={} corpus_sha256={}",
        verified.bundle_id,
        verified.receipt_count,
        verified.signature_count,
        verified.corpus_sha256
    ))
}

fn verify_memo_path(memo_path: &str, sig_path: &str) -> Result<String, String> {
    let memo_bytes =
        fs::read(memo_path).map_err(|err| format!("failed to read {memo_path}: {err}"))?;
    let memo_sha256 = sha256_hex(&memo_bytes);
    let sig =
        fs::read_to_string(sig_path).map_err(|err| format!("failed to read {sig_path}: {err}"))?;
    let fields = parse_signature_fields(&sig)?;

    require_field(&fields, "signature_format", "chio-memo-signature.v1")?;
    require_field(&fields, "scheme", "cosign-github-oidc-test")?;
    require_field(&fields, "signed_payload", "m02-memo.md:sha256")?;

    let signer = field_value(&fields, "signer_identity")?;
    let signed_hash = field_value(&fields, "memo_sha256")?;
    if signed_hash != memo_sha256 {
        return Err(format!(
            "memo sha256 mismatch: expected {signed_hash}, computed {memo_sha256}"
        ));
    }
    let expected_signature = memo_signature(&memo_sha256, signer);
    let signature = field_value(&fields, "signature")?;
    if signature != expected_signature {
        return Err("memo detached signature mismatch".to_owned());
    }

    Ok(format!(
        "verified memo {memo_path} signer={signer} sha256={memo_sha256}"
    ))
}

fn parse_signature_fields(sig: &str) -> Result<Vec<(&str, &str)>, String> {
    let mut fields = Vec::new();
    for line in sig.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            return Err(format!("invalid signature line: {trimmed}"));
        };
        fields.push((key.trim(), value.trim()));
    }
    Ok(fields)
}

fn require_field(fields: &[(&str, &str)], key: &str, expected: &str) -> Result<(), String> {
    let actual = field_value(fields, key)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{key} mismatch: expected {expected}, got {actual}"))
    }
}

fn field_value<'a>(fields: &'a [(&str, &str)], key: &str) -> Result<&'a str, String> {
    fields
        .iter()
        .find_map(|(candidate, value)| (*candidate == key).then_some(*value))
        .ok_or_else(|| format!("missing signature field: {key}"))
}

fn memo_signature(memo_sha256: &str, signer: &str) -> String {
    sha256_hex(format!("memo_sha256:{memo_sha256}:signer_identity:{signer}").as_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
