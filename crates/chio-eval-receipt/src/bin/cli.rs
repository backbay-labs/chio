use std::env;
use std::fs;
use std::process::ExitCode;

use chio_eval_receipt::verify_bundle;
use sha2::{Digest, Sha256};

/// Recognized scheme literal for the self-generated test sample memo signature.
///
/// This is intentionally NOT `sigstore-cosign` or any other real-cryptography
/// label. The memo signature in this repository is a self-generated SHA-256
/// receipt; rendering it as `sigstore-cosign` would misrepresent it as a
/// vendor-issued cosign attestation. Real partner cryptographic attestation is
/// deferred to trajectory-4 (M02-followup).
const SYNTHETIC_TEST_SAMPLE: &str = "synthetic-test-sample";

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
    require_field(&fields, "scheme", SYNTHETIC_TEST_SAMPLE)?;
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

    // Render the scheme literal verbatim. Do NOT remap to `sigstore-cosign` or
    // any other vendor label: this signature is a self-generated test sample,
    // not a vendor cryptographic attestation.
    let scheme = field_value(&fields, "scheme")?;
    Ok(format!(
        "verified memo {memo_path} signer={signer} sha256={memo_sha256} scheme={scheme}"
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

#[cfg(test)]
mod tests {
    use super::{memo_signature, sha256_hex, verify_memo_path, SYNTHETIC_TEST_SAMPLE};
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    fn write_temp(name: &str, contents: &[u8]) -> Result<PathBuf, String> {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        path.push(format!(
            "chio-eval-receipt-test-{}-{nanos}-{name}",
            std::process::id(),
        ));
        let mut file = fs::File::create(&path).map_err(|err| format!("create temp file: {err}"))?;
        file.write_all(contents)
            .map_err(|err| format!("write temp file: {err}"))?;
        Ok(path)
    }

    fn path_str(path: &Path) -> Result<&str, String> {
        path.to_str().ok_or_else(|| "non-utf8 temp path".to_owned())
    }

    #[test]
    fn synthetic_test_sample_constant_is_not_sigstore_cosign() {
        // Guard against accidental remapping back to a vendor-cosign label.
        assert_eq!(SYNTHETIC_TEST_SAMPLE, "synthetic-test-sample");
        assert_ne!(SYNTHETIC_TEST_SAMPLE, "sigstore-cosign");
        assert_ne!(SYNTHETIC_TEST_SAMPLE, "cosign-github-oidc-test");
    }

    #[test]
    fn verifier_renders_scheme_literal_verbatim() -> Result<(), String> {
        let memo = b"sample memo body for synthetic-test-sample render check\n";
        let memo_sha = sha256_hex(memo);
        let signer = "https://example.invalid/synthetic-test-sample-signer";
        let signature = memo_signature(&memo_sha, signer);
        let sig_body = format!(
            "signature_format: chio-memo-signature.v1\n\
             scheme: synthetic-test-sample\n\
             signer_identity: {signer}\n\
             signed_payload: m02-memo.md:sha256\n\
             memo_sha256: {memo_sha}\n\
             signature: {signature}\n",
        );

        let memo_path = write_temp("memo.md", memo)?;
        let sig_path = write_temp("memo.sig", sig_body.as_bytes())?;

        let result = verify_memo_path(path_str(&memo_path)?, path_str(&sig_path)?);
        // Cleanup before asserting (best effort).
        let _ = fs::remove_file(&memo_path);
        let _ = fs::remove_file(&sig_path);

        let message = result?;
        assert!(
            message.contains("scheme=synthetic-test-sample"),
            "verifier output should print the literal scheme verbatim, got: {message}"
        );
        assert!(
            !message.contains("sigstore-cosign"),
            "verifier must not remap synthetic-test-sample to sigstore-cosign, got: {message}"
        );
        assert!(
            !message.contains("cosign-github-oidc-test"),
            "verifier must not surface the legacy cosign-github-oidc-test literal, got: {message}"
        );
        Ok(())
    }

    #[test]
    fn verifier_rejects_legacy_cosign_github_oidc_test_scheme() -> Result<(), String> {
        let memo = b"legacy literal rejection test memo\n";
        let memo_sha = sha256_hex(memo);
        let signer = "https://example.invalid/legacy-signer";
        let signature = memo_signature(&memo_sha, signer);
        let sig_body = format!(
            "signature_format: chio-memo-signature.v1\n\
             scheme: cosign-github-oidc-test\n\
             signer_identity: {signer}\n\
             signed_payload: m02-memo.md:sha256\n\
             memo_sha256: {memo_sha}\n\
             signature: {signature}\n",
        );

        let memo_path = write_temp("legacy-memo.md", memo)?;
        let sig_path = write_temp("legacy-memo.sig", sig_body.as_bytes())?;

        let result = verify_memo_path(path_str(&memo_path)?, path_str(&sig_path)?);
        let _ = fs::remove_file(&memo_path);
        let _ = fs::remove_file(&sig_path);

        let err = result.err().ok_or_else(|| {
            "legacy cosign-github-oidc-test literal must be rejected by the verifier".to_owned()
        })?;
        assert!(
            err.contains("scheme mismatch"),
            "expected scheme mismatch error, got: {err}"
        );
        Ok(())
    }
}
