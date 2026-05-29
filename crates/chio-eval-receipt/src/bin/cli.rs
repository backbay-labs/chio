use std::env;
use std::fs;
use std::process::ExitCode;

use chio_eval_receipt::{verify_bundle, verify_fixture_bundle, BundleError, VerifiedBundle};
use sha2::{Digest, Sha256};

/// Recognized scheme literal for the self-generated test sample memo signature.
///
/// This is intentionally NOT `sigstore-cosign` or any other real-cryptography
/// label. The memo signature in this repository is a self-generated SHA-256
/// receipt; rendering it as `sigstore-cosign` would misrepresent it as a
/// vendor-issued cosign attestation. Real partner cryptographic attestation is
/// deferred to follow-on work.
const SYNTHETIC_TEST_SAMPLE: &str = "synthetic-test-sample";

/// Closed set of fields permitted in a `chio-memo-signature.v1` sig file.
///
/// Keeping this list explicit lets the verifier reject duplicate keys and any
/// unknown extension fields. That fail-closes two parser-disagreement attacks:
/// (1) a malicious sig that lists `scheme: synthetic-test-sample` first and
/// `scheme: sigstore-cosign` second, hoping a downstream tool picks the second
/// occurrence; (2) sneaking attacker-controlled claims past the verifier in
/// fields it never reads.
const ALLOWED_SIGNATURE_FIELDS: &[&str] = &[
    "signature_format",
    "scheme",
    "signer_identity",
    "signed_payload",
    "memo_sha256",
    "signature",
];

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
        [command, bundle_path] if command == "verify-fixture" => {
            verify_fixture_bundle_path(bundle_path)
        }
        [command, memo_path, sig_path] if command == "verify-memo" => {
            verify_memo_path(memo_path, sig_path)
        }
        _ => Err(
            "usage: chio-eval-receipt verify <bundle-path> | verify-fixture <bundle-path> | verify-memo <memo-path> <sig-path>".to_owned(),
        ),
    }
}

fn verify_bundle_path(bundle_path: &str) -> Result<String, String> {
    verify_bundle_path_with(bundle_path, verify_bundle)
}

fn verify_fixture_bundle_path(bundle_path: &str) -> Result<String, String> {
    verify_bundle_path_with(bundle_path, verify_fixture_bundle)
}

fn verify_bundle_path_with(
    bundle_path: &str,
    verifier: fn(&str) -> Result<VerifiedBundle, BundleError>,
) -> Result<String, String> {
    let bundle_json = fs::read_to_string(bundle_path)
        .map_err(|err| format!("failed to read {bundle_path}: {err}"))?;
    let verified =
        verifier(&bundle_json).map_err(|err| format!("failed to verify {bundle_path}: {err}"))?;
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
    require_field(&fields, "signed_payload", "memo.md:sha256")?;

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
    let mut fields: Vec<(&str, &str)> = Vec::new();
    for line in sig.lines() {
        // Lines that are entirely whitespace are tolerated as separators, but
        // we deliberately do not skip `#`-prefixed comments: the
        // chio-memo-signature.v1 format has no comment syntax, and silently
        // dropping arbitrary attacker-controlled bytes from a signed input is
        // exactly the parser-tolerance pattern that has caused real-world
        // signature verification bypasses.
        if line.chars().all(char::is_whitespace) {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(format!("invalid signature line: {}", line.trim()));
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() {
            return Err("signature field key must not be empty".to_owned());
        }
        if !ALLOWED_SIGNATURE_FIELDS.contains(&key) {
            return Err(format!("unknown signature field: {key}"));
        }
        if fields.iter().any(|(existing, _)| *existing == key) {
            return Err(format!("duplicate signature field: {key}"));
        }
        fields.push((key, value));
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
             signed_payload: memo.md:sha256\n\
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
            "verifier must not surface the cosign-github-oidc-test scheme literal, got: {message}"
        );
        Ok(())
    }

    #[test]
    fn verifier_rejects_duplicate_scheme_field() -> Result<(), String> {
        // A sig file with two `scheme:` lines (one synthetic-test-sample, one
        // sigstore-cosign) must not slip through because the verifier happens
        // to match the first occurrence. Reject duplicates outright so any
        // downstream parser disagreement fail-closes.
        let memo = b"duplicate-scheme rejection test memo\n";
        let memo_sha = sha256_hex(memo);
        let signer = "https://example.invalid/dup-scheme-signer";
        let signature = memo_signature(&memo_sha, signer);
        let sig_body = format!(
            "signature_format: chio-memo-signature.v1\n\
             scheme: synthetic-test-sample\n\
             scheme: sigstore-cosign\n\
             signer_identity: {signer}\n\
             signed_payload: memo.md:sha256\n\
             memo_sha256: {memo_sha}\n\
             signature: {signature}\n",
        );

        let memo_path = write_temp("dup-scheme-memo.md", memo)?;
        let sig_path = write_temp("dup-scheme-memo.sig", sig_body.as_bytes())?;

        let result = verify_memo_path(path_str(&memo_path)?, path_str(&sig_path)?);
        let _ = fs::remove_file(&memo_path);
        let _ = fs::remove_file(&sig_path);

        let err = result
            .err()
            .ok_or_else(|| "duplicate scheme field must be rejected".to_owned())?;
        assert!(
            err.contains("duplicate signature field: scheme"),
            "expected duplicate-field rejection, got: {err}"
        );
        Ok(())
    }

    #[test]
    fn verifier_rejects_unknown_field() -> Result<(), String> {
        // The chio-memo-signature.v1 format is a closed set. Tolerating
        // attacker-controlled extension fields would let a malicious memo
        // smuggle claims (e.g. forged cosign certs, secret material) past the
        // verifier in fields it never reads.
        let memo = b"unknown-field rejection test memo\n";
        let memo_sha = sha256_hex(memo);
        let signer = "https://example.invalid/unknown-field-signer";
        let signature = memo_signature(&memo_sha, signer);
        let sig_body = format!(
            "signature_format: chio-memo-signature.v1\n\
             scheme: synthetic-test-sample\n\
             signer_identity: {signer}\n\
             signed_payload: memo.md:sha256\n\
             memo_sha256: {memo_sha}\n\
             signature: {signature}\n\
             attacker_claim: forged-cosign-cert\n",
        );

        let memo_path = write_temp("unknown-field-memo.md", memo)?;
        let sig_path = write_temp("unknown-field-memo.sig", sig_body.as_bytes())?;

        let result = verify_memo_path(path_str(&memo_path)?, path_str(&sig_path)?);
        let _ = fs::remove_file(&memo_path);
        let _ = fs::remove_file(&sig_path);

        let err = result
            .err()
            .ok_or_else(|| "unknown signature field must be rejected".to_owned())?;
        assert!(
            err.contains("unknown signature field: attacker_claim"),
            "expected unknown-field rejection, got: {err}"
        );
        Ok(())
    }

    #[test]
    fn verifier_rejects_comment_line() -> Result<(), String> {
        // The format has no comment syntax; silently dropping `#`-prefixed
        // lines is parser tolerance the verifier should not extend.
        let memo = b"comment rejection test memo\n";
        let memo_sha = sha256_hex(memo);
        let signer = "https://example.invalid/comment-signer";
        let signature = memo_signature(&memo_sha, signer);
        let sig_body = format!(
            "# spurious comment line\n\
             signature_format: chio-memo-signature.v1\n\
             scheme: synthetic-test-sample\n\
             signer_identity: {signer}\n\
             signed_payload: memo.md:sha256\n\
             memo_sha256: {memo_sha}\n\
             signature: {signature}\n",
        );

        let memo_path = write_temp("comment-memo.md", memo)?;
        let sig_path = write_temp("comment-memo.sig", sig_body.as_bytes())?;

        let result = verify_memo_path(path_str(&memo_path)?, path_str(&sig_path)?);
        let _ = fs::remove_file(&memo_path);
        let _ = fs::remove_file(&sig_path);

        let err = result
            .err()
            .ok_or_else(|| "comment-prefixed lines must be rejected".to_owned())?;
        assert!(
            err.contains("unknown signature field: # spurious comment line")
                || err.contains("invalid signature line"),
            "expected comment rejection, got: {err}"
        );
        Ok(())
    }

    #[test]
    fn verifier_rejects_cosign_github_oidc_test_scheme() -> Result<(), String> {
        let memo = b"scheme rejection test memo\n";
        let memo_sha = sha256_hex(memo);
        let signer = "https://example.invalid/rejected-scheme-signer";
        let signature = memo_signature(&memo_sha, signer);
        let sig_body = format!(
            "signature_format: chio-memo-signature.v1\n\
             scheme: cosign-github-oidc-test\n\
             signer_identity: {signer}\n\
             signed_payload: memo.md:sha256\n\
             memo_sha256: {memo_sha}\n\
             signature: {signature}\n",
        );

        let memo_path = write_temp("rejected-scheme-memo.md", memo)?;
        let sig_path = write_temp("rejected-scheme-memo.sig", sig_body.as_bytes())?;

        let result = verify_memo_path(path_str(&memo_path)?, path_str(&sig_path)?);
        let _ = fs::remove_file(&memo_path);
        let _ = fs::remove_file(&sig_path);

        let err = result.err().ok_or_else(|| {
            "cosign-github-oidc-test scheme must be rejected by the verifier".to_owned()
        })?;
        assert!(
            err.contains("scheme mismatch"),
            "expected scheme mismatch error, got: {err}"
        );
        Ok(())
    }
}
