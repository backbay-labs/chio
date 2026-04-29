//! Trust-boundary fuzz target for `chio_attest_verify::SigstoreVerifier::verify_bundle`.

#![no_main]

use std::sync::OnceLock;

use chio_attest_verify::{AttestVerifier, ExpectedIdentity, SigstoreVerifier};
use libfuzzer_sys::fuzz_target;

// The embedded TUF trust root is validated at compile time by `build.rs`;
// if construction fails at runtime we have no fuzz signal and return early.
static VERIFIER: OnceLock<Option<SigstoreVerifier>> = OnceLock::new();

fn verifier() -> Option<&'static SigstoreVerifier> {
    VERIFIER
        .get_or_init(|| SigstoreVerifier::with_embedded_root().ok())
        .as_ref()
}

// Constant identity keeps corpus inputs stable; varying it would mask
// parse-path failures behind issuer-mismatch errors before the bundle is read.
fn expected_identity() -> ExpectedIdentity {
    ExpectedIdentity {
        certificate_identity_regexp:
            r"https://github\.com/backbay/chio/\.github/workflows/release-binaries\.yml@refs/tags/v.*"
                .to_owned(),
        certificate_oidc_issuer: "https://token.actions.githubusercontent.com".to_owned(),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(verifier) = verifier() else {
        return;
    };

    let split = data.len() / 2;
    let (artifact, bundle_json) = data.split_at(split);
    let expected = expected_identity();

    // The trust-boundary contract guarantees this is fail-closed; the only
    // outcomes we care about are `Err(_)` (good) or a panic/abort (which
    // libFuzzer reports as a crash). We deliberately ignore the `Ok(_)`
    // branch because no arbitrary input can satisfy the keyless flow.
    let _ = verifier.verify_bundle(artifact, bundle_json, &expected);
});
