//! Offline receiver verification of the three-vendor proof package.

use chio_attest_buyer_core::context::ChioVerificationContext;
use chio_attest_buyer_core::proof_package::ChioProofPackage;
use chio_attest_buyer_core::report::verify_package_report;
use chio_attest_buyer_core::trust_bundle::{
    verifier_trust_bundle_from_json, ChioVerifierTrustBundle,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn parse_fixture<T: serde::de::DeserializeOwned>(label: &str, document: &str) -> T {
    match serde_json::from_str(document) {
        Ok(value) => value,
        Err(error) => panic!("failed to parse {label} fixture: {error}"),
    }
}

pub fn bench(c: &mut Criterion) {
    let package: ChioProofPackage = parse_fixture(
        "buyer proof package",
        include_str!("../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"),
    );
    let trust_bundle: ChioVerifierTrustBundle = match verifier_trust_bundle_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/verifier-trust-bundle.json"
    )) {
        Ok(trust_bundle) => trust_bundle,
        Err(error) => panic!("failed to parse buyer trust bundle fixture: {error}"),
    };
    let context: ChioVerificationContext = parse_fixture(
        "buyer verification context",
        include_str!("../../../../examples/chio-3vendor/fixtures/verification-context.json"),
    );
    let baseline = verify_package_report(&package, &trust_bundle, &context);
    assert!(
        baseline.accepted,
        "buyer verification benchmark fixture must be accepted"
    );

    c.bench_function("buyer_proof_package_verify", |b| {
        b.iter(|| {
            let report = verify_package_report(
                black_box(&package),
                black_box(&trust_bundle),
                black_box(&context),
            );
            assert!(
                black_box(report.accepted),
                "buyer verification benchmark rejected its fixture"
            );
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
