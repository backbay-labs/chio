use chio_core::canonical::canonical_json_bytes;
use chio_tee::redact::{DefaultRedactor, RedactClass, RedactedPayload, Redactor};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence, TestCaseError};
use serde::Serialize;

const MAX_PAYLOAD_BYTES: usize = 16 * 1024;

#[derive(Debug, Serialize)]
struct StableManifestView<'a> {
    pass_id: &'a str,
    matches: &'a [chio_tee::RedactionMatch],
}

fn proptest_config() -> Config {
    Config {
        cases: 64,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "crates/chio-tee/proptest-regressions/redact_determinism.txt",
        ))),
        timeout: 30_000,
        max_shrink_time: 5_000,
        max_shrink_iters: 512,
        ..Config::default()
    }
}

fn redact_classes() -> impl Strategy<Value = RedactClass> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(secrets, pii_basic, pii_extended, bearer_tokens, custom)| RedactClass {
                secrets,
                pii_basic,
                pii_extended,
                bearer_tokens,
                custom,
            },
        )
}

fn redact_once(
    redactor: &DefaultRedactor,
    payload: &[u8],
    classes: RedactClass,
) -> Result<RedactedPayload, TestCaseError> {
    redactor
        .redact_payload(payload, classes)
        .map_err(|error| TestCaseError::fail(format!("redactor failed closed: {error}")))
}

fn stable_manifest_bytes(output: &RedactedPayload) -> Result<Vec<u8>, TestCaseError> {
    let view = StableManifestView {
        pass_id: &output.manifest.pass_id,
        matches: &output.manifest.matches,
    };
    canonical_json_bytes(&view)
        .map_err(|error| TestCaseError::fail(format!("canonical JSON failed: {error}")))
}

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn redaction_is_deterministic_for_payload_and_classes(
        payload in vec(any::<u8>(), 0..=MAX_PAYLOAD_BYTES),
        classes in redact_classes(),
    ) {
        let redactor = DefaultRedactor;
        let first = redact_once(&redactor, &payload, classes)?;
        let second = redact_once(&redactor, &payload, classes)?;

        prop_assert_eq!(&first.bytes, &second.bytes);
        prop_assert_eq!(&first.manifest.pass_id, &second.manifest.pass_id);
        prop_assert_eq!(&first.manifest.matches, &second.manifest.matches);
        prop_assert_eq!(stable_manifest_bytes(&first)?, stable_manifest_bytes(&second)?);
    }
}
