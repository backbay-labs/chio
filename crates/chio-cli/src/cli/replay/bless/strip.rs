// Local capability guard for `chio replay --bless`.

const REPLAY_BLESS_CAPABILITY: &str = "chio:tee/bless@1";
const REPLAY_BLESS_CAPABILITY_ENV: &str = "CHIO_TEE_BLESS_CAPABILITY";

fn require_replay_bless_capability() -> Result<(), CliError> {
    validate_replay_bless_capability(std::env::var(REPLAY_BLESS_CAPABILITY_ENV).ok())
}

fn validate_replay_bless_capability(value: Option<String>) -> Result<(), CliError> {
    match value {
        Some(value) if value == REPLAY_BLESS_CAPABILITY => Ok(()),
        Some(value) => Err(CliError::Other(format!(
            "`{REPLAY_BLESS_CAPABILITY_ENV}` must be `{REPLAY_BLESS_CAPABILITY}` for replay bless, got `{value}`"
        ))),
        None => Err(CliError::Other(format!(
            "replay bless requires `{REPLAY_BLESS_CAPABILITY_ENV}={REPLAY_BLESS_CAPABILITY}`"
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_bless_capability_tests {
    use super::*;

    #[test]
    fn bless_capability_constant_matches_milestone_gate() {
        assert_eq!(REPLAY_BLESS_CAPABILITY, "chio:tee/bless@1");
    }

    #[test]
    fn bless_capability_guard_accepts_exact_value() {
        validate_replay_bless_capability(Some("chio:tee/bless@1".to_string())).unwrap();
    }

    #[test]
    fn bless_capability_guard_rejects_missing_value() {
        let err = validate_replay_bless_capability(None).unwrap_err();
        assert!(err.to_string().contains(REPLAY_BLESS_CAPABILITY_ENV));
    }
}
