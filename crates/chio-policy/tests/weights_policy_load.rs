//! Integration coverage for `policy.weights_card_required`.
//!
//! Locks the fail-closed load contract:
//!
//! - Default is `disabled`; provider bind is unaffected.
//! - `required` parses cleanly with no issuer regex.
//! - `required_with_pin` without an `issuer_san_regex` rejects at load.
//! - `required_with_pin` with a non-parsing regex rejects at load.
//! - `required_with_pin` with a valid regex parses cleanly.
//! - YAML round-trip preserves both the variant and the regex.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_policy::{WeightsCardConfig, WeightsCardLoadError, WeightsCardRequired};

#[test]
fn parse_disabled_yaml_block() {
    let yaml = r#"
mode: disabled
"#;
    let cfg: WeightsCardConfig = serde_yml::from_str(yaml).unwrap();
    assert_eq!(cfg.mode, WeightsCardRequired::Disabled);
    assert!(cfg.validate().is_ok());
    assert!(!cfg.enforces_card_binding());
}

#[test]
fn parse_required_yaml_block_no_pin() {
    let yaml = r#"
mode: required
"#;
    let cfg: WeightsCardConfig = serde_yml::from_str(yaml).unwrap();
    assert_eq!(cfg.mode, WeightsCardRequired::Required);
    assert!(cfg.validate().is_ok());
    assert!(cfg.enforces_card_binding());
}

#[test]
fn parse_required_with_pin_yaml_block() {
    let yaml = r#"
mode: required_with_pin
issuer_san_regex: 'https://example\.com/.*'
"#;
    let cfg: WeightsCardConfig = serde_yml::from_str(yaml).unwrap();
    assert_eq!(cfg.mode, WeightsCardRequired::RequiredWithPin);
    assert_eq!(
        cfg.issuer_san_regex.as_deref(),
        Some("https://example\\.com/.*")
    );
    assert!(cfg.validate().is_ok());
    assert!(cfg.enforces_card_binding());
}

#[test]
fn required_with_pin_without_regex_fails_at_load() {
    let yaml = r#"
mode: required_with_pin
"#;
    let cfg: WeightsCardConfig = serde_yml::from_str(yaml).unwrap();
    assert_eq!(
        cfg.validate(),
        Err(WeightsCardLoadError::PinModeWithoutRegex)
    );
}

#[test]
fn required_with_pin_with_empty_regex_fails_at_load() {
    let yaml = r#"
mode: required_with_pin
issuer_san_regex: ''
"#;
    let cfg: WeightsCardConfig = serde_yml::from_str(yaml).unwrap();
    assert_eq!(
        cfg.validate(),
        Err(WeightsCardLoadError::EmptyIssuerSanRegex)
    );
}

#[test]
fn required_with_pin_with_invalid_regex_fails_at_load() {
    let yaml = r#"
mode: required_with_pin
issuer_san_regex: '[unbalanced'
"#;
    let cfg: WeightsCardConfig = serde_yml::from_str(yaml).unwrap();
    let err = cfg.validate();
    assert!(matches!(
        err,
        Err(WeightsCardLoadError::InvalidIssuerSanRegex(_))
    ));
}

#[test]
fn yaml_round_trip_through_serialize_and_deserialize() {
    let cfg = WeightsCardConfig::required_with_pin("issuer/regex/.*");
    let s = serde_yml::to_string(&cfg).unwrap();
    let again: WeightsCardConfig = serde_yml::from_str(&s).unwrap();
    assert_eq!(cfg, again);
    assert!(again.validate().is_ok());
}

#[test]
fn invalid_variant_rejects_at_yaml_parse() {
    let yaml = r#"
mode: required_yes_please
"#;
    let res: Result<WeightsCardConfig, _> = serde_yml::from_str(yaml);
    assert!(
        res.is_err(),
        "unknown variant must reject at YAML parse, got {res:?}"
    );
}

#[test]
fn empty_yaml_block_falls_back_to_default_disabled() {
    let yaml = r#"
{}
"#;
    let cfg: WeightsCardConfig = serde_yml::from_str(yaml).unwrap();
    assert_eq!(cfg.mode, WeightsCardRequired::Disabled);
    assert!(cfg.validate().is_ok());
}
