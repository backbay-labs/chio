//! `policy.weights_card_required` enum for the Chio runtime.
//!
//! Declares whether the kernel enforces signed model-card binding at
//! provider bind. The enum is loaded once at kernel start and consumed by
//! the binding refusal path in `chio-kernel`.
//!
//! # Variants
//!
//! - [`WeightsCardRequired::Disabled`] -- default. No model-card check;
//!   provider bind succeeds without a signed card. Deployments that have
//!   not yet adopted model-card binding sit on this default.
//! - [`WeightsCardRequired::Required`] -- provider bind MUST present a
//!   signed model card whose `weights_hash` matches the loaded weights.
//!   Any cosign bundle the configured `chio-attest-verify` trust root
//!   accepts is sufficient.
//! - [`WeightsCardRequired::RequiredWithPin`] -- like
//!   [`WeightsCardRequired::Required`], plus the cosign bundle's Fulcio
//!   certificate identity SAN MUST match the configured `issuer_san_regex`.
//!   This is the production posture for federated deployments where one
//!   operator publishes cards consumed across many tenants.
//!
//! # Fail-closed loading
//!
//! [`WeightsCardConfig::validate`] inspects the parsed config against the
//! operator's issuer-pin provisioning and rejects invalid combinations at
//! load time. The invalid combination is
//! [`WeightsCardRequired::RequiredWithPin`] without an `issuer_san_regex`
//! configured. It is caught BEFORE any provider bind so a misconfigured
//! deployment does not brick at first bind.
//!
//! `Required` without an `issuer_san_regex` is permitted (any cosign-signed
//! card the workspace trust root accepts is sufficient). `RequiredWithPin`
//! without a regex is REJECTED.
//!
//! # Wire format
//!
//! The enum is serialized as a snake_case string in YAML / JSON for parity
//! with `policy.crypto_floor`. Stable textual form:
//!
//! - `"disabled"` -- [`WeightsCardRequired::Disabled`]
//! - `"required"` -- [`WeightsCardRequired::Required`]
//! - `"required_with_pin"` -- [`WeightsCardRequired::RequiredWithPin`]

use serde::{Deserialize, Serialize};

/// Whether the kernel enforces signed model-card binding at provider bind.
///
/// See module documentation for the full state table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WeightsCardRequired {
    /// No model-card check. Default for deployments that have not adopted
    /// model-card binding.
    Disabled,
    /// Provider bind MUST present a signed model card whose `weights_hash`
    /// matches the loaded weights. Any cosign bundle the configured
    /// `chio-attest-verify` trust root accepts is sufficient.
    Required,
    /// Like [`Self::Required`], plus the cosign bundle's Fulcio cert SAN
    /// MUST match the configured `issuer_san_regex`.
    RequiredWithPin,
}

impl Default for WeightsCardRequired {
    /// Default is [`WeightsCardRequired::Disabled`] so deployments that
    /// have not adopted model-card binding keep their existing
    /// provider-bind behaviour.
    fn default() -> Self {
        Self::Disabled
    }
}

/// Operator configuration block for `policy.weights_card_required`.
///
/// Holds the enum variant plus the optional issuer-pin regex consumed by
/// the [`WeightsCardRequired::RequiredWithPin`] variant. The regex is
/// validated at load time (fail-closed contract) and forwarded
/// verbatim to `chio_attest_verify::ExpectedIdentity::certificate_identity_regexp`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WeightsCardConfig {
    /// Enforcement variant.
    #[serde(default)]
    pub mode: WeightsCardRequired,
    /// Cosign Fulcio cert SAN regex pinned by
    /// [`WeightsCardRequired::RequiredWithPin`]. Forwarded to
    /// `chio_attest_verify::ExpectedIdentity::certificate_identity_regexp`.
    /// MUST be present when `mode == RequiredWithPin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_san_regex: Option<String>,
}

/// Errors emitted by [`WeightsCardConfig::validate`]. Each variant is a
/// fail-closed load rejection.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum WeightsCardLoadError {
    /// `RequiredWithPin` without an `issuer_san_regex` configured.
    /// Provider bind would never succeed against this combination because
    /// the cosign verifier cannot pin an empty regex; rejecting at load
    /// surfaces the misconfiguration before any bind attempts.
    #[error(
        "policy.weights_card_required = required_with_pin requires \
         policy.weights_card_required.issuer_san_regex to be configured"
    )]
    PinModeWithoutRegex,
    /// `issuer_san_regex` was configured but does not parse as a valid
    /// regular expression.
    #[error("policy.weights_card_required.issuer_san_regex does not parse as a regex: {0}")]
    InvalidIssuerSanRegex(String),
    /// Empty string regex. The cosign verifier anchors the regex on both
    /// ends; an empty regex matches only the empty SAN, which never
    /// occurs in practice. Reject at load to make the deployment intent
    /// explicit.
    #[error(
        "policy.weights_card_required.issuer_san_regex must be a non-empty regex \
         (use a permissive pattern like '.*' if no pin is desired -- but prefer mode = required)"
    )]
    EmptyIssuerSanRegex,
}

impl WeightsCardConfig {
    /// Build a [`WeightsCardConfig`] in [`WeightsCardRequired::Disabled`]
    /// mode.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            mode: WeightsCardRequired::Disabled,
            issuer_san_regex: None,
        }
    }

    /// Build a [`WeightsCardConfig`] in [`WeightsCardRequired::Required`]
    /// mode.
    #[must_use]
    pub fn required() -> Self {
        Self {
            mode: WeightsCardRequired::Required,
            issuer_san_regex: None,
        }
    }

    /// Build a [`WeightsCardConfig`] in
    /// [`WeightsCardRequired::RequiredWithPin`] mode pinning a specific
    /// issuer SAN regex.
    pub fn required_with_pin(issuer_san_regex: impl Into<String>) -> Self {
        Self {
            mode: WeightsCardRequired::RequiredWithPin,
            issuer_san_regex: Some(issuer_san_regex.into()),
        }
    }

    /// Validate the loaded config. Fail-closed:
    ///
    /// - `RequiredWithPin` without an `issuer_san_regex` is rejected.
    /// - An empty `issuer_san_regex` is rejected.
    /// - A non-parsing `issuer_san_regex` is rejected.
    pub fn validate(&self) -> Result<(), WeightsCardLoadError> {
        match self.mode {
            WeightsCardRequired::Disabled | WeightsCardRequired::Required => {
                if let Some(regex_src) = &self.issuer_san_regex {
                    // Optional regex even in non-pin modes still must parse if
                    // present, otherwise it would silently mislead operators
                    // who later flip mode to RequiredWithPin.
                    Self::compile_regex(regex_src)?;
                }
                Ok(())
            }
            WeightsCardRequired::RequiredWithPin => {
                let regex_src = self
                    .issuer_san_regex
                    .as_deref()
                    .ok_or(WeightsCardLoadError::PinModeWithoutRegex)?;
                Self::compile_regex(regex_src)?;
                Ok(())
            }
        }
    }

    fn compile_regex(src: &str) -> Result<(), WeightsCardLoadError> {
        if src.is_empty() {
            return Err(WeightsCardLoadError::EmptyIssuerSanRegex);
        }
        regex::Regex::new(src)
            .map(|_| ())
            .map_err(|err| WeightsCardLoadError::InvalidIssuerSanRegex(format!("{err}")))
    }

    /// Convenience: true when provider bind MUST verify a model card.
    #[must_use]
    pub fn enforces_card_binding(&self) -> bool {
        matches!(
            self.mode,
            WeightsCardRequired::Required | WeightsCardRequired::RequiredWithPin
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled() {
        let cfg = WeightsCardConfig::default();
        assert_eq!(cfg.mode, WeightsCardRequired::Disabled);
        assert!(cfg.issuer_san_regex.is_none());
        assert!(cfg.validate().is_ok());
        assert!(!cfg.enforces_card_binding());
    }

    #[test]
    fn required_validates_without_pin() {
        let cfg = WeightsCardConfig::required();
        assert!(cfg.validate().is_ok());
        assert!(cfg.enforces_card_binding());
    }

    #[test]
    fn required_with_pin_without_regex_is_rejected() {
        let cfg = WeightsCardConfig {
            mode: WeightsCardRequired::RequiredWithPin,
            issuer_san_regex: None,
        };
        assert_eq!(
            cfg.validate(),
            Err(WeightsCardLoadError::PinModeWithoutRegex)
        );
    }

    #[test]
    fn required_with_pin_with_empty_regex_is_rejected() {
        let cfg = WeightsCardConfig {
            mode: WeightsCardRequired::RequiredWithPin,
            issuer_san_regex: Some(String::new()),
        };
        assert_eq!(
            cfg.validate(),
            Err(WeightsCardLoadError::EmptyIssuerSanRegex)
        );
    }

    #[test]
    fn required_with_pin_with_invalid_regex_is_rejected() {
        let cfg = WeightsCardConfig {
            mode: WeightsCardRequired::RequiredWithPin,
            issuer_san_regex: Some("[unbalanced".into()),
        };
        let err = cfg.validate();
        assert!(matches!(
            err,
            Err(WeightsCardLoadError::InvalidIssuerSanRegex(_))
        ));
    }

    #[test]
    fn required_with_pin_with_valid_regex_is_accepted() {
        let cfg = WeightsCardConfig::required_with_pin("https://example\\.com/.*");
        assert!(cfg.validate().is_ok());
        assert!(cfg.enforces_card_binding());
    }

    #[test]
    fn yaml_round_trip_disabled() {
        let cfg = WeightsCardConfig::disabled();
        let s = match serde_yml::to_string(&cfg) {
            Ok(s) => s,
            Err(e) => panic!("serialize must succeed: {e}"),
        };
        let again: WeightsCardConfig = match serde_yml::from_str(&s) {
            Ok(c) => c,
            Err(e) => panic!("deserialize must succeed: {e}"),
        };
        assert_eq!(cfg, again);
    }

    #[test]
    fn yaml_round_trip_required_with_pin() {
        let cfg = WeightsCardConfig::required_with_pin("issuer/.*");
        let s = match serde_yml::to_string(&cfg) {
            Ok(s) => s,
            Err(e) => panic!("serialize must succeed: {e}"),
        };
        let again: WeightsCardConfig = match serde_yml::from_str(&s) {
            Ok(c) => c,
            Err(e) => panic!("deserialize must succeed: {e}"),
        };
        assert_eq!(cfg, again);
    }

    #[test]
    fn variant_serialization_matches_snake_case() {
        let mut cfg = WeightsCardConfig {
            mode: WeightsCardRequired::Required,
            ..WeightsCardConfig::default()
        };
        let s = match serde_yml::to_string(&cfg.mode) {
            Ok(s) => s.trim().to_string(),
            Err(e) => panic!("serialize must succeed: {e}"),
        };
        assert_eq!(s, "required");
        cfg.mode = WeightsCardRequired::RequiredWithPin;
        let s = match serde_yml::to_string(&cfg.mode) {
            Ok(s) => s.trim().to_string(),
            Err(e) => panic!("serialize must succeed: {e}"),
        };
        assert_eq!(s, "required_with_pin");
    }
}
