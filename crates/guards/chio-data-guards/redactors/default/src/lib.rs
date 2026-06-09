//! Default redactor for `chio:guards/redact@0.1.0`.
//!
//! The WIT shape lives in `wit/chio-guards-redact/world.wit`. This
//! crate ships the default regex-driven implementation Chio's tee uses
//! before any frame is buffered; tenants may swap in a signed override
//! module under `[tee.redactors]`.
//!
//! Coverage:
//!
//! - secrets: AWS access keys, JWTs, Stripe live/test keys, OpenAI-style
//!   `sk-...` keys, generic high-entropy `[A-Za-z0-9_]{32,}` runs.
//! - basic PII: email, US E.164 phone, US SSN, credit-card (Luhn-checked).
//! - bearer tokens: `Authorization: Bearer <...>` strips the token body.
//!
//! Failure mode: an `Err` returned from [`redact_payload`] MUST cause
//! the tee to refuse persistence and emit `tee.redact_failed`.

use std::sync::LazyLock;
use std::time::Instant;

use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

/// Pass identity stamped onto every [`RedactionManifest`].
///
/// Tenants reading the manifest can pin redactor behaviour by exact
/// `pass_id`. Bumped when default coverage changes.
pub const PASS_ID: &str = "redactors@1.5.0+default";

/// Mirror of the WIT `redact-class` flags.
///
/// Multiple classes compose; the guest applies all selected redactors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RedactClass {
    /// API keys, tokens, high-entropy strings.
    pub secrets: bool,
    /// email, phone, SSN, credit-card.
    pub pii_basic: bool,
    /// addresses, names, DOB.
    pub pii_extended: bool,
    /// `Authorization: Bearer <...>`.
    pub bearer_tokens: bool,
    /// tenant-supplied module.
    pub custom: bool,
}

impl RedactClass {
    /// All classes the default redactor implements.
    ///
    /// `pii_extended` and `custom` are accepted but currently no-ops
    /// in the default implementation; the WIT contract requires the
    /// guest accept the flag combination without erroring.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            secrets: true,
            pii_basic: true,
            pii_extended: true,
            bearer_tokens: true,
            custom: false,
        }
    }

    /// Convenience: every default-supported class enabled.
    #[must_use]
    pub const fn default_full() -> Self {
        Self {
            secrets: true,
            pii_basic: true,
            pii_extended: false,
            bearer_tokens: true,
            custom: false,
        }
    }
}

/// One match the redactor produced. Mirrors WIT `redaction-match`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionMatch {
    /// e.g. `"secrets.aws-key"`, `"pii.email"`.
    pub class: String,
    /// Byte offset in the *original* payload.
    pub offset: u32,
    /// Byte length of the match in the original payload.
    pub length: u32,
    /// Canonical replacement string written into the redacted output.
    pub replacement: String,
}

/// Manifest summarizing a redaction pass; signed into the frame.
/// Mirrors WIT `redaction-manifest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionManifest {
    /// e.g. `"redactors@1.5.0+default"`.
    pub pass_id: String,
    pub matches: Vec<RedactionMatch>,
    pub elapsed_micros: u64,
}

/// Output of the host call. Mirrors WIT `redacted-payload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedPayload {
    /// Post-redaction bytes (UTF-8 if input was UTF-8).
    pub bytes: Vec<u8>,
    pub manifest: RedactionManifest,
}

/// Failure modes for the default redactor.
///
/// Every variant fails the redactor closed: the tee must refuse
/// persistence on `Err(_)`.
#[derive(Debug, thiserror::Error)]
pub enum RedactError {
    /// A match offset or length exceeded what the WIT `u32` can carry.
    /// Indicates a payload >= 4 GiB; the tee should refuse.
    #[error("match offset/length overflows u32: {0}")]
    Overflow(String),
    /// Convenience surface for callers that want to assert UTF-8 input.
    /// The default redactor itself is bytewise and does not require it.
    #[error("invalid utf-8: {0}")]
    InvalidUtf8(String),
}

// -------------------------------------------------------------------------
// Compiled regexes. Static `LazyLock` initialisation guarantees the
// regex compiles once per process; we hold `Option<Regex>` so a
// vetted-constant compile failure is silently skipped instead of
// panicking on the tee's hot path. The clippy gate
// (`unwrap_used = "deny"`, `expect_used = "deny"`) is enforced
// workspace-wide and so neither appears here.
// -------------------------------------------------------------------------

/// Build a [`Regex`] or yield `None`. A `None` here means the redactor
/// silently skips the corresponding class for this process; the tee's
/// `--paranoid` heuristic (zero-match-on-large-payload quarantine)
/// catches the misconfiguration downstream.
///
/// To surface the failure earlier, [`validate_default_redactor_compiles`]
/// re-attempts every default pattern at startup and returns the list of
/// failures so callers can refuse to serve traffic when a vetted
/// constant fails to compile (the fail-closed contract spelled out in
/// the module docs).
fn try_compile(pattern: &str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(re) => Some(re),
        Err(error) => {
            // We deliberately avoid `tracing` here so the redactor stays
            // dependency-light for the wasm32-wasip2 guest export. The
            // `validate_default_redactor_compiles` startup hook below is
            // the load-bearing surface for fail-closed callers.
            eprintln!(
                "chio-data-guards-redactors-default: regex compile failed for pattern `{pattern}`: {error}"
            );
            None
        }
    }
}

// -------------------------------------------------------------------------
// Single source of truth for every default-pattern source string.
//
// The `LazyLock`-pinned `Regex` instances on the redactor hot path and
// the `validate_default_redactor_compiles` startup hook both compile
// from these same `&'static str` constants, so a future divergence is
// impossible by construction: there is only one string per label, and
// editing it changes both the runtime regex and the validator.
// -------------------------------------------------------------------------

const PATTERN_AWS_KEY: &str = r"(?-u)\bAKIA[0-9A-Z]{16}\b";
const PATTERN_JWT: &str = r"(?-u)\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b";
const PATTERN_STRIPE: &str = r"(?-u)\bsk_(?:live|test)_[0-9A-Za-z]{24,}\b";
const PATTERN_STRIPE_PUB: &str = r"(?-u)\bpk_(?:live|test)_[0-9A-Za-z]{24,}\b";
const PATTERN_OPENAI_KEY: &str = r"(?-u)\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b";
const PATTERN_HIGH_ENTROPY: &str = r"(?-u)\b[A-Za-z0-9_]{32,}\b";
const PATTERN_EMAIL: &str = r"(?-u)\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b";
// US phone: optional +1, then (xxx) xxx-xxxx OR xxx-xxx-xxxx OR xxx.xxx.xxxx OR xxx xxx xxxx.
const PATTERN_PHONE_US: &str =
    r"(?-u)(?:\+?1[\s\-.])?(?:\(\d{3}\)|\d{3})[\s\-.]\d{3}[\s\-.]\d{4}\b";
const PATTERN_SSN_US: &str = r"(?-u)\b\d{3}-\d{2}-\d{4}\b";
// Credit-card candidate: 13-19 digits possibly broken by spaces/hyphens.
// Final accept gated by Luhn check below.
const PATTERN_CARD: &str = r"(?-u)\b(?:\d[ -]?){12,18}\d\b";
const PATTERN_BEARER: &str = r"(?i-u)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}";

/// Default redactor patterns the [`validate_default_redactor_compiles`]
/// startup hook re-checks. The `&str` entries point at the same
/// `PATTERN_*` constants the runtime `LazyLock` instances below compile
/// from, so the validator and the redactor hot path are guaranteed to
/// stay in lockstep. Adding a new class without updating this list is
/// caught by the `default_pattern_inventory_matches_lazylocks` test.
const DEFAULT_PATTERNS: &[(&str, &str)] = &[
    ("secrets.aws-key", PATTERN_AWS_KEY),
    ("secrets.jwt", PATTERN_JWT),
    ("secrets.stripe", PATTERN_STRIPE),
    ("secrets.stripe-pub", PATTERN_STRIPE_PUB),
    ("secrets.openai-key", PATTERN_OPENAI_KEY),
    ("secrets.high-entropy", PATTERN_HIGH_ENTROPY),
    ("pii.email", PATTERN_EMAIL),
    ("pii.phone-us", PATTERN_PHONE_US),
    ("pii.ssn-us", PATTERN_SSN_US),
    ("pii.credit-card", PATTERN_CARD),
    ("bearer.authorization", PATTERN_BEARER),
];

/// Re-check every default redactor pattern at startup so deployments
/// that prefer a hard fail-closed contract over the `--paranoid`
/// downstream heuristic can refuse to serve traffic when a vetted
/// constant unexpectedly fails to compile. Returns an error describing
/// every (label, pattern) pair that failed.
///
/// This complements the soft fallback in [`try_compile`]: callers that
/// want the original silent-skip behaviour simply skip this hook,
/// callers that want the strict load-time guarantee call it during
/// service bootstrap. Because the validator and the runtime
/// `LazyLock` instances share the same `PATTERN_*` source strings,
/// validating these patterns is equivalent to validating the runtime
/// regexes themselves.
pub fn validate_default_redactor_compiles() -> Result<(), Vec<String>> {
    let mut failures = Vec::new();
    for (label, pattern) in DEFAULT_PATTERNS {
        if Regex::new(pattern).is_err() {
            failures.push(format!("{label} (`{pattern}`)"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

static AWS_KEY: LazyLock<Option<Regex>> = LazyLock::new(|| try_compile(PATTERN_AWS_KEY));
static JWT: LazyLock<Option<Regex>> = LazyLock::new(|| try_compile(PATTERN_JWT));
static STRIPE: LazyLock<Option<Regex>> = LazyLock::new(|| try_compile(PATTERN_STRIPE));
static STRIPE_PUB: LazyLock<Option<Regex>> = LazyLock::new(|| try_compile(PATTERN_STRIPE_PUB));
static OPENAI_KEY: LazyLock<Option<Regex>> = LazyLock::new(|| try_compile(PATTERN_OPENAI_KEY));
static HIGH_ENTROPY: LazyLock<Option<Regex>> = LazyLock::new(|| try_compile(PATTERN_HIGH_ENTROPY));

static EMAIL: LazyLock<Option<Regex>> = LazyLock::new(|| try_compile(PATTERN_EMAIL));
static PHONE_US: LazyLock<Option<Regex>> = LazyLock::new(|| try_compile(PATTERN_PHONE_US));
static SSN_US: LazyLock<Option<Regex>> = LazyLock::new(|| try_compile(PATTERN_SSN_US));
static CARD: LazyLock<Option<Regex>> = LazyLock::new(|| try_compile(PATTERN_CARD));

static BEARER: LazyLock<Option<Regex>> = LazyLock::new(|| try_compile(PATTERN_BEARER));

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------

/// Mirror of the WIT `redact-payload` host call.
///
/// Returns the full [`RedactedPayload`] (post-redaction bytes plus a
/// manifest summarizing every match). On error the caller MUST treat
/// the pass as failed and refuse persistence.
pub fn redact_payload(
    payload: &[u8],
    classes: RedactClass,
) -> Result<RedactedPayload, RedactError> {
    let started = Instant::now();
    let mut matches: Vec<RedactionMatch> = Vec::new();
    let mut spans: Vec<(usize, usize, Vec<u8>)> = Vec::new();

    if classes.secrets {
        for (label, re) in [
            ("secrets.aws-key", AWS_KEY.as_ref()),
            ("secrets.jwt", JWT.as_ref()),
            ("secrets.stripe", STRIPE.as_ref()),
            ("secrets.stripe-pub", STRIPE_PUB.as_ref()),
            ("secrets.openai-key", OPENAI_KEY.as_ref()),
            ("secrets.high-entropy", HIGH_ENTROPY.as_ref()),
        ] {
            if let Some(re) = re {
                collect(payload, re, label, &mut matches, &mut spans, |label| {
                    if label == "secrets.high-entropy" {
                        "[REDACTED-BEARER]".to_string()
                    } else if label == "secrets.stripe"
                        || label == "secrets.stripe-pub"
                        || label == "secrets.openai-key"
                    {
                        "[REDACTED-API-KEY]".to_string()
                    } else {
                        format!("<redacted:{label}>")
                    }
                })?;
            }
        }
    }

    if classes.bearer_tokens {
        if let Some(re) = BEARER.as_ref() {
            collect(
                payload,
                re,
                "bearer.authorization",
                &mut matches,
                &mut spans,
                |_| "Bearer [REDACTED-BEARER]".to_string(),
            )?;
        }
    }

    if classes.pii_basic {
        if let Some(re) = EMAIL.as_ref() {
            collect(payload, re, "pii.email", &mut matches, &mut spans, |_| {
                "[REDACTED-EMAIL]".to_string()
            })?;
        }
        if let Some(re) = PHONE_US.as_ref() {
            collect(
                payload,
                re,
                "pii.phone-us",
                &mut matches,
                &mut spans,
                |_| "[REDACTED-PHONE]".to_string(),
            )?;
        }
        if let Some(re) = SSN_US.as_ref() {
            collect(payload, re, "pii.ssn-us", &mut matches, &mut spans, |_| {
                "[REDACTED-SSN]".to_string()
            })?;
        }
        if let Some(re) = CARD.as_ref() {
            collect_with_filter(
                payload,
                re,
                "pii.credit-card",
                &mut matches,
                &mut spans,
                luhn_ok,
                |_| "[REDACTED-CC]".to_string(),
            )?;
        }
    }

    // pii_extended and custom are intentional no-ops in the default
    // redactor; tenants needing those classes ship a custom module.

    let bytes = apply_spans(payload, spans);
    let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);

    // Sort by original-offset for stable manifest emission.
    matches.sort_by_key(|m| (m.offset, m.length));

    Ok(RedactedPayload {
        bytes,
        manifest: RedactionManifest {
            pass_id: PASS_ID.to_string(),
            matches,
            elapsed_micros,
        },
    })
}

/// Convenience wrapper that runs the default-full class set and
/// returns just the redacted bytes. Used by simple call sites that
/// don't need the manifest.
pub fn redact(payload: &[u8]) -> Result<Vec<u8>, RedactError> {
    Ok(redact_payload(payload, RedactClass::default_full())?.bytes)
}

// -------------------------------------------------------------------------
// internals
// -------------------------------------------------------------------------

fn collect(
    payload: &[u8],
    re: &Regex,
    label: &str,
    matches: &mut Vec<RedactionMatch>,
    spans: &mut Vec<(usize, usize, Vec<u8>)>,
    replacement_for: impl Fn(&str) -> String,
) -> Result<(), RedactError> {
    collect_with_filter(
        payload,
        re,
        label,
        matches,
        spans,
        |_| true,
        replacement_for,
    )
}

#[allow(clippy::too_many_arguments)]
fn collect_with_filter(
    payload: &[u8],
    re: &Regex,
    label: &str,
    matches: &mut Vec<RedactionMatch>,
    spans: &mut Vec<(usize, usize, Vec<u8>)>,
    accept: impl Fn(&[u8]) -> bool,
    replacement_for: impl Fn(&str) -> String,
) -> Result<(), RedactError> {
    for m in re.find_iter(payload) {
        let start = m.start();
        let end = m.end();
        let slice = &payload[start..end];
        if !accept(slice) {
            continue;
        }
        if overlaps(spans, start, end) {
            continue;
        }
        let replacement = replacement_for(label);
        let offset =
            u32::try_from(start).map_err(|_| RedactError::Overflow(format!("offset {start}")))?;
        let length = u32::try_from(end - start)
            .map_err(|_| RedactError::Overflow(format!("length {}", end - start)))?;
        matches.push(RedactionMatch {
            class: label.to_string(),
            offset,
            length,
            replacement: replacement.clone(),
        });
        spans.push((start, end, replacement.into_bytes()));
    }
    Ok(())
}

fn overlaps(spans: &[(usize, usize, Vec<u8>)], start: usize, end: usize) -> bool {
    spans.iter().any(|(s, e, _)| !(end <= *s || start >= *e))
}

fn apply_spans(payload: &[u8], mut spans: Vec<(usize, usize, Vec<u8>)>) -> Vec<u8> {
    if spans.is_empty() {
        return payload.to_vec();
    }
    spans.sort_by_key(|(s, _, _)| *s);
    let mut out = Vec::with_capacity(payload.len());
    let mut cursor = 0usize;
    for (start, end, replacement) in spans {
        if start < cursor {
            // Already covered by a prior overlapping replacement; skip.
            continue;
        }
        out.extend_from_slice(&payload[cursor..start]);
        out.extend_from_slice(&replacement);
        cursor = end;
    }
    if cursor < payload.len() {
        out.extend_from_slice(&payload[cursor..]);
    }
    out
}

fn luhn_ok(bytes: &[u8]) -> bool {
    // Strip spaces/hyphens, then run Luhn.
    let digits: Vec<u8> = bytes
        .iter()
        .filter(|b| (**b as char).is_ascii_digit())
        .map(|b| b - b'0')
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum: u32 = 0;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = u32::from(*d);
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn full() -> RedactClass {
        RedactClass::default_full()
    }

    #[test]
    fn empty_payload_yields_empty_manifest() {
        let out = redact_payload(b"", full()).unwrap();
        assert_eq!(out.bytes, b"");
        assert!(out.manifest.matches.is_empty());
        assert_eq!(out.manifest.pass_id, PASS_ID);
    }

    #[test]
    fn aws_key_is_redacted() {
        let payload = b"key=AKIAIOSFODNN7EXAMPLE end";
        let out = redact_payload(payload, full()).unwrap();
        assert!(!out.bytes.windows(20).any(|w| w == b"AKIAIOSFODNN7EXAMPLE"));
        assert!(
            out.manifest
                .matches
                .iter()
                .any(|m| m.class == "secrets.aws-key"),
            "matches: {:?}",
            out.manifest.matches
        );
    }

    #[test]
    fn email_is_redacted_with_canonical_marker() {
        let payload = b"contact: alice@example.com please";
        let out = redact_payload(payload, full()).unwrap();
        let body = String::from_utf8(out.bytes).unwrap();
        assert!(body.contains("[REDACTED-EMAIL]"));
        assert!(!body.contains("alice@example.com"));
    }

    #[test]
    fn us_phone_is_redacted() {
        let payload = b"call (415) 555-2671 today";
        let out = redact_payload(payload, full()).unwrap();
        let body = String::from_utf8(out.bytes).unwrap();
        assert!(body.contains("[REDACTED-PHONE]"));
        assert!(!body.contains("555-2671"));
    }

    #[test]
    fn bearer_token_is_redacted() {
        let payload = b"Authorization: Bearer abcdef0123456789abcdef0123456789abcdef\r\n";
        let out = redact_payload(payload, full()).unwrap();
        let body = String::from_utf8(out.bytes).unwrap();
        assert!(body.contains("[REDACTED-BEARER]"));
        assert!(!body.contains("abcdef0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn stripe_key_is_redacted() {
        let payload = b"key sk_live_abcdefghijklmnopqrstuvwx more";
        let out = redact_payload(payload, full()).unwrap();
        let body = String::from_utf8(out.bytes).unwrap();
        assert!(body.contains("[REDACTED-API-KEY]"));
        assert!(!body.contains("sk_live_abcdefghijklmnopqrstuvwx"));
    }

    #[test]
    fn openai_project_key_is_redacted_as_whole_secret() {
        let payload = b"OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDE_1234567890 end";
        let out = redact_payload(payload, full()).unwrap();
        let body = String::from_utf8(out.bytes).unwrap();
        assert!(body.contains("[REDACTED-API-KEY]"));
        assert!(!body.contains("sk-proj-"));
        assert!(out
            .manifest
            .matches
            .iter()
            .any(|m| m.class == "secrets.openai-key"));
    }

    #[test]
    fn pk_live_stripe_key_is_redacted() {
        let payload = b"pk_live_abcdefghijklmnopqrstuvwx";
        let out = redact_payload(payload, full()).unwrap();
        let body = String::from_utf8(out.bytes).unwrap();
        assert!(body.contains("[REDACTED-API-KEY]"));
    }

    #[test]
    fn jwt_is_redacted() {
        let payload =
            b"token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf";
        let out = redact_payload(payload, full()).unwrap();
        assert!(out
            .manifest
            .matches
            .iter()
            .any(|m| m.class == "secrets.jwt" || m.class == "secrets.high-entropy"));
    }

    #[test]
    fn ssn_is_redacted_when_pii_basic_set() {
        let payload = b"ssn: 123-45-6789 end";
        let out = redact_payload(payload, full()).unwrap();
        let body = String::from_utf8(out.bytes).unwrap();
        assert!(body.contains("[REDACTED-SSN]"));
    }

    #[test]
    fn credit_card_luhn_pass_is_redacted() {
        // 4111 1111 1111 1111 is a Visa Luhn-valid test number.
        let payload = b"card 4111 1111 1111 1111 ok";
        let out = redact_payload(payload, full()).unwrap();
        let body = String::from_utf8(out.bytes).unwrap();
        assert!(body.contains("[REDACTED-CC]"), "body: {body}");
    }

    #[test]
    fn credit_card_luhn_fail_is_kept() {
        // 1234 5678 9012 3456 is not Luhn-valid.
        let payload = b"random 1234 5678 9012 3456 stays";
        let out = redact_payload(payload, full()).unwrap();
        let body = String::from_utf8(out.bytes).unwrap();
        assert!(body.contains("1234 5678 9012 3456"));
    }

    #[test]
    fn no_class_means_no_changes() {
        let payload = b"alice@example.com sk_live_abcdefghijklmnopqrstuvwx";
        let out = redact_payload(payload, RedactClass::default()).unwrap();
        assert_eq!(out.bytes, payload);
        assert!(out.manifest.matches.is_empty());
    }

    #[test]
    fn manifest_offsets_are_in_original_payload_space() {
        let payload = b"-----alice@example.com-----";
        let out = redact_payload(payload, full()).unwrap();
        let m = out
            .manifest
            .matches
            .iter()
            .find(|m| m.class == "pii.email")
            .unwrap();
        assert_eq!(m.offset, 5);
        assert_eq!(m.length, 17);
    }

    #[test]
    fn convenience_redact_returns_just_bytes() {
        let bytes = redact(b"alice@example.com").unwrap();
        let body = String::from_utf8(bytes).unwrap();
        assert!(body.contains("[REDACTED-EMAIL]"));
    }

    #[test]
    fn redact_class_all_includes_extended() {
        let all = RedactClass::all();
        assert!(all.pii_extended);
        assert!(all.secrets);
        assert!(all.pii_basic);
        assert!(all.bearer_tokens);
    }

    #[test]
    fn luhn_helper_validates_known_numbers() {
        assert!(luhn_ok(b"4111111111111111"));
        assert!(!luhn_ok(b"1234567890123456"));
    }

    #[test]
    fn validate_default_redactor_compiles_succeeds_on_known_patterns() {
        // Every vetted-constant pattern must compile cleanly; a failure
        // here means a maintainer broke a default pattern and the
        // soft-fallback `try_compile` would have masked it. The startup
        // validator surfaces such regressions for callers that prefer a
        // hard fail-closed contract.
        validate_default_redactor_compiles().expect("default patterns must compile");
    }

    #[test]
    fn default_pattern_inventory_matches_lazylocks() {
        // Trip-wire: if a maintainer adds a new pattern to the redactor
        // hot path without updating DEFAULT_PATTERNS, the startup
        // validator silently stops covering it. Counting the inventory
        // against the live `LazyLock` siblings keeps them in lockstep.
        let live: &[&LazyLock<Option<Regex>>] = &[
            &AWS_KEY,
            &JWT,
            &STRIPE,
            &STRIPE_PUB,
            &OPENAI_KEY,
            &HIGH_ENTROPY,
            &EMAIL,
            &PHONE_US,
            &SSN_US,
            &CARD,
            &BEARER,
        ];
        assert_eq!(DEFAULT_PATTERNS.len(), live.len());
        for entry in live {
            assert!(
                entry.is_some(),
                "live LazyLock pattern unexpectedly None; check `try_compile` warning on stderr"
            );
        }
    }

    #[test]
    fn default_patterns_match_runtime_lazylock_sources() {
        // Regression for the validator/runtime divergence concern: the
        // startup validator must check the same patterns the runtime
        // LazyLocks compile from. Asserting `DEFAULT_PATTERNS[i].1 ==
        // <RUNTIME_REGEX>.as_str()` proves the validator and the
        // hot-path regex compiled the same source string, even if a
        // future edit nudges one constant and forgets the other.
        let live: &[(&str, &LazyLock<Option<Regex>>)] = &[
            ("secrets.aws-key", &AWS_KEY),
            ("secrets.jwt", &JWT),
            ("secrets.stripe", &STRIPE),
            ("secrets.stripe-pub", &STRIPE_PUB),
            ("secrets.openai-key", &OPENAI_KEY),
            ("secrets.high-entropy", &HIGH_ENTROPY),
            ("pii.email", &EMAIL),
            ("pii.phone-us", &PHONE_US),
            ("pii.ssn-us", &SSN_US),
            ("pii.credit-card", &CARD),
            ("bearer.authorization", &BEARER),
        ];
        assert_eq!(DEFAULT_PATTERNS.len(), live.len());
        for ((default_label, default_pattern), (live_label, lazy)) in
            DEFAULT_PATTERNS.iter().zip(live.iter())
        {
            assert_eq!(default_label, live_label, "label order drift");
            let runtime = lazy
                .as_ref()
                .expect("runtime LazyLock pattern unexpectedly None");
            assert_eq!(
                *default_pattern,
                runtime.as_str(),
                "DEFAULT_PATTERNS[{default_label}] diverged from the runtime LazyLock source"
            );
        }
    }

    #[test]
    fn multibyte_utf8_around_match_is_preserved() {
        // Email regex anchors with `\b`. Multibyte characters around the
        // match must not split codepoints in the output and the matched
        // span must still resolve to the email bytes only.
        let payload = "café alice@example.com 携帯".as_bytes();
        let out = redact_payload(payload, full()).unwrap();
        let body = String::from_utf8(out.bytes).expect("output must remain valid utf-8");
        assert!(body.contains("café"));
        assert!(body.contains("携帯"));
        assert!(body.contains("[REDACTED-EMAIL]"));
        assert!(!body.contains("alice@example.com"));
    }

    #[test]
    fn ssn_adjacent_to_emoji_is_redacted_without_corruption() {
        // Sanity check that a `\b`-anchored regex match on bytes inside a
        // utf-8 stream with adjacent multi-byte characters still slices on
        // codepoint boundaries (regex::bytes word boundary fires only at
        // ASCII word edges, which are valid utf-8 boundaries).
        let payload = "🚨 ssn 123-45-6789 🚨".as_bytes();
        let out = redact_payload(payload, full()).unwrap();
        let body = String::from_utf8(out.bytes).expect("output must remain valid utf-8");
        assert!(body.contains("[REDACTED-SSN]"));
        assert!(body.contains("🚨"));
        assert!(!body.contains("123-45-6789"));
    }
}
