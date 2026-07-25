use std::collections::BTreeSet;

use chio_core_types::canonical::canonical_json_bytes_from_str;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    canonical_outcome_bytes, domain_digest, envelope_digest, load_canonical_outcome_json,
    validate_current_window, validate_digest, validate_text, validate_window, OutcomeError,
    OutcomeSignerTrustV1,
};

pub const OUTCOME_PREDICATE_SCHEMA: &str = chio_core_types::CHIO_OUTCOME_PREDICATE_V1_SCHEMA;

const PREDICATE_ID_DOMAIN: &[u8] = b"chio.outcome.predicate.id.v1\0";
const PREDICATE_BODY_DIGEST_DOMAIN: &[u8] = b"chio.outcome.predicate.body.v1\0";
const MAX_ASSERTIONS: usize = 256;
const MAX_POINTER_CHARS: usize = 2_048;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutcomeComparatorV1 {
    Exists,
    Eq { value: Value },
    Ne { value: Value },
    Lt { value: Value },
    Lte { value: Value },
    Gt { value: Value },
    Gte { value: Value },
}

impl OutcomeComparatorV1 {
    fn validate(&self) -> Result<(), OutcomeError> {
        match self {
            Self::Exists | Self::Eq { .. } | Self::Ne { .. } => Ok(()),
            Self::Lt { value } | Self::Lte { value } | Self::Gt { value } | Self::Gte { value } => {
                integer(value)
                    .map(|_| ())
                    .ok_or(OutcomeError::InvalidField("ordered_comparator_value"))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeAssertionV1 {
    pub pointer: String,
    pub comparator: OutcomeComparatorV1,
}

impl OutcomeAssertionV1 {
    fn validate(&self) -> Result<(), OutcomeError> {
        validate_pointer(&self.pointer)?;
        self.comparator.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomePredicateInputV1 {
    pub assertions: Vec<OutcomeAssertionV1>,
    pub provider_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomePredicateBodyV1 {
    schema: String,
    predicate_id: String,
    assertions: Vec<OutcomeAssertionV1>,
    provider_id: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PredicateIdPreimage<'a> {
    schema: &'a str,
    assertions: &'a [OutcomeAssertionV1],
    provider_id: &'a str,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl OutcomePredicateBodyV1 {
    pub fn new(input: OutcomePredicateInputV1) -> Result<Self, OutcomeError> {
        let mut body = Self {
            schema: OUTCOME_PREDICATE_SCHEMA.to_owned(),
            predicate_id: String::new(),
            assertions: input.assertions,
            provider_id: input.provider_id,
            issued_at_unix_ms: input.issued_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
        };
        body.predicate_id = body.derived_id()?;
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), OutcomeError> {
        if self.schema != OUTCOME_PREDICATE_SCHEMA {
            return Err(OutcomeError::InvalidField("predicate_schema"));
        }
        validate_digest("predicate_id", &self.predicate_id)?;
        validate_text("provider_id", &self.provider_id)?;
        validate_window(self.issued_at_unix_ms, self.expires_at_unix_ms)?;
        if self.assertions.is_empty() || self.assertions.len() > MAX_ASSERTIONS {
            return Err(OutcomeError::InvalidField("assertions"));
        }
        let mut unique = BTreeSet::new();
        for assertion in &self.assertions {
            assertion.validate()?;
            if !unique.insert(canonical_outcome_bytes(assertion)?) {
                return Err(OutcomeError::InvalidField("duplicate_assertion"));
            }
        }
        if self.predicate_id != self.derived_id()? {
            return Err(OutcomeError::BindingMismatch);
        }
        Ok(())
    }

    fn derived_id(&self) -> Result<String, OutcomeError> {
        domain_digest(
            PREDICATE_ID_DOMAIN,
            &PredicateIdPreimage {
                schema: &self.schema,
                assertions: &self.assertions,
                provider_id: &self.provider_id,
                issued_at_unix_ms: self.issued_at_unix_ms,
                expires_at_unix_ms: self.expires_at_unix_ms,
            },
        )
    }

    #[must_use]
    pub fn predicate_id(&self) -> &str {
        &self.predicate_id
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub fn assertions(&self) -> &[OutcomeAssertionV1] {
        &self.assertions
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedOutcomePredicateV1(SignedExportEnvelope<OutcomePredicateBodyV1>);

impl SignedOutcomePredicateV1 {
    pub fn sign(body: OutcomePredicateBodyV1, signer: &Keypair) -> Result<Self, OutcomeError> {
        body.validate()?;
        SignedExportEnvelope::sign(body, signer)
            .map(Self)
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))
    }

    #[must_use]
    pub const fn body(&self) -> &OutcomePredicateBodyV1 {
        &self.0.body
    }
}

pub struct OutcomePredicateVerificationV1<'a> {
    pub provider_id: &'a str,
    pub trust: &'a OutcomeSignerTrustV1,
    pub trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone)]
pub struct VerifiedOutcomePredicateV1 {
    signed: SignedOutcomePredicateV1,
    body_digest: String,
    envelope_digest: String,
}

impl VerifiedOutcomePredicateV1 {
    #[must_use]
    pub const fn body(&self) -> &OutcomePredicateBodyV1 {
        self.signed.body()
    }

    #[must_use]
    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
}

pub fn verify_outcome_predicate(
    canonical_envelope: &[u8],
    context: &OutcomePredicateVerificationV1<'_>,
) -> Result<VerifiedOutcomePredicateV1, OutcomeError> {
    let signed: SignedOutcomePredicateV1 = load_canonical_outcome_json(canonical_envelope)?;
    signed.body().validate()?;
    if signed.body().provider_id != context.provider_id
        || signed.body().provider_id != context.trust.principal_id()
    {
        return Err(OutcomeError::BindingMismatch);
    }
    if signed.0.signer_key != *context.trust.key()
        || !signed
            .0
            .verify_signature()
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))?
    {
        return Err(OutcomeError::AuthorityVerification);
    }
    validate_current_window(
        signed.body().issued_at_unix_ms,
        signed.body().expires_at_unix_ms,
        context.trust.max_lifetime_ms(),
        context.trusted_now_unix_ms,
    )?;
    Ok(VerifiedOutcomePredicateV1 {
        body_digest: domain_digest(PREDICATE_BODY_DIGEST_DOMAIN, signed.body())?,
        envelope_digest: envelope_digest(&signed)?,
        signed,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeEvaluationReasonV1 {
    AssertionMismatch,
    MissingTarget,
    TargetNotInteger,
    InvalidOutputJson,
    DeliveryCancelled,
    OutputBlocked,
    OutputMutationAfterEvaluation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutcomeEvaluationV1 {
    Passed,
    Failed {
        assertion_index: u32,
        reason: OutcomeEvaluationReasonV1,
    },
    Unevaluable {
        reason: OutcomeEvaluationReasonV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOutcomeEvaluationV1 {
    evaluation: OutcomeEvaluationV1,
    output_digest: String,
    predicate_id: String,
    predicate_digest: String,
}

impl VerifiedOutcomeEvaluationV1 {
    #[must_use]
    pub const fn evaluation(&self) -> &OutcomeEvaluationV1 {
        &self.evaluation
    }

    #[must_use]
    pub fn output_digest(&self) -> &str {
        &self.output_digest
    }

    #[must_use]
    pub fn predicate_id(&self) -> &str {
        &self.predicate_id
    }

    #[must_use]
    pub fn predicate_digest(&self) -> &str {
        &self.predicate_digest
    }
}

pub fn evaluate_outcome_predicate(
    predicate: &VerifiedOutcomePredicateV1,
    output: &[u8],
) -> VerifiedOutcomeEvaluationV1 {
    VerifiedOutcomeEvaluationV1 {
        evaluation: evaluate(predicate, output),
        output_digest: sha256_hex(output),
        predicate_id: predicate.body().predicate_id().to_owned(),
        predicate_digest: predicate.envelope_digest().to_owned(),
    }
}

fn evaluate(predicate: &VerifiedOutcomePredicateV1, output: &[u8]) -> OutcomeEvaluationV1 {
    let Ok(output_text) = std::str::from_utf8(output) else {
        return OutcomeEvaluationV1::Unevaluable {
            reason: OutcomeEvaluationReasonV1::InvalidOutputJson,
        };
    };
    if canonical_json_bytes_from_str(output_text).is_err() {
        return OutcomeEvaluationV1::Unevaluable {
            reason: OutcomeEvaluationReasonV1::InvalidOutputJson,
        };
    }
    let document: Value = match serde_json::from_slice(output) {
        Ok(document) => document,
        Err(_) => {
            return OutcomeEvaluationV1::Unevaluable {
                reason: OutcomeEvaluationReasonV1::InvalidOutputJson,
            };
        }
    };
    for (index, assertion) in predicate.body().assertions.iter().enumerate() {
        let Some(target) = select_pointer(&document, &assertion.pointer) else {
            return OutcomeEvaluationV1::Failed {
                assertion_index: u32::try_from(index).unwrap_or(u32::MAX),
                reason: OutcomeEvaluationReasonV1::MissingTarget,
            };
        };
        let passed = match &assertion.comparator {
            OutcomeComparatorV1::Exists => true,
            OutcomeComparatorV1::Eq { value } => canonical_equal(target, value),
            OutcomeComparatorV1::Ne { value } => !canonical_equal(target, value),
            OutcomeComparatorV1::Lt { value }
            | OutcomeComparatorV1::Lte { value }
            | OutcomeComparatorV1::Gt { value }
            | OutcomeComparatorV1::Gte { value } => {
                let Some(left) = integer(target) else {
                    return OutcomeEvaluationV1::Unevaluable {
                        reason: OutcomeEvaluationReasonV1::TargetNotInteger,
                    };
                };
                let Some(right) = integer(value) else {
                    return OutcomeEvaluationV1::Unevaluable {
                        reason: OutcomeEvaluationReasonV1::TargetNotInteger,
                    };
                };
                match &assertion.comparator {
                    OutcomeComparatorV1::Lt { .. } => left < right,
                    OutcomeComparatorV1::Lte { .. } => left <= right,
                    OutcomeComparatorV1::Gt { .. } => left > right,
                    OutcomeComparatorV1::Gte { .. } => left >= right,
                    _ => false,
                }
            }
        };
        if !passed {
            return OutcomeEvaluationV1::Failed {
                assertion_index: u32::try_from(index).unwrap_or(u32::MAX),
                reason: OutcomeEvaluationReasonV1::AssertionMismatch,
            };
        }
    }
    OutcomeEvaluationV1::Passed
}

fn validate_pointer(pointer: &str) -> Result<(), OutcomeError> {
    if pointer.is_empty() {
        return Ok(());
    }
    if pointer.chars().count() > MAX_POINTER_CHARS
        || !pointer.starts_with('/')
        || pointer.chars().any(char::is_control)
    {
        return Err(OutcomeError::InvalidField("pointer"));
    }
    let bytes = pointer.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            if index + 1 >= bytes.len() || !matches!(bytes[index + 1], b'0' | b'1') {
                return Err(OutcomeError::InvalidField("pointer_escape"));
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn select_pointer<'a>(document: &'a Value, pointer: &str) -> Option<&'a Value> {
    if pointer.is_empty() {
        return Some(document);
    }
    let mut current = document;
    for token in pointer.split('/').skip(1) {
        let token = token.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Object(object) => object.get(&token)?,
            Value::Array(array) => {
                let bytes = token.as_bytes();
                let valid_index = token == "0"
                    || bytes.first().is_some_and(|first| {
                        first.is_ascii_digit()
                            && *first != b'0'
                            && bytes[1..].iter().all(u8::is_ascii_digit)
                    });
                if !valid_index {
                    return None;
                }
                array.get(token.parse::<usize>().ok()?)?
            }
            _ => return None,
        };
    }
    Some(current)
}

fn integer(value: &Value) -> Option<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
}

fn canonical_equal(left: &Value, right: &Value) -> bool {
    match (
        canonical_outcome_bytes(left),
        canonical_outcome_bytes(right),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}
