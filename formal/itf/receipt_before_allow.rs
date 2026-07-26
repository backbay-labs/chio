use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde_json::{Map, Value};

const REQUIRED_VARIABLES: [&str; 4] = ["allowed", "budget_checked", "clock", "receipt_log"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiptBeforeAllowWitness {
    pub(crate) authority: String,
    pub(crate) capability: String,
}

#[derive(Debug)]
pub(crate) struct TraceDecodeError {
    message: String,
}

impl fmt::Display for TraceDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for TraceDecodeError {}

pub(crate) fn decode_receipt_before_allow(
    variables: &[String],
    states: &[Map<String, Value>],
) -> Result<ReceiptBeforeAllowWitness, TraceDecodeError> {
    let actual_variables: BTreeSet<&str> = variables.iter().map(String::as_str).collect();
    let required_variables: BTreeSet<&str> = REQUIRED_VARIABLES.into_iter().collect();
    if variables.len() != REQUIRED_VARIABLES.len() || actual_variables != required_variables {
        return Err(invalid(
            "receipt-before-allow variables do not match the registered mapping",
        ));
    }

    let mut witness = None;
    for (index, state) in states.iter().enumerate() {
        let allowed = decode_set_map(required(state, "allowed", index)?, index, "allowed")?;
        let budget_checked = decode_set_map(
            required(state, "budget_checked", index)?,
            index,
            "budget_checked",
        )?;
        let receipt_log =
            decode_receipt_map(required(state, "receipt_log", index)?, index, "receipt_log")?;
        decode_integer(
            required(state, "clock", index)?,
            &format!("state {index} clock"),
        )?;

        let allowed_domain: BTreeSet<&str> = allowed.keys().map(String::as_str).collect();
        let budget_domain: BTreeSet<&str> = budget_checked.keys().map(String::as_str).collect();
        let receipt_domain: BTreeSet<&str> = receipt_log.keys().map(String::as_str).collect();
        if allowed_domain != budget_domain || allowed_domain != receipt_domain {
            return Err(invalid(format!(
                "state {index} authority map domains do not match"
            )));
        }

        if witness.is_none() {
            witness = find_violation(&allowed, &receipt_log);
        }
    }

    witness.ok_or_else(|| invalid("trace does not contain a receipt-before-allow violation"))
}

fn required<'a>(
    state: &'a Map<String, Value>,
    name: &str,
    index: usize,
) -> Result<&'a Value, TraceDecodeError> {
    state
        .get(name)
        .ok_or_else(|| invalid(format!("state {index} has no {name} value")))
}

fn decode_set_map(
    value: &Value,
    index: usize,
    name: &str,
) -> Result<BTreeMap<String, BTreeSet<String>>, TraceDecodeError> {
    let label = format!("state {index} {name}");
    let entries = tagged_array(value, "#map", &label)?;
    let mut decoded = BTreeMap::new();
    for entry in entries {
        let (key, value) = decode_pair(entry, &label)?;
        let authority = decode_integer(key, &format!("{label} authority"))?;
        let capabilities = decode_integer_set(value, &format!("{label} authority {authority}"))?;
        if decoded.insert(authority.clone(), capabilities).is_some() {
            return Err(invalid(format!("{label} repeats authority {authority}")));
        }
    }
    Ok(decoded)
}

#[derive(Debug)]
struct Receipt {
    capability: String,
    allow: bool,
}

fn decode_receipt_map(
    value: &Value,
    index: usize,
    name: &str,
) -> Result<BTreeMap<String, Vec<Receipt>>, TraceDecodeError> {
    let label = format!("state {index} {name}");
    let entries = tagged_array(value, "#map", &label)?;
    let mut decoded = BTreeMap::new();
    for entry in entries {
        let (key, value) = decode_pair(entry, &label)?;
        let authority = decode_integer(key, &format!("{label} authority"))?;
        let sequence = value
            .as_array()
            .ok_or_else(|| invalid(format!("{label} authority {authority} is not a sequence")))?;
        let mut receipts = Vec::with_capacity(sequence.len());
        for (receipt_index, receipt) in sequence.iter().enumerate() {
            receipts.push(decode_receipt(
                receipt,
                &format!("{label} authority {authority} receipt {receipt_index}"),
            )?);
        }
        if decoded.insert(authority.clone(), receipts).is_some() {
            return Err(invalid(format!("{label} repeats authority {authority}")));
        }
    }
    Ok(decoded)
}

fn decode_receipt(value: &Value, label: &str) -> Result<Receipt, TraceDecodeError> {
    let record = value
        .as_object()
        .ok_or_else(|| invalid(format!("{label} is not a record")))?;
    let expected: BTreeSet<&str> = ["cap", "seen_epoch", "t", "verdict"].into_iter().collect();
    let actual: BTreeSet<&str> = record.keys().map(String::as_str).collect();
    if actual != expected {
        return Err(invalid(format!("{label} fields do not match the mapping")));
    }
    let capability = decode_integer(
        record
            .get("cap")
            .ok_or_else(|| invalid(format!("{label} has no capability")))?,
        &format!("{label} capability"),
    )?;
    decode_integer(
        record
            .get("t")
            .ok_or_else(|| invalid(format!("{label} has no timestamp")))?,
        &format!("{label} timestamp"),
    )?;
    decode_integer(
        record
            .get("seen_epoch")
            .ok_or_else(|| invalid(format!("{label} has no epoch")))?,
        &format!("{label} epoch"),
    )?;
    let verdict = record
        .get("verdict")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{label} verdict is not a string")))?;
    let allow = match verdict {
        "allow" => true,
        "deny" => false,
        _ => return Err(invalid(format!("{label} has an unknown verdict"))),
    };
    Ok(Receipt { capability, allow })
}

fn decode_pair<'a>(
    value: &'a Value,
    label: &str,
) -> Result<(&'a Value, &'a Value), TraceDecodeError> {
    let pair = value
        .as_array()
        .ok_or_else(|| invalid(format!("{label} contains a non-pair entry")))?;
    if pair.len() != 2 {
        return Err(invalid(format!("{label} contains a non-pair entry")));
    }
    let key = pair
        .first()
        .ok_or_else(|| invalid(format!("{label} pair has no key")))?;
    let value = pair
        .get(1)
        .ok_or_else(|| invalid(format!("{label} pair has no value")))?;
    Ok((key, value))
}

fn decode_integer_set(value: &Value, label: &str) -> Result<BTreeSet<String>, TraceDecodeError> {
    let entries = tagged_array(value, "#set", label)?;
    let mut decoded = BTreeSet::new();
    for entry in entries {
        let integer = decode_integer(entry, label)?;
        if !decoded.insert(integer.clone()) {
            return Err(invalid(format!("{label} repeats integer {integer}")));
        }
    }
    Ok(decoded)
}

fn decode_integer(value: &Value, label: &str) -> Result<String, TraceDecodeError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{label} is not an integer")))?;
    if object.len() != 1 {
        return Err(invalid(format!("{label} is not an exact integer tag")));
    }
    let integer = object
        .get("#bigint")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{label} is not an integer")))?;
    if !is_decimal_integer(integer) {
        return Err(invalid(format!("{label} has an invalid integer value")));
    }
    Ok(integer.to_string())
}

fn tagged_array<'a>(
    value: &'a Value,
    tag: &str,
    label: &str,
) -> Result<&'a [Value], TraceDecodeError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{label} is not a {tag} value")))?;
    if object.len() != 1 {
        return Err(invalid(format!("{label} is not an exact {tag} value")));
    }
    object
        .get(tag)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(format!("{label} is not a {tag} value")))
}

fn is_decimal_integer(value: &str) -> bool {
    if let Some(digits) = value.strip_prefix('-') {
        return digits
            .as_bytes()
            .first()
            .is_some_and(|first| first.is_ascii_digit() && *first != b'0')
            && digits.bytes().all(|byte| byte.is_ascii_digit());
    }
    value == "0"
        || value
            .as_bytes()
            .first()
            .is_some_and(|first| first.is_ascii_digit() && *first != b'0')
            && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn find_violation(
    allowed: &BTreeMap<String, BTreeSet<String>>,
    receipt_log: &BTreeMap<String, Vec<Receipt>>,
) -> Option<ReceiptBeforeAllowWitness> {
    for (authority, capabilities) in allowed {
        let receipts = receipt_log.get(authority)?;
        for capability in capabilities {
            let has_allow = receipts
                .iter()
                .any(|receipt| receipt.allow && receipt.capability == *capability);
            if !has_allow {
                return Some(ReceiptBeforeAllowWitness {
                    authority: authority.clone(),
                    capability: capability.clone(),
                });
            }
        }
    }
    None
}

fn invalid(message: impl Into<String>) -> TraceDecodeError {
    TraceDecodeError {
        message: message.into(),
    }
}
