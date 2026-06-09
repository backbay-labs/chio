//! Dynamic metadata payloads for Envoy access logs and downstream filters.

use prost_types::{value::Kind, Struct, Value};

const VERDICT_KEY: &str = "chio.verdict";
const DENIAL_REASON_KEY: &str = "chio.denial_reason";
const DENIAL_GUARD_KEY: &str = "chio.denial_guard";
const HTTP_STATUS_KEY: &str = "chio.http_status";
const FAIL_CLOSED_KEY: &str = "chio.fail_closed";

pub(crate) fn allow_dynamic_metadata() -> Struct {
    struct_from_fields([(VERDICT_KEY, string_value("allow"))])
}

pub(crate) fn deny_dynamic_metadata(reason: &str, guard: &str, http_status: u16) -> Struct {
    struct_from_fields([
        (VERDICT_KEY, string_value("deny")),
        (DENIAL_REASON_KEY, string_value(reason)),
        (DENIAL_GUARD_KEY, string_value(guard)),
        (HTTP_STATUS_KEY, number_value(http_status)),
    ])
}

pub(crate) fn fail_closed_dynamic_metadata(reason: &str) -> Struct {
    struct_from_fields([
        (VERDICT_KEY, string_value("deny")),
        (DENIAL_REASON_KEY, string_value(reason)),
        (DENIAL_GUARD_KEY, string_value("fail_closed")),
        (HTTP_STATUS_KEY, number_value(500)),
        (FAIL_CLOSED_KEY, bool_value(true)),
    ])
}

fn struct_from_fields<const N: usize>(fields: [(&str, Value); N]) -> Struct {
    Struct {
        fields: fields
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    }
}

fn string_value(value: &str) -> Value {
    Value {
        kind: Some(Kind::StringValue(value.to_string())),
    }
}

fn number_value(value: u16) -> Value {
    Value {
        kind: Some(Kind::NumberValue(f64::from(value))),
    }
}

fn bool_value(value: bool) -> Value {
    Value {
        kind: Some(Kind::BoolValue(value)),
    }
}
