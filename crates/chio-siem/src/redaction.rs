use std::fmt;

use chio_log_redact::redacted;

pub(crate) fn redact_for_operator_log(value: impl fmt::Display) -> String {
    redacted!(value).to_string()
}
