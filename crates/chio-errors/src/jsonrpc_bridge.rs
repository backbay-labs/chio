use crate::{lookup_jsonrpc_code, ErrorCodeSpec};

#[must_use]
pub fn to_jsonrpc_code(entry: &ErrorCodeSpec) -> Option<i32> {
    entry.jsonrpc_code
}

#[must_use]
pub fn from_jsonrpc_code(code: i32) -> Option<&'static ErrorCodeSpec> {
    lookup_jsonrpc_code(code)
}

#[must_use]
pub fn round_trip_jsonrpc_code(entry: &ErrorCodeSpec) -> Option<&'static ErrorCodeSpec> {
    to_jsonrpc_code(entry).and_then(from_jsonrpc_code)
}
