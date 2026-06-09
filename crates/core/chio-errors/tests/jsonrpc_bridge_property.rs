use std::collections::BTreeSet;

pub use chio_errors::{jsonrpc_bridge, ErrorCodeSpec, ERROR_CODES};

const WIRE_REGISTRY: &str = include_str!("../../../../spec/errors/chio-error-registry.v1.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WireRegistryEntry {
    code: i32,
    jsonrpc_code: Option<i32>,
}

#[test]
fn generated_jsonrpc_codes_round_trip_through_bridge() {
    let fixture_entries = parse_wire_registry_entries();
    let fixture_codes = fixture_entries
        .iter()
        .map(|entry| entry.code)
        .collect::<BTreeSet<_>>();
    let mut bridged_codes = BTreeSet::new();

    for entry in ERROR_CODES
        .iter()
        .filter(|entry| entry.jsonrpc_code.is_some())
    {
        let code = match jsonrpc_bridge::to_jsonrpc_code(entry) {
            Some(code) => code,
            None => panic!("{} should have a JSON-RPC registry pointer", entry.urn),
        };

        assert!(
            fixture_codes.contains(&code),
            "{} points at missing JSON-RPC registry code {code}",
            entry.urn
        );
        assert!(
            bridged_codes.insert(code),
            "duplicate JSON-RPC registry pointer {code}"
        );

        let round_tripped = match jsonrpc_bridge::round_trip_jsonrpc_code(entry) {
            Some(round_tripped) => round_tripped,
            None => panic!("{} failed JSON-RPC bridge round trip", entry.urn),
        };

        assert_eq!(round_tripped.urn, entry.urn);
        assert_eq!(jsonrpc_bridge::from_jsonrpc_code(code), Some(round_tripped));
    }

    assert_eq!(
        bridged_codes.len(),
        fixture_codes.len(),
        "generated registry and JSON-RPC fixture should expose the same bridged codes"
    );
}

#[test]
fn unmapped_jsonrpc_values_fail_closed() {
    let fixture_entries = parse_wire_registry_entries();
    let fixture_codes = fixture_entries
        .iter()
        .map(|entry| entry.code)
        .collect::<BTreeSet<_>>();

    for value in [i32::MIN, -32600, -32002, -1, 0, 1, 999, 9999, i32::MAX] {
        assert!(!fixture_codes.contains(&value));
        assert_eq!(jsonrpc_bridge::from_jsonrpc_code(value), None);
    }

    for wire_code in fixture_entries
        .iter()
        .filter_map(|entry| entry.jsonrpc_code)
    {
        assert_eq!(jsonrpc_bridge::from_jsonrpc_code(wire_code), None);
    }

    for entry in ERROR_CODES
        .iter()
        .filter(|entry| entry.jsonrpc_code.is_none())
    {
        assert_eq!(jsonrpc_bridge::to_jsonrpc_code(entry), None);
        assert_eq!(jsonrpc_bridge::round_trip_jsonrpc_code(entry), None);
    }
}

fn parse_wire_registry_entries() -> Vec<WireRegistryEntry> {
    let mut entries = Vec::new();
    let mut code = None;
    let mut jsonrpc_code = None;

    for line in WIRE_REGISTRY.lines() {
        let trimmed = line.trim();

        if let Some(value) = trimmed.strip_prefix("\"code\": ") {
            code = Some(parse_i32(value, "code"));
            jsonrpc_code = None;
        } else if let Some(value) = trimmed.strip_prefix("\"jsonrpcCode\": ") {
            jsonrpc_code = Some(parse_i32(value, "jsonrpcCode"));
        } else if line.starts_with("    }") {
            if let Some(code) = code.take() {
                entries.push(WireRegistryEntry { code, jsonrpc_code });
                jsonrpc_code = None;
            }
        }
    }

    if let Some(code) = code {
        entries.push(WireRegistryEntry { code, jsonrpc_code });
    }

    assert!(
        !entries.is_empty(),
        "fixture should contain registry entries"
    );
    entries
}

fn parse_i32(value: &str, field: &str) -> i32 {
    let trimmed = value.trim_end_matches(',').trim();

    match trimmed.parse::<i32>() {
        Ok(value) => value,
        Err(error) => panic!("failed to parse {field} value {trimmed}: {error}"),
    }
}
