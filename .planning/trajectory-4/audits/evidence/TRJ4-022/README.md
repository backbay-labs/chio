# TRJ4-022 Evidence - chio-tee-frame Timestamp Validation

## Scope

`schema::validate_timestamp` now keeps the exact v1 wire shape
`YYYY-MM-DDTHH:MM:SS.mmmZ` and also parses the value with an RFC3339 parser.
This rejects impossible month, day, hour, minute, and second values that
previously matched the digit pattern.

## Validation

- `cargo test -p chio-tee-frame` passed: 21 unit tests, 2 property tests, 0 doc
  tests.
- `cargo check -p chio-http-core -p chio-tee-frame -p chio-conformance`
  passed.
- `cargo clippy -p chio-http-core -p chio-tee-frame -p chio-conformance --tests -- -D warnings`
  passed.

## Test Coverage

- Missing millisecond precision rejects.
- `2026-13-99T25:99:99.999Z` rejects.
