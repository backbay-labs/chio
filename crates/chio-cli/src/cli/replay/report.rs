// Structured JSON output for `chio replay --json`.
//
// Owns the stable `chio.replay.report/v1` schema. JSON shape on stdout:
//
// ```json
// {
//   "schema": "chio.replay.report/v1",
//   "log_path": "<positional arg>",
//   "receipts_checked": <integer>,
//   "computed_root": "<lowercase hex>",
//   "expected_root": "<lowercase hex>" | null,
//   "first_divergence": null | {
//     "kind": "verdict_drift" | "signature_mismatch" | "parse_error"
//           | "schema_mismatch" | "redaction_mismatch" | "merkle_mismatch",
//     "receipt_index": <integer>,
//     "receipt_id": "<id>" | null,
//     "json_pointer": "<rfc 6901>" | null,
//     "byte_offset": <integer> | null,
//     "expected": "<string>" | null,
//     "observed": "<string>" | null,
//     "detail": "<string>" | null
//   },
//   "exit_code": 0 | 10 | 20 | 30 | 40 | 50
// }
// ```
//
// [`SCHEMA_ID`] is the only field downstream consumers MUST byte-match before
// parsing the rest of the document. Schema file is at
// `spec/schemas/chio-replay-report/v1.schema.json`.

use serde::{Deserialize, Serialize};

/// Stable schema identifier emitted in the `schema` field. Downstream
/// consumers MUST gate on a byte-equal match before parsing the rest of
/// the document.
pub const SCHEMA_ID: &str = "chio.replay.report/v1";

/// Divergence kinds the pipeline can attribute. `snake_case` serialization
/// matches the schema in `spec/schemas/chio-replay-report/v1.schema.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceKind {
    /// Stored decision disagrees with what the current build produces
    /// (drives exit code 10).
    VerdictDrift,
    /// Ed25519 signature re-verification failed (drives exit code 20).
    SignatureMismatch,
    /// Receipt could not be deserialized (drives exit code 30).
    ParseError,
    /// Receipt schema validation failed (drives exit code 40).
    SchemaMismatch,
    /// Redaction manifest mismatch (drives exit code 50).
    RedactionMismatch,
    /// Recomputed Merkle root differs from `--expect-root`. Mapped to
    /// exit code 20 at the dispatch layer; the shape is for triage only.
    MerkleMismatch,
}

/// Per-divergence detail block. `null` for a clean run.
///
/// Fields are deliberately optional so the report can carry partial
/// attribution: a parse error has no `receipt_id` and a signature
/// mismatch has no `json_pointer`. Consumers MUST gate field access on
/// `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Divergence {
    /// Shape of the divergence (drives exit code mapping).
    pub kind: DivergenceKind,
    /// Zero-based index of the offending receipt in reader-yield order.
    pub receipt_index: usize,
    /// `id` of the offending receipt when known. `None` for pre-read /
    /// parse-failure shapes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub receipt_id: Option<String>,
    /// RFC 6901 JSON pointer to the offending field. `None` for whole-
    /// receipt or pre-read shapes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub json_pointer: Option<String>,
    /// Byte offset into the log file where the receipt starts. `None`
    /// for directory-mode runs.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub byte_offset: Option<u64>,
    /// Stored / expected value at `json_pointer`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expected: Option<String>,
    /// Newly-derived / observed value at `json_pointer`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub observed: Option<String>,
    /// Free-form human-readable detail. Present for shapes that do not
    /// decompose into `expected` / `observed`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<String>,
}

/// `chio.replay.report/v1` document rendered on `--json` runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayReport {
    /// Stable schema identifier. Always [`SCHEMA_ID`].
    pub schema: String,
    /// `<log>` positional argument, recorded verbatim.
    pub log_path: String,
    /// Count of receipts the pipeline processed.
    pub receipts_checked: usize,
    /// Lowercase-hex SHA-256 synthetic root from the Merkle accumulator.
    /// Empty string when the run aborted before any receipt was folded.
    pub computed_root: String,
    /// Lowercase-hex root the run was asserted against (`--expect-root`).
    /// `None` when the user did not supply an expectation.
    pub expected_root: Option<String>,
    /// First divergence the pipeline observed. `None` for a clean run.
    pub first_divergence: Option<Divergence>,
    /// Process exit code the dispatch layer will use.
    pub exit_code: i32,
}

impl ReplayReport {
    /// Construct a clean-run report (`exit_code == 0`,
    /// `first_divergence == None`).
    #[must_use]
    pub fn clean(
        log_path: impl Into<String>,
        receipts_checked: usize,
        computed_root: impl Into<String>,
        expected_root: Option<String>,
    ) -> Self {
        Self {
            schema: SCHEMA_ID.to_string(),
            log_path: log_path.into(),
            receipts_checked,
            computed_root: computed_root.into(),
            expected_root,
            first_divergence: None,
            exit_code: 0,
        }
    }

    /// Construct a divergence report. The `exit_code` MUST match the
    /// canonical registry mapping for the [`DivergenceKind`]; callers
    /// can use [`exit_code_for`] to derive it.
    #[must_use]
    pub fn diverged(
        log_path: impl Into<String>,
        receipts_checked: usize,
        computed_root: impl Into<String>,
        expected_root: Option<String>,
        first_divergence: Divergence,
        exit_code: i32,
    ) -> Self {
        Self {
            schema: SCHEMA_ID.to_string(),
            log_path: log_path.into(),
            receipts_checked,
            computed_root: computed_root.into(),
            expected_root,
            first_divergence: Some(first_divergence),
            exit_code,
        }
    }
}

/// Canonical exit-code mapping for a [`DivergenceKind`].
/// [`DivergenceKind::MerkleMismatch`] maps to 20 (same as signature mismatch)
/// because a root mismatch implies at least one receipt's signed bytes differ.
#[must_use]
pub fn exit_code_for(kind: DivergenceKind) -> i32 {
    match kind {
        DivergenceKind::VerdictDrift => 10,
        DivergenceKind::SignatureMismatch | DivergenceKind::MerkleMismatch => 20,
        DivergenceKind::ParseError => 30,
        DivergenceKind::SchemaMismatch => 40,
        DivergenceKind::RedactionMismatch => 50,
    }
}

/// Render `report` to `writer` as a single line of JSON followed by a
/// trailing newline.
///
/// The output is `serde_json::to_writer(...)` plus a `\n`: callers that
/// want pretty-printed output should round-trip through
/// [`render_json_string`] and re-pretty-print themselves. The
/// single-line shape is required so consumers that pipe `chio replay
/// --json | jq` see a stable byte stream regardless of pipeline
/// buffering.
pub fn render_json<W: std::io::Write>(
    writer: &mut W,
    report: &ReplayReport,
) -> Result<(), std::io::Error> {
    serde_json::to_writer(&mut *writer, report).map_err(std::io::Error::other)?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// Render `report` to a single line of JSON (no trailing newline).
///
/// Convenience helper for tests and callers that want the bytes in
/// memory before deciding where to write them. The byte sequence is
/// identical to what [`render_json`] writes minus the trailing `\n`.
pub fn render_json_string(report: &ReplayReport) -> Result<String, serde_json::Error> {
    serde_json::to_string(report)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_report_tests {
    use super::*;

    #[test]
    fn schema_id_is_chio_replay_report_v1() {
        assert_eq!(SCHEMA_ID, "chio.replay.report/v1");
    }

    #[test]
    fn clean_report_serializes_with_null_divergence_and_exit_zero() {
        let report = ReplayReport::clean(
            "./receipts/",
            42,
            "abc123",
            Some("abc123".to_string()),
        );
        let json = render_json_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["schema"], "chio.replay.report/v1");
        assert_eq!(value["log_path"], "./receipts/");
        assert_eq!(value["receipts_checked"], 42);
        assert_eq!(value["computed_root"], "abc123");
        assert_eq!(value["expected_root"], "abc123");
        assert!(value["first_divergence"].is_null());
        assert_eq!(value["exit_code"], 0);
    }

    #[test]
    fn clean_report_with_no_expected_root_serializes_null() {
        let report = ReplayReport::clean("./log.ndjson", 1, "deadbeef", None);
        let value: serde_json::Value =
            serde_json::from_str(&render_json_string(&report).unwrap()).unwrap();
        assert!(
            value["expected_root"].is_null(),
            "expected_root MUST serialize as JSON null when not asserted",
        );
    }

    #[test]
    fn divergence_kinds_serialize_as_snake_case() {
        // Pin every variant: the wire enum is the public contract.
        let cases = [
            (DivergenceKind::VerdictDrift, "verdict_drift"),
            (DivergenceKind::SignatureMismatch, "signature_mismatch"),
            (DivergenceKind::ParseError, "parse_error"),
            (DivergenceKind::SchemaMismatch, "schema_mismatch"),
            (DivergenceKind::RedactionMismatch, "redaction_mismatch"),
            (DivergenceKind::MerkleMismatch, "merkle_mismatch"),
        ];
        for (kind, expected) in cases {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{expected}\""));
        }
    }

    #[test]
    fn divergence_kinds_round_trip_through_serde() {
        for kind in [
            DivergenceKind::VerdictDrift,
            DivergenceKind::SignatureMismatch,
            DivergenceKind::ParseError,
            DivergenceKind::SchemaMismatch,
            DivergenceKind::RedactionMismatch,
            DivergenceKind::MerkleMismatch,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: DivergenceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn exit_code_mapping_matches_canonical_registry() {
        assert_eq!(exit_code_for(DivergenceKind::VerdictDrift), 10);
        assert_eq!(exit_code_for(DivergenceKind::SignatureMismatch), 20);
        assert_eq!(exit_code_for(DivergenceKind::MerkleMismatch), 20);
        assert_eq!(exit_code_for(DivergenceKind::ParseError), 30);
        assert_eq!(exit_code_for(DivergenceKind::SchemaMismatch), 40);
        assert_eq!(exit_code_for(DivergenceKind::RedactionMismatch), 50);
    }

    #[test]
    fn verdict_drift_report_serializes_full_shape() {
        let divergence = Divergence {
            kind: DivergenceKind::VerdictDrift,
            receipt_index: 7,
            receipt_id: Some("rcpt-drift-0001".to_string()),
            json_pointer: Some("/decision/verdict".to_string()),
            byte_offset: Some(1024),
            expected: Some("allow".to_string()),
            observed: Some("deny".to_string()),
            detail: None,
        };
        let report = ReplayReport::diverged(
            "./receipts/",
            8,
            "abc",
            None,
            divergence,
            exit_code_for(DivergenceKind::VerdictDrift),
        );
        let json = render_json_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["exit_code"], 10);
        let div = &value["first_divergence"];
        assert_eq!(div["kind"], "verdict_drift");
        assert_eq!(div["receipt_index"], 7);
        assert_eq!(div["receipt_id"], "rcpt-drift-0001");
        assert_eq!(div["json_pointer"], "/decision/verdict");
        assert_eq!(div["byte_offset"], 1024);
        assert_eq!(div["expected"], "allow");
        assert_eq!(div["observed"], "deny");
        assert!(div.get("detail").is_none(), "absent fields skipped");
    }

    #[test]
    fn signature_mismatch_report_omits_pointer_and_carries_signer_in_detail() {
        let divergence = Divergence {
            kind: DivergenceKind::SignatureMismatch,
            receipt_index: 3,
            receipt_id: Some("rcpt-bad-sig-0001".to_string()),
            json_pointer: None,
            byte_offset: None,
            expected: None,
            observed: None,
            detail: Some(
                "signer=ed25519:deadbeef... signature mismatch".to_string(),
            ),
        };
        let report = ReplayReport::diverged(
            "./capture.ndjson",
            5,
            "abc",
            None,
            divergence,
            exit_code_for(DivergenceKind::SignatureMismatch),
        );
        let value: serde_json::Value =
            serde_json::from_str(&render_json_string(&report).unwrap()).unwrap();

        assert_eq!(value["exit_code"], 20);
        let div = &value["first_divergence"];
        assert_eq!(div["kind"], "signature_mismatch");
        assert!(div.get("json_pointer").is_none());
        assert!(div.get("byte_offset").is_none());
        assert!(div.get("expected").is_none());
        assert!(div.get("observed").is_none());
        assert_eq!(
            div["detail"],
            "signer=ed25519:deadbeef... signature mismatch",
        );
    }

    #[test]
    fn parse_error_report_omits_receipt_id() {
        // Parse error: the receipt was never deserialized far enough to
        // attribute an id. The schema permits `receipt_id == null`.
        let divergence = Divergence {
            kind: DivergenceKind::ParseError,
            receipt_index: 0,
            receipt_id: None,
            json_pointer: None,
            byte_offset: Some(0),
            expected: None,
            observed: None,
            detail: Some("malformed JSON at line 1: expected `{`".to_string()),
        };
        let report = ReplayReport::diverged(
            "./busted.ndjson",
            0,
            String::new(),
            None,
            divergence,
            exit_code_for(DivergenceKind::ParseError),
        );
        let value: serde_json::Value =
            serde_json::from_str(&render_json_string(&report).unwrap()).unwrap();

        assert_eq!(value["exit_code"], 30);
        assert_eq!(value["first_divergence"]["kind"], "parse_error");
        assert!(value["first_divergence"].get("receipt_id").is_none());
        assert_eq!(value["first_divergence"]["byte_offset"], 0);
    }

    #[test]
    fn merkle_mismatch_report_carries_root_pair() {
        let divergence = Divergence {
            kind: DivergenceKind::MerkleMismatch,
            receipt_index: 0,
            receipt_id: None,
            json_pointer: None,
            byte_offset: None,
            expected: Some("aaaa".to_string()),
            observed: Some("bbbb".to_string()),
            detail: Some("recomputed root does not match --expect-root".to_string()),
        };
        let report = ReplayReport::diverged(
            "./receipts/",
            10,
            "bbbb",
            Some("aaaa".to_string()),
            divergence,
            exit_code_for(DivergenceKind::MerkleMismatch),
        );
        let value: serde_json::Value =
            serde_json::from_str(&render_json_string(&report).unwrap()).unwrap();

        assert_eq!(value["exit_code"], 20);
        assert_eq!(value["computed_root"], "bbbb");
        assert_eq!(value["expected_root"], "aaaa");
        let div = &value["first_divergence"];
        assert_eq!(div["kind"], "merkle_mismatch");
        assert_eq!(div["expected"], "aaaa");
        assert_eq!(div["observed"], "bbbb");
    }

    #[test]
    fn report_round_trips_through_serde() {
        // Pin the deserialize path: external tooling that reads the
        // report back in (e.g. CI summary scripts) MUST get the same
        // struct out.
        let original = ReplayReport::diverged(
            "./log.ndjson",
            12,
            "deadbeef",
            Some("cafebabe".to_string()),
            Divergence {
                kind: DivergenceKind::VerdictDrift,
                receipt_index: 4,
                receipt_id: Some("rcpt-0004".to_string()),
                json_pointer: Some("/decision/verdict".to_string()),
                byte_offset: Some(512),
                expected: Some("allow".to_string()),
                observed: Some("deny".to_string()),
                detail: None,
            },
            10,
        );
        let json = render_json_string(&original).unwrap();
        let parsed: ReplayReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn render_json_writes_single_line_with_trailing_newline() {
        let report = ReplayReport::clean("./l", 1, "ab", None);
        let mut buf: Vec<u8> = Vec::new();
        render_json(&mut buf, &report).unwrap();
        let text = std::str::from_utf8(&buf).unwrap();
        assert!(text.ends_with('\n'), "trailing newline required: {text:?}");
        // Exactly one newline (the trailing one): no internal newlines
        // would creep in if a future refactor switched to
        // to_writer_pretty.
        assert_eq!(
            text.matches('\n').count(),
            1,
            "report must be single-line JSON: {text}",
        );
    }

    #[test]
    fn render_json_string_matches_render_json_minus_newline() {
        let report = ReplayReport::clean("./l", 1, "ab", None);
        let mut buf: Vec<u8> = Vec::new();
        render_json(&mut buf, &report).unwrap();
        let from_writer = std::str::from_utf8(&buf).unwrap();
        let from_string = render_json_string(&report).unwrap();
        assert_eq!(from_writer.trim_end_matches('\n'), from_string);
    }

    #[test]
    fn schema_field_is_first_byte_string_in_serialized_output() {
        // serde_json honours field declaration order on serialize. The
        // schema field is declared first on `ReplayReport` so consumers
        // can byte-match the leading bytes (`{"schema":"chio.replay.report/v1"`)
        // without parsing the full document. This pin trips if a future
        // refactor reorders the struct.
        let report = ReplayReport::clean("./l", 0, String::new(), None);
        let json = render_json_string(&report).unwrap();
        assert!(
            json.starts_with("{\"schema\":\"chio.replay.report/v1\""),
            "schema must be the first serialized field: {json}",
        );
    }

    #[test]
    fn divergence_optional_fields_omitted_when_none() {
        // The `skip_serializing_if = "Option::is_none"` guard pins the
        // wire shape: a report consumer must not see `null`-valued
        // optional fields (only absent ones). This keeps the byte
        // shape stable when fields evolve from required-with-null to
        // optional-and-absent or vice versa.
        let divergence = Divergence {
            kind: DivergenceKind::ParseError,
            receipt_index: 0,
            receipt_id: None,
            json_pointer: None,
            byte_offset: None,
            expected: None,
            observed: None,
            detail: None,
        };
        let json = serde_json::to_string(&divergence).unwrap();
        // Only `kind` and `receipt_index` survive serialization.
        assert_eq!(json, "{\"kind\":\"parse_error\",\"receipt_index\":0}");
    }

    #[test]
    fn schema_file_on_disk_pins_schema_id() {
        // Cross-check: the schema constant MUST match the const string
        // in `spec/schemas/chio-replay-report/v1.schema.json`. Reading
        // the file at test time lets a refactor that renames the
        // constant without updating the schema (or vice versa) trip
        // here rather than in a downstream consumer.
        let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .join("spec/schemas/chio-replay-report/v1.schema.json");
        let bytes = std::fs::read(&schema_path).unwrap_or_else(|e| {
            panic!(
                "schema file must exist at {}: {e}",
                schema_path.display(),
            )
        });
        let schema_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let schema_const = schema_json["properties"]["schema"]["const"]
            .as_str()
            .expect("schema.properties.schema.const must be a string");
        assert_eq!(
            schema_const, SCHEMA_ID,
            "schema file const and SCHEMA_ID drifted",
        );
    }
}
