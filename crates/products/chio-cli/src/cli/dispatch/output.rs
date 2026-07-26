use super::*;

pub(crate) fn write_cli_error(
    writer: &mut impl Write,
    error: &CliError,
    json_output: bool,
) -> std::io::Result<()> {
    let report = error.report();
    if json_output {
        serde_json::to_writer(&mut *writer, &report).map_err(std::io::Error::other)?;
        writeln!(writer)
    } else {
        writeln!(writer, "error [{}]: {}", report.code, report.message)?;
        writeln!(writer, "context: {}", report.context)?;
        writeln!(writer, "suggested fix: {}", report.suggested_fix)
    }
}

pub(super) fn write_bytes(
    writer: &mut impl Write,
    bytes: &[u8],
    context: &str,
) -> Result<(), CliError> {
    writer
        .write_all(bytes)
        .map_err(|err| CliError::Other(format!("{context} write: {err}")))
}

pub(super) fn write_pretty_json_line<T: serde::Serialize>(
    writer: &mut impl Write,
    value: &T,
    context: &str,
) -> Result<(), CliError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| CliError::Other(format!("{context} serialize: {err}")))?;
    write_bytes(writer, &bytes, context)?;
    write_bytes(writer, b"\n", context)
}

#[cfg(test)]
mod dispatch_output_tests {
    use super::*;

    #[test]
    fn write_pretty_json_line_preserves_pretty_json_and_trailing_newline() {
        let mut output = Vec::new();
        write_pretty_json_line(
            &mut output,
            &serde_json::json!({
                "schema": "chio.test/v1",
                "allowed": true
            }),
            "test output",
        )
        .unwrap_or_else(|error| panic!("write JSON line: {error}"));

        let rendered = String::from_utf8(output)
            .unwrap_or_else(|error| panic!("rendered output is UTF-8: {error}"));
        assert!(rendered.ends_with('\n'));
        assert!(rendered.contains("\n  \"schema\": \"chio.test/v1\""));
        assert!(rendered.contains("\n  \"allowed\": true"));
    }
}
