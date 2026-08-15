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
        writeln!(
            writer,
            "error [{}]: {}",
            terminal_safe(&report.code),
            terminal_safe(&report.message)
        )?;
        writeln!(
            writer,
            "context: {}",
            terminal_safe(&report.context.to_string())
        )?;
        writeln!(
            writer,
            "suggested fix: {}",
            terminal_safe(&report.suggested_fix)
        )
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

    #[test]
    fn human_errors_cannot_inject_terminal_controls() {
        let error = CliError::cli_other_error("bad\n\u{1b}[2Jforged".to_string());
        let mut output = Vec::new();
        write_cli_error(&mut output, &error, false)
            .unwrap_or_else(|write_error| panic!("write human error: {write_error}"));
        let rendered = String::from_utf8(output)
            .unwrap_or_else(|utf8_error| panic!("rendered output is UTF-8: {utf8_error}"));
        assert!(rendered.contains("bad\\n\\u{1b}[2Jforged"));
        assert_eq!(rendered.chars().filter(|character| *character == '\n').count(), 3);
        assert!(!rendered.contains('\u{1b}'));
    }
}
