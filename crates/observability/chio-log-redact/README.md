# chio-log-redact

`chio-log-redact` provides tracing log-redaction primitives for Chio's
operator-facing telemetry. Use the `redacted!` macro at any log site that may
carry payload, body, prompt, tool arguments, tool output, user message, or
downstream response text, and install `RedactionLayer` as the sink-facing
tracing layer so every observed event field passes through the same default
redaction tree.

Use this crate to keep sensitive content out of logs while preserving
structured, operator-readable telemetry.
