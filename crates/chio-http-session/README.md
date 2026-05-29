# chio-http-session

`chio-http-session` provides a per-session journal for the Chio runtime: an
append-only, hash-chained record that tracks request history, cumulative data
flow (bytes read and written), delegation depth, and tool invocation sequence
within a single session. The journal persists across requests within a session
and is available to all guards. Each entry includes a SHA-256 hash of the
previous entry, forming a tamper-evident chain.

Use this crate when a guard needs session-level history rather than just the
current request.
