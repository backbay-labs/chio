# chio-http-session

`chio-http-session` provides a per-session journal for the Chio runtime: an
append-only, hash-chained record that tracks request history, cumulative data
flow (bytes read and written), delegation depth, and tool invocation sequence
within a single session. The journal persists across requests within a session
and is available to all guards. Each entry includes a SHA-256 hash of the
previous entry, forming a tamper-evident chain.

Use this crate when a guard needs session-level history rather than just the
current request.

## Entry Hash Computation

The `entry_hash` is the SHA-256 digest of the following fields concatenated in
order. Integers are little-endian bytes, strings are encoded as `u64`
little-endian byte length followed by UTF-8 bytes, and booleans are encoded as
`0x01` for true or `0x00` for false:

1. `sequence` (8 bytes, LE)
2. `prev_hash` (`u64` byte length LE || UTF-8 bytes)
3. `timestamp_secs` (8 bytes, LE)
4. `tool_name` (`u64` byte length LE || UTF-8 bytes)
5. `server_id` (`u64` byte length LE || UTF-8 bytes)
6. `agent_id` (`u64` byte length LE || UTF-8 bytes)
7. `bytes_read` (8 bytes, LE)
8. `bytes_written` (8 bytes, LE)
9. `delegation_depth` (4 bytes, LE)
10. `allowed` (1 byte: `0x01` for true, `0x00` for false)
