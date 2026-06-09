# chio-tee

`chio-tee` is the Chio TEE shadow runner. It is a sidecar that observes
kernel-bound traffic through the `TrafficTap` hook surface and, per evaluation,
redacts the request and response payloads (fail-closed), persists the redacted
blobs encrypted under the tenant key, and appends a tenant-signed
`chio-tee-frame.v1` record to an append-only NDJSON capture file. That capture
stream is consumed downstream by `chio replay --bless`.

Use this crate to capture signed, redacted records of kernel decisions for
later replay. The frame wire format is defined in `chio-tee-frame`.
