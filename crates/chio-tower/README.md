# chio-tower

`chio-tower` is Tower middleware for Chio capability validation and receipt
signing. It provides a `tower::Layer` that wraps any HTTP service with Chio
evaluation: extracting caller identity, evaluating requests against the kernel,
and attaching signed receipts to responses. It works with replayable Tower
request body types, including Axum's `axum::body::Body` and bytes-backed HTTP
bodies.

Use this crate to add Chio enforcement to an existing Tower or Axum service.
Real `tonic::body::Body` replay remains a follow-on concern and is not claimed
as fully covered by the current middleware contract.

Capability tokens may be presented in `X-Chio-Capability` or the
`chio_capability` query parameter. Requests with duplicate `chio_capability`
query parameters are rejected as ambiguous and receive a signed deny receipt.
