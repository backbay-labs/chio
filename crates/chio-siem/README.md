# chio-siem

`chio-siem` is the SIEM exporter pipeline for Chio's receipt audit log. It
provides the abstractions for forwarding receipt events to external SIEM
systems such as Splunk or Elasticsearch. It depends on `chio-core` (for
`ChioReceipt` and `FinancialReceiptMetadata`), reads the kernel receipt
database directly via rusqlite, and depends on `chio-kernel` for its
read-only receipt boundary (`ReceiptReadBoundary` / `ReceiptReadContext`).
The dependency is one-directional, so SIEM HTTP-client surface stays out of
the kernel TCB.

Use this crate to stream signed receipt events into your audit and detection
tooling.
