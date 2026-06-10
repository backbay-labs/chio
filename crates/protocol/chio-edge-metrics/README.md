# chio-edge-metrics

`chio-edge-metrics` is the shared receipt-write metrics sink for Chio's
protocol edge crates (MCP, ACP, A2A, and others). Every edge surfaces the same
`chio_receipt_write_total` series through the workspace `chio-metrics-spec`
registry: each response emerging from the kernel boundary increments the
counter with an `outcome` label.

The recorder, accessor, and renderer logic is identical across edges, so it
lives here once. Counter state stays per-edge: the crate exposes a
`ReceiptWriteCounters` instance type rather than module-level globals, so one
edge's dispatches never advance another edge's counter.
