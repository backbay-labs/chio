# Runnable examples: chio-federation-transport-iroh

Each example is a self-contained, deterministic demo that stands up two (or three)
in-process iroh endpoints over loopback (`RelayMode::Disabled`, `127.0.0.1:0`,
fixed seeds) and drives ONE lane end-to-end with the crate's real APIs. Each is
also a living doc and a smoke test: it prints the flow, asserts the fail-closed
invariant, and exits non-zero if the invariant is violated.

Run one with (the `-p` flag is required; a bare `cargo build` pulls the whole
workspace):

```bash
cargo run -p chio-federation-transport-iroh --example <name>
```

| Example | Lane | Demonstrates |
| --- | --- | --- |
| `admission_gate` | accept-time gate (all lanes) | An admitted `EndpointId` completes a request/response; an unadmitted one is `Reject(403)` at `after_handshake`, before any handler runs. |
| `pheromone_exchange` | a: directed batches | Operator A delivers a `PheromoneGossipBatch`; B resolves the authenticated sender via the gate and feeds that `kernel_id` into the real per-frame verifier, which accepts. An unadmitted sender is rejected at the gate. |
| `revocation_catchup` | e: content-addressed catch-up | An authority publishes signed epoch roots over iroh-blobs; a follower fetches and verifies against a PINNED signer key. A forged root (same `signer_id`, different key) is rejected `BadSignature`: BLAKE3 integrity is not authenticity. |
| `bilateral_cosign` | d: bidi DSSE co-sign | Org B requests; Org A verifies `org_b_signature` over `pae_bytes` and binds the authenticated `EndpointId` to the claimed `org_b_kernel_id`, then co-signs the exact bytes. An Org B claiming a different kernel id is refused without a signature. |
| `fanout_gossip` | c: cross-operator fan-out | Three admitted nodes join a per-treaty gossip topic (A -> B -> C). A self-signed deposit broadcast by A reaches C RELAYED through B, and is origin-verified from the payload alone. A tampered frame from the admitted relay B is rejected: `delivered_from` never launders a frame. |

## Notes

- These mirror the crate's own tests and the validated iroh PoCs (signed
  directory verify -> admission gate -> lane handler + client path).
- `revocation_catchup` uses the iroh-blobs catch-up substrate (ADAPTER-SPEC lane e)
  rather than the direct revocation-lane QUIC push: the direct
  `RevocationHandler::accept` returns without awaiting `conn.closed()`, so on
  loopback the reply frame truncates before the dialer reads it. Both paths share
  the same pinned-signer authenticity check.
- `pheromone_exchange` uses a small in-example acceptor (mirroring the crate's own
  `CannedReportHandler` test double) because the real `PheromoneBatchHandler`
  requires a `RelayBatchReceiver` whose report type lives in `chio-pheromone-runtime`,
  which is not a dependency here. The gate, the wire client, and the per-frame
  verifier it drives are all the real crate APIs.
