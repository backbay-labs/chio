# JSON-RPC replay fixtures

Files used by `examples/chiodome-bilateral/scripts/run-with-kb-mcp.sh
--check` to drive a noninteractive replay. There are two shapes here:

| File                          | Used by                                       | Speaks                                  |
|-------------------------------|-----------------------------------------------|-----------------------------------------|
| `kb-replay.jsonrpc`           | `chio mcp serve` AND `chio mcp wrap`          | newline-delimited JSON-RPC client frames |
| `kb-stub-server-fixture.json` | `chio mcp wrap --e2e-fixture` (default check) | `chio_mcp_adapter` server fixture shape  |

## kb-replay.jsonrpc

Newline-delimited JSON-RPC frames. Pipe into a wrapped server's stdin to
exercise initialise + tools/list + a couple of `tools/call` frames
(including one destructive call that the demo policy denies).

```
chio mcp serve --policy ./policy.yaml --server-id srv-kb-mcp-demo \
  -- mcp-remote http://127.0.0.1:8111/mcp/ \
  < ./fixtures/jsonrpc-replay/kb-replay.jsonrpc
```

Frame layout:

| id | method        | meaning                                        |
|----|---------------|------------------------------------------------|
| 0  | initialize    | open session                                   |
| 1  | tools/list    | enumerate the wrapped surface                  |
| 2  | tools/call    | `echo` (read-only; allowed)                    |
| 3  | tools/call    | `read_file` (read-only; allowed)               |
| 4  | tools/call    | `delete_record` (destructive; MUST deny)       |

When wired against `chio mcp serve` with `--receipt-db`, frame 2/3/4 can
produce persisted Chio receipts in the configured SQLite store. The default
`--check` mode does not run this path; the receipt assertion is available only
in `--full` mode when `CHIODOME_DEMO_ASSERT_RECEIPTS=1` and `CHIO_RECEIPT_DB`
are set.

## kb-stub-server-fixture.json

Stub MCP-server fixture in the shape `chio mcp wrap --e2e-fixture`
expects (`tools` + `responses` + `allow`). The `--check` smoke gate
in `run-with-kb-mcp.sh` runs `chio mcp wrap --e2e-fixture` with this
file so the script is exercisable end-to-end with NO running KB MCP.

The wrap path produces per-frame attestation transcripts but does not
sign full Chio receipts; that path requires `chio mcp serve` against a
real upstream MCP server. See the script's `--check` mode for the
mediation-transcript sink and the `--full` mode for the real KB-MCP path.
