# MCP receipt association

A tools/call result produced from a kernel response includes:

```json
{
  "_meta": {
    "chioReceipt": {
      "receiptId": "<content-derived receipt ID>",
      "requestId": "<kernel request ID>"
    }
  }
}
```

The edge takes these identities from the evaluated response and operation
context. Tool-returned metadata cannot override this association. The kernel
request ID is distinct from the client's JSON-RPC ID. Existing execution-nonce
metadata is preserved.

Use receiptId for an exact lookup with the same authorized receipt read boundary
as the application. `chio receipt explain RECEIPT_ID --admin-all` supports a
local administrative lookup when the matching `--receipt-db` is supplied.
The scaffold's demo prints and explains this ID after each call, including when
previous demo calls exist in the same database.

Metadata identifies evidence; it is not a signature-verification result or
proof of an external effect. Preflight and pending decisions retain their
existing semantics. A refusal before kernel evaluation has no kernel response
and does not acquire a fabricated receipt ID. Clients must tolerate that absence.

Independent `chio check` invocations use fresh request IDs, including when they
share persistent admission state. Repeating a CLI invocation requests another
policy evaluation; it is not an idempotent retry of the previous invocation.
