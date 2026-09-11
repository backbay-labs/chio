# Agent protocol clients

Run the official A2A Python client against a Chio-governed HTTP agent:

```sh
uv run --locked a2a_client.py "Review the release checklist"
```

The command builds the Rust host, starts it on an available loopback port, pins
its kernel key and connects with a random application credential. Discovery,
SendMessage and GetTask use a2a-sdk 1.1.2 over HTTP JSON-RPC, using A2A 1.0
protobuf JSON. The default authority grants two document counts. The third
call is refused and retains its own signed receipt. An identical message retry
returns the original task and does not consume another invocation.

Each run retains its authority, SQLite receipts, wire exchange and verified
results in `.state/a2a-<run-id>`. The token and signing material stay in the
private local state directory. The capture contains public keys and results.
A missing application credential is rejected before execution.

The verifier checks the operator-selected signer, exact input, stable message
association, every retained stream chunk, the projected artifact and task
lookup. Protocol task lookup is scoped to the caller and retained in memory
for five minutes, up to 128 results. The kernel's SQLite receipts remain after
the host stops. This blocking agent advertises no SSE or push notifications;
it rejects asynchronous/continuation requests it cannot fulfill.

`authority.json` controls the tool grant. The qualification client expects the
default two-invocation allowance to prove its third-call refusal. The host
accepts only new state directories and never overwrites an earlier run.
