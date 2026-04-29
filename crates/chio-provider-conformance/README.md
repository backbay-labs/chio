# chio-provider-conformance

Replay and re-record provider-native Chio conformance fixtures.

## Replay fixtures

The crate stores canonical NDJSON captures under `fixtures/<provider>/`.
Each line uses `chio-provider-conformance.capture.v1` and is consumed by the
replay tests for OpenAI, Anthropic, and Bedrock.

## Re-record fixtures

Use the record CLI from the workspace root:

```bash
cargo run -p chio-provider-conformance --bin record -- \
  --provider openai \
  --scenario openai_basic_single_tool_call
```

Supported providers are `openai`, `anthropic`, and `bedrock`. The `--scenario`
value is the fixture id without `.ndjson`; the CLI rejects path-like values and
only writes inside `crates/chio-provider-conformance/fixtures/<provider>/`.

Required environment:

| Provider | Environment |
| --- | --- |
| OpenAI | `OPENAI_API_KEY`, `OPENAI_ORGANIZATION` |
| Anthropic | `ANTHROPIC_API_KEY`, `CHIO_ANTHROPIC_WORKSPACE_ID` |
| Bedrock | `AWS_PROFILE` or `AWS_ACCESS_KEY_ID` plus `AWS_SECRET_ACCESS_KEY` |

The recorder uses the existing fixture as the scenario seed, sends the seeded
provider request to the live upstream API, records the upstream response or SSE
events, regenerates allow verdict records from the adapter lift path, and
rewrites the fixture atomically. Bedrock non-streaming capture uses the AWS CLI
for `bedrock-runtime converse`; Bedrock streaming scenarios remain a
fail-closed unsupported path until the event-stream SDK capture lands.

## API-pin bump workflow

1. Bump the provider API pin in the adapter crate metadata or transport
   constant.
2. Export the provider credentials listed above.
3. Re-record each affected fixture scenario with `record`.
4. Run the provider replay tests for the affected corpus.
5. Include the pin change and fixture diff in one reviewable PR.
