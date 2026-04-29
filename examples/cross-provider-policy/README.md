# Cross-provider policy demo

This example proves that one Chio policy can be evaluated against semantically equivalent OpenAI, Anthropic, and Bedrock tool-call fixtures without live provider credentials.

Run:

```bash
cargo run -p cross-provider-policy --quiet -- --dry-run
```

The dry run loads `policy.yaml`, replays the deterministic single-weather-tool fixtures through the native provider replay harness, and emits three normalized receipt bodies. The receipts keep provider provenance (`provider`, `request_id`, `api_version`, `principal`, `received_at`) intact, while the policy id, tool name, arguments, and verdict are asserted byte-equal after canonical JSON normalization.

The command is offline-only. It reads the fixture corpus under `crates/chio-provider-conformance/fixtures/{openai,anthropic,bedrock}` and does not require OpenAI, Anthropic, AWS, or STS credentials.
