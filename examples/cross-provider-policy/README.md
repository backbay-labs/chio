# Cross-provider policy demo

This example proves that one Chio policy can be evaluated against semantically equivalent tool-call fixtures across all eight native provider adapters without live provider credentials.

Run:

```bash
cargo run -p cross-provider-policy --quiet -- --dry-run
```

The dry run loads `policy.yaml`, evaluates the deterministic single-weather-tool fixtures, and emits eight normalized receipt bodies (OpenAI, Anthropic, Bedrock, Gemini, Mistral, Groq, Ollama, Cohere). The receipts keep provider provenance (`provider`, `request_id`, `api_version`, `principal`, `received_at`) intact, while the policy id, tool name, arguments, and verdict are asserted byte-equal after canonical JSON normalization.

The deep adapter replay harness covers the OpenAI, Anthropic, and Bedrock providers. The Gemini, Mistral, Groq, Ollama, and Cohere providers use the NDJSON capture path that backs the cross-provider verdict-equality oracle.

The command is offline-only. It reads the fixture corpus under `crates/chio-provider-conformance/fixtures/{openai,anthropic,bedrock,gemini,mistral,groq,ollama,cohere}` and does not require any upstream credentials.
