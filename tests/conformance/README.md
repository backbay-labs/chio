# Chio Conformance Fixtures

This directory holds the E8 Slice A interoperability and conformance assets.

Structure:

- `scenarios/`
  Versioned scenario descriptors used by the harness.
- `results/`
  Machine-readable result artifacts. Generated output should land here or in CI artifacts.
- `peers/`
  External peer fixtures and bootstrap assets for JavaScript and Python, plus the Go live lanes.
- `fixtures/`
  Shared policies, manifests, and transcripts used by scenarios.
- `reports/`
  Generated Markdown summaries derived from JSON result artifacts.

Rules:

- scenario descriptors are the source of truth for scenario identity and categorization
- reports are generated, not hand-edited
- peer assets should be minimal, explicit, and easy to reproduce in CI
- Chio-specific trust assertions should be reported separately from MCP-core compatibility

The MCP core scenario set lives under `scenarios/mcp_core/`.

Generate a sample Markdown matrix from the checked-in sample result artifact with:

```bash
cargo run -p chio-conformance --bin chio-conformance-report -- \
  --scenarios-dir tests/conformance/scenarios \
  --results-dir tests/conformance/results \
  --output /tmp/chio-compatibility-matrix.md
```

Run the live MCP core remote HTTP harness with real JS and Python peers:

```bash
cargo run -p chio-conformance --bin chio-conformance-runner --
```

By default that command:

- boots `chio mcp serve-http` against `fixtures/mcp_core/mock_mcp_server.py`
- runs the JS and Python client peers against the remote edge
- writes JSON result artifacts under `tests/conformance/results/generated/mcp-core-live/`
- writes a generated report to `tests/conformance/reports/generated/mcp-core-live.md`

Task scenarios live under `scenarios/tasks/`.
Auth scenarios live under `scenarios/auth/`.
Notification scenarios live under `scenarios/notifications/`.
Nested callback scenarios live under `scenarios/nested_callbacks/`.
The native Chio conformance lane lives under `native/`.

Current live status:

- MCP core remote HTTP matrix is green across the JS and Python peers
- MCP core remote HTTP lane is also green for the Go peer
- Task creation, `tasks/get`, and `tasks/result` are green across the JS and Python peers
- `tasks/cancel` is green across the JS and Python peers for the remote HTTP wrapped-tool path
- Task creation, `tasks/get`, `tasks/result`, and `tasks/cancel` are also green for the Go peer
- Remote HTTP auth/discovery is green across the JS and Python peers, including protected-resource metadata, authorization-server metadata, auth-code initialization, token-exchange initialization, and unauthenticated `WWW-Authenticate` challenges
- Remote HTTP auth/discovery is also green for the Go peer, including protected-resource metadata, authorization-server metadata, auth-code initialization, token-exchange initialization, and unauthenticated `WWW-Authenticate` challenges
- Remote HTTP notifications/subscriptions are green across the JS and Python peers, including `resources/subscribe`, forwarded `notifications/resources/updated`, and forwarded resource/tool/prompt `list_changed` notifications
- Remote HTTP notifications/subscriptions are also green for the Go peer
- Remote HTTP nested callbacks are green across the JS and Python peers, including `sampling/createMessage`, form-mode `elicitation/create`, URL-mode `elicitation/create` plus `notifications/elicitation/complete`, and `roots/list`
- Remote HTTP nested callbacks are also green for the Go peer, including `sampling/createMessage`, form-mode `elicitation/create`, URL-mode `elicitation/create` plus `notifications/elicitation/complete`, and `roots/list`

Generate the auth matrix against the local OAuth-backed edge with:

```bash
cargo run -p chio-conformance --bin chio-conformance-runner -- \
  --auth-mode oauth-local \
  --scenarios-dir tests/conformance/scenarios/auth \
  --results-dir tests/conformance/results/generated/auth \
  --report-output tests/conformance/reports/generated/auth.md
```

Generate the notification matrix with:

```bash
cargo run -p chio-conformance --bin chio-conformance-runner -- \
  --scenarios-dir tests/conformance/scenarios/notifications \
  --results-dir tests/conformance/results/generated/notifications \
  --report-output tests/conformance/reports/generated/notifications.md
```

Generate the nested callback matrix with:

```bash
cargo run -p chio-conformance --bin chio-conformance-runner -- \
  --scenarios-dir tests/conformance/scenarios/nested_callbacks \
  --results-dir tests/conformance/results/generated/nested-callbacks \
  --report-output tests/conformance/reports/generated/nested-callbacks.md
```

Run the Go live lanes with:

```bash
cargo run -p chio-conformance --bin chio-conformance-runner -- \
  --peer go \
  --scenarios-dir tests/conformance/scenarios/mcp_core \
  --results-dir tests/conformance/results/generated/mcp-core-go-live \
  --report-output tests/conformance/reports/generated/mcp-core-go-live.md
```

```bash
cargo run -p chio-conformance --bin chio-conformance-runner -- \
  --peer go \
  --auth-mode oauth-local \
  --scenarios-dir tests/conformance/scenarios/auth \
  --results-dir tests/conformance/results/generated/auth-go-live \
  --report-output tests/conformance/reports/generated/auth-go-live.md
```

Run the C++ hosted MCP lane with:

```bash
cargo run -p chio-conformance --bin chio-conformance-runner -- \
  --peer cpp \
  --scenarios-dir tests/conformance/scenarios/mcp_core \
  --results-dir tests/conformance/results/generated/mcp-core-cpp-live \
  --report-output tests/conformance/reports/generated/mcp-core-cpp-live.md
```

The C++ peer builds `sdks/cpp/chio-cpp` and uses the SDK curl transport for
live HTTP. It should remain green across MCP core, tasks, auth, notifications,
and nested callbacks.

Run the dedicated native Chio lane with:

```bash
target/debug/chio-native-conformance-fixture --http-listen 127.0.0.1:9954
```

```bash
target/debug/chio-native-conformance-runner \
  --scenarios-dir tests/conformance/native/scenarios \
  --results-output tests/conformance/native/results/generated/chio-self.json \
  --report-output tests/conformance/native/reports/generated/chio-self.md \
  --stdio-command target/debug/chio-native-conformance-fixture \
  --http-base-url http://127.0.0.1:9954
```
