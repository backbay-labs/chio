# `chio-go`

Pure-Go SDK for the Chio trust and receipt-control plane.

Current scope:

- pure-Go invariant helpers backed by the shared bindings vectors
- remote HTTP transport helpers for JSON-RPC over streamable HTTP
- beta `Client` and `Session` APIs for initialize/session, tools/resources/prompts, notifications, tasks, and nested callbacks
- auth discovery helpers and hosted OAuth flow helpers
- nested callback routing helpers for sampling, elicitation, and roots
- task, subscription, completion, and log-level helpers on `Session`
- `CGO_ENABLED=0` support by default
- no CGO bridge requirement

Current release posture:

- release-ready beta with live conformance coverage across MCP core, tasks, auth, notifications, and nested callbacks
- module version plumbing, consumer-build smoke checks, and release qualification are in place
- aligned to the current Chio protocol and release docs
- broader external publication through Git tags and proxy propagation remains a later 1.0 milestone

Current live conformance coverage:

- MCP core: initialize/session, tools/resources/prompts
- Tasks: task creation, progress, and cancellation
- Auth: discovery, authorization-code initialize, and token-exchange initialize
- Notifications: subscriptions and list-change events
- Nested callbacks: sampling, elicitation, and roots callbacks

Current beta limitations:

- the package should be treated as beta, not yet 1.0 stable
- broad external publishing and compatibility validation still need hardening
- no CGO/native bridge is provided or required

Run the current checks with:

```sh
CGO_ENABLED=0 go test ./...
```

Run the current live Go conformance lanes with:

```sh
cargo test -p chio-conformance --test mcp_core_go_live --test tasks_go_live --test auth_go_live --test notifications_go_live --test nested_callbacks_go_live -- --nocapture
```

Run the release qualification with:

```sh
./scripts/check-chio-go-release.sh
```

Release process details live in [RELEASING.md](./RELEASING.md).
