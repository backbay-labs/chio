# Anthropic SDK Example

This example shows how to expose Chio-governed tools to Claude through the
Anthropic SDK while the hosted session itself is managed by
`@chio-protocol/sdk`.

## What it does

- initializes a hosted Chio session through `@chio-protocol/sdk`
- lists tools from the hosted edge and maps them into Anthropic tool
  definitions
- routes `tool_use` requests back through Chio's typed client
- resolves the resulting receipt through the trust service query API

## Prerequisites

- Node.js 22+
- the phase `309` demo stack running locally, or equivalent direct
  `chio trust serve` plus `chio mcp serve-http` processes
- optional: `ANTHROPIC_API_KEY` for a live Claude call

## Install

From this directory:

```bash
npm --prefix ../../sdks/typescript/chio-ts ci
npm --prefix ../../sdks/typescript/chio-ts run build
npm install
```

## Offline verification

The script defaults to the Docker quickstart endpoints:

- `CHIO_BASE_URL=http://127.0.0.1:8931`
- `CHIO_CONTROL_URL=http://127.0.0.1:8940`
- `CHIO_AUTH_TOKEN=demo-token`

`--dry-run` exercises the Chio SDK path only. It initializes the hosted session,
lists tools, performs a governed `echo_text` call, and resolves the resulting
receipt.

```bash
node run.mjs --dry-run
```

## Live Claude run

```bash
ANTHROPIC_API_KEY=... node run.mjs "Use the echo_text tool to say hello from Claude."
```

Optional environment variables:

- `ANTHROPIC_MODEL`: defaults to `claude-sonnet-4-20250514`
- `CHIO_BASE_URL`: hosted edge base URL
- `CHIO_CONTROL_URL`: trust service base URL
- `CHIO_AUTH_TOKEN`: bearer token accepted by both services

See also:

- [docs/start-here/PROGRESSIVE_TUTORIAL.md](../../docs/start-here/PROGRESSIVE_TUTORIAL.md)
- [examples/docker/README.md](../docker/README.md)
