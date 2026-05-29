# OpenAI-Compatible Example

This example demonstrates Chio governance over function calling by mapping the
hosted edge tool inventory into OpenAI Chat Completions tool definitions and
executing the returned function calls through `@chio-protocol/sdk`.

## What it does

- initializes a hosted Chio session through `@chio-protocol/sdk`
- lists tools from the hosted edge and converts them into OpenAI-compatible
  function definitions
- routes tool calls back through Chio's typed client
- resolves the resulting receipt through the trust service query API

## Prerequisites

- Node.js 22+
- the phase `309` demo stack running locally, or equivalent direct
  `chio trust serve` plus `chio mcp serve-http` processes
- optional: an OpenAI-compatible Chat Completions endpoint and API key for a
  live function-calling run

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

## Live OpenAI-Compatible Run

```bash
OPENAI_API_KEY=... node run.mjs "Use the echo_text function to say hello from GPT."
```

Optional environment variables:

- `OPENAI_MODEL`: defaults to `gpt-5-mini`
- `OPENAI_BASE_URL`: override the Chat Completions base URL for another
  OpenAI-compatible provider
- `CHIO_BASE_URL`: hosted edge base URL
- `CHIO_CONTROL_URL`: trust service base URL
- `CHIO_AUTH_TOKEN`: bearer token accepted by both services

See also:

- [docs/start-here/PROGRESSIVE_TUTORIAL.md](../../docs/start-here/PROGRESSIVE_TUTORIAL.md)
- [examples/docker/README.md](../docker/README.md)
