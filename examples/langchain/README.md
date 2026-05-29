# LangChain Tool Example

This example wraps a Chio-governed hosted-edge tool as a LangChain
`StructuredTool` while the hosted session itself is managed by `chio-sdk`.

## What it does

- initializes a hosted Chio session through `chio-sdk`
- lists tools from the hosted HTTP edge
- exposes the governed tool as a LangChain `StructuredTool`
- invokes the tool through LangChain while Chio policy enforcement remains in
  the execution path
- resolves the resulting receipt through the trust service query API

## Install

From this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ../../sdks/python/chio-py -e .
```

## Run

```bash
python run.py
```

The script defaults to the phase `309` Docker quickstart endpoints:

- `CHIO_BASE_URL=http://127.0.0.1:8931`
- `CHIO_CONTROL_URL=http://127.0.0.1:8940`
- `CHIO_AUTH_TOKEN=demo-token`

The example prints a JSON summary containing the hosted session ID, active
capability ID, tool inventory, echoed payload, and receipt ID.

Optional environment variables:

- `CHIO_BASE_URL`: hosted edge base URL
- `CHIO_CONTROL_URL`: trust service base URL
- `CHIO_AUTH_TOKEN`: bearer token accepted by both services
- `CHIO_MESSAGE`: override the demo input message

See also:

- [docs/start-here/PROGRESSIVE_TUTORIAL.md](../../docs/start-here/PROGRESSIVE_TUTORIAL.md)
- [examples/docker/README.md](../docker/README.md)
