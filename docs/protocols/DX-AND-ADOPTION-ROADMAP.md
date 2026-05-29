# DX and Adoption Roadmap

**Status:** Draft
**Date:** 2026-04-15

> A DX review found four critical adoption blockers: zero packages published to
> any registry, no way to test without a running kernel, no 5-minute quickstart
> for non-Rust developers, and zero framework integrations shipping as code.
> This document plans the fix for each, ordered by impact on time-to-first-tool-call.

---

## 1. Package Publishing Plan

### 1.1 Current State

Every SDK is path-referenced. `chio-fastapi` depends on `chio-sdk-python` via
`path = "../chio-sdk-python"` in `tool.uv.sources`. The TypeScript packages
(`@chio-protocol/node-http`, `@chio-protocol/fastify`, `@chio-protocol/express`,
`@chio-protocol/elysia`) have no `publishConfig` and are not on npm. A developer
cannot `pip install` or `npm install` anything. This means zero organic
discovery through registry search, zero integration with dependency scanners,
and zero ability to pin a known-good version.

### 1.2 Priority Order

| Order | Package | Registry | Why first |
|-------|---------|----------|-----------|
| 1 | `chio-sdk-python` | PyPI | Foundation -- every Python integration depends on it |
| 2 | `chio-fastapi` | PyPI | Most popular Python web framework for AI backends |
| 3 | `chio-langchain` | PyPI | Largest agent framework ecosystem |
| 4 | `@chio-protocol/node-http` | npm | Foundation -- every TS integration depends on it |
| 5 | `@chio-protocol/fastify` | npm | Popular TS server framework |
| 6 | `@chio-protocol/express` | npm | Widest TS server adoption |
| 7 | `chio-asgi` | PyPI | Needed by chio-fastapi and chio-django, publish to decouple |
| 8 | `chio-django` | PyPI | Second most popular Python web framework |

Rust crates (`chio-core`, `chio-kernel`, `chio-manifest`, `chio-mcp-adapter`) should
publish to crates.io after the SDK packages ship. The Rust crates serve
infrastructure authors, not the primary adoption funnel.

### 1.3 Versioning Strategy

All packages start at `0.1.0` (already declared in pyproject.toml / package.json).
Follow semantic versioning with these rules:

- **0.x.y**: pre-1.0 breaking changes allowed in minor bumps.
- All packages in the same language share a version. `chio-sdk-python` 0.2.0 and
  `chio-fastapi` 0.2.0 are tested together. This avoids a matrix explosion of
  cross-version compatibility.
- The `chio-sdk-python` dependency spec in downstream packages uses `>=0.x.0,<0.y.0`
  (compatible minor range) so that patch releases propagate without pinning.

### 1.4 CI/CD for Automated Publishing

```
on:
  push:
    tags: ["py-v*"]       # triggers Python publish
    tags: ["ts-v*"]       # triggers TypeScript publish
    tags: ["rs-v*"]       # triggers Rust publish

jobs:
  publish-python:
    steps:
      - checkout
      - uv sync
      - uv run pytest (all Python SDK packages)
      - uv build --package chio-sdk-python
      - uv build --package chio-asgi
      - uv build --package chio-fastapi
      - uv build --package chio-langchain
      - twine upload dist/*
    secrets:
      PYPI_API_TOKEN (scoped to chio-* packages)

  publish-typescript:
    steps:
      - checkout
      - cd sdks/typescript
      - npm ci --workspaces
      - npm test --workspaces
      - npm publish --workspace packages/node-http --access public
      - npm publish --workspace packages/fastify --access public
      - npm publish --workspace packages/express --access public
      - npm publish --workspace packages/elysia --access public
    secrets:
      NPM_TOKEN (scoped to @chio-protocol org)
```

Each publish job runs the full test suite first. Tags are separate per language
so a Python-only change does not trigger an npm publish.

### 1.5 Pre-publish Checklist (per package)

- [ ] README with install, 3-line usage, link to docs
- [ ] `py.typed` marker (Python) or `types` field (TypeScript)
- [ ] License file included in distribution
- [ ] `project.urls` / `repository` field pointing to GitHub
- [ ] At least 3 passing tests
- [ ] No path-only dependencies remaining (all `>=x.y.z` on registry)

---

## 2. Testing Without the Kernel

### 2.1 Problem

Every `ChioClient` method makes an HTTP call to `http://127.0.0.1:9090`. There
is no `MockChioClient`, no `allow_all()` fixture, no dry-run mode. A developer
writing a LangChain tool cannot test their Chio integration without compiling
and running the Rust sidecar binary. This blocks:

- Unit tests in CI (no Rust toolchain available)
- Local development iteration (compile time)
- Framework integration authors who need fast feedback loops

### 2.2 Python: `chio_sdk.testing` Module

Ship a `testing` submodule in `chio-sdk-python` with zero additional dependencies
(uses only `chio_sdk.models` and `chio_sdk.errors`).

```python
from chio_sdk.testing import MockChioClient, allow_all, deny_all, with_policy

# -- Quick fixtures for common cases --

async def test_tool_allowed():
    """allow_all() returns a mock client that approves every tool call."""
    client = allow_all()
    receipt = await client.evaluate_tool_call(
        capability_id="test-cap",
        tool_server="fs",
        tool_name="read_file",
        parameters={"path": "/tmp/hello.txt"},
    )
    assert receipt.is_allowed
    assert receipt.tool_name == "read_file"
    assert receipt.signature != ""  # deterministic test signature


async def test_tool_denied():
    """deny_all() returns a mock client that denies every tool call."""
    client = deny_all()
    receipt = await client.evaluate_tool_call(
        capability_id="test-cap",
        tool_server="fs",
        tool_name="write_file",
        parameters={"path": "/etc/passwd", "content": "pwned"},
    )
    assert receipt.is_denied
    assert receipt.decision.reason is not None


async def test_selective_policy():
    """with_policy() accepts a callback that receives the tool call and
    returns a Decision."""
    def my_policy(tool_server: str, tool_name: str, params: dict) -> "Decision":
        from chio_sdk.models import Decision
        if tool_name == "read_file":
            return Decision.allow()
        return Decision.deny(
            reason="write operations require approval",
            guard="test-policy",
        )

    client = with_policy(my_policy)

    r1 = await client.evaluate_tool_call(
        capability_id="cap-1",
        tool_server="fs",
        tool_name="read_file",
        parameters={"path": "/tmp/safe.txt"},
    )
    assert r1.is_allowed

    r2 = await client.evaluate_tool_call(
        capability_id="cap-1",
        tool_server="fs",
        tool_name="write_file",
        parameters={"path": "/tmp/unsafe.txt", "content": "data"},
    )
    assert r2.is_denied
```

### 2.3 `MockChioClient` Implementation Contract

`MockChioClient` is a drop-in replacement for `ChioClient`. It has the same
method signatures but never opens a network connection.

```python
class MockChioClient:
    """In-memory Chio client for testing. No sidecar required."""

    def __init__(
        self,
        *,
        policy: PolicyCallback | None = None,
        default_verdict: str = "allow",
    ) -> None: ...

    # Same public API as ChioClient:
    async def evaluate_tool_call(self, ...) -> ChioReceipt: ...
    async def evaluate_http_request(self, ...) -> EvaluateResponse: ...
    async def create_capability(self, ...) -> CapabilityToken: ...
    async def validate_capability(self, ...) -> bool: ...
    async def verify_receipt(self, ...) -> bool: ...
    async def health(self) -> dict[str, Any]: ...

    # Test inspection:
    @property
    def call_log(self) -> list[RecordedCall]: ...
    def assert_tool_called(self, tool_name: str, *, times: int = 1) -> None: ...
    def assert_tool_not_called(self, tool_name: str) -> None: ...
    def reset(self) -> None: ...
```

Receipts generated by `MockChioClient` use a deterministic test keypair so that
`verify_receipt()` works within the mock without a sidecar. The `call_log`
property records every evaluation for test assertions.

### 2.4 TypeScript: `@chio-protocol/node-http/testing`

Same pattern, exported from a `/testing` subpath:

```typescript
import { mockChioClient, allowAll, denyAll, withPolicy } from "@chio-protocol/node-http/testing";

// allowAll() -- every tool call returns an allow receipt
const client = allowAll();

// denyAll() -- every tool call returns a deny receipt
const client = denyAll();

// withPolicy() -- custom decision logic
const client = withPolicy((server, tool, params) => {
  if (tool === "read_file") return { verdict: "allow" };
  return { verdict: "deny", reason: "blocked by test policy", guard: "test" };
});

// Inspection
client.callLog; // RecordedCall[]
client.assertToolCalled("read_file", { times: 1 });
client.reset();
```

### 2.5 Framework Integration Test Helpers

Each framework integration package should re-export its language's mock client
with framework-specific wiring. For example, `chio-fastapi` should export a
pytest fixture:

```python
# In chio_fastapi.testing:
import pytest
from chio_sdk.testing import MockChioClient, allow_all

@pytest.fixture
def chio_client() -> MockChioClient:
    return allow_all()

@pytest.fixture
def chio_app(chio_client: MockChioClient):
    """FastAPI TestClient with Chio middleware using the mock client."""
    from fastapi.testclient import TestClient
    # ... wire up middleware with chio_client ...
```

---

## 3. Five-Minute Quickstart Path

### 3.1 Goal

A Python developer with no Rust toolchain runs their first Chio-protected tool
call in under 5 minutes. The path has three steps: install SDK, start sidecar,
run code.

### 3.2 Step 1: Install the SDK

```bash
pip install chio-sdk-python
```

This is blocked on section 1 (package publishing). Until then, the quickstart
uses a git-based install:

```bash
pip install "chio-sdk-python @ git+https://github.com/backbay-labs/chio.git#subdirectory=sdks/python/chio-sdk-python"
```

### 3.3 Step 2: Start the Sidecar

Four distribution channels, ordered by ease of use:

**Option A: Docker (zero install)**

```bash
docker run -p 9090:9090 ghcr.io/backbay-labs/chio-sidecar:latest
```

The container bundles the `chio` binary with a permissive default policy. It
listens on port 9090 and logs to stderr.

**Option B: Homebrew (macOS/Linux)**

```bash
brew install backbay/tap/chio
chio mcp serve --policy default.toml
```

The tap publishes pre-built binaries for `darwin-arm64`, `darwin-x86_64`,
`linux-arm64`, and `linux-x86_64`.

**Option C: cargo-binstall (Rust users)**

```bash
cargo binstall chio-cli
chio mcp serve --policy default.toml
```

Downloads pre-built binaries from GitHub Releases instead of compiling.

**Option D: npx (Node developers)**

```bash
npx @chio-protocol/sidecar
```

The `@chio-protocol/sidecar` npm package contains platform-specific binaries
selected at install time via `optionalDependencies` (same pattern as
`@esbuild/*`, `@swc/*`). Supported platforms:

| Platform | Package |
|----------|---------|
| macOS arm64 | `@chio-protocol/sidecar-darwin-arm64` |
| macOS x86_64 | `@chio-protocol/sidecar-darwin-x64` |
| Linux arm64 | `@chio-protocol/sidecar-linux-arm64` |
| Linux x86_64 | `@chio-protocol/sidecar-linux-x64` |
| Windows arm64 | `@chio-protocol/sidecar-win32-arm64` |
| Windows x86_64 | `@chio-protocol/sidecar-win32-x64` |

### 3.4 GitHub Releases Binary Matrix

Every tagged release publishes pre-built binaries:

```
chio-v0.1.0-darwin-arm64.tar.gz
chio-v0.1.0-darwin-x64.tar.gz
chio-v0.1.0-linux-arm64.tar.gz
chio-v0.1.0-linux-x64.tar.gz
chio-v0.1.0-win32-arm64.zip
chio-v0.1.0-win32-x64.zip
```

Built in CI using cross-compilation (`cross` for Linux, native for macOS,
`cross` or `cargo-xwin` for Windows). SHA-256 checksums published alongside
each archive.

### 3.5 Step 3: Run the Quickstart

The complete quickstart tutorial -- 10 lines of Python to protect a tool call:

```python
# quickstart.py -- protect a tool call with Chio in 10 lines
import asyncio
from chio_sdk import ChioClient, ChioScope, ToolGrant, Operation

async def main():
    async with ChioClient() as chio:
        # 1. Create a capability that only allows read_file on the "fs" server
        scope = ChioScope(grants=[
            ToolGrant(server_id="fs", tool_name="read_file", operations=[Operation.INVOKE])
        ])
        cap = await chio.create_capability(subject="agent-001", scope=scope)

        # 2. Evaluate a tool call -- kernel checks scope, runs guards, signs receipt
        receipt = await chio.evaluate_tool_call(
            capability_id=cap.id, tool_server="fs",
            tool_name="read_file", parameters={"path": "/tmp/hello.txt"},
        )
        print(f"Decision: {receipt.decision.verdict}")  # "allow"
        print(f"Receipt:  {receipt.id}")                 # signed proof

        # 3. Try an unauthorized tool -- kernel denies it
        receipt2 = await chio.evaluate_tool_call(
            capability_id=cap.id, tool_server="fs",
            tool_name="write_file", parameters={"path": "/etc/passwd", "content": "x"},
        )
        print(f"Decision: {receipt2.decision.verdict}")  # "deny"

asyncio.run(main())
```

Output:

```
Decision: allow
Receipt:  chio-receipt-a1b2c3d4
Decision: deny
```

### 3.6 Quickstart Without a Sidecar (Testing Mode)

For developers who want to try the API without any binary at all:

```python
# quickstart_testing.py -- no sidecar needed
import asyncio
from chio_sdk.testing import allow_all

async def main():
    client = allow_all()
    receipt = await client.evaluate_tool_call(
        capability_id="demo", tool_server="fs",
        tool_name="read_file", parameters={"path": "/tmp/hello.txt"},
    )
    print(f"Decision: {receipt.decision.verdict}")  # "allow"
    print(f"Receipt:  {receipt.id}")
    print(f"(mock -- no sidecar running)")

asyncio.run(main())
```

This path lets developers evaluate the API shape before committing to running
infrastructure.

---

## 4. Flagship Integration: `chio-code-agent`

### 4.1 Rationale

Coding agents (Claude Code, Cursor, Windsurf, any MCP-based coding agent) are
the highest-volume tool-calling pattern today and Chio's best-covered use case.
The review found that coding agents are the clearest onboarding path (section
4 of REVIEW-FINDINGS-AND-NEXT-STEPS.md). An `chio-code-agent` package serves as
both the primary demo ("this is what Chio does") and a production-ready tool.

### 4.2 What It Does

`chio-code-agent` wraps file, shell, and git tool calls for coding agents with:

- **File system scoping**: read allowed anywhere in project, write restricted
  to project directory, no writes to dotfiles or config outside project root.
- **Shell command governance**: allowlist of safe commands (ls, cat, grep, git
  status, git diff), denylist of destructive commands (rm -rf, chmod 777,
  curl | bash), command length limits.
- **Git operation scoping**: commit and branch allowed, force-push denied,
  rebase restricted to local branches.
- **Zero-config defaults**: ships with a sensible default policy that works
  out of the box. Override with a local policy YAML file.

### 4.3 Zero-Config Default Policy

```toml
# chio-code-agent default policy (built-in, override with --policy path/to/policy.yaml)

[[server]]
id = "filesystem"

[[server.tool]]
name = "read_file"
allow = true

[[server.tool]]
name = "write_file"
allow = true
constraints = [
    { type = "path_prefix", value = "." },       # project root only
    { type = "regex_match", value = "^(?!.*(\\.env|\\.ssh|credentials))" },
]

[[server.tool]]
name = "list_directory"
allow = true

[[server]]
id = "shell"

[[server.tool]]
name = "execute"
allow = true
constraints = [
    { type = "max_length", value = 500 },  # command length limit
]
deny_patterns = [
    "rm -rf /",
    "chmod 777",
    "curl.*| bash",
    "wget.*| sh",
    "> /dev/sd",
]

[[server]]
id = "git"

[[server.tool]]
name = "*"
allow = true
deny_patterns = [
    "push --force",
    "push -f",
    "reset --hard",
    "clean -fd",
]
```

### 4.4 Integration Modes

**Mode 1: MCP sidecar (works with any MCP client)**

```bash
# NOTE: --policy takes a YAML file path, not a bare policy name.
# The chio-code-agent default policy ships as a built-in; custom overrides
# use --policy ./my-policy.yaml
chio mcp serve --policy ./chio-code-agent-policy.yaml --server-id filesystem -- npx @modelcontextprotocol/server-filesystem .
```

The Chio kernel sits between the MCP client (Claude Code, Cursor) and the MCP
tool server. Every tool call is evaluated, every result gets a receipt.

**Mode 2: Python wrapper (for custom agents)**

```python
from chio_code_agent import CodeAgent

agent = CodeAgent(project_root=".")
result = await agent.read_file("src/main.py")       # allowed
result = await agent.write_file(".env", "SECRET=x")  # denied
result = await agent.shell("ls -la")                  # allowed
result = await agent.shell("rm -rf /")                # denied
```

### 4.5 The "This Is What Chio Does" Demo

The demo script that goes on the landing page and in every conference talk:

```bash
# Terminal 1: start the sidecar with coding agent policy
# NOTE: --policy takes a file path. The Docker image bundles a default
# policy at /etc/chio/code-agent-policy.yaml for the demo.
docker run -p 9090:9090 ghcr.io/backbay-labs/chio-sidecar:latest --policy /etc/chio/code-agent-policy.yaml

# Terminal 2: try safe and unsafe operations
python -c "
import asyncio
from chio_sdk import ChioClient

async def demo():
    async with ChioClient() as chio:
        # Safe: read a file
        r = await chio.evaluate_tool_call(
            capability_id='agent-1', tool_server='filesystem',
            tool_name='read_file', parameters={'path': 'src/main.py'})
        print(f'read_file: {r.decision.verdict}')     # allow

        # Unsafe: write to .env
        r = await chio.evaluate_tool_call(
            capability_id='agent-1', tool_server='filesystem',
            tool_name='write_file', parameters={'path': '.env', 'content': 'KEY=stolen'})
        print(f'write .env: {r.decision.verdict}')    # deny

        # Unsafe: destructive shell
        r = await chio.evaluate_tool_call(
            capability_id='agent-1', tool_server='shell',
            tool_name='execute', parameters={'command': 'rm -rf /'})
        print(f'rm -rf /: {r.decision.verdict}')      # deny

asyncio.run(demo())
"
```

Output:

```
read_file: allow
write .env: deny -- constraint violation: path matches deny pattern (.env)
rm -rf /: deny -- constraint violation: command matches deny pattern (rm -rf /)
```

---

## 5. Framework Integration Shipping Plan

### 5.1 Shipping Criteria (per integration)

Every framework integration must meet this bar before publishing:

1. **Working package** installable from the registry with `pip install` or
   `npm install`.
2. **3 tests minimum**: one allow path, one deny path, one receipt verification.
   Tests must pass without a running sidecar (use `MockChioClient`).
3. **README** with a complete example (install, configure, use).

### 5.2 CrewAI: `chio-crewai`

CrewAI is the highest priority because it has the largest mindshare among
multi-agent frameworks and the worst default trust model (every agent can call
every tool with no authorization check).

```python
# pip install chio-crewai

from crewai import Agent, Task, Crew
from chio_crewai import ChioBaseTool, chio_crew

# Wrap any CrewAI tool with Chio governance
class SecureFileReader(ChioBaseTool):
    name = "read_file"
    server_id = "filesystem"
    description = "Read a file from the project directory"

    def _run(self, path: str) -> str:
        return open(path).read()

# Per-role scoping: researcher can only read, writer can read+write
researcher = Agent(
    role="researcher",
    tools=[SecureFileReader()],
    chio_scope=ChioScope(grants=[
        ToolGrant(server_id="filesystem", tool_name="read_file",
                  operations=[Operation.INVOKE]),
    ]),
)

writer = Agent(
    role="writer",
    tools=[SecureFileReader(), SecureFileWriter()],
    chio_scope=ChioScope(grants=[
        ToolGrant(server_id="filesystem", tool_name="*",
                  operations=[Operation.INVOKE]),
    ]),
)

# chio_crew() wraps Crew to enforce per-agent capability scoping
crew = chio_crew(Crew(agents=[researcher, writer], tasks=[...]))
crew.kickoff()
```

**Key design choice**: `ChioBaseTool` extends CrewAI's `BaseTool` and
intercepts `_run()` / `_arun()` to call `chio_client.evaluate_tool_call()`
before delegating to the actual implementation. The `chio_scope` attribute on
`Agent` is used to create a per-agent capability token at crew startup.

### 5.3 AutoGen: `chio-autogen`

```python
# pip install chio-autogen

from autogen import AssistantAgent, UserProxyAgent
from chio_autogen import chio_function, ChioUserProxy

# Wrap function registration with Chio governance
@chio_function(server_id="calculator", tool_name="compute")
def compute(expression: str) -> str:
    return str(eval(expression))  # governed by Chio, not raw eval

# ChioUserProxy enforces capability checks before function execution
proxy = ChioUserProxy(
    name="user_proxy",
    chio_scope=ChioScope(grants=[
        ToolGrant(server_id="calculator", tool_name="compute",
                  operations=[Operation.INVOKE],
                  constraints=[Constraint.max_length(100)]),
    ]),
)
proxy.register_function({"compute": compute})
```

**Key design choice**: `@chio_function` is a decorator that wraps the registered
function. `ChioUserProxy` extends `UserProxyAgent` to inject capability tokens
into the execution context.

### 5.4 LlamaIndex: `chio-llamaindex`

```python
# pip install chio-llamaindex

from llama_index.core.tools import FunctionTool
from chio_llamaindex import ChioFunctionTool

# Wrap any LlamaIndex FunctionTool
def search_documents(query: str) -> str:
    return "results..."

tool = ChioFunctionTool.from_defaults(
    fn=search_documents,
    server_id="search",
    tool_name="search_documents",
)

# Use with any LlamaIndex agent -- Chio evaluates before execution
agent = OpenAIAgent.from_tools([tool])
```

**Key design choice**: `ChioFunctionTool` extends `FunctionTool` and overrides
`call()` / `acall()` to insert the evaluate/record cycle.

### 5.5 Vercel AI SDK: `@chio-protocol/ai-sdk`

```typescript
// npm install @chio-protocol/ai-sdk

import { tool } from "ai";
import { chioTool } from "@chio-protocol/ai-sdk";
import { z } from "zod";

// Wrap Vercel AI SDK tool() with Chio governance
const readFile = chioTool({
  serverId: "filesystem",
  toolName: "read_file",
  description: "Read a file",
  parameters: z.object({ path: z.string() }),
  execute: async ({ path }) => {
    return await fs.readFile(path, "utf-8");
  },
});

// Use with generateText / streamText -- Chio evaluates before execute()
const result = await generateText({
  model: openai("gpt-4o"),
  tools: { readFile },
  prompt: "Read the README",
});
```

**Key design choice**: `chioTool()` wraps the Vercel AI SDK `tool()` function.
It calls `chio.evaluate()` before `execute()` and `chio.record()` after. The
wrapper is transparent -- it returns a standard `Tool` object that works with
`generateText`, `streamText`, and `useChat`.

### 5.6 Shipping Timeline

| Week | Milestone |
|------|-----------|
| W1 | `chio-sdk-python` on PyPI, `chio_sdk.testing` module merged |
| W2 | `chio-crewai` package with 3 tests, published to PyPI |
| W3 | `@chio-protocol/node-http` on npm, `@chio-protocol/ai-sdk` with 3 tests |
| W4 | `chio-autogen` and `chio-llamaindex` packages with tests |
| W5 | `chio-code-agent` package with default policy and demo script |

---

## 6. Error Message Improvements

### 6.1 Current Error (Denied Tool Call)

```
ChioDeniedError: denied
```

That is the entire error. No tool name, no scope information, no guidance.

### 6.2 Proposed Error (Denied Tool Call)

```
Chio DENIED: tool "write_file" on server "filesystem"

  What was denied:
    write_file({ path: ".env", content: "SECRET=x" })

  Why it was denied:
    Constraint violation: path ".env" matches deny pattern "\.env"

  What scope was needed:
    ToolGrant(server_id="filesystem", tool_name="write_file",
              operations=[Invoke], constraints=[])

  What scope was granted:
    ToolGrant(server_id="filesystem", tool_name="write_file",
              operations=[Invoke],
              constraints=[path_prefix("."), regex_match("^(?!.*(\.env))")])

  Guard that denied:
    path-constraint-guard (built-in)

  Receipt ID:
    chio-receipt-7f3a9b2c

  Next steps:
    - If this tool call should be allowed, update your policy to remove
      the path constraint: https://docs.chio-protocol.dev/policies/constraints
    - If this is expected, the receipt above is your audit proof
    - Run `chio check --verbose --tool write_file --server filesystem`
      to trace the full guard evaluation pipeline
```

### 6.3 Implementation Changes

The `ChioDeniedError` class in `chio_sdk/errors.py` needs additional fields:

```python
class ChioDeniedError(ChioError):
    def __init__(
        self,
        message: str,
        *,
        guard: str | None = None,
        reason: str | None = None,
        tool_name: str | None = None,
        tool_server: str | None = None,
        parameters: dict | None = None,
        scope_needed: dict | None = None,
        scope_granted: dict | None = None,
        receipt_id: str | None = None,
        docs_url: str | None = None,
    ) -> None: ...
```

The sidecar's 403 response body must include these fields. The kernel already
has the information (it evaluates scope and runs guards) -- the gap is in the
response serialization.

### 6.4 Structured JSON Error (for programmatic consumers)

```json
{
  "code": "Chio-DENIED",
  "tool_name": "write_file",
  "tool_server": "filesystem",
  "reason": "Constraint violation: path matches deny pattern",
  "guard": "path-constraint-guard",
  "scope_needed": {
    "grants": [{"server_id": "filesystem", "tool_name": "write_file", "operations": ["Invoke"]}]
  },
  "scope_granted": {
    "grants": [{"server_id": "filesystem", "tool_name": "write_file", "operations": ["Invoke"],
                "constraints": [{"type": "regex_match", "value": "^(?!.*(\\. env))"}]}]
  },
  "receipt_id": "chio-receipt-7f3a9b2c",
  "docs_url": "https://docs.chio-protocol.dev/errors/Chio-DENIED",
  "suggested_fix": "Update your policy to remove the path constraint, or use a capability with broader scope."
}
```

The CLI already has `suggested_fix` and error code fields in its structured
output (see `write_cli_error` in `chio-cli/src/main.rs`). The SDK error path
needs to match that quality.

---

## 7. Migration Guides

### 7.1 Migrating from MCP to Chio

**Key message**: you do not replace your MCP server. You put Chio in front of it.

```
Before:
  MCP Client --> MCP Server (stdio/SSE)

After:
  MCP Client --> Chio Kernel --> MCP Server (stdio/SSE)
                 (evaluates)    (unchanged)
```

**Steps (3 commands)**:

```bash
# 1. Install Chio
brew install backbay/tap/chio

# 2. Write a minimal policy (or use the default)
cat > chio-policy.yaml << 'EOF'
version: "1.1.0"
guards:
  forbidden_path:
    patterns: ["**/.ssh/**", "**/.env"]
  shell_command:
    enabled: true
EOF

# 3. Wrap your existing MCP server launch command
# Before:
npx @modelcontextprotocol/server-filesystem .
# After (--policy takes a YAML file path):
chio mcp serve --policy ./chio-policy.yaml --server-id my-mcp-server -- npx @modelcontextprotocol/server-filesystem .
```

Nothing changes in the MCP server. Nothing changes in the MCP client (it still
speaks MCP over stdio). Chio sits in the middle, evaluating every `tools/call`
and signing receipts. The `chio mcp serve` command already exists in the CLI.

**What you gain**:

- Every tool call gets a signed receipt (audit trail)
- Scope enforcement (deny tools not in the capability)
- Guard pipeline (rate limits, content inspection, cost caps)
- Budget tracking (per-session and per-agent cost limits)

### 7.2 Adding Chio to an Existing FastAPI App

Three lines of code:

```python
# Before:
from fastapi import FastAPI
app = FastAPI()

# After (3 lines added):
from fastapi import FastAPI
from chio_fastapi import ChioMiddleware          # line 1

app = FastAPI()
app.add_middleware(ChioMiddleware)               # line 2
# That's it. CHIO_SIDECAR_URL defaults to http://127.0.0.1:9090

# Optional: configure
app.add_middleware(                             # line 3 (replaces line 2)
    ChioMiddleware,
    sidecar_url="http://127.0.0.1:9090",
    fail_open=False,
    exclude_paths=["/health", "/metrics"],
)
```

The middleware intercepts every request, calls `chio.evaluate_http_request()`,
and either passes the request through (with an `X-Chio-Receipt` header) or
returns a 403 with the denial details.

### 7.3 Adding Chio to an Existing Express App

Three lines of code:

```typescript
// Before:
import express from "express";
const app = express();

// After (3 lines added):
import express from "express";
import { arcMiddleware } from "@chio-protocol/express";  // line 1

const app = express();
app.use(arcMiddleware());                                // line 2
// That's it. CHIO_SIDECAR_URL defaults to http://127.0.0.1:9090

// Optional: configure
app.use(arcMiddleware({                                  // line 3 (replaces line 2)
  sidecarUrl: "http://127.0.0.1:9090",
  failOpen: false,
  excludePaths: ["/health", "/metrics"],
}));
```

Same pattern as FastAPI: intercept, evaluate, pass-through or deny.

---

## 8. Observability for Developers

### 8.1 `chio check --verbose` Trace Mode

The `chio check` command already evaluates a single tool call against a policy.
Add `--verbose` to show the full guard evaluation trace:

```bash
$ chio check --verbose --policy ./chio-policy.yaml \
    --tool write_file --server filesystem \
    --params '{"path": ".env", "content": "SECRET=x"}'

[chio] Loading policy from ./chio-policy.yaml
[chio]   Policy hash: sha256:a1b2c3d4...
[chio]   Tool servers declared: 2 (filesystem, shell)
[chio]   Guards loaded: 3 (scope-check, path-constraint, rate-limit)

[chio] Evaluating: filesystem::write_file
[chio]   Capability: cap-default (scope: filesystem/write_file [Invoke])
[chio]   Parameter hash: sha256:e5f6a7b8...

[chio] Guard pipeline:
[chio]   [1/3] scope-check ............ PASS (tool in scope)
[chio]   [2/3] path-constraint ........ FAIL
[chio]         Constraint: regex_match("^(?!.*(\.env))")
[chio]         Parameter:  path = ".env"
[chio]         Result:     path matches deny pattern
[chio]   [3/3] rate-limit ............. SKIP (short-circuited after deny)

[chio] Decision: DENY
[chio]   Guard:  path-constraint
[chio]   Reason: Constraint violation: path ".env" matches deny pattern
[chio] Receipt: chio-receipt-7f3a9b2c (signed, persisted)
```

This output is the single most useful debugging tool for policy authors. It
answers "why was my tool call denied?" without reading source code.

### 8.2 Receipt Inspector CLI

```bash
# List recent receipts
$ chio receipts list --limit 10
ID                    TIME                 SERVER      TOOL         VERDICT
chio-receipt-7f3a9b2c  2026-04-15 14:32:01  filesystem  write_file   deny
chio-receipt-3e4f5a6b  2026-04-15 14:31:58  filesystem  read_file    allow
chio-receipt-1c2d3e4f  2026-04-15 14:31:55  shell       execute      allow

# Inspect a single receipt
$ chio receipts show chio-receipt-7f3a9b2c
Receipt: chio-receipt-7f3a9b2c
  Timestamp:     2026-04-15T14:32:01Z
  Server:        filesystem
  Tool:          write_file
  Decision:      deny
  Guard:         path-constraint
  Reason:        Constraint violation: path ".env" matches deny pattern
  Parameters:    {"content": "SECRET=x", "path": ".env"}
  Parameter hash: sha256:e5f6a7b8...
  Policy hash:   sha256:a1b2c3d4...
  Kernel key:    ed25519:9a8b7c6d...
  Signature:     ed25519:f1e2d3c4... (VALID)
  Content hash:  sha256:b2c3d4e5... (chain link to previous receipt)

# Verify a receipt chain
$ chio receipts verify --session session-abc123
Verifying receipt chain for session session-abc123...
  Receipt 1: chio-receipt-1c2d3e4f -- signature VALID
  Receipt 2: chio-receipt-3e4f5a6b -- signature VALID, chain link VALID
  Receipt 3: chio-receipt-7f3a9b2c -- signature VALID, chain link VALID
Chain integrity: VALID (3 receipts, 0 gaps)

# Export receipts for compliance
$ chio receipts export --session session-abc123 --format json > receipts.json
```

Note: `chio trust serve` already provides a receipt dashboard (web UI). These
CLI commands complement it for terminal-based workflows and CI pipelines.

### 8.3 Guard Evaluation Trace in Logs

When `RUST_LOG=chio_kernel=debug` is set, the kernel logs the full guard
evaluation trace to stderr. This is already partially implemented. The
improvement is standardizing the log format so it can be parsed by log
aggregators:

```
2026-04-15T14:32:01.123Z DEBUG chio_kernel::guard: guard_pipeline_start tool="write_file" server="filesystem" guards=3
2026-04-15T14:32:01.124Z DEBUG chio_kernel::guard: guard_eval guard="scope-check" result="pass" duration_us=42
2026-04-15T14:32:01.125Z DEBUG chio_kernel::guard: guard_eval guard="path-constraint" result="deny" reason="path matches deny pattern" duration_us=18
2026-04-15T14:32:01.125Z DEBUG chio_kernel::guard: guard_pipeline_end tool="write_file" verdict="deny" total_duration_us=67 receipt_id="chio-receipt-7f3a9b2c"
```

Key fields for observability dashboards:

- `guard_pipeline_start` / `guard_pipeline_end` for latency tracking
- `duration_us` per guard for performance profiling
- `receipt_id` for correlation with the receipt store
- Structured key-value format for parsing (not free-text)

### 8.4 SDK-Level Tracing

The Python and TypeScript SDKs should emit traces when a logger is configured:

```python
import logging
logging.getLogger("chio_sdk").setLevel(logging.DEBUG)

# Now every evaluate_tool_call logs:
# DEBUG chio_sdk: evaluate_tool_call server="filesystem" tool="read_file" -> allow (42ms)
# DEBUG chio_sdk: evaluate_tool_call server="filesystem" tool="write_file" -> deny (18ms) guard="path-constraint"
```

```typescript
import { setLogLevel } from "@chio-protocol/node-http";
setLogLevel("debug");

// Now every evaluate logs:
// [chio] evaluate server=filesystem tool=read_file -> allow (42ms)
// [chio] evaluate server=filesystem tool=write_file -> deny (18ms) guard=path-constraint
```

---

## 9. Success Metrics

| Metric | Current | Target (W6) |
|--------|---------|-------------|
| Packages on PyPI | 0 | 4 (chio-sdk-python, chio-asgi, chio-fastapi, chio-langchain) |
| Packages on npm | 0 | 3 (@chio-protocol/node-http, express, fastify) |
| Time to first tool call (Python dev) | unbounded (requires Rust toolchain) | < 5 minutes |
| Test without sidecar | impossible | `MockChioClient` in Python + TypeScript |
| Framework integrations with tests | 0 | 3 (chio-crewai, chio-autogen, @chio-protocol/ai-sdk) |
| Error message includes "what to do next" | no | yes (all SDK errors) |
| Pre-built binary platforms | 0 | 6 (darwin/linux/win, arm64/x64) |

---

## 10. Dependencies and Sequencing

```
Week 1: chio_sdk.testing + chio-sdk-python on PyPI
            |
            v
Week 2: chio-crewai (uses chio_sdk.testing for tests)
         + chio-fastapi on PyPI
         + Docker sidecar image (ghcr.io)
            |
            v
Week 3: @chio-protocol/node-http on npm
         + @chio-protocol/ai-sdk (uses node-http/testing)
         + Homebrew tap + GitHub Releases binaries
            |
            v
Week 4: chio-autogen + chio-llamaindex on PyPI
         + npx @chio-protocol/sidecar
         + Error message improvements merged
            |
            v
Week 5: chio-code-agent package + demo
         + Migration guides published
         + chio check --verbose + receipts CLI
            |
            v
Week 6: Quickstart tutorial on docs site
         + Blog post: "Secure your coding agent in 5 minutes"
```

The critical path is: `chio_sdk.testing` (unblocks all integration testing)
then `chio-sdk-python` on PyPI (unblocks all downstream Python packages) then
sidecar distribution (unblocks the quickstart).
