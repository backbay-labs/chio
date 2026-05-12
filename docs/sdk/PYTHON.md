# Chio Python SDK Reference

This document covers all five Chio Python packages. Each package communicates with the Chio Rust kernel via a localhost HTTP sidecar, so there is no native compilation or FFI required.

## Quick Start

```bash
# Core client (required by all other packages)
pip install chio-sdk-python

# Pick your framework integration
pip install chio-asgi       # Starlette, FastAPI, Litestar, any ASGI framework
pip install chio-fastapi    # FastAPI decorators and dependency injection
pip install chio-django     # Django/DRF middleware
pip install chio-langchain  # LangChain tool integration
```

```python
from chio_sdk.client import ChioClient

async with ChioClient() as client:
    healthy = await client.health()
    print(healthy)
```

## Sidecar Communication Model

All Chio Python SDKs communicate with the Chio Rust kernel through localhost HTTP. The kernel runs as a sidecar process alongside your application.

- **Default URL**: `http://127.0.0.1:9090`
- **Configurable via**: `CHIO_SIDECAR_URL` environment variable or constructor argument
- **No native compilation or FFI**: pure Python over HTTP
- **Fail-closed by default**: when the sidecar is unreachable, requests are denied (503). Configure `fail_open=True` to forward without a receipt and expose an explicit `ChioPassthrough` marker.

---

## 1. chio-sdk-python

The core client library. All other Chio Python packages depend on this.

### Installation

```bash
pip install chio-sdk-python
```

### ChioClient

Async HTTP client for the Chio sidecar kernel. Uses `httpx` under the hood.

```python
from chio_sdk.client import ChioClient

# Default: connects to http://127.0.0.1:9090
client = ChioClient()

# Custom URL and timeout
client = ChioClient("http://localhost:9090", timeout=15.0)

# Use as async context manager
async with ChioClient() as client:
    data = await client.health()
```

**Constructor parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `base_url` | `str \| None` | `"http://127.0.0.1:9090"` | Base URL of the Chio sidecar |
| `timeout` | `float` | `5.0` | Request timeout in seconds |

### Capability Operations

```python
from chio_sdk.client import ChioClient
from chio_sdk.models import ChioScope, ToolGrant, Operation

async with ChioClient() as client:
    # Create a capability token
    scope = ChioScope(grants=[
        ToolGrant(
            server_id="deploy-server",
            tool_name="deploy",
            operations=[Operation.INVOKE],
        ),
    ])
    token = await client.create_capability(
        subject="<hex-ed25519-pubkey>",
        scope=scope,
        ttl_seconds=3600,
    )

    # Validate a token
    is_valid = await client.validate_capability(token)

    # Attenuate (narrow) a token
    narrower_scope = ChioScope(grants=[
        ToolGrant(
            server_id="deploy-server",
            tool_name="deploy",
            operations=[Operation.INVOKE],
            max_invocations=5,
        ),
    ])
    child_token = await client.attenuate_capability(
        token, new_scope=narrower_scope
    )
```

### Tool Evaluation

```python
receipt = await client.evaluate_tool_call(
    capability_id="cap-abc-123",
    tool_server="my-server",
    tool_name="my-tool",
    parameters={"key": "value"},
)

if receipt.is_allowed:
    print(f"Allowed, receipt: {receipt.id}")
else:
    print(f"Denied by {receipt.decision.guard}: {receipt.decision.reason}")
```

### HTTP Request Evaluation

```python
from chio_sdk.models import CallerIdentity, AuthMethod

caller = CallerIdentity(
    subject="user-123",
    auth_method=AuthMethod.bearer(token_hash="abc..."),
    verified=False,
)

evaluation = await client.evaluate_http_request(
    request_id="req-001",
    method="POST",
    route_pattern="/api/tools/{tool_id}",
    path="/api/tools/42",
    caller=caller,
    body_hash="sha256hex...",
    capability_token='{"id":"cap-abc-123", ...}',
)
http_receipt = evaluation.receipt
```

### Receipt Verification

```python
# Single receipt
valid = await client.verify_receipt(chio_receipt)

# HTTP receipt
valid = await client.verify_http_receipt(http_receipt)

# Receipt chain (contiguous content hashes)
chain_valid = await client.verify_receipt_chain([receipt1, receipt2, receipt3])
```

### Typed Models

All models use Pydantic v2 and match the Rust kernel's canonical JSON format.

**CapabilityToken** -- Ed25519-signed, scoped, time-bounded capability token.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Unique token identifier |
| `issuer` | `str` | Hex-encoded Ed25519 public key of the issuer |
| `subject` | `str` | Hex-encoded Ed25519 public key of the agent |
| `scope` | `ChioScope` | What this token authorizes |
| `issued_at` | `int` | Unix timestamp |
| `expires_at` | `int` | Unix timestamp |
| `delegation_chain` | `list[DelegationLink]` | Delegation history |
| `signature` | `str` | Hex-encoded Ed25519 signature |

**ChioReceipt** -- signed proof that a tool call was evaluated by the kernel.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Receipt identifier |
| `timestamp` | `int` | Unix timestamp |
| `capability_id` | `str` | Token used for the call |
| `tool_server` | `str` | Tool server ID |
| `tool_name` | `str` | Tool name |
| `action` | `ToolCallAction` | Parameters and their hash |
| `decision` | `Decision` | Kernel verdict (`allow`, `deny`, `cancelled`, `incomplete`) |
| `content_hash` | `str` | SHA-256 of canonical request content |
| `policy_hash` | `str` | Hash of the policy set used |
| `evidence` | `list[GuardEvidence]` | Per-guard evaluation evidence |
| `kernel_key` | `str` | Kernel's Ed25519 public key |
| `signature` | `str` | Ed25519 signature over the receipt |

**HttpReceipt** -- signed receipt for HTTP request evaluation.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Receipt identifier |
| `request_id` | `str` | Correlation ID for the HTTP request |
| `route_pattern` | `str` | Matched route pattern |
| `method` | `str` | HTTP method |
| `caller_identity_hash` | `str` | SHA-256 of caller identity |
| `verdict` | `Verdict` | HTTP-layer verdict |
| `evidence` | `list[GuardEvidence]` | Per-guard evaluation evidence |
| `response_status` | `int` | Chio evaluation-time HTTP status. Deny receipts carry the concrete Chio error status; allow receipts may be signed before the downstream app or upstream response exists. |
| `timestamp` | `int` | Unix timestamp |
| `content_hash` | `str` | SHA-256 of canonical request content |
| `policy_hash` | `str` | Policy set hash |
| `kernel_key` | `str` | Kernel's Ed25519 public key |
| `signature` | `str` | Ed25519 signature |

**ChioPassthrough** -- explicit fail-open degraded state for HTTP integrations.

| Field | Type | Description |
|-------|------|-------------|
| `mode` | `str` | Currently `"allow_without_receipt"` |
| `error` | `str` | Chio error code, typically `chio_sidecar_unreachable` |
| `message` | `str` | Operator-readable passthrough reason |

**Decision** -- kernel verdict on a tool call.

```python
from chio_sdk.models import Decision

d = Decision.allow()
d = Decision.deny(reason="rate limit exceeded", guard="velocity-guard")
d.is_allowed  # bool
d.is_denied   # bool
```

**Verdict** -- HTTP-layer verdict (extends Decision with `http_status`).

```python
from chio_sdk.models import Verdict

v = Verdict.deny(reason="forbidden", guard="rbac", http_status=403)
v.http_status  # 403
```

**CallerIdentity** and **AuthMethod**:

```python
from chio_sdk.models import CallerIdentity, AuthMethod

# Bearer token
caller = CallerIdentity(
    subject="token-hash",
    auth_method=AuthMethod.bearer(token_hash="abc123"),
    verified=False,
)

# API key
caller = CallerIdentity(
    subject="key-hash",
    auth_method=AuthMethod.api_key(key_name="x-api-key", key_hash="def456"),
    verified=False,
)

# Cookie
caller = CallerIdentity(
    subject="cookie-hash",
    auth_method=AuthMethod.cookie(cookie_name="session", cookie_hash="ghi789"),
    verified=False,
)

# Anonymous
caller = CallerIdentity.anonymous()
```

### Error Types

| Error | Code | When |
|-------|------|------|
| `ChioError` | varies | Base error for all SDK operations |
| `ChioConnectionError` | `CONNECTION_ERROR` | Cannot reach the sidecar |
| `ChioTimeoutError` | `TIMEOUT` | Sidecar request timed out |
| `ChioDeniedError` | `DENIED` | Kernel denied the request (has `.guard` and `.reason`) |
| `ChioValidationError` | `VALIDATION_ERROR` | Local validation failed before contacting sidecar |

---

## 2. chio-asgi

ASGI middleware for any ASGI framework (FastAPI, Starlette, Litestar, etc.).

### Installation

```bash
pip install chio-asgi
```

### Basic Usage

```python
from fastapi import FastAPI
from chio_asgi import ChioASGIMiddleware, ChioASGIConfig

app = FastAPI()
app.add_middleware(
    ChioASGIMiddleware,
    config=ChioASGIConfig(sidecar_url="http://127.0.0.1:9090"),
)
```

With Litestar:

```python
from litestar import Litestar
from chio_asgi import ChioASGIMiddleware

app = Litestar(middleware=[ChioASGIMiddleware])
```

### Configuration

`ChioASGIConfig` is a frozen dataclass with these fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `sidecar_url` | `str` | `"http://127.0.0.1:9090"` | Sidecar base URL |
| `timeout` | `float` | `5.0` | Sidecar request timeout in seconds |
| `exclude_paths` | `frozenset[str]` | `frozenset()` | Paths to skip evaluation |
| `exclude_methods` | `frozenset[str]` | `frozenset({"OPTIONS"})` | HTTP methods to skip |
| `receipt_header` | `str` | `"X-Chio-Receipt"` | Response header for receipt ID |
| `fail_open` | `bool` | `False` | Allow requests when sidecar is unreachable, without attaching a synthetic Chio receipt |

```python
config = ChioASGIConfig(
    sidecar_url="http://127.0.0.1:9090",
    exclude_paths=frozenset({"/health", "/ready"}),
    exclude_methods=frozenset({"OPTIONS", "HEAD"}),
    fail_open=False,
)
```

### Identity Extractors

The middleware uses a `CompositeExtractor` by default, which tries these extractors in order:

1. **BearerTokenExtractor** -- `Authorization: Bearer <token>` header
2. **ApiKeyExtractor** -- `X-API-Key` header (configurable header name)
3. **CookieExtractor** -- `session` cookie (configurable cookie name)
4. Falls back to **anonymous** if none match

All credential values are hashed with SHA-256 before being sent to the sidecar. Raw secrets are never transmitted.

Custom extractors:

```python
from chio_asgi import ChioASGIMiddleware, ChioASGIConfig
from chio_asgi.extractors import (
    CompositeExtractor,
    BearerTokenExtractor,
    ApiKeyExtractor,
    CookieExtractor,
    IdentityExtractor,
)

# Custom composite with different order or config
extractor = CompositeExtractor([
    ApiKeyExtractor(header_name="x-my-api-key"),
    BearerTokenExtractor(),
    CookieExtractor(cookie_name="auth_session"),
])

app.add_middleware(
    ChioASGIMiddleware,
    config=ChioASGIConfig(),
    extractor=extractor,
)
```

You can implement `IdentityExtractor` to build fully custom extractors:

```python
from chio_asgi.extractors import IdentityExtractor
from chio_sdk.models import CallerIdentity

class MyExtractor(IdentityExtractor):
    def extract(self, scope: dict) -> CallerIdentity | None:
        # Return CallerIdentity or None to skip to next extractor
        ...
```

### Receipt Callback

```python
from chio_sdk.models import HttpReceipt

async def log_receipt(receipt: HttpReceipt) -> None:
    print(f"Chio receipt: {receipt.id}, verdict: {receipt.verdict.verdict}")

app.add_middleware(
    ChioASGIMiddleware,
    config=ChioASGIConfig(),
    on_receipt=log_receipt,
)
```

---

## 3. chio-fastapi

FastAPI-specific decorators and dependency injection for route-level Chio enforcement.

### Installation

```bash
pip install chio-fastapi
```

### Decorators

**`@chio_requires(server_id, tool_name, operations=None)`**

Enforces that the request carries a valid Chio capability token (via `X-Chio-Capability` header or `chio_capability` query parameter) authorizing the specified server/tool/operations.

```python
from fastapi import FastAPI, Request
from chio_fastapi import chio_requires

app = FastAPI()

@app.post("/tools/deploy")
@chio_requires("deploy-server", "deploy", ["Invoke"])
async def deploy(request: Request):
    receipt = request.state.chio_receipt  # HttpReceipt attached on success
    return {"status": "deployed", "receipt_id": receipt.id}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `server_id` | `str` | required | Chio tool server ID |
| `tool_name` | `str` | required | Tool name |
| `operations` | `list[str] \| None` | `["Invoke"]` | Required operations |

**`@chio_approval(threshold_cents=0, currency="USD")`**

Requires human approval above a monetary threshold. Must be combined with `@chio_requires`. Checks for an `X-Chio-Approval` header.

```python
@app.post("/tools/transfer")
@chio_approval(threshold_cents=10000)
@chio_requires("payments", "transfer", ["Invoke"])
async def transfer(request: Request):
    ...
```

**`@chio_budget(max_cost_cents, currency="USD")`**

Enforces a per-request budget limit. If the invocation cost would exceed the limit, the sidecar denies the request.

```python
@app.post("/tools/query")
@chio_budget(max_cost_cents=500, currency="USD")
@chio_requires("ai", "query", ["Invoke"])
async def query(request: Request):
    ...
```

### Dependency Injection

```python
from fastapi import Depends, Request
from chio_sdk.client import ChioClient
from chio_sdk.models import ChioPassthrough, CallerIdentity, HttpReceipt
from chio_fastapi.dependencies import (
    get_chio_client,
    get_chio_passthrough,
    get_chio_receipt,
    get_caller_identity,
    set_chio_client,
)

# Inject the Chio client
@app.get("/items")
async def list_items(client: ChioClient = Depends(get_chio_client)):
    health = await client.health()
    ...

# Inject caller identity (extracted from request headers)
@app.get("/me")
async def whoami(caller: CallerIdentity = Depends(get_caller_identity)):
    return {"subject": caller.subject, "method": caller.auth_method.method}

# Inject receipt (set by middleware or decorators)
@app.get("/receipt")
async def show_receipt(receipt: HttpReceipt | None = Depends(get_chio_receipt)):
    if receipt is None:
        return {"status": "no receipt"}
    return {"receipt_id": receipt.id}

# Inject explicit fail-open passthrough state
@app.get("/authority")
async def show_authority(
    passthrough: ChioPassthrough | None = Depends(get_chio_passthrough),
):
    if passthrough is not None:
        return {"mode": passthrough.mode, "error": passthrough.error}
    return {"mode": "governed"}

# Override the client singleton for testing
set_chio_client(mock_client)
set_chio_client(None)  # reset to default
```

---

## 4. chio-django

Django middleware for Chio protocol evaluation. Uses synchronous `httpx` since Django WSGI middleware runs synchronously.

### Installation

```bash
pip install chio-django
```

### Setup

Add to your Django settings:

```python
# settings.py

MIDDLEWARE = [
    # ... other middleware ...
    "chio_django.ChioDjangoMiddleware",
    # ... other middleware ...
]

# Chio configuration
CHIO_SIDECAR_URL = "http://127.0.0.1:9090"  # default
CHIO_FAIL_OPEN = False                        # default, fail-closed
CHIO_EXCLUDE_PATHS = ["/health", "/ready"]    # paths to skip
CHIO_EXCLUDE_METHODS = ["OPTIONS"]            # methods to skip (default)
CHIO_RECEIPT_HEADER = "X-Chio-Receipt"         # response header (default)
CHIO_TIMEOUT = 5.0                            # seconds (default)
```

### Django Settings Reference

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `CHIO_SIDECAR_URL` | `str` | `"http://127.0.0.1:9090"` | Sidecar base URL |
| `CHIO_FAIL_OPEN` | `bool` | `False` | Allow when sidecar is down |
| `CHIO_EXCLUDE_PATHS` | `list[str]` | `[]` | Paths to skip evaluation |
| `CHIO_EXCLUDE_METHODS` | `list[str]` | `["OPTIONS"]` | HTTP methods to skip |
| `CHIO_RECEIPT_HEADER` | `str` | `"X-Chio-Receipt"` | Response header name for receipt ID |
| `CHIO_TIMEOUT` | `float` | `5.0` | Request timeout in seconds |

### Accessing Receipts in Views

```python
from django.http import JsonResponse

def my_view(request):
    # Receipt is attached by middleware on successful evaluation
    receipt = getattr(request, "chio_receipt", None)
    passthrough = getattr(request, "chio_passthrough", None)
    if receipt:
        return JsonResponse({
            "receipt_id": receipt.get("id"),
            "verdict": receipt.get("verdict", {}).get("verdict"),
        })
    if passthrough:
        return JsonResponse({
            "mode": passthrough.mode,
            "error": passthrough.error,
        })
    return JsonResponse({"status": "no receipt"})
```

### DRF Support

The middleware works with Django REST Framework out of the box. It runs at the Django middleware layer, so all DRF views benefit from Chio evaluation automatically.

### Identity Extraction

The Django middleware extracts caller identity from request headers using the same priority as other Chio SDKs:

1. `Authorization: Bearer <token>` header
2. `X-API-Key` header
3. `session` cookie
4. Falls back to anonymous

---

## 5. chio-langchain

Wrap Chio tools as LangChain `BaseTool` objects for use in agents, chains, and pipelines.

### Installation

```bash
pip install chio-langchain
```

### ChioToolkit (Auto-Discovery)

Discover tools from the sidecar's registered tool server manifests:

```python
from chio_langchain import ChioToolkit

toolkit = ChioToolkit(
    capability_id="cap-abc-123",
    sidecar_url="http://127.0.0.1:9090",
)

# Discover all tools from all servers
tools = await toolkit.get_tools()

# Discover tools from a specific server only
tools = await toolkit.get_tools(server_id="my-server")
```

**ChioToolkit constructor:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `capability_id` | `str` | required | Chio capability token ID |
| `sidecar_url` | `str` | `"http://127.0.0.1:9090"` | Sidecar base URL |

### ChioTool (Manual Creation)

Create a tool when you know the definition ahead of time:

```python
tool = toolkit.create_tool(
    name="search",
    description="Search the knowledge base",
    server_id="knowledge-server",
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "limit": {"type": "integer", "description": "Max results"},
        },
        "required": ["query"],
    },
)
```

### Using with LangChain Agents

```python
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI

toolkit = ChioToolkit(capability_id="cap-abc-123")
tools = await toolkit.get_tools()

llm = ChatOpenAI(model="gpt-4")
agent = create_openai_tools_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)

result = await executor.ainvoke({"input": "Deploy the latest build"})
```

Chio tools require async invocation. They raise `NotImplementedError` if called synchronously. Use `ainvoke` or `_arun`.

### Accessing Receipts

After each tool invocation, the signed receipt is stored on the tool:

```python
tool = toolkit.create_tool(
    name="deploy",
    description="Deploy to production",
    server_id="deploy-server",
)

result = await tool.ainvoke({"environment": "production"})
receipt = tool.last_receipt  # ChioReceipt or None
if receipt and receipt.is_allowed:
    print(f"Deployed with receipt {receipt.id}")
```

### Error Handling

On denial or sidecar errors, ChioTool returns a JSON string with error details rather than raising an exception. This allows LangChain agents to observe and react to denials:

```json
{"error": "denied", "guard": "velocity-guard", "reason": "rate limit exceeded"}
```

---

## 6. chio-hermes

Hermes Agent plugin. Wires Chio's `CodeAgent` tool surface
(file/shell/git) into the Hermes tool registry, enforces the bundled
policy via a `pre_tool_call` hook, and writes per-session signed
receipts to a JSONL log. Long-form integration guide lives at
[`docs/integrations/HERMES.md`](../integrations/HERMES.md).

### Installation

Install Hermes itself first (curl-installer or
`pip install --upgrade git+https://github.com/NousResearch/hermes-agent.git`),
then into the same Python environment:

```bash
pip install chio-hermes
```

### Quickstart

Enable the plugin in `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - chio
```

Set the two required environment variables (`hermes setup` will prompt
for them; the capability id is masked):

```bash
export CHIO_SIDECAR_URL="http://127.0.0.1:9090"
export CHIO_CAPABILITY_ID="$(hermes chio --json issue --tool-server fs --tool-server shell --tool-server git --subject <hex-pubkey> | jq -r .capability_id)"
```

Twelve tools land under the single `chio` toolset
(`chio_file_read`, `chio_file_write`, `chio_file_edit`, `chio_file_list`,
`chio_file_search`, `chio_shell_run`, `chio_git_status`, `chio_git_diff`,
`chio_git_log`, `chio_git_add`, `chio_git_commit`, `chio_git_run`).
Receipts surface in-session via `/chio receipts` and are appended to
`<get_hermes_home()>/logs/chio-receipts.jsonl`. The JSONL log is a
session convenience; the canonical audit store is the sidecar's
`--receipts-db`.

See [`docs/integrations/HERMES.md`](../integrations/HERMES.md) for the
full surface (Path A vs Path B, capability lifecycle, failure-mode
table, custom policy, troubleshooting).
