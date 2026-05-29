# chio-asgi

ASGI middleware for the [Chio protocol](../../../spec/PROTOCOL.md). It
intercepts incoming HTTP requests, extracts the caller identity, evaluates
the request against Chio policy via the sidecar kernel, and either forwards
the request or rejects it based on the verdict. It works with any ASGI
framework (FastAPI, Starlette, Litestar, and others).

## Install

```bash
uv pip install chio-asgi
# or
pip install chio-asgi
```

The package depends on `chio-sdk-python`.

## Quickstart

```python
from chio_asgi import ChioASGIMiddleware, ChioASGIConfig

# Starlette / FastAPI
app.add_middleware(
    ChioASGIMiddleware,
    config=ChioASGIConfig(sidecar_url="http://127.0.0.1:9090"),
)
```

```python
from litestar import Litestar
from chio_asgi import ChioASGIMiddleware

app = Litestar(middleware=[ChioASGIMiddleware])
```

## Identity extraction

Caller identity is resolved by pluggable extractors. The package ships
`BearerTokenExtractor`, `ApiKeyExtractor`, `CookieExtractor`, and a
`CompositeExtractor` that tries several in order; implement the
`IdentityExtractor` protocol to add your own. Configure them through
`ChioASGIConfig`.

## Behaviour

- Each request is evaluated through the Chio sidecar before it reaches your
  application. Allow verdicts forward the request; deny verdicts return a
  structured rejection response.
- The middleware fails closed: if the sidecar is unreachable, requests are
  denied.
- The receipt id for the evaluated request is exposed on the response via
  the configurable `receipt_header` (default `X-Chio-Receipt`) so
  downstream systems can correlate the verdict.

## License

Apache-2.0
