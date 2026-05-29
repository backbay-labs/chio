# chio-django

Django integration for the [Chio protocol](../../../spec/PROTOCOL.md).
A request middleware (with Django REST Framework support) that evaluates
incoming requests against Chio policy via the sidecar kernel and rejects
denied requests before they reach your views.

## Install

```bash
uv pip install chio-django
# or
pip install chio-django
```

The package depends on `chio-sdk-python` and `django`.

## Quickstart

Add the middleware to `settings.py`:

```python
MIDDLEWARE = [
    # ...
    "chio_django.middleware.ChioDjangoMiddleware",
]

CHIO_SIDECAR_URL = "http://127.0.0.1:9090"
CHIO_FAIL_OPEN = False
CHIO_EXCLUDE_PATHS = ["/health", "/ready"]
CHIO_EXCLUDE_METHODS = ["OPTIONS"]
CHIO_RECEIPT_HEADER = "X-Chio-Receipt"
```

## Settings

- `CHIO_SIDECAR_URL` -- sidecar base URL (default `http://127.0.0.1:9090`).
- `CHIO_FAIL_OPEN` -- if `True`, allow when the sidecar is down (default
  `False`, i.e. fail closed).
- `CHIO_EXCLUDE_PATHS` -- list of paths that bypass evaluation (default
  `[]`).
- `CHIO_EXCLUDE_METHODS` -- HTTP methods that bypass evaluation (default
  `["OPTIONS"]`).
- `CHIO_RECEIPT_HEADER` -- response header carrying the receipt id
  (default `X-Chio-Receipt`).
- `CHIO_TIMEOUT` -- sidecar request timeout in seconds (default `5`).

## What is in the box

- `ChioDjangoMiddleware` -- the request middleware.
- `ChioErrorCode` and `chio_error_response` -- consistent, typed denial
  responses.

## Behaviour

The middleware defaults to fail-closed: a deny verdict or an unreachable
sidecar rejects the request unless you explicitly set
`CHIO_FAIL_OPEN = True`.

## License

Apache-2.0
