# Python SDK Example

This example assumes a running Chio hosted edge plus trust service.

Required environment variables:

- `CHIO_BASE_URL`: Chio hosted edge base URL, for example `http://127.0.0.1:8931`
- `CHIO_CONTROL_URL`: Chio trust-service base URL, for example `http://127.0.0.1:8940`
- `CHIO_AUTH_TOKEN`: bearer token accepted by both services

Run it with:

```bash
CHIO_BASE_URL=http://127.0.0.1:8931 \
CHIO_CONTROL_URL=http://127.0.0.1:8940 \
CHIO_AUTH_TOKEN=demo-token \
python sdks/python/chio-py/examples/governed_hello.py
```

The script initializes a session, discovers the default capability issued for
that session, invokes `echo_text`, and then reads the resulting receipt through
`ReceiptQueryClient`.
