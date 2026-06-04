# hello-django

Minimal Django example using [`sdks/python/chio-django`](../../sdks/python/chio-django/).

## What It Demonstrates

- `GET /hello` is allowed and exposes the Chio receipt id through the view
- `POST /echo` is denied without a capability token
- `POST /echo` succeeds with a trust-issued capability token
- Django request bodies remain readable after Chio middleware hashing
- the smoke flow captures app, sidecar, and trust artifacts in one bundle

## Files

```text
README.md
ARCHITECTURE.md
manage.py
pyproject.toml
hello_project/
hello_app/
openapi.yaml
policy.yaml
run.sh
smoke.sh
```

## Run

Start the app only:

```bash
./run.sh
```

Run the full end-to-end smoke flow:

```bash
./smoke.sh
```

Run the package-local Django route tests:

```bash
uv run --project . python manage.py test hello_app
```

The route tests disable Chio middleware so Django payload validation can be
checked without a live sidecar. The smoke flow is still the authority for live
sidecar evaluation, capability gating, receipt verification, and persisted
receipt evidence.
