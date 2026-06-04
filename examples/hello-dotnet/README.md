# hello-dotnet

Minimal ASP.NET example using [`sdks/dotnet/ChioMiddleware`](../../sdks/dotnet/ChioMiddleware/).

## What It Demonstrates

- `GET /hello` and `POST /echo` behind the real ASP.NET Chio middleware
- `/healthz` as a sidecar-independent readiness endpoint
- deny without capability and allow with a trust-issued capability token
- receipt ids emitted on the response header path for governed requests
- local route contract validation for the echo payload

## Files

```text
ARCHITECTURE.md
README.md
HelloApp.cs
HelloChio.csproj
Program.cs
openapi.yaml
policy.yaml
run.sh
smoke.sh
tests/
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

Run the focused route contract tests:

```bash
dotnet test tests/HelloChio.Tests.csproj
```
