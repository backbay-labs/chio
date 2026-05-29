# hello-drogon

Minimal C++ Drogon example using [`sdks/cpp/chio-drogon`](../../sdks/cpp/chio-drogon/).

## What It Demonstrates

- `GET /hello` is protected by `chio::drogon::ChioMiddleware`
- `POST /echo` is denied without a capability token
- `POST /echo` succeeds with a trust-issued capability token
- allowed handlers can read the Chio receipt id through `chio::drogon::receipt_id`
- the smoke flow uses `chio trust serve` and `chio api protect` with persisted sidecar receipts
- the governed POST smoke verifies that the receipt content hash is bound to the exact raw JSON bytes sent by the client

The example is optional because Drogon is not always installed on developer
machines. `run.sh` and `smoke.sh` skip with a clear message when CMake is
missing or CMake cannot find `Drogon::Drogon`.

## Files

```text
CMakeLists.txt
README.md
main.cpp
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

If Drogon is installed outside a default CMake search path, set
`CMAKE_PREFIX_PATH` before running either script.
