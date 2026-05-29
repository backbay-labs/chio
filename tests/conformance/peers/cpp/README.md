# Chio C++ Conformance Peer

This peer exercises the hosted MCP surface through `sdks/cpp/chio-cpp` and
the SDK `CurlHttpTransport`. It covers the package-backed C++ hosted surface:
session initialization, tools, resources, prompts, tasks, auth discovery,
notifications, and nested callbacks.

Build:

```bash
cmake -S tests/conformance/peers/cpp -B target/chio-cpp-peer
cmake --build target/chio-cpp-peer
```

Run against a live Chio MCP edge:

```bash
target/chio-cpp-peer/chio_cpp_conformance_peer \
  --base-url http://127.0.0.1:8080 \
  --auth-token conformance-token \
  --scenarios-dir tests/conformance/scenarios/mcp_core \
  --results-output tests/conformance/results/generated/cpp-remote-http.json \
  --artifacts-dir tests/conformance/results/generated/artifacts/cpp
```

The peer writes Chio conformance JSON using `peer: "cpp"` so the shared report
generator can ingest it.
