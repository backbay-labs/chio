# Chio C++ SDK

`chio-cpp` is the first-class C++17 SDK for Chio hosted MCP sessions, receipt
queries, DPoP signing, deterministic invariant checks, and HTTP substrate
sidecar evaluation.

The public API is native C++: `std::string`, `std::string_view`, `std::vector`,
RAII-owned objects, and a user-supplied `HttpTransport`. Rust is used only
behind a narrow C ABI for deterministic security invariants such as canonical
JSON, SHA-256, Ed25519 signing, and signed Chio artifact verification.

## Public Surface

- `chio::Client` and `chio::Session` for hosted MCP session lifecycle and tool,
  resource, prompt, and task calls.
- `chio::ReceiptQueryClient` for receipt query API calls.
- `chio::invariants::*` for canonical JSON, SHA-256, Ed25519, capability,
  receipt, and manifest verification.
- `chio::DpopProof` and `chio::sign_dpop_proof` for Chio DPoP request proofs.
- `chio::http::Evaluator` and HTTP request models for `spec/HTTP-SUBSTRATE.md`.

## Build

```bash
cmake -S sdks/cpp/chio-cpp -B target/chio-cpp \
  -DCHIO_CPP_BUILD_TESTS=ON \
  -DCHIO_CPP_BUILD_EXAMPLES=ON \
  -DCHIO_CPP_ENABLE_CURL=OFF
cmake --build target/chio-cpp
ctest --test-dir target/chio-cpp --output-on-failure
```

Enable the optional libcurl transport with `-DCHIO_CPP_ENABLE_CURL=ON`.
Production users can also supply their own implementation of
`chio::HttpTransport`.

## Install And Consume

```bash
cmake --install target/chio-cpp --prefix /tmp/chio-cpp
```

Consumer `CMakeLists.txt`:

```cmake
find_package(ChioCpp CONFIG REQUIRED)
add_executable(app main.cpp)
target_link_libraries(app PRIVATE ChioCpp::chio_cpp)
```

## Boundaries

The Rust ABI is intentionally limited to JSON strings and byte buffers with
explicit `chio_buffer_free` ownership. Session runtime, HTTP transport,
callbacks, subscriptions, and tool orchestration stay in C++.

Guard authoring lives in the separate `sdks/guard/chio-guard-cpp` package so
WASM component tooling does not burden ordinary C++ client users.
