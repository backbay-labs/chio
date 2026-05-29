# Chio Guard C++ SDK

`chio-guard-cpp` is the separate C++17 guard authoring package for Chio WASM
guard components. It tracks `wit/chio-guard/world.wit` and stays independent
from `sdks/cpp/chio-cpp` so client applications do not need WASI SDK or
component-model tools.

The package has two layers:

- a header-only native authoring API for ordinary C++ tests and local logic
- optional WIT/component tooling for building WASI guest guard components

## Native Authoring Types

The header-only `chio::guard` namespace provides lightweight C++ structs for
the guard request and verdict model:

```cpp
#include "chio/guard.hpp"

class PathGuard final : public chio::guard::Guard {
 public:
  chio::guard::Verdict evaluate(const chio::guard::GuardRequest& request) override {
    if (request.extracted_path && request.extracted_path->find("..") != std::string::npos) {
      return chio::guard::Verdict::deny("path traversal denied");
    }
    return chio::guard::Verdict::allow();
  }
};
```

Run the local non-WASI compile smoke:

```bash
./sdks/guard/chio-guard-cpp/scripts/check-native.sh
```

Or configure the package directly:

```bash
cmake -S sdks/guard/chio-guard-cpp -B sdks/guard/chio-guard-cpp/build-native
cmake --build sdks/guard/chio-guard-cpp/build-native
ctest --test-dir sdks/guard/chio-guard-cpp/build-native --output-on-failure
```

## WIT Bindings

Generate guest bindings when `wit-bindgen` is available. The default uses
`wit-bindgen c` because its generated C bindings are C++ compatible and produce
`guard.h`, `guard.c`, and `guard_component_type.o`.

```bash
./sdks/guard/chio-guard-cpp/scripts/generate-types.sh
```

The output directory can be overridden:

```bash
./sdks/guard/chio-guard-cpp/scripts/generate-types.sh \
  --out-dir /tmp/chio-guard-generated
```

## Sample Guard Component

Build the sample path guard with the WASI SDK when the toolchain is available:

```bash
WASI_SDK_PATH=/opt/wasi-sdk ./sdks/guard/chio-guard-cpp/scripts/build-guard.sh
```

The script configures CMake with:

- `CHIO_GUARD_CPP_GENERATE=ON`
- `CHIO_GUARD_CPP_BUILD_WASI_COMPONENT=ON`
- `CHIO_GUARD_CPP_WIT_BINDGEN_SUBCOMMAND=c`
- the WASI SDK CMake toolchain

The sample component adapter is intentionally small and package-local. It uses
generated WIT C/C++ bindings only at the component boundary, then delegates to
the same `PathGuard` C++ class used by the native smoke test.

## CMake Options

- `CHIO_GUARD_CPP_BUILD_EXAMPLES`: build sample C++ guard sources, default `ON`.
- `CHIO_GUARD_CPP_BUILD_TESTS`: register the native smoke test, default `ON`.
- `CHIO_GUARD_CPP_GENERATE`: run `wit-bindgen`, default `OFF`.
- `CHIO_GUARD_CPP_BUILD_WASI_COMPONENT`: build the sample WASI component, default `OFF`.
- `CHIO_GUARD_CPP_WIT_BINDGEN_SUBCOMMAND`: `c` or `cpp`, default `c`.
- `CHIO_GUARD_CPP_GENERATED_DIR`: generated binding output directory.

This package intentionally avoids linking to the main C++ client SDK. Guard
components implement the WIT world; ordinary clients use `chio-cpp`.
