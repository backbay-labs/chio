# Chio C++ Kernel SDK

`chio-cpp-kernel` is the separate C++17 package for offline, in-process
kernel-style operations. It is intentionally independent from
`sdks/cpp/chio-cpp`, which owns hosted sessions, HTTP transport, auth,
callbacks, and tool orchestration.

By default the package builds as a deterministic fail-closed facade so ordinary
CMake consumers are not forced to run Cargo. For Rust-backed evaluation, enable
the optional `chio-cpp-kernel-ffi` backend and point CMake at the generated
header and library.

## Public API

The public header is:

```cpp
#include <chio/kernel.hpp>
```

It exposes only the offline kernel surface:

- `chio::kernel::Kernel`
- `chio::kernel::KernelOptions`
- `chio::kernel::EvaluateRequest`
- `chio::kernel::EvaluateResult`

`Kernel::evaluate` returns a structured deny result when no backend is linked.
With `CHIO_CPP_KERNEL_ENABLE_FFI=ON`, it calls the portable Rust kernel core
through the narrow JSON C ABI exported by `crates/chio-cpp-kernel-ffi`.
Successful FFI-backed evaluations expose the matched capability grant index when
the Rust response includes it, and also retain the original backend JSON in
`EvaluateResult::raw_result_json` for consumers that need backend-specific
metadata.

## Build

```bash
cmake -S sdks/cpp/chio-cpp-kernel -B target/chio-cpp-kernel
cmake --build target/chio-cpp-kernel
ctest --test-dir target/chio-cpp-kernel --output-on-failure
```

The package has no dependency on the main C++ SDK package and does not require
Cargo for the default fail-closed build.

To verify the Rust-backed path:

```bash
./sdks/cpp/chio-cpp-kernel/scripts/check-with-ffi.sh
```

That script runs `cargo test -p chio-cpp-kernel-ffi`, builds the Rust library,
links `chio-cpp-kernel` against it, and runs CTest.
