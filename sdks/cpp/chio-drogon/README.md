# chio-drogon

`chio-drogon` is an optional C++17 integration package for Drogon applications. It exports `ChioDrogon::chio_drogon` and links to `ChioCpp::chio_cpp` and `Drogon::Drogon` when both packages are available.

The package uses the Chio HTTP sidecar model. Requests are converted into `chio::http::ChioHttpRequest`, evaluated by the sidecar, and allowed into the Drogon handler only when the sidecar returns an `allow` verdict.

## CMake

```cmake
find_package(ChioDrogon CONFIG REQUIRED)

target_link_libraries(app PRIVATE ChioDrogon::chio_drogon)
```

If Drogon is not installed, configuring this package directly skips the target by default:

```bash
cmake -S sdks/cpp/chio-drogon -B build/chio-drogon
```

Use `-DCHIO_DROGON_REQUIRE_DEPS=ON` when missing dependencies should fail configuration.

## Usage

```cpp
#include <drogon/drogon.h>
#include "chio/drogon.hpp"

int main() {
  chio::drogon::Options options;
  options.sidecar_url = "http://127.0.0.1:9090";
  chio::drogon::configure(options);

  drogon::app().registerMiddleware(
      std::make_shared<chio::drogon::ChioMiddleware>());
  drogon::app().run();
}
```

`ChioMiddleware` is a Drogon middleware, not a filter. For route-level registration, use the fully qualified name `chio::drogon::ChioMiddleware` in Drogon route registration.

## Behavior

- Behavior is always fail-closed: any sidecar evaluation failure denies the request.
- The sidecar URL is resolved from `Options::sidecar_url`, then `CHIO_SIDECAR_URL`, then `http://127.0.0.1:9090`.
- The body hash is computed over Drogon's raw request body bytes.
- Only `Options::selected_headers` are copied into `ChioHttpRequest.headers`.
- `Authorization`, `Cookie`, `X-Api-Key`, and `X-Chio-Capability` are never copied into `ChioHttpRequest.headers`, even if selected.
- Capability tokens are extracted from `X-Chio-Capability` or the `chio_capability` query parameter and forwarded to the Chio evaluator as the raw capability token.
- `chio_capability` is not copied into `ChioHttpRequest.query`.
- If `chio-drogon` vendors the sibling `chio-cpp` project, it enables the optional libcurl transport for the default sidecar client. Package consumers can still pass a custom `Options::transport`.

After an allowed evaluation, handlers can read the sidecar receipt id:

```cpp
auto id = chio::drogon::receipt_id(req);
```

Skip paths and route pattern overrides are explicit options:

```cpp
chio::drogon::Options options;
options.skip_paths = {"/healthz", "/metrics"};
options.route_pattern_resolver = [](const drogon::HttpRequest& req) {
  if (req.path().rfind("/orders/", 0) == 0) {
    return "/orders/{id}";
  }
  return std::string(req.path());
};
chio::drogon::configure(options);
```
