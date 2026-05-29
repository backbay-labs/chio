#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <drogon/HttpMiddleware.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>

#include "chio/http_substrate.hpp"
#include "chio/transport.hpp"

namespace chio::drogon {

using RoutePatternResolver = std::function<std::string(const ::drogon::HttpRequest&)>;

enum class SidecarFailureMode {
  FailClosed,
  FailOpenWithoutReceipt,
  AllowWithoutReceipt = FailOpenWithoutReceipt,
};

struct Options {
  std::string sidecar_url;
  chio::HttpTransportPtr transport;
  std::uint32_t timeout_ms = 5000;
  SidecarFailureMode sidecar_failure_mode = SidecarFailureMode::FailClosed;
  std::vector<std::string> selected_headers = {
      "accept",
      "content-type",
      "x-request-id",
      "x-correlation-id",
  };
  std::vector<std::string> skip_paths;
  RoutePatternResolver route_pattern_resolver;
};

void configure(Options options);

std::string receipt_id(const ::drogon::HttpRequestPtr& req);
std::string receipt_id(const ::drogon::HttpRequest& req);

class ChioMiddleware : public ::drogon::HttpMiddleware<ChioMiddleware> {
 public:
  ChioMiddleware();
  explicit ChioMiddleware(Options options);

  void invoke(const ::drogon::HttpRequestPtr& req,
              ::drogon::MiddlewareNextCallback&& next_cb,
              ::drogon::MiddlewareCallback&& middleware_cb) override;

 private:
  Options options_;
};

}  // namespace chio::drogon
