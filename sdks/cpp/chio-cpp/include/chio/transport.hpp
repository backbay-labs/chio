#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "chio/result.hpp"

namespace chio {

class CancellationToken {
 public:
  void cancel() { cancelled_.store(true); }
  bool cancelled() const { return cancelled_.load(); }

 private:
  std::atomic<bool> cancelled_{false};
};

struct RetryPolicy {
  int max_attempts = 1;
  std::chrono::milliseconds initial_backoff{100};
  std::chrono::milliseconds max_backoff{1000};
};

struct HttpRequest {
  std::string method;
  std::string url;
  std::map<std::string, std::string> headers;
  std::string body;
  std::chrono::milliseconds timeout{30000};
  int attempt = 1;
  std::shared_ptr<CancellationToken> cancellation;
  std::function<Result<void>(const std::string&)> stream_message;
};

struct HttpResponse {
  int status = 0;
  std::map<std::string, std::string> headers;
  std::string body;
  std::chrono::milliseconds elapsed{0};
  int attempt = 1;
};

struct TraceEvent {
  std::string operation;
  HttpRequest request;
  HttpResponse response;
  Error error;
};

class TraceSink {
 public:
  virtual ~TraceSink() = default;
  virtual void record(const TraceEvent& event) = 0;
};

class HttpTransport {
 public:
  virtual ~HttpTransport() = default;
  virtual Result<HttpResponse> send(const HttpRequest& request) = 0;
};

#ifdef CHIO_CPP_HAS_CURL
class CurlHttpTransport final : public HttpTransport {
 public:
  Result<HttpResponse> send(const HttpRequest& request) override;
};
#endif

using HttpTransportPtr = std::shared_ptr<HttpTransport>;
using TraceSinkPtr = std::shared_ptr<TraceSink>;

}  // namespace chio
