#pragma once

#include <cstddef>
#include <mutex>
#include <utility>
#include <vector>

#include "chio/transport.hpp"

namespace chio::test {

class FakeTransport final : public HttpTransport {
 public:
  FakeTransport() = default;
  explicit FakeTransport(std::vector<HttpResponse> responses)
      : responses_(std::move(responses)) {}

  void push_response(HttpResponse response) {
    std::lock_guard<std::mutex> lock(mu_);
    responses_.push_back(std::move(response));
  }

  Result<HttpResponse> send(const HttpRequest& request) override {
    std::lock_guard<std::mutex> lock(mu_);
    requests_.push_back(request);
    if (responses_.empty()) {
      return Result<HttpResponse>::failure(
          Error{ErrorCode::Transport, "no fake response queued", "FakeTransport::send"});
    }
    auto response = std::move(responses_.front());
    responses_.erase(responses_.begin());
    response.attempt = request.attempt;
    return Result<HttpResponse>::success(std::move(response));
  }

  std::vector<HttpRequest> requests_snapshot() const {
    std::lock_guard<std::mutex> lock(mu_);
    return requests_;
  }

  std::size_t request_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return requests_.size();
  }

  void clear_requests() {
    std::lock_guard<std::mutex> lock(mu_);
    requests_.clear();
  }

 private:
  mutable std::mutex mu_;
  std::vector<HttpRequest> requests_;
  std::vector<HttpResponse> responses_;
};

class NoopTransport final : public HttpTransport {
 public:
  Result<HttpResponse> send(const HttpRequest&) override {
    return Result<HttpResponse>::failure(
        Error{ErrorCode::Transport, "noop transport does not send requests", "NoopTransport::send"});
  }
};

class RecordingTraceSink final : public TraceSink {
 public:
  void record(const TraceEvent& event) override {
    std::lock_guard<std::mutex> lock(mu_);
    events_.push_back(event);
  }

  std::vector<TraceEvent> events_snapshot() const {
    std::lock_guard<std::mutex> lock(mu_);
    return events_;
  }

  std::size_t event_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return events_.size();
  }

  void clear_events() {
    std::lock_guard<std::mutex> lock(mu_);
    events_.clear();
  }

 private:
  mutable std::mutex mu_;
  std::vector<TraceEvent> events_;
};

}  // namespace chio::test
