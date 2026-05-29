#pragma once

#include <algorithm>
#include <chrono>
#include <string>
#include <thread>

#include "chio/transport.hpp"

namespace chio::detail {

inline std::string body_snippet(const std::string& body) {
  constexpr std::size_t max_len = 512;
  if (body.size() <= max_len) {
    return body;
  }
  return body.substr(0, max_len);
}

inline bool retryable_status(int status) {
  return status == 408 || status == 429 || status >= 500;
}

inline Result<HttpResponse> send_with_policy(HttpTransportPtr transport,
                                             HttpRequest request,
                                             RetryPolicy policy,
                                             TraceSinkPtr trace_sink,
                                             std::string operation) {
  if (!transport) {
    return Result<HttpResponse>::failure(
        Error{ErrorCode::Transport, "missing HTTP transport", std::move(operation)});
  }
  policy.max_attempts = std::max(1, policy.max_attempts);
  auto backoff = policy.initial_backoff;
  Error last_error{ErrorCode::Transport, "request was not attempted", operation};

  for (int attempt = 1; attempt <= policy.max_attempts; ++attempt) {
    request.attempt = attempt;
    if (request.cancellation && request.cancellation->cancelled()) {
      return Result<HttpResponse>::failure(
          Error{ErrorCode::Transport, "request cancelled before send", operation, {}, {}, {}, {}, false});
    }

    const auto started = std::chrono::steady_clock::now();
    auto response = transport->send(request);
    if (response) {
      auto value = response.move_value();
      value.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - started);
      value.attempt = attempt;
      if (trace_sink) {
        trace_sink->record(TraceEvent{operation, request, value, Error::none()});
      }
      if (!retryable_status(value.status) || attempt == policy.max_attempts) {
        return Result<HttpResponse>::success(std::move(value));
      }
      last_error = Error{ErrorCode::Transport,
                         "retryable HTTP status " + std::to_string(value.status),
                         operation,
                         value.status,
                         body_snippet(value.body),
                         {},
                         {},
                         true};
    } else {
      last_error = response.error();
      last_error.operation = operation;
      if (trace_sink) {
        trace_sink->record(TraceEvent{operation, request, {}, last_error});
      }
      if (!last_error.retryable || attempt == policy.max_attempts) {
        return Result<HttpResponse>::failure(last_error);
      }
    }

    if (request.cancellation && request.cancellation->cancelled()) {
      return Result<HttpResponse>::failure(
          Error{ErrorCode::Transport, "request cancelled during retry", operation, {}, {}, {}, {}, false});
    }
    std::this_thread::sleep_for(backoff);
    backoff = std::min(policy.max_backoff, backoff * 2);
  }

  return Result<HttpResponse>::failure(last_error);
}

}  // namespace chio::detail
