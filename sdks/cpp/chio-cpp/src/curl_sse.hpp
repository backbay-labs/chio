#pragma once

#include <cstddef>
#include <functional>
#include <string>

#include "chio/result.hpp"
#include "json.hpp"
#include "json_rpc.hpp"
#include "sse.hpp"

namespace chio {
namespace detail {

constexpr std::size_t kSseCompactThreshold = 4096;

inline bool is_terminal_message(const std::string& payload, const std::string& id_json) {
  return is_jsonrpc_terminal_response(payload, id_json);
}

struct CurlBodyCapture {
  std::string body;
  std::string scan_buffer;
  std::string id_json;
  std::size_t scan_pos = 0;
  bool complete = false;
  bool callback_failed = false;
  SseEventData pending_event;
  Error callback_error;
  std::function<Result<void>(const std::string&)> stream_message;
};

inline void compact_processed_sse(CurlBodyCapture& capture) {
  if (capture.scan_pos < kSseCompactThreshold) {
    return;
  }
  capture.scan_buffer.erase(0, capture.scan_pos);
  capture.scan_pos = 0;
}

inline void scan_sse_events(CurlBodyCapture& capture) {
  while (true) {
    const auto line_start = capture.scan_pos;
    const auto line_end = capture.scan_buffer.find('\n', line_start);
    if (line_end == std::string::npos) {
      compact_processed_sse(capture);
      return;
    }
    capture.scan_pos = line_end + 1;
    std::string_view line(capture.scan_buffer.data() + line_start, line_end - line_start);
    if (is_sse_blank_line(line)) {
      auto delivered = flush_sse_event(capture.pending_event, [&](const std::string& payload) {
        if (capture.stream_message) {
          auto handled = capture.stream_message(payload);
          if (!handled) {
            return handled;
          }
        }
        if (is_terminal_message(payload, capture.id_json)) {
          capture.complete = true;
        }
        return Result<void>::success();
      });
      if (!delivered) {
        capture.callback_failed = true;
        capture.callback_error = delivered.error();
        capture.complete = true;
        return;
      }
      if (capture.complete) {
        return;
      }
      compact_processed_sse(capture);
      continue;
    }
    if (line.rfind("data:", 0) == 0) {
      append_sse_data_line(capture.pending_event, line);
    }
    compact_processed_sse(capture);
  }
}

inline std::size_t write_curl_body(char* ptr,
                                   std::size_t size,
                                   std::size_t nmemb,
                                   void* userdata) {
  auto* capture = static_cast<CurlBodyCapture*>(userdata);
  const std::size_t len = size * nmemb;
  capture->body.append(ptr, len);
  capture->scan_buffer.append(ptr, len);
  scan_sse_events(*capture);
  if (capture->callback_failed || (capture->complete && capture->stream_message)) {
    return 0;
  }
  return len;
}

}  // namespace detail
}  // namespace chio
