#pragma once

#include <string>
#include <string_view>

#include "chio/result.hpp"

namespace chio::detail {

struct SseEventData {
  std::string payload;
  bool has_data = false;
};

inline std::string_view trim_sse_cr(std::string_view line) {
  if (!line.empty() && line.back() == '\r') {
    line.remove_suffix(1);
  }
  return line;
}

inline bool is_sse_blank_line(std::string_view line) {
  return trim_sse_cr(line).empty();
}

inline void append_sse_data_line(SseEventData& event, std::string_view line) {
  auto value = trim_sse_cr(line.substr(5));
  if (!value.empty() && value.front() == ' ') {
    value.remove_prefix(1);
  }
  if (event.has_data) {
    event.payload.push_back('\n');
  }
  event.payload.append(value.data(), value.size());
  event.has_data = true;
}

template <typename Callback>
Result<void> flush_sse_event(SseEventData& event, Callback&& callback) {
  if (!event.has_data) {
    return Result<void>::success();
  }
  auto payload = std::move(event.payload);
  event.payload.clear();
  event.has_data = false;
  if (payload.empty() || payload == "[DONE]") {
    return Result<void>::success();
  }
  return callback(payload);
}

template <typename Callback>
Result<void> for_each_sse_event(std::string_view body,
                                Callback&& callback,
                                bool flush_tail = true) {
  SseEventData event;
  std::size_t offset = 0;
  while (offset < body.size()) {
    const auto line_end = body.find('\n', offset);
    if (line_end == std::string_view::npos) {
      if (!flush_tail) {
        return Result<void>::success();
      }
      const auto line = body.substr(offset);
      if (is_sse_blank_line(line)) {
        auto flushed = flush_sse_event(event, callback);
        if (!flushed) {
          return flushed;
        }
      } else if (line.rfind("data:", 0) == 0) {
        append_sse_data_line(event, line);
      }
      offset = body.size();
      break;
    }

    const auto line = body.substr(offset, line_end - offset);
    offset = line_end + 1;
    if (is_sse_blank_line(line)) {
      auto flushed = flush_sse_event(event, callback);
      if (!flushed) {
        return flushed;
      }
      continue;
    }
    if (line.rfind("data:", 0) == 0) {
      append_sse_data_line(event, line);
    }
  }

  return flush_tail ? flush_sse_event(event, callback) : Result<void>::success();
}

}  // namespace chio::detail
