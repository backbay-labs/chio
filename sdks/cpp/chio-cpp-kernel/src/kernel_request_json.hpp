#pragma once

#include "chio/kernel.hpp"

#include <cstddef>
#include <optional>
#include <sstream>
#include <string>

#include "json_field.hpp"

namespace chio {
namespace kernel {
namespace detail {

inline std::optional<std::uint64_t> effective_now_secs(
    const KernelOptions& options,
    const EvaluateRequest& request) {
  if (request.now_secs.has_value()) {
    return request.now_secs;
  }
  return options.default_now_secs;
}

inline std::string build_kernel_request_json(const KernelOptions& options,
                                             const EvaluateRequest& request) {
  const auto now_secs = effective_now_secs(options, request);

  std::ostringstream out;
  out << "{";
  out << "\"capability\":" << request.capability_json;
  out << ",\"trusted_issuers\":[";
  for (std::size_t i = 0; i < request.trusted_issuers_hex.size(); ++i) {
    if (i != 0) {
      out << ",";
    }
    out << "\"" << detail::escape_json(request.trusted_issuers_hex[i]) << "\"";
  }
  out << "]";
  out << ",\"request\":" << request.request_json;
  if (now_secs.has_value()) {
    out << ",\"now_secs\":" << *now_secs;
  }
  out << "}";
  return out.str();
}

}  // namespace detail
}  // namespace kernel
}  // namespace chio
