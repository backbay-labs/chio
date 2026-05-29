#include "path_guard.hpp"

#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

// This file targets the C/C++ bindings produced by:
//   wit-bindgen c --world guard --out-dir <generated> wit/chio-guard
//
// The generated header is intentionally not committed. Build it with
// scripts/generate-types.sh or scripts/build-guard.sh.
#include "guard.h"

namespace {

std::string from_generated_string(const guard_string_t& value) {
  return std::string(reinterpret_cast<const char*>(value.ptr), value.len);
}

std::vector<std::string> from_generated_string_list(const guard_list_string_t& values) {
  std::vector<std::string> result;
  result.reserve(values.len);
  for (std::size_t i = 0; i < values.len; ++i) {
    result.push_back(from_generated_string(values.ptr[i]));
  }
  return result;
}

std::optional<std::string> from_generated_optional_string(const guard_option_string_t& value) {
  if (!value.is_some) {
    return std::nullopt;
  }
  return from_generated_string(value.val);
}

std::optional<std::uint32_t> from_generated_optional_u32(const guard_option_u32_t& value) {
  if (!value.is_some) {
    return std::nullopt;
  }
  return value.val;
}

chio::guard::GuardRequest to_guard_request(
    const exports_chio_guard_types_guard_request_t& request) {
  chio::guard::GuardRequest result;
  result.tool_name = from_generated_string(request.tool_name);
  result.server_id = from_generated_string(request.server_id);
  result.agent_id = from_generated_string(request.agent_id);
  result.arguments_json = from_generated_string(request.arguments);
  result.scopes = from_generated_string_list(request.scopes);
  result.action_type = from_generated_optional_string(request.action_type);
  result.extracted_path = from_generated_optional_string(request.extracted_path);
  result.extracted_target = from_generated_optional_string(request.extracted_target);
  result.filesystem_roots = from_generated_string_list(request.filesystem_roots);
  result.matched_grant_index = from_generated_optional_u32(request.matched_grant_index);
  return result;
}

void set_generated_string(guard_string_t* out, const std::string& value) {
  out->len = value.size();
  out->ptr = static_cast<decltype(out->ptr)>(std::malloc(value.size()));
  if (out->ptr == nullptr && !value.empty()) {
    out->len = 0;
    return;
  }
  if (!value.empty()) {
    std::memcpy(out->ptr, value.data(), value.size());
  }
}

void set_verdict(exports_chio_guard_types_verdict_t* out, const chio::guard::Verdict& verdict) {
  if (verdict.allowed()) {
    out->tag = 0;
    return;
  }
  out->tag = 1;
  set_generated_string(&out->val.deny, verdict.reason);
}

}  // namespace

extern "C" void exports_chio_guard_evaluate(
    exports_chio_guard_types_guard_request_t* request,
    exports_chio_guard_types_verdict_t* ret) {
  PathGuard guard;
  const auto native_request = to_guard_request(*request);
  set_verdict(ret, guard.evaluate(native_request));
  exports_chio_guard_types_guard_request_free(request);
}
