#pragma once

#include <string>

#include "json.hpp"

namespace chio::detail {

inline std::string request_id_json(const std::string& body) {
  auto parsed = detail::parse_json(body);
  if (!parsed || !parsed->is_object()) {
    return {};
  }
  const auto* id = parsed->get("id");
  return id == nullptr ? std::string() : id->dump();
}

inline bool is_jsonrpc_terminal_response(const JsonValue& value,
                                         const std::string& id_json) {
  if (id_json.empty() || !value.is_object()) {
    return false;
  }
  if (value.string_field("jsonrpc") != "2.0") {
    return false;
  }
  const auto* id = value.get("id");
  if (id == nullptr || id->dump() != id_json) {
    return false;
  }
  return value.get("result") != nullptr || value.get("error") != nullptr;
}

inline bool is_jsonrpc_terminal_response(const std::string& payload,
                                         const std::string& id_json) {
  auto parsed = detail::parse_json(payload);
  if (!parsed) {
    return false;
  }
  return is_jsonrpc_terminal_response(*parsed, id_json);
}

}  // namespace chio::detail
