#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "chio/transport.hpp"

namespace chio {

template <typename T>
struct TypedResponse {
  T value;
  std::string raw_json;
  HttpResponse response;
};

struct SessionInfo {
  std::string session_id;
  std::string protocol_version;
  std::string server_name;
  std::string server_version;
};

struct Tool {
  std::string name;
  std::string title;
  std::string description;
  std::string input_schema_json;
  std::map<std::string, std::string> annotations;
};

struct Resource {
  std::string uri;
  std::string name;
  std::string description;
  std::string mime_type;
};

struct Prompt {
  std::string name;
  std::string title;
  std::string description;
};

struct Task {
  std::string task_id;
  std::string status;
  std::string raw_json;
};

struct Receipt {
  std::string receipt_id;
  std::optional<std::string> decision;
  std::string receipt_kind;
  std::string boundary_class;
  std::string raw_json;
};

struct EvaluateVerdict {
  std::string verdict;
  std::string reason;
  std::string receipt_json;
  std::string raw_json;
};

}  // namespace chio
