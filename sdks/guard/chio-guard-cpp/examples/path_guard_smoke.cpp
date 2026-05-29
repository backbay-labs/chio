#include "path_guard.hpp"

#include <iostream>
#include <string>

namespace {

chio::guard::GuardRequest request_with_path(std::string path) {
  chio::guard::GuardRequest request;
  request.tool_name = "read_file";
  request.server_id = "fs";
  request.agent_id = "agent";
  request.arguments_json = "{\"path\":\"" + path + "\"}";
  request.scopes = {"fs:read"};
  request.action_type = "file_access";
  request.extracted_path = std::move(path);
  request.filesystem_roots = {"/workspace"};
  request.matched_grant_index = 0;
  return request;
}

int fail(const char* message) {
  std::cerr << message << '\n';
  return 1;
}

}  // namespace

int main() {
  PathGuard guard;

  auto allowed = chio::guard::evaluate_guard(guard, request_with_path("/workspace/src/main.cpp"));
  if (!allowed.allowed()) {
    return fail("expected normal workspace path to be allowed");
  }

  auto denied = chio::guard::evaluate_guard(guard, request_with_path("../secret.txt"));
  if (!denied.denied()) {
    return fail("expected parent traversal path to be denied");
  }

  auto functional = chio::guard::FunctionGuard([](const chio::guard::GuardRequest& request) {
    if (request.tool_name == "blocked_tool") {
      return chio::guard::Verdict::deny("tool is blocked");
    }
    return chio::guard::Verdict::allow();
  });

  chio::guard::GuardRequest blocked;
  blocked.tool_name = "blocked_tool";
  if (!functional.evaluate(blocked).denied()) {
    return fail("expected function guard to deny blocked tool");
  }

  std::cout << "chio-guard-cpp native smoke passed\n";
  return 0;
}
