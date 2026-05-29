#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace chio::guard {

enum class VerdictKind {
  Allow,
  Deny,
};

struct Verdict {
  VerdictKind kind = VerdictKind::Deny;
  std::string reason;

  static Verdict allow() { return Verdict{VerdictKind::Allow, {}}; }

  static Verdict deny(std::string message) {
    return Verdict{VerdictKind::Deny, std::move(message)};
  }

  [[nodiscard]] bool allowed() const { return kind == VerdictKind::Allow; }

  [[nodiscard]] bool denied() const { return kind == VerdictKind::Deny; }
};

struct GuardRequest {
  std::string tool_name;
  std::string server_id;
  std::string agent_id;
  std::string arguments_json;
  std::vector<std::string> scopes;
  std::optional<std::string> action_type;
  std::optional<std::string> extracted_path;
  std::optional<std::string> extracted_target;
  std::vector<std::string> filesystem_roots;
  std::optional<std::uint32_t> matched_grant_index;
};

using GuardFn = std::function<Verdict(const GuardRequest&)>;

class Guard {
 public:
  virtual ~Guard() = default;
  virtual Verdict evaluate(const GuardRequest& request) = 0;
};

class FunctionGuard final : public Guard {
 public:
  explicit FunctionGuard(GuardFn fn) : fn_(std::move(fn)) {}

  Verdict evaluate(const GuardRequest& request) override {
    if (!fn_) {
      return Verdict::deny("guard function not configured");
    }
    return fn_(request);
  }

 private:
  GuardFn fn_;
};

[[nodiscard]] inline Verdict evaluate_guard(Guard& guard, const GuardRequest& request) {
  return guard.evaluate(request);
}

[[nodiscard]] inline bool path_contains_parent_reference(std::string_view path) {
  if (path == "..") {
    return true;
  }
  if (path.find("../") != std::string_view::npos) {
    return true;
  }
  if (path.find("/..") != std::string_view::npos) {
    return true;
  }
  return path.find("\\..") != std::string_view::npos ||
         path.find("..\\") != std::string_view::npos;
}

}  // namespace chio::guard
