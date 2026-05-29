#include "path_guard.hpp"

chio::guard::Verdict PathGuard::evaluate(const chio::guard::GuardRequest& request) {
  if (!request.extracted_path) {
    return chio::guard::Verdict::allow();
  }
  if (chio::guard::path_contains_parent_reference(*request.extracted_path)) {
    return chio::guard::Verdict::deny("path traversal denied");
  }
  return chio::guard::Verdict::allow();
}
