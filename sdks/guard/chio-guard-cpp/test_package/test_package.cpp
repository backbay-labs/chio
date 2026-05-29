#include "chio/guard.hpp"

#include <iostream>

int main() {
  if (!chio::guard::path_contains_parent_reference("../etc/passwd")) {
    std::cerr << "expected parent reference to be detected\n";
    return 1;
  }
  if (chio::guard::path_contains_parent_reference("etc/passwd")) {
    std::cerr << "did not expect parent reference\n";
    return 1;
  }

  chio::guard::FunctionGuard allow_guard([](const chio::guard::GuardRequest&) {
    return chio::guard::Verdict::allow();
  });
  if (!allow_guard.evaluate({}).allowed()) {
    std::cerr << "function guard did not allow\n";
    return 1;
  }
  return 0;
}
