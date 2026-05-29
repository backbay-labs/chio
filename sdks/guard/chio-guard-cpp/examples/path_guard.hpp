#pragma once

#include "chio/guard.hpp"

class PathGuard final : public chio::guard::Guard {
 public:
  chio::guard::Verdict evaluate(const chio::guard::GuardRequest& request) override;
};
