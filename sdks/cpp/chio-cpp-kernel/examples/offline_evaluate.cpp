#include "chio/kernel.hpp"

#include <iostream>

int main() {
  chio::kernel::Kernel kernel;

  chio::kernel::EvaluateRequest request;
  request.request_json = "{\"request_id\":\"req-1\",\"tool_name\":\"echo\"}";
  request.capability_json = "{\"id\":\"cap-1\"}";
  request.trusted_issuers_hex.push_back("00");

  const auto result = kernel.evaluate(request);
  std::cout << result.result_json << "\n";
  return 0;
}
