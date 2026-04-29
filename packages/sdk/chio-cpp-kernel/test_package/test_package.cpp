#include "chio/kernel.hpp"

#include <cstring>
#include <iostream>

int main() {
  const char* version = chio::kernel::Kernel::version();
  if (version == nullptr || std::strlen(version) == 0) {
    std::cerr << "expected non-empty kernel version\n";
    return 1;
  }
  chio::kernel::Kernel kernel{};
  if (kernel.options().kernel_id != "chio-cpp-kernel") {
    std::cerr << "unexpected default kernel_id\n";
    return 1;
  }
  return 0;
}
