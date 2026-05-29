#include "chio/chio.hpp"

#include <iostream>

int main() {
  auto hash = chio::invariants::sha256_hex_utf8("hello");
  if (!hash) {
    std::cerr << hash.error().message << "\n";
    return 1;
  }
  return hash.value() ==
                 "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
             ? 0
             : 1;
}
