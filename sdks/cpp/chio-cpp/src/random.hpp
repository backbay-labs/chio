#pragma once

#include <cstddef>
#include <random>
#include <string>

namespace chio::detail {

inline std::string random_hex(std::size_t bytes) {
  constexpr char kHexDigits[] = "0123456789abcdef";
  std::random_device rng;
  std::string out;
  out.reserve(bytes * 2);
  for (std::size_t i = 0; i < bytes; ++i) {
    const auto byte = static_cast<unsigned int>(rng() & 0xffU);
    out.push_back(kHexDigits[(byte >> 4U) & 0x0FU]);
    out.push_back(kHexDigits[byte & 0x0FU]);
  }
  return out;
}

}  // namespace chio::detail
