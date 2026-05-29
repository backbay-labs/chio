#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "chio/invariants.hpp"

namespace chio::detail {

inline std::string bearer_cache_key(std::string_view token) {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(token.size());
  for (unsigned char ch : token) {
    bytes.push_back(ch);
  }
  auto digest = invariants::sha256_hex_bytes(bytes);
  if (!digest) {
    return {};
  }
  return "sha256:" + digest.value();
}

}  // namespace chio::detail
