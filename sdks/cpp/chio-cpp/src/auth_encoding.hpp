#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace chio::detail {

inline std::string base64url_encode(const std::vector<std::uint8_t>& bytes) {
  static constexpr char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve(((bytes.size() + 2U) / 3U) * 4U);

  std::size_t offset = 0;
  while (offset + 3U <= bytes.size()) {
    const std::uint32_t chunk =
        (static_cast<std::uint32_t>(bytes[offset]) << 16U) |
        (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
        static_cast<std::uint32_t>(bytes[offset + 2U]);
    out.push_back(alphabet[(chunk >> 18U) & 0x3FU]);
    out.push_back(alphabet[(chunk >> 12U) & 0x3FU]);
    out.push_back(alphabet[(chunk >> 6U) & 0x3FU]);
    out.push_back(alphabet[chunk & 0x3FU]);
    offset += 3U;
  }

  const std::size_t remaining = bytes.size() - offset;
  if (remaining == 1U) {
    const std::uint32_t chunk =
        static_cast<std::uint32_t>(bytes[offset]) << 16U;
    out.push_back(alphabet[(chunk >> 18U) & 0x3FU]);
    out.push_back(alphabet[(chunk >> 12U) & 0x3FU]);
  } else if (remaining == 2U) {
    const std::uint32_t chunk =
        (static_cast<std::uint32_t>(bytes[offset]) << 16U) |
        (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U);
    out.push_back(alphabet[(chunk >> 18U) & 0x3FU]);
    out.push_back(alphabet[(chunk >> 12U) & 0x3FU]);
    out.push_back(alphabet[(chunk >> 6U) & 0x3FU]);
  }

  return out;
}

}  // namespace chio::detail
