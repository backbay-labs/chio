#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "chio/result.hpp"

namespace chio::invariants {

std::uint32_t ffi_abi_version();
Result<std::string> ffi_build_info();

Result<std::string> canonicalize_json(std::string_view input_json);
Result<std::string> sha256_hex_utf8(std::string_view input_utf8);
Result<std::string> sha256_hex_bytes(const std::vector<std::uint8_t>& input);

Result<std::string> sign_utf8_message_ed25519(std::string_view input_utf8,
                                              std::string_view seed_hex);
Result<bool> verify_utf8_message_ed25519(std::string_view input_utf8,
                                         std::string_view public_key_hex,
                                         std::string_view signature_hex);

Result<std::string> sign_json_ed25519(std::string_view input_json,
                                      std::string_view seed_hex);
Result<bool> verify_json_signature_ed25519(std::string_view input_json,
                                           std::string_view public_key_hex,
                                           std::string_view signature_hex);

Result<std::string> verify_capability_json(std::string_view input_json,
                                           std::uint64_t now_secs,
                                           std::uint32_t max_delegation_depth);
Result<std::string> verify_receipt_json(std::string_view input_json);
Result<std::string> verify_manifest_json(std::string_view input_json);

}  // namespace chio::invariants
