#include "chio/invariants.hpp"

#include <cstring>

#include "chio/chio_ffi.h"

namespace chio::invariants {
namespace {

class FfiBuffer {
 public:
  explicit FfiBuffer(ChioFfiBuffer buffer) : buffer_(buffer) {}
  ~FfiBuffer() { chio_buffer_free(buffer_); }

  FfiBuffer(const FfiBuffer&) = delete;
  FfiBuffer& operator=(const FfiBuffer&) = delete;

  FfiBuffer(FfiBuffer&& other) noexcept : buffer_(other.buffer_) {
    other.buffer_ = ChioFfiBuffer{nullptr, 0};
  }
  FfiBuffer& operator=(FfiBuffer&& other) noexcept {
    if (this == &other) {
      return *this;
    }
    chio_buffer_free(buffer_);
    buffer_ = other.buffer_;
    other.buffer_ = ChioFfiBuffer{nullptr, 0};
    return *this;
  }

  std::string to_string() const {
    if (buffer_.ptr == nullptr || buffer_.len == 0) {
      return {};
    }
    return std::string(reinterpret_cast<const char*>(buffer_.ptr), buffer_.len);
  }

 private:
  ChioFfiBuffer buffer_{nullptr, 0};
};

Result<std::string> from_ffi(ChioFfiResult result, std::string operation) {
  FfiBuffer buffer(result.data);
  std::string payload;
  payload = buffer.to_string();
  if (result.status == CHIO_FFI_STATUS_OK) {
    return Result<std::string>::success(std::move(payload));
  }
  return Result<std::string>::failure(
      Error{static_cast<ErrorCode>(result.error_code),
            std::move(payload),
            std::move(operation),
            {},
            {},
            result.status,
            result.error_code,
            false});
}

Result<bool> bool_from_ffi(ChioFfiResult result, std::string operation) {
  auto text = from_ffi(result, std::move(operation));
  if (!text) {
    return Result<bool>::failure(text.error());
  }
  return Result<bool>::success(text.value() == "true");
}

std::string owned(std::string_view input) {
  return std::string(input.data(), input.size());
}

}  // namespace

std::uint32_t ffi_abi_version() {
  return chio_ffi_abi_version();
}

Result<std::string> ffi_build_info() {
  return from_ffi(chio_ffi_build_info(), "invariants::ffi_build_info");
}

Result<std::string> canonicalize_json(std::string_view input_json) {
  auto input = owned(input_json);
  return from_ffi(chio_canonicalize_json(input.c_str()),
                  "invariants::canonicalize_json");
}

Result<std::string> sha256_hex_utf8(std::string_view input_utf8) {
  auto input = owned(input_utf8);
  return from_ffi(chio_sha256_hex_utf8(input.c_str()),
                  "invariants::sha256_hex_utf8");
}

Result<std::string> sha256_hex_bytes(const std::vector<std::uint8_t>& input) {
  return from_ffi(chio_sha256_hex_bytes(input.data(), input.size()),
                  "invariants::sha256_hex_bytes");
}

Result<std::string> sign_utf8_message_ed25519(std::string_view input_utf8,
                                              std::string_view seed_hex) {
  auto input = owned(input_utf8);
  auto seed = owned(seed_hex);
  return from_ffi(chio_sign_utf8_message_ed25519(input.c_str(), seed.c_str()),
                  "invariants::sign_utf8_message_ed25519");
}

Result<bool> verify_utf8_message_ed25519(std::string_view input_utf8,
                                         std::string_view public_key_hex,
                                         std::string_view signature_hex) {
  auto input = owned(input_utf8);
  auto key = owned(public_key_hex);
  auto sig = owned(signature_hex);
  return bool_from_ffi(
      chio_verify_utf8_message_ed25519(input.c_str(), key.c_str(), sig.c_str()),
      "invariants::verify_utf8_message_ed25519");
}

Result<std::string> sign_json_ed25519(std::string_view input_json,
                                      std::string_view seed_hex) {
  auto input = owned(input_json);
  auto seed = owned(seed_hex);
  return from_ffi(chio_sign_json_ed25519(input.c_str(), seed.c_str()),
                  "invariants::sign_json_ed25519");
}

Result<bool> verify_json_signature_ed25519(std::string_view input_json,
                                           std::string_view public_key_hex,
                                           std::string_view signature_hex) {
  auto input = owned(input_json);
  auto key = owned(public_key_hex);
  auto sig = owned(signature_hex);
  return bool_from_ffi(
      chio_verify_json_signature_ed25519(input.c_str(), key.c_str(), sig.c_str()),
      "invariants::verify_json_signature_ed25519");
}

Result<std::string> verify_capability_json(std::string_view input_json,
                                           std::uint64_t now_secs,
                                           std::uint32_t max_delegation_depth) {
  auto input = owned(input_json);
  return from_ffi(
      chio_verify_capability_json(input.c_str(), now_secs, max_delegation_depth),
      "invariants::verify_capability_json");
}

Result<std::string> verify_receipt_json(std::string_view input_json) {
  auto input = owned(input_json);
  return from_ffi(chio_verify_receipt_json(input.c_str()),
                  "invariants::verify_receipt_json");
}

Result<std::string> verify_manifest_json(std::string_view input_json) {
  auto input = owned(input_json);
  return from_ffi(chio_verify_manifest_json(input.c_str()),
                  "invariants::verify_manifest_json");
}

}  // namespace chio::invariants
