#include "chio/kernel.hpp"

#include <sstream>
#include <utility>

#include "json_field.hpp"
#include "kernel_request_json.hpp"

#ifdef CHIO_CPP_KERNEL_ENABLE_FFI
#include "chio/chio_kernel_ffi.h"
#endif

namespace chio {
namespace kernel {
namespace {

#ifdef CHIO_CPP_KERNEL_ENABLE_FFI
std::string code_name(int code) {
  switch (code) {
    case CHIO_KERNEL_FFI_ERROR_NONE:
      return "";
    case CHIO_KERNEL_FFI_ERROR_INVALID_JSON:
      return "invalid_json";
    case CHIO_KERNEL_FFI_ERROR_INVALID_HEX:
      return "invalid_hex";
    case CHIO_KERNEL_FFI_ERROR_INVALID_CAPABILITY:
      return "invalid_capability";
    case CHIO_KERNEL_FFI_ERROR_INVALID_PASSPORT:
      return "invalid_passport";
    case CHIO_KERNEL_FFI_ERROR_KEY_MISMATCH:
      return "key_mismatch";
    case CHIO_KERNEL_FFI_ERROR_SIGNING_FAILED:
      return "signing_failed";
    case CHIO_KERNEL_FFI_ERROR_INTERNAL:
      return "internal";
    default:
      return "ffi_error";
  }
}

#endif

std::string result_json(const EvaluateResult& result) {
  std::ostringstream out;
  out << "{";
  out << "\"ok\":" << (result.ok ? "true" : "false");
  out << ",\"verdict\":\"" << detail::escape_json(result.verdict) << "\"";
  out << ",\"reason\":\"" << detail::escape_json(result.reason) << "\"";
  out << ",\"error_code\":\"" << detail::escape_json(result.error_code) << "\"";
  out << ",\"error_message\":\"" << detail::escape_json(result.error_message) << "\"";
  if (result.matched_grant_index.has_value()) {
    out << ",\"matched_grant_index\":" << *result.matched_grant_index;
  }
  if (!result.raw_result_json.empty()) {
    out << ",\"raw_result_json\":\"" << detail::escape_json(result.raw_result_json) << "\"";
  }
  out << "}";
  return out.str();
}

EvaluateResult failure(std::string code, std::string message, std::string reason) {
  EvaluateResult result;
  result.ok = false;
  result.verdict = "deny";
  result.reason = std::move(reason);
  result.error_code = std::move(code);
  result.error_message = std::move(message);
  result.result_json = result_json(result);
  return result;
}

#ifdef CHIO_CPP_KERNEL_ENABLE_FFI
class KernelFfiBuffer {
 public:
  explicit KernelFfiBuffer(ChioKernelFfiBuffer buffer) : buffer_(buffer) {}
  KernelFfiBuffer(const KernelFfiBuffer&) = delete;
  KernelFfiBuffer& operator=(const KernelFfiBuffer&) = delete;
  ~KernelFfiBuffer() { chio_kernel_buffer_free(buffer_); }

  std::string str() const {
    if (buffer_.ptr == nullptr || buffer_.len == 0) {
      return {};
    }
    return std::string(reinterpret_cast<const char*>(buffer_.ptr),
                       buffer_.len);
  }

 private:
  ChioKernelFfiBuffer buffer_;
};

EvaluateResult from_ffi_result(ChioKernelFfiResult ffi_result) {
  KernelFfiBuffer data(ffi_result.data);
  std::string body = data.str();
  if (ffi_result.status == CHIO_KERNEL_FFI_STATUS_OK) {
    EvaluateResult result;
    result.ok = true;
    result.verdict = detail::json_string_field(body, "verdict").value_or("deny");
    result.reason = detail::json_string_field(body, "reason").value_or("");
    result.matched_grant_index = detail::json_uint_field(body, "matched_grant_index");
    result.raw_result_json = body;
    result.result_json = result_json(result);
    return result;
  }

  return failure(code_name(ffi_result.error_code), body, body);
}
#endif

}  // namespace

Kernel::Kernel(KernelOptions options) : options_(std::move(options)) {}

const KernelOptions& Kernel::options() const { return options_; }

const char* Kernel::version() { return "0.1.0"; }

bool Kernel::ffi_enabled() {
#ifdef CHIO_CPP_KERNEL_ENABLE_FFI
  return true;
#else
  return false;
#endif
}

EvaluateResult Kernel::evaluate(const EvaluateRequest& request) const {
  if (request.request_json.empty()) {
    return failure(
        "invalid_argument",
        "EvaluateRequest.request_json must not be empty",
        "request payload missing");
  }

  if (request.capability_json.empty()) {
    return failure(
        "invalid_argument",
        "EvaluateRequest.capability_json must not be empty",
        "capability payload missing");
  }

  if (request.trusted_issuers_hex.empty()) {
    return failure(
        "invalid_argument",
        "EvaluateRequest.trusted_issuers_hex must not be empty",
        "trusted issuer set missing");
  }

  if (!options_.policy_json.empty()) {
    return failure(
        "unsupported_policy",
        "KernelOptions.policy_json is not supported by the current C++ kernel FFI backend",
        "fail-closed because configured policy would otherwise be ignored");
  }

#ifdef CHIO_CPP_KERNEL_ENABLE_FFI
  const std::string envelope = detail::build_kernel_request_json(options_, request);
  return from_ffi_result(chio_kernel_evaluate_json(envelope.c_str()));
#else
  return failure(
      "unsupported",
      "chio-cpp-kernel was built without chio-cpp-kernel-ffi",
      "fail-closed until the Rust kernel FFI backend is linked");
#endif
}

}  // namespace kernel
}  // namespace chio
