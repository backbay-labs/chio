#pragma once

#include <functional>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace chio {

enum class ErrorCode {
  None = 0,
  InvalidPublicKey = 1,
  InvalidHex = 2,
  InvalidSignature = 3,
  Json = 4,
  CanonicalJson = 5,
  CapabilityExpired = 6,
  CapabilityNotYetValid = 7,
  CapabilityRevoked = 8,
  DelegationChainBroken = 9,
  AttenuationViolation = 10,
  ScopeMismatch = 11,
  SignatureVerificationFailed = 12,
  DelegationDepthExceeded = 13,
  InvalidHashLength = 14,
  MerkleProofFailed = 15,
  EmptyTree = 16,
  InvalidProofIndex = 17,
  EmptyManifest = 18,
  DuplicateToolName = 19,
  UnsupportedSchema = 20,
  ManifestVerificationFailed = 21,
  Transport = 200,
  Protocol = 201,
  Internal = 255,
};

struct Error {
  ErrorCode code = ErrorCode::None;
  std::string message;
  std::string operation;
  std::optional<int> http_status;
  std::string response_body_snippet;
  std::optional<int> ffi_status;
  std::optional<int> ffi_error_code;
  bool retryable = false;

  static Error none() { return {}; }
};

template <typename T>
class Result;

template <>
class Result<void> {
 public:
  static Result success() { return Result(true, Error::none()); }
  static Result failure(Error error) { return Result(false, std::move(error)); }

  bool ok() const { return ok_; }
  explicit operator bool() const { return ok(); }

  const Error& error() const { return error_; }

  template <typename F>
  auto map(F&& f) const -> Result<decltype(f())> {
    using U = decltype(f());
    if (!ok()) {
      return Result<U>::failure(error_);
    }
    if constexpr (std::is_void<U>::value) {
      f();
      return Result<void>::success();
    } else {
      return Result<U>::success(f());
    }
  }

  template <typename F>
  auto and_then(F&& f) const -> decltype(f()) {
    using R = decltype(f());
    if (!ok()) {
      return R::failure(error_);
    }
    return f();
  }

  template <typename F>
  Result or_else(F&& f) const {
    if (ok()) {
      return Result::success();
    }
    return f(error_);
  }

 private:
  Result(bool ok, Error error) : ok_(ok), error_(std::move(error)) {}

  bool ok_ = false;
  Error error_{ErrorCode::Internal, "result has no value"};
};

template <typename T>
class Result {
 public:
  static Result success(T value) { return Result(std::move(value)); }
  static Result failure(Error error) { return Result(std::move(error)); }

  bool ok() const { return value_.has_value(); }
  explicit operator bool() const { return ok(); }

  const T& value() const { return *value_; }
  T& value() { return *value_; }
  T&& move_value() { return std::move(*value_); }

  const Error& error() const { return error_; }

  template <typename F>
  auto map(F&& f) const -> Result<decltype(f(value()))> {
    using U = decltype(f(value()));
    if (!ok()) {
      return Result<U>::failure(error_);
    }
    if constexpr (std::is_void<U>::value) {
      f(value());
      return Result<void>::success();
    } else {
      return Result<U>::success(f(value()));
    }
  }

  template <typename F>
  auto and_then(F&& f) const -> decltype(f(value())) {
    using R = decltype(f(value()));
    if (!ok()) {
      return R::failure(error_);
    }
    return f(value());
  }

  template <typename F>
  Result or_else(F&& f) const {
    if (ok()) {
      return Result::success(value());
    }
    return f(error_);
  }

 private:
  explicit Result(T value) : value_(std::move(value)) {}
  explicit Result(Error error) : error_(std::move(error)) {}

  std::optional<T> value_;
  Error error_{ErrorCode::Internal, "result has no value"};
};

}  // namespace chio
