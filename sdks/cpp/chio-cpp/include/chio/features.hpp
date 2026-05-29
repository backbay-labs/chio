#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "chio/dpop.hpp"
#include "chio/models.hpp"
#include "chio/receipt_query.hpp"
#include "chio/result.hpp"
#include "chio/session.hpp"

namespace chio {

class Client;

class Clock {
 public:
  virtual ~Clock() = default;
  virtual std::uint64_t now_unix_secs() const = 0;
};

using ClockPtr = std::shared_ptr<Clock>;

class SystemClock final : public Clock {
 public:
  std::uint64_t now_unix_secs() const override;
};

class NonceGenerator {
 public:
  virtual ~NonceGenerator() = default;
  virtual Result<std::string> generate_nonce() = 0;
};

using NonceGeneratorPtr = std::shared_ptr<NonceGenerator>;

class RandomNonceGenerator final : public NonceGenerator {
 public:
  Result<std::string> generate_nonce() override;
};

class KeyProvider {
 public:
  virtual ~KeyProvider() = default;
  virtual Result<std::string> ed25519_seed_hex() = 0;
};

using KeyProviderPtr = std::shared_ptr<KeyProvider>;

class StaticSeedKeyProvider final : public KeyProvider {
 public:
  explicit StaticSeedKeyProvider(std::string seed_hex);
  Result<std::string> ed25519_seed_hex() override;

 private:
  std::string seed_hex_;
};

class DpopProofBuilder {
 public:
  DpopProofBuilder& capability_id(std::string value);
  DpopProofBuilder& tool_server(std::string value);
  DpopProofBuilder& tool_name(std::string value);
  DpopProofBuilder& action_args_json(std::string value);
  DpopProofBuilder& key_provider(KeyProviderPtr value);
  DpopProofBuilder& nonce_generator(NonceGeneratorPtr value);
  DpopProofBuilder& clock(ClockPtr value);

  Result<DpopProof> build() const;

 private:
  DpopSignParams params_;
  KeyProviderPtr key_provider_;
  NonceGeneratorPtr nonce_generator_;
  ClockPtr clock_;
};

class ReceiptVerifier {
 public:
  explicit ReceiptVerifier(std::shared_ptr<ReceiptQueryClient> remote_query = {});

  Result<std::string> verify_local(std::string receipt_json) const;
  Result<std::string> verify(std::string receipt_json,
                             const std::map<std::string, std::string>& fallback_query = {}) const;

 private:
  std::shared_ptr<ReceiptQueryClient> remote_query_;
};

using RevocationHook = std::function<Result<bool>(const std::string& capability_id)>;

class CapabilityVerifier {
 public:
  CapabilityVerifier(ClockPtr clock = std::make_shared<SystemClock>(),
                     std::uint32_t max_delegation_depth = UINT32_MAX,
                     RevocationHook revocation_hook = {});

  Result<std::string> verify(std::string capability_json) const;

 private:
  ClockPtr clock_;
  std::uint32_t max_delegation_depth_;
  RevocationHook revocation_hook_;
};

class ToolClient {
 public:
  ToolClient(Session& session, std::string name);

  Result<std::string> call_json(std::string arguments_json = "{}") const;
  Result<TypedResponse<std::string>> call_typed(std::string arguments_json = "{}") const;

 private:
  Session* session_;
  std::string name_;
};

class SessionPool {
 public:
  Result<std::shared_ptr<Session>> get_or_initialize(const Client& client);
  void clear();

 private:
  std::mutex mu_;
  std::map<std::string, std::weak_ptr<Session>> sessions_;
  std::map<std::string, std::weak_ptr<std::mutex>> initialization_locks_;
};

}  // namespace chio
