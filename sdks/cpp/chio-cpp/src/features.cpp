#include "chio/features.hpp"

#include <chrono>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include "auth_cache.hpp"
#include "chio/client.hpp"
#include "chio/invariants.hpp"
#include "json.hpp"
#include "random.hpp"

namespace chio {
namespace {

std::string capability_id_from_json(const std::string& capability_json) {
  auto parsed = detail::parse_json(capability_json);
  if (parsed) {
    auto id = parsed->string_field("id");
    if (!id.empty()) {
      return id;
    }
    id = parsed->string_field("capability_id");
    if (!id.empty()) {
      return id;
    }
  }
  auto id = detail::extract_json_string_field(capability_json, "id");
  if (!id.empty()) {
    return id;
  }
  return detail::extract_json_string_field(capability_json, "capability_id");
}

std::string session_pool_key(const ClientOptions& options,
                             const HttpTransport* transport,
                             const TraceSink* trace_sink) {
  std::ostringstream key;
  key << "base=" << options.base_url << "\n"
      << "protocol=" << options.protocol_version << "\n"
      << "client_name=" << options.client_name << "\n"
      << "client_version=" << options.client_version << "\n"
      << "capabilities=" << options.client_capabilities_json << "\n"
      << "transport@" << transport << "\n"
      << "trace_sink@" << trace_sink << "\n"
      << "timeout_ms=" << options.timeout.count() << "\n"
      << "retry_attempts=" << options.retry_policy.max_attempts << "\n"
      << "retry_initial_ms=" << options.retry_policy.initial_backoff.count() << "\n"
      << "retry_max_ms=" << options.retry_policy.max_backoff.count() << "\n";
  if (options.token_provider) {
    auto provider_key = options.token_provider->cache_key();
    if (provider_key.empty()) {
      key << "token_provider@" << options.token_provider.get();
    } else {
      key << "token_provider=" << provider_key;
    }
  } else {
    auto bearer_key = detail::bearer_cache_key(options.bearer_token);
    if (bearer_key.empty()) {
      key << "bearer_storage@" << static_cast<const void*>(&options.bearer_token);
    } else {
      key << "bearer=" << bearer_key;
    }
  }
  return key.str();
}

void prune_session_pool_locked(
    std::map<std::string, std::weak_ptr<Session>>& sessions,
    std::map<std::string, std::weak_ptr<std::mutex>>& initialization_locks) {
  for (auto it = sessions.begin(); it != sessions.end();) {
    if (it->second.expired()) {
      it = sessions.erase(it);
    } else {
      ++it;
    }
  }

  for (auto it = initialization_locks.begin(); it != initialization_locks.end();) {
    if (it->second.expired() && sessions.find(it->first) == sessions.end()) {
      it = initialization_locks.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace

std::uint64_t SystemClock::now_unix_secs() const {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

Result<std::string> RandomNonceGenerator::generate_nonce() {
  return Result<std::string>::success(detail::random_hex(16));
}

StaticSeedKeyProvider::StaticSeedKeyProvider(std::string seed_hex)
    : seed_hex_(std::move(seed_hex)) {}

Result<std::string> StaticSeedKeyProvider::ed25519_seed_hex() {
  if (seed_hex_.empty()) {
    return Result<std::string>::failure(
        Error{ErrorCode::Protocol, "seed is empty",
              "StaticSeedKeyProvider::ed25519_seed_hex"});
  }
  return Result<std::string>::success(seed_hex_);
}

DpopProofBuilder& DpopProofBuilder::capability_id(std::string value) {
  params_.capability_id = std::move(value);
  return *this;
}

DpopProofBuilder& DpopProofBuilder::tool_server(std::string value) {
  params_.tool_server = std::move(value);
  return *this;
}

DpopProofBuilder& DpopProofBuilder::tool_name(std::string value) {
  params_.tool_name = std::move(value);
  return *this;
}

DpopProofBuilder& DpopProofBuilder::action_args_json(std::string value) {
  params_.action_args_json = std::move(value);
  return *this;
}

DpopProofBuilder& DpopProofBuilder::key_provider(KeyProviderPtr value) {
  key_provider_ = std::move(value);
  return *this;
}

DpopProofBuilder& DpopProofBuilder::nonce_generator(NonceGeneratorPtr value) {
  nonce_generator_ = std::move(value);
  return *this;
}

DpopProofBuilder& DpopProofBuilder::clock(ClockPtr value) {
  clock_ = std::move(value);
  return *this;
}

Result<DpopProof> DpopProofBuilder::build() const {
  if (!key_provider_) {
    return Result<DpopProof>::failure(
        Error{ErrorCode::Protocol, "key provider is required", "DpopProofBuilder::build"});
  }
  auto params = params_;
  auto seed = key_provider_->ed25519_seed_hex();
  if (!seed) {
    return Result<DpopProof>::failure(seed.error());
  }
  params.agent_seed_hex = seed.value();
  if (params.nonce.empty()) {
    auto generator = nonce_generator_ ? nonce_generator_
                                      : std::make_shared<RandomNonceGenerator>();
    auto nonce = generator->generate_nonce();
    if (!nonce) {
      return Result<DpopProof>::failure(nonce.error());
    }
    params.nonce = nonce.value();
  }
  if (params.issued_at == 0) {
    auto clock = clock_ ? clock_ : std::make_shared<SystemClock>();
    params.issued_at = clock->now_unix_secs();
  }
  return sign_dpop_proof(params);
}

ReceiptVerifier::ReceiptVerifier(std::shared_ptr<ReceiptQueryClient> remote_query)
    : remote_query_(std::move(remote_query)) {}

Result<std::string> ReceiptVerifier::verify_local(std::string receipt_json) const {
  return invariants::verify_receipt_json(receipt_json);
}

Result<std::string> ReceiptVerifier::verify(
    std::string receipt_json,
    const std::map<std::string, std::string>& fallback_query) const {
  auto local = verify_local(std::move(receipt_json));
  if (local || !remote_query_) {
    return local;
  }
  return remote_query_->query(fallback_query);
}

CapabilityVerifier::CapabilityVerifier(ClockPtr clock,
                                       std::uint32_t max_delegation_depth,
                                       RevocationHook revocation_hook)
    : clock_(std::move(clock)),
      max_delegation_depth_(max_delegation_depth),
      revocation_hook_(std::move(revocation_hook)) {}

Result<std::string> CapabilityVerifier::verify(std::string capability_json) const {
  const auto capability_id = capability_id_from_json(capability_json);
  if (revocation_hook_ && !capability_id.empty()) {
    auto revoked = revocation_hook_(capability_id);
    if (!revoked) {
      return Result<std::string>::failure(revoked.error());
    }
    if (revoked.value()) {
      return Result<std::string>::failure(
          Error{ErrorCode::CapabilityRevoked, "capability is revoked",
                "CapabilityVerifier::verify"});
    }
  }
  const auto now = clock_ ? clock_->now_unix_secs() : SystemClock().now_unix_secs();
  return invariants::verify_capability_json(capability_json, now, max_delegation_depth_);
}

ToolClient::ToolClient(Session& session, std::string name)
    : session_(&session), name_(std::move(name)) {}

Result<std::string> ToolClient::call_json(std::string arguments_json) const {
  return session_->call_tool(name_, std::move(arguments_json));
}

Result<TypedResponse<std::string>> ToolClient::call_typed(
    std::string arguments_json) const {
  const auto id = session_->next_id();
  auto raw = session_->send_envelope_response(
      "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
      ",\"method\":\"tools/call\",\"params\":{\"name\":" + detail::quote(name_) +
      ",\"arguments\":" + arguments_json + "}}");
  if (!raw) {
    return Result<TypedResponse<std::string>>::failure(raw.error());
  }
  return Result<TypedResponse<std::string>>::success(raw.move_value());
}

Result<std::shared_ptr<Session>> SessionPool::get_or_initialize(const Client& client) {
  const auto key = session_pool_key(client.options_,
                                    client.transport_.get(),
                                    client.trace_sink_.get());
  std::shared_ptr<std::mutex> initialization_lock;
  {
    std::lock_guard<std::mutex> lock(mu_);
    prune_session_pool_locked(sessions_, initialization_locks_);
    auto found = sessions_.find(key);
    if (found != sessions_.end()) {
      auto existing = found->second.lock();
      if (existing) {
        return Result<std::shared_ptr<Session>>::success(existing);
      }
    }
    auto& pending_lock_ref = initialization_locks_[key];
    auto pending_lock = pending_lock_ref.lock();
    if (!pending_lock) {
      pending_lock = std::make_shared<std::mutex>();
      pending_lock_ref = pending_lock;
    }
    initialization_lock = pending_lock;
  }

  std::lock_guard<std::mutex> key_lock(*initialization_lock);
  {
    std::lock_guard<std::mutex> lock(mu_);
    auto found = sessions_.find(key);
    if (found != sessions_.end()) {
      auto existing = found->second.lock();
      if (existing) {
        return Result<std::shared_ptr<Session>>::success(existing);
      }
    }
  }

  auto initialized = client.initialize();
  if (!initialized) {
    return Result<std::shared_ptr<Session>>::failure(initialized.error());
  }
  auto session = std::make_shared<Session>(initialized.move_value());
  std::lock_guard<std::mutex> lock(mu_);
  prune_session_pool_locked(sessions_, initialization_locks_);
  sessions_[key] = session;
  return Result<std::shared_ptr<Session>>::success(std::move(session));
}

void SessionPool::clear() {
  std::lock_guard<std::mutex> lock(mu_);
  sessions_.clear();
  initialization_locks_.clear();
}

}  // namespace chio
