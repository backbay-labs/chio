#include "chio/dpop.hpp"

#include <chrono>
#include <sstream>
#include <string_view>

#include "chio/invariants.hpp"
#include "json.hpp"
#include "random.hpp"

namespace chio {
namespace {

std::uint64_t now_unix_secs() {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

std::string parsed_string_field(const std::string& json, std::string_view field) {
  auto parsed = detail::parse_json(json);
  if (!parsed || !parsed->is_object()) {
    return {};
  }
  const auto* value = parsed->get(field);
  if (value == nullptr || !value->is_string()) {
    return {};
  }
  return value->as_string();
}

}  // namespace

std::string DpopProof::to_json() const {
  return "{\"body\":" + body_json + ",\"signature\":" + detail::quote(signature_hex) + "}";
}

Result<DpopProof> sign_dpop_proof(const DpopSignParams& params) {
  auto canonical_args = invariants::canonicalize_json(params.action_args_json);
  if (!canonical_args) {
    return Result<DpopProof>::failure(canonical_args.error());
  }
  auto action_hash = invariants::sha256_hex_utf8(canonical_args.value());
  if (!action_hash) {
    return Result<DpopProof>::failure(action_hash.error());
  }

  auto key_signature =
      invariants::sign_utf8_message_ed25519("derive_key", params.agent_seed_hex);
  if (!key_signature) {
    return Result<DpopProof>::failure(key_signature.error());
  }
  const auto agent_key = parsed_string_field(key_signature.value(), "public_key_hex");
  if (agent_key.empty()) {
    return Result<DpopProof>::failure(
        Error{ErrorCode::Protocol, "failed to derive DPoP agent public key"});
  }

  const auto nonce = params.nonce.empty() ? detail::random_hex(16) : params.nonce;
  const auto issued_at = params.issued_at == 0 ? now_unix_secs() : params.issued_at;

  std::ostringstream body;
  body << "{"
       << "\"action_hash\":" << detail::quote(action_hash.value()) << ","
       << "\"agent_key\":" << detail::quote(agent_key) << ","
       << "\"capability_id\":" << detail::quote(params.capability_id) << ","
       << "\"issued_at\":" << issued_at << ","
       << "\"nonce\":" << detail::quote(nonce) << ","
       << "\"schema\":\"chio.dpop_proof.v1\","
       << "\"tool_name\":" << detail::quote(params.tool_name) << ","
       << "\"tool_server\":" << detail::quote(params.tool_server) << "}";

  auto signed_body = invariants::sign_json_ed25519(body.str(), params.agent_seed_hex);
  if (!signed_body) {
    return Result<DpopProof>::failure(signed_body.error());
  }
  const auto signature = parsed_string_field(signed_body.value(), "signature_hex");
  if (signature.empty()) {
    return Result<DpopProof>::failure(
        Error{ErrorCode::Protocol, "failed to sign DPoP proof body"});
  }

  return Result<DpopProof>::success(DpopProof{body.str(), signature});
}

}  // namespace chio
