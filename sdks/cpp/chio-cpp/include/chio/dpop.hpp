#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "chio/result.hpp"

namespace chio {

struct DpopProof {
  std::string body_json;
  std::string signature_hex;

  std::string to_json() const;
};

struct DpopSignParams {
  std::string capability_id;
  std::string tool_server;
  std::string tool_name;
  std::string action_args_json;
  std::string agent_seed_hex;
  std::string nonce;
  std::uint64_t issued_at = 0;
};

Result<DpopProof> sign_dpop_proof(const DpopSignParams& params);

}  // namespace chio
