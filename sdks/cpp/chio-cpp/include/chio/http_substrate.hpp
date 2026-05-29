#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "chio/models.hpp"
#include "chio/result.hpp"
#include "chio/transport.hpp"

namespace chio::http {

struct AuthMethod {
  std::string method = "anonymous";
  std::map<std::string, std::string> fields;

  std::string to_json() const;
};

struct CallerIdentity {
  std::string subject = "anonymous";
  AuthMethod auth_method;
  bool verified = false;
  std::string tenant;
  std::string agent_id;

  std::string to_json() const;
};

struct ChioHttpRequest {
  std::string request_id;
  std::string method;
  std::string route_pattern;
  std::string path;
  std::map<std::string, std::string> query;
  std::map<std::string, std::string> headers;
  CallerIdentity caller;
  std::string body_hash;
  std::uint64_t body_length = 0;
  std::string session_id;
  std::string capability_id;
  std::uint64_t timestamp = 0;

  std::string to_json() const;
};

class Evaluator {
 public:
  Evaluator(std::string sidecar_url, HttpTransportPtr transport, std::uint32_t timeout_ms = 5000);

  Result<std::string> evaluate(const ChioHttpRequest& request,
                               const std::string& capability_token = "") const;
  Result<bool> verify_receipt(std::string receipt_json) const;
  Result<std::string> health() const;

 private:
  std::string sidecar_url_;
  HttpTransportPtr transport_;
  std::uint32_t timeout_ms_;
};

class Middleware {
 public:
  explicit Middleware(Evaluator evaluator);

  EvaluateVerdict evaluate_fail_closed(const ChioHttpRequest& request) const;

 private:
  Evaluator evaluator_;
};

std::string receipt_id_from_verdict(const EvaluateVerdict& verdict);

}  // namespace chio::http
