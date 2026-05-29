#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "chio/result.hpp"
#include "chio/transport.hpp"

namespace chio {

class TokenProvider {
 public:
  virtual ~TokenProvider() = default;
  virtual Result<std::string> access_token() = 0;
  virtual std::string cache_key() const { return {}; }
};

using TokenProviderPtr = std::shared_ptr<TokenProvider>;

class StaticBearerTokenProvider final : public TokenProvider {
 public:
  explicit StaticBearerTokenProvider(std::string token);
  Result<std::string> access_token() override;
  std::string cache_key() const override;

 private:
  std::string token_;
};

struct PkceChallenge {
  std::string verifier;
  std::string challenge;
  std::string method = "S256";

  static Result<PkceChallenge> from_verifier(std::string verifier);
  static Result<PkceChallenge> generate();
};

struct OAuthMetadata {
  std::string issuer;
  std::string authorization_endpoint;
  std::string token_endpoint;
  std::string jwks_uri;
  std::string resource;
  std::vector<std::string> authorization_servers;
  std::vector<std::string> grant_types_supported;
  std::vector<std::string> scopes_supported;
  std::string raw_json;
};

struct TokenExchangeRequest {
  std::string token_endpoint;
  std::string grant_type = "authorization_code";
  std::string code;
  std::string redirect_uri;
  std::string code_verifier;
  std::string client_id;
  std::string client_secret;
  std::string refresh_token;
  std::string resource;
  std::string subject_token;
  std::string subject_token_type;
  std::vector<std::string> scopes;
};

class OAuthMetadataClient {
 public:
  OAuthMetadataClient(std::string base_url,
                      HttpTransportPtr transport,
                      std::chrono::milliseconds timeout = std::chrono::milliseconds(30000));

  Result<OAuthMetadata> discover_protected_resource() const;
  Result<OAuthMetadata> discover_authorization_server(std::string metadata_url) const;
  Result<std::string> exchange_token(const TokenExchangeRequest& request) const;

 private:
  Result<std::string> get_json(std::string url, std::string operation) const;

  std::string base_url_;
  HttpTransportPtr transport_;
  std::chrono::milliseconds timeout_;
};

}  // namespace chio
