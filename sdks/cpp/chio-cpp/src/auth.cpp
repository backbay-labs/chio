#include "chio/auth.hpp"

#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <random>
#include <sstream>
#include <string_view>
#include <utility>

#include "auth_cache.hpp"
#include "auth_encoding.hpp"
#include "chio/invariants.hpp"
#include "json.hpp"
#include "transport_util.hpp"

namespace chio {
namespace {

std::string join_scope(const std::vector<std::string>& scopes) {
  std::string out;
  for (std::size_t i = 0; i < scopes.size(); ++i) {
    if (i != 0) {
      out += " ";
    }
    out += scopes[i];
  }
  return out;
}

std::string random_urlsafe(std::size_t bytes) {
  static constexpr char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  std::random_device rng;
  std::uniform_int_distribution<std::size_t> pick(0, sizeof(alphabet) - 2);
  std::string out;
  out.reserve(bytes);
  for (std::size_t i = 0; i < bytes; ++i) {
    out.push_back(alphabet[pick(rng)]);
  }
  return out;
}

Result<std::vector<std::uint8_t>> hex_to_bytes(const std::string& hex) {
  if (hex.size() % 2 != 0) {
    return Result<std::vector<std::uint8_t>>::failure(
        Error{ErrorCode::InvalidHex, "hex string has odd length", "PkceChallenge"});
  }
  std::vector<std::uint8_t> out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const auto pair = hex.substr(i, 2);
    char* end = nullptr;
    const auto value = std::strtoul(pair.c_str(), &end, 16);
    if (end == nullptr || *end != '\0') {
      return Result<std::vector<std::uint8_t>>::failure(
          Error{ErrorCode::InvalidHex, "hex string contains invalid byte",
                "PkceChallenge"});
    }
    out.push_back(static_cast<std::uint8_t>(value));
  }
  return Result<std::vector<std::uint8_t>>::success(std::move(out));
}

OAuthMetadata parse_metadata(const std::string& raw_json) {
  OAuthMetadata metadata;
  metadata.raw_json = raw_json;
  auto parsed = detail::parse_json(raw_json);
  if (!parsed) {
    return metadata;
  }
  metadata.issuer = parsed->string_field("issuer");
  metadata.authorization_endpoint = parsed->string_field("authorization_endpoint");
  metadata.token_endpoint = parsed->string_field("token_endpoint");
  metadata.jwks_uri = parsed->string_field("jwks_uri");
  metadata.resource = parsed->string_field("resource");
  const auto* authorization_servers = parsed->get("authorization_servers");
  if (authorization_servers != nullptr && authorization_servers->is_array()) {
    for (const auto& server : authorization_servers->as_array()) {
      if (server.is_string()) {
        metadata.authorization_servers.push_back(server.as_string());
      }
    }
  }
  const auto* grants = parsed->get("grant_types_supported");
  if (grants != nullptr && grants->is_array()) {
    for (const auto& grant : grants->as_array()) {
      if (grant.is_string()) {
        metadata.grant_types_supported.push_back(grant.as_string());
      }
    }
  }
  const auto* scopes = parsed->get("scopes_supported");
  if (scopes != nullptr && scopes->is_array()) {
    for (const auto& scope : scopes->as_array()) {
      if (scope.is_string()) {
        metadata.scopes_supported.push_back(scope.as_string());
      }
    }
  }
  return metadata;
}

void add_form_field(std::string& body,
                    std::string_view key,
                    const std::string& value,
                    bool& first) {
  if (value.empty()) {
    return;
  }
  if (!first) {
    body += "&";
  }
  first = false;
  body += detail::form_url_encode(key);
  body += "=";
  body += detail::form_url_encode(value);
}

}  // namespace

StaticBearerTokenProvider::StaticBearerTokenProvider(std::string token)
    : token_(std::move(token)) {}

Result<std::string> StaticBearerTokenProvider::access_token() {
  if (token_.empty()) {
    return Result<std::string>::failure(
        Error{ErrorCode::Protocol, "bearer token is empty",
              "StaticBearerTokenProvider::access_token"});
  }
  return Result<std::string>::success(token_);
}

std::string StaticBearerTokenProvider::cache_key() const {
  auto key = detail::bearer_cache_key(token_);
  if (key.empty()) {
    return {};
  }
  return "static-bearer:" + key;
}

Result<PkceChallenge> PkceChallenge::from_verifier(std::string verifier) {
  if (verifier.size() < 43 || verifier.size() > 128) {
    return Result<PkceChallenge>::failure(
        Error{ErrorCode::Protocol, "PKCE verifier must be 43 to 128 characters",
              "PkceChallenge::from_verifier"});
  }
  auto digest = invariants::sha256_hex_utf8(verifier);
  if (!digest) {
    return Result<PkceChallenge>::failure(digest.error());
  }
  auto bytes = hex_to_bytes(digest.value());
  if (!bytes) {
    return Result<PkceChallenge>::failure(bytes.error());
  }
  return Result<PkceChallenge>::success(
      PkceChallenge{std::move(verifier), detail::base64url_encode(bytes.value()), "S256"});
}

Result<PkceChallenge> PkceChallenge::generate() {
  return from_verifier(random_urlsafe(64));
}

OAuthMetadataClient::OAuthMetadataClient(std::string base_url,
                                         HttpTransportPtr transport,
                                         std::chrono::milliseconds timeout)
    : base_url_(detail::trim_right_slash(std::move(base_url))),
      transport_(std::move(transport)),
      timeout_(timeout) {}

Result<std::string> OAuthMetadataClient::get_json(std::string url,
                                                  std::string operation) const {
  HttpRequest request{
      "GET",
      std::move(url),
      {{"Accept", "application/json"}},
      "",
      timeout_,
  };
  auto response = detail::send_with_policy(transport_, std::move(request), {}, {},
                                           std::move(operation));
  if (!response) {
    return Result<std::string>::failure(response.error());
  }
  if (response.value().status < 200 || response.value().status >= 300) {
    return Result<std::string>::failure(
        Error{ErrorCode::Protocol,
              "OAuth metadata request returned HTTP " +
                  std::to_string(response.value().status),
              "OAuthMetadataClient::get_json",
              response.value().status,
              detail::body_snippet(response.value().body),
              {},
              {},
              detail::retryable_status(response.value().status)});
  }
  return Result<std::string>::success(response.value().body);
}

Result<OAuthMetadata> OAuthMetadataClient::discover_protected_resource() const {
  auto raw = get_json(base_url_ + "/.well-known/oauth-protected-resource/mcp",
                      "OAuthMetadataClient::discover_protected_resource");
  if (!raw) {
    return Result<OAuthMetadata>::failure(raw.error());
  }
  return Result<OAuthMetadata>::success(parse_metadata(raw.value()));
}

Result<OAuthMetadata> OAuthMetadataClient::discover_authorization_server(
    std::string metadata_url) const {
  auto raw = get_json(std::move(metadata_url),
                      "OAuthMetadataClient::discover_authorization_server");
  if (!raw) {
    return Result<OAuthMetadata>::failure(raw.error());
  }
  return Result<OAuthMetadata>::success(parse_metadata(raw.value()));
}

Result<std::string> OAuthMetadataClient::exchange_token(
    const TokenExchangeRequest& request) const {
  if (request.token_endpoint.empty()) {
    return Result<std::string>::failure(
        Error{ErrorCode::Protocol, "token_endpoint is required",
              "OAuthMetadataClient::exchange_token"});
  }

  std::string body;
  bool first = true;
  add_form_field(body, "grant_type", request.grant_type, first);
  add_form_field(body, "code", request.code, first);
  add_form_field(body, "redirect_uri", request.redirect_uri, first);
  add_form_field(body, "code_verifier", request.code_verifier, first);
  add_form_field(body, "client_id", request.client_id, first);
  add_form_field(body, "client_secret", request.client_secret, first);
  add_form_field(body, "refresh_token", request.refresh_token, first);
  add_form_field(body, "resource", request.resource, first);
  add_form_field(body, "subject_token", request.subject_token, first);
  add_form_field(body, "subject_token_type", request.subject_token_type, first);
  add_form_field(body, "scope", join_scope(request.scopes), first);

  HttpRequest http_request{
      "POST",
      request.token_endpoint,
      {{"Accept", "application/json"},
       {"Content-Type", "application/x-www-form-urlencoded"}},
      std::move(body),
      timeout_,
  };
  auto response = detail::send_with_policy(transport_, std::move(http_request), {}, {},
                                           "OAuthMetadataClient::exchange_token");
  if (!response) {
    return Result<std::string>::failure(response.error());
  }
  if (response.value().status < 200 || response.value().status >= 300) {
    return Result<std::string>::failure(
        Error{ErrorCode::Protocol,
              "token exchange returned HTTP " + std::to_string(response.value().status),
              "OAuthMetadataClient::exchange_token",
              response.value().status,
              detail::body_snippet(response.value().body),
              {},
              {},
              detail::retryable_status(response.value().status)});
  }
  return Result<std::string>::success(response.value().body);
}

}  // namespace chio
