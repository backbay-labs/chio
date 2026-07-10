#include "chio/drogon.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>
#include <string_view>
#include <utility>

#include <json/json.h>

#include "chio/invariants.hpp"

namespace chio::drogon {
namespace {

constexpr const char* kReceiptAttribute = "chio.receipt_id";
constexpr const char* kCapabilityHeader = "x-chio-capability";
constexpr const char* kCapabilityQuery = "chio_capability";
constexpr const char* kReceiptHeader = "X-Chio-Receipt-Id";
constexpr const char* kDefaultSidecarUrl = "http://127.0.0.1:9090";

std::mutex& config_mutex() {
  static std::mutex mutex;
  return mutex;
}

Options& configured_options() {
  static Options options;
  return options;
}

bool parse_json(const std::string& input, Json::Value* out);
std::string string_field(const Json::Value& value, const char* name);
std::string compact_json(const Json::Value& value);

std::string lower_ascii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return value;
}

bool is_sensitive_header(const std::string& lower_name) {
  return lower_name == "authorization" || lower_name == "cookie" ||
         lower_name == "x-api-key" || lower_name == kCapabilityHeader;
}

bool should_skip_path(const std::string& path, const Options& options) {
  return std::find(options.skip_paths.begin(), options.skip_paths.end(), path) !=
         options.skip_paths.end();
}

bool is_supported_method(std::string_view method) {
  return method == "GET" || method == "POST" || method == "PUT" ||
         method == "PATCH" || method == "DELETE" || method == "HEAD" ||
         method == "OPTIONS";
}

std::map<std::string, std::string> selected_headers(
    const ::drogon::HttpRequest& req,
    const std::vector<std::string>& configured_headers) {
  std::map<std::string, std::string> out;
  for (const auto& name : configured_headers) {
    const auto lower_name = lower_ascii(name);
    if (lower_name.empty() || is_sensitive_header(lower_name)) {
      continue;
    }
    const auto& value = req.getHeader(lower_name);
    if (!value.empty()) {
      out.emplace(lower_name, value);
    }
  }
  return out;
}

int hex_value(char ch) {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return ch - 'a' + 10;
  }
  if (ch >= 'A' && ch <= 'F') {
    return ch - 'A' + 10;
  }
  return -1;
}

std::string query_decode(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (std::size_t i = 0; i < value.size(); ++i) {
    const char ch = value[i];
    if (ch == '+') {
      out.push_back(' ');
      continue;
    }
    if (ch == '%' && i + 2 < value.size()) {
      const int hi = hex_value(value[i + 1]);
      const int lo = hex_value(value[i + 2]);
      if (hi >= 0 && lo >= 0) {
        out.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
        continue;
      }
    }
    out.push_back(ch);
  }
  return out;
}

std::map<std::string, std::string> parse_query(const std::string& query) {
  std::map<std::string, std::string> out;
  std::size_t start = 0;
  while (start <= query.size()) {
    const auto end = query.find('&', start);
    const auto part =
        query.substr(start, end == std::string::npos ? std::string::npos : end - start);
    if (!part.empty()) {
      const auto equal = part.find('=');
      const auto key = query_decode(std::string_view(part).substr(0, equal));
      if (key != kCapabilityQuery) {
        const auto raw_value =
            equal == std::string::npos ? std::string{} : part.substr(equal + 1);
        out.emplace(key, query_decode(raw_value));
      }
    }
    if (end == std::string::npos) {
      break;
    }
    start = end + 1;
  }
  return out;
}

std::string capability_token(const ::drogon::HttpRequest& req) {
  const auto& header_token = req.getHeader(kCapabilityHeader);
  if (!header_token.empty()) {
    return header_token;
  }

  const auto query = req.query();
  std::size_t start = 0;
  while (start <= query.size()) {
    const auto end = query.find('&', start);
    const auto part =
        query.substr(start, end == std::string::npos ? std::string::npos : end - start);
    const auto equal = part.find('=');
    const auto key = query_decode(std::string_view(part).substr(0, equal));
    if (key == kCapabilityQuery) {
      if (equal == std::string::npos) {
        return {};
      }
      return query_decode(part.substr(equal + 1));
    }
    if (end == std::string::npos) {
      break;
    }
    start = end + 1;
  }
  return {};
}

std::string request_id(const ::drogon::HttpRequest& req) {
  const auto& request_id_header = req.getHeader("x-request-id");
  if (!request_id_header.empty()) {
    return request_id_header;
  }
  static std::atomic<std::uint64_t> counter{0};
  return "drogon-" + std::to_string(std::time(nullptr)) + "-" +
         std::to_string(counter.fetch_add(1));
}

std::string route_pattern(const ::drogon::HttpRequest& req, const Options& options) {
  if (options.route_pattern_resolver) {
    auto resolved = options.route_pattern_resolver(req);
    if (!resolved.empty()) {
      return resolved;
    }
  }
  const auto pattern = req.matchedPathPattern();
  if (pattern.empty()) {
    return req.path();
  }
  return std::string(pattern.data(), pattern.size());
}

std::string capability_id_from_token(const std::string& token) {
  if (token.empty()) {
    return {};
  }
  Json::Value root;
  if (!parse_json(token, &root) || !root.isObject()) {
    return {};
  }
  return string_field(root, "id");
}

chio::http::CallerIdentity caller_identity(const ::drogon::HttpRequest& req) {
  chio::http::CallerIdentity caller;
  const auto& authorization = req.getHeader("authorization");
  if (authorization.rfind("Bearer ", 0) == 0 && authorization.size() > 7) {
    const auto token = authorization.substr(7);
    auto token_hash = chio::invariants::sha256_hex_utf8(token);
    if (token_hash) {
      caller.subject = "bearer:" + token_hash.value().substr(0, 16);
      caller.auth_method.method = "bearer";
      caller.auth_method.fields["token_hash"] = token_hash.value();
      caller.verified = true;
      return caller;
    }
  }

  const auto& api_key = req.getHeader("x-api-key");
  if (!api_key.empty()) {
    auto key_hash = chio::invariants::sha256_hex_utf8(api_key);
    if (key_hash) {
      caller.subject = "api_key:" + key_hash.value().substr(0, 16);
      caller.auth_method.method = "api_key";
      caller.auth_method.fields["key_name"] = "x-api-key";
      caller.auth_method.fields["key_hash"] = key_hash.value();
      caller.verified = true;
    }
  }
  return caller;
}

chio::Result<chio::http::ChioHttpRequest> build_chio_request(
    const ::drogon::HttpRequest& req,
    const Options& options) {
  const auto body = req.body();
  std::vector<std::uint8_t> body_bytes;
  body_bytes.reserve(body.size());
  for (char ch : body) {
    body_bytes.push_back(static_cast<std::uint8_t>(ch));
  }

  auto body_hash = chio::invariants::sha256_hex_bytes(body_bytes);
  if (!body_hash) {
    return chio::Result<chio::http::ChioHttpRequest>::failure(body_hash.error());
  }

  chio::http::ChioHttpRequest out;
  out.request_id = request_id(req);
  out.method = req.methodString();
  out.route_pattern = route_pattern(req, options);
  out.path = req.path();
  out.query = parse_query(req.query());
  out.headers = selected_headers(req, options.selected_headers);
  out.body_length = static_cast<std::uint64_t>(body.size());
  if (!body.empty()) {
    out.body_hash = body_hash.value();
  }
  out.caller = caller_identity(req);
  out.capability_id = capability_id_from_token(capability_token(req));
  out.timestamp = static_cast<std::uint64_t>(std::time(nullptr));
  return chio::Result<chio::http::ChioHttpRequest>::success(std::move(out));
}

bool parse_json(const std::string& input, Json::Value* out) {
  Json::CharReaderBuilder builder;
  std::string errors;
  std::istringstream stream(input);
  return Json::parseFromStream(builder, stream, out, &errors);
}

std::string string_field(const Json::Value& value, const char* name) {
  const auto& field = value[name];
  if (!field.isString()) {
    return {};
  }
  return field.asString();
}

std::string compact_json(const Json::Value& value) {
  Json::StreamWriterBuilder builder;
  builder["indentation"] = "";
  return Json::writeString(builder, value);
}

std::string receipt_id_from_response(const Json::Value& root) {
  auto id = string_field(root, "receipt_id");
  if (!id.empty()) {
    return id;
  }
  const auto& receipt = root["receipt"];
  if (!receipt.isObject()) {
    return {};
  }
  id = string_field(receipt, "receipt_id");
  if (!id.empty()) {
    return id;
  }
  return string_field(receipt, "id");
}

struct ParsedSidecarVerdict {
  std::string verdict;
  std::string reason;
};

ParsedSidecarVerdict verdict_from_response(const Json::Value& root) {
  ParsedSidecarVerdict out;
  const auto& verdict = root["verdict"];
  if (verdict.isObject()) {
    out.verdict = string_field(verdict, "verdict");
    out.reason = string_field(verdict, "reason");
  } else {
    out.verdict = string_field(root, "verdict");
  }
  if (out.reason.empty()) {
    out.reason = string_field(root, "reason");
  }
  return out;
}

std::string json_escape(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (const char ch : value) {
    switch (ch) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(ch) < 0x20) {
          std::ostringstream escaped;
          escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                  << static_cast<int>(static_cast<unsigned char>(ch));
          out += escaped.str();
        } else {
          out.push_back(ch);
        }
        break;
    }
  }
  return out;
}

::drogon::HttpResponsePtr chio_error_response(::drogon::HttpStatusCode status,
                                              std::string error,
                                              std::string message,
                                              std::string receipt_id = {}) {
  auto response = ::drogon::HttpResponse::newHttpResponse();
  response->setStatusCode(status);
  response->setContentTypeCode(::drogon::CT_APPLICATION_JSON);
  if (!receipt_id.empty()) {
    response->addHeader(kReceiptHeader, receipt_id);
  }
  std::string body = "{\"error\":\"" + json_escape(error) + "\",\"message\":\"" +
                     json_escape(message) + "\"";
  if (!receipt_id.empty()) {
    body += ",\"receipt_id\":\"" + json_escape(receipt_id) + "\"";
  }
  body += "}";
  response->setBody(std::move(body));
  return response;
}

std::string sidecar_url(const Options& options) {
  if (!options.sidecar_url.empty()) {
    return options.sidecar_url;
  }
  const char* env_value = std::getenv("CHIO_SIDECAR_URL");
  if (env_value != nullptr && std::string_view(env_value).size() > 0) {
    return env_value;
  }
  return kDefaultSidecarUrl;
}

}  // namespace

void configure(Options options) {
  std::lock_guard<std::mutex> lock(config_mutex());
  configured_options() = std::move(options);
}

std::string receipt_id(const ::drogon::HttpRequestPtr& req) {
  if (!req) {
    return {};
  }
  return receipt_id(*req);
}

std::string receipt_id(const ::drogon::HttpRequest& req) {
  return req.attributes()->get<std::string>(kReceiptAttribute);
}

ChioMiddleware::ChioMiddleware() {
  std::lock_guard<std::mutex> lock(config_mutex());
  options_ = configured_options();
#ifdef CHIO_CPP_HAS_CURL
  if (!options_.transport) {
    options_.transport = std::make_shared<chio::CurlHttpTransport>();
  }
#endif
}

ChioMiddleware::ChioMiddleware(Options options) : options_(std::move(options)) {
#ifdef CHIO_CPP_HAS_CURL
  if (!options_.transport) {
    options_.transport = std::make_shared<chio::CurlHttpTransport>();
  }
#endif
}

void ChioMiddleware::invoke(const ::drogon::HttpRequestPtr& req,
                            ::drogon::MiddlewareNextCallback&& next_cb,
                            ::drogon::MiddlewareCallback&& middleware_cb) {
  if (!req) {
    middleware_cb(chio_error_response(::drogon::k500InternalServerError,
                                      "chio_internal_error",
                                      "missing request"));
    return;
  }

  req->attributes()->erase(kReceiptAttribute);

  if (should_skip_path(req->path(), options_)) {
    next_cb(std::move(middleware_cb));
    return;
  }

  if (!is_supported_method(req->methodString())) {
    middleware_cb(chio_error_response(::drogon::k405MethodNotAllowed,
                                      "chio_evaluation_failed",
                                      "unsupported HTTP method"));
    return;
  }

  auto chio_request = build_chio_request(*req, options_);
  if (!chio_request) {
    middleware_cb(chio_error_response(::drogon::k500InternalServerError,
                                      "chio_evaluation_failed",
                                      "failed to hash request body"));
    return;
  }

  const auto raw_capability = capability_token(*req);
  chio::http::Evaluator evaluator(sidecar_url(options_), options_.transport, options_.timeout_ms);
  auto evaluation = evaluator.evaluate(chio_request.value(), raw_capability);
  if (!evaluation) {
    middleware_cb(chio_error_response(::drogon::k502BadGateway,
                                      "chio_sidecar_unreachable",
                                      "chio sidecar evaluation failed"));
    return;
  }

  Json::Value root;
  if (!parse_json(evaluation.value(), &root)) {
    middleware_cb(chio_error_response(::drogon::k502BadGateway,
                                      "chio_sidecar_unreachable",
                                      "chio sidecar returned malformed JSON"));
    return;
  }

  const auto verdict = verdict_from_response(root);
  if (verdict.verdict.empty()) {
    middleware_cb(chio_error_response(::drogon::k502BadGateway,
                                      "chio_sidecar_unreachable",
                                      "chio sidecar response missing verdict"));
    return;
  }

  const auto id = receipt_id_from_response(root);
  const auto receipt_verdict = verdict_from_response(root["receipt"]);

  if (verdict.verdict != "allow" || receipt_verdict.verdict != "allow") {
    auto reason = verdict.reason;
    if (reason.empty()) {
      reason = "request denied";
    }
    middleware_cb(chio_error_response(::drogon::k403Forbidden,
                                      "chio_access_denied",
                                      std::move(reason),
                                      id));
    return;
  }

  const auto& receipt = root["receipt"];
  if (!receipt.isObject()) {
    middleware_cb(chio_error_response(::drogon::k502BadGateway,
                                      "chio_invalid_receipt",
                                      "chio sidecar response missing receipt"));
    return;
  }
  auto verified = evaluator.verify_receipt(compact_json(receipt));
  if (!verified || !verified.value()) {
    middleware_cb(chio_error_response(::drogon::k502BadGateway,
                                      "chio_invalid_receipt",
                                      "chio sidecar returned an unverified receipt",
                                      id));
    return;
  }

  if (!id.empty()) {
    req->attributes()->insert(kReceiptAttribute, id);
  }

  next_cb([middleware_cb = std::move(middleware_cb), id](
              const ::drogon::HttpResponsePtr& response) mutable {
    if (response && !id.empty()) {
      response->addHeader(kReceiptHeader, id);
    }
    middleware_cb(response);
  });
}

}  // namespace chio::drogon
