#include "chio/chio.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

struct Args {
  std::string base_url;
  std::string auth_mode = "static-bearer";
  std::string auth_token;
  std::string admin_token;
  std::string auth_scope = "mcp:invoke";
  std::string scenarios_dir;
  std::string results_output;
  std::string artifacts_dir;
};

struct Scenario {
  std::string id;
  std::string category;
};

struct AuthContext {
  std::string mode;
  std::string access_token;
  chio::OAuthMetadata protected_resource_metadata;
  chio::OAuthMetadata authorization_server_metadata;
};

struct Result {
  Scenario scenario;
  std::string status;
  std::string assertion_name;
  std::string assertion_status;
  std::string message;
  std::uint64_t duration_ms = 0;
};

std::string json_escape(const std::string& input) {
  std::ostringstream out;
  for (unsigned char c : input) {
    switch (c) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (c < 0x20) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(c) << std::dec << std::setfill(' ');
        } else {
          out << static_cast<char>(c);
        }
    }
  }
  return out.str();
}

std::string quote(const std::string& input) {
  return "\"" + json_escape(input) + "\"";
}

std::string url_encode(const std::string& input) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;
  for (unsigned char c : input) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      escaped << c;
    } else {
      escaped << '%' << std::uppercase << std::setw(2) << int(c) << std::nouppercase;
    }
  }
  return escaped.str();
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

std::string url_decode(const std::string& input) {
  std::string decoded;
  decoded.reserve(input.size());
  for (std::size_t i = 0; i < input.size(); ++i) {
    const char c = input[i];
    if (c == '%' && i + 2 < input.size()) {
      const int high = hex_value(input[i + 1]);
      const int low = hex_value(input[i + 2]);
      if (high >= 0 && low >= 0) {
        decoded.push_back(static_cast<char>((high << 4) | low));
        i += 2;
        continue;
      }
    }
    decoded.push_back(c == '+' ? ' ' : c);
  }
  return decoded;
}

std::string read_file(const std::filesystem::path& path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("failed to read " + path.string());
  }
  return std::string((std::istreambuf_iterator<char>(input)),
                     std::istreambuf_iterator<char>());
}

void write_file(const std::filesystem::path& path, const std::string& value) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream output(path);
  if (!output) {
    throw std::runtime_error("failed to write " + path.string());
  }
  output << value;
}

std::string extract_string_field(const std::string& json, const std::string& field) {
  const std::string needle = "\"" + field + "\"";
  auto pos = json.find(needle);
  if (pos == std::string::npos) {
    return {};
  }
  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) {
    return {};
  }
  pos = json.find('"', pos + 1);
  if (pos == std::string::npos) {
    return {};
  }
  std::string out;
  bool escaped = false;
  for (std::size_t i = pos + 1; i < json.size(); ++i) {
    const char c = json[i];
    if (escaped) {
      out.push_back(c);
      escaped = false;
      continue;
    }
    if (c == '\\') {
      escaped = true;
      continue;
    }
    if (c == '"') {
      return out;
    }
    out.push_back(c);
  }
  return {};
}

std::vector<Scenario> load_scenarios(const std::filesystem::path& root) {
  std::vector<std::filesystem::path> files;
  for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
    if (entry.is_regular_file() && entry.path().extension() == ".json") {
      files.push_back(entry.path());
    }
  }
  std::sort(files.begin(), files.end());

  std::vector<Scenario> scenarios;
  for (const auto& file : files) {
    const auto contents = read_file(file);
    Scenario scenario;
    scenario.id = extract_string_field(contents, "id");
    scenario.category = extract_string_field(contents, "category");
    if (!scenario.id.empty()) {
      scenarios.push_back(std::move(scenario));
    }
  }
  return scenarios;
}

Args parse_args(int argc, char** argv) {
  Args args;
  std::map<std::string, std::string*> fields{
      {"--base-url", &args.base_url},
      {"--auth-mode", &args.auth_mode},
      {"--auth-token", &args.auth_token},
      {"--admin-token", &args.admin_token},
      {"--auth-scope", &args.auth_scope},
      {"--scenarios-dir", &args.scenarios_dir},
      {"--results-output", &args.results_output},
      {"--artifacts-dir", &args.artifacts_dir},
  };

  for (int i = 1; i < argc; i += 2) {
    if (i + 1 >= argc) {
      throw std::runtime_error("missing value for " + std::string(argv[i]));
    }
    const auto found = fields.find(argv[i]);
    if (found == fields.end()) {
      continue;
    }
    *found->second = argv[i + 1];
  }
  if (args.auth_token.empty()) {
    if (const char* env = std::getenv("CHIO_CONFORMANCE_AUTH_TOKEN")) {
      args.auth_token = env;
    }
  }
  if (args.admin_token.empty()) {
    if (const char* env = std::getenv("CHIO_CONFORMANCE_ADMIN_TOKEN")) {
      args.admin_token = env;
    }
  }
  if (args.base_url.empty() || args.auth_token.empty() || args.scenarios_dir.empty() ||
      args.results_output.empty() || args.artifacts_dir.empty()) {
    throw std::runtime_error("missing required C++ conformance peer arguments");
  }
  return args;
}

Result pass(Scenario scenario, std::uint64_t duration_ms, std::string assertion_name) {
  return Result{std::move(scenario),
                "pass",
                std::move(assertion_name),
                "pass",
                {},
                duration_ms};
}

Result fail(Scenario scenario,
            std::uint64_t duration_ms,
            std::string assertion_name,
            std::string message) {
  return Result{std::move(scenario),
                "fail",
                std::move(assertion_name),
                "fail",
                std::move(message),
                duration_ms};
}

Result unsupported(Scenario scenario, std::uint64_t duration_ms, std::string message) {
  return Result{std::move(scenario),
                "unsupported",
                "scenario_supported_by_cpp_peer",
                "fail",
                std::move(message),
                duration_ms};
}

bool contains(const std::string& value, const std::string& needle) {
  return value.find(needle) != std::string::npos;
}

std::string error_text(const chio::Error& error) {
  if (error.response_body_snippet.empty()) {
    return error.message;
  }
  return error.message + " body: " + error.response_body_snippet;
}

bool contains_value(const std::vector<std::string>& values, const std::string& expected) {
  return std::find(values.begin(), values.end(), expected) != values.end();
}

std::string trim_slashes(std::string value) {
  while (!value.empty() && value.front() == '/') {
    value.erase(value.begin());
  }
  while (!value.empty() && value.back() == '/') {
    value.pop_back();
  }
  return value;
}

std::string authorization_server_metadata_url(const std::string& base_url,
                                              const std::string& issuer) {
  std::string metadata_base = base_url;
  std::string issuer_path = issuer;
  const auto scheme = issuer.find("://");
  if (scheme != std::string::npos) {
    const auto origin_end = issuer.find('/', scheme + 3);
    metadata_base = origin_end == std::string::npos ? issuer : issuer.substr(0, origin_end);
    issuer_path =
        origin_end == std::string::npos ? std::string() : issuer.substr(origin_end);
  }
  issuer_path = trim_slashes(std::move(issuer_path));
  std::string base = std::move(metadata_base);
  while (!base.empty() && base.back() == '/') {
    base.pop_back();
  }
  if (issuer_path.empty()) {
    return base + "/.well-known/oauth-authorization-server";
  }
  return base + "/.well-known/oauth-authorization-server/" + issuer_path;
}

std::string header_value(const std::map<std::string, std::string>& headers,
                         std::string name) {
  std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  for (const auto& header : headers) {
    auto key = header.first;
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    if (key == name) {
      return header.second;
    }
  }
  return {};
}

std::string query_value(const std::string& url, const std::string& key) {
  const auto query_start = url.find('?');
  if (query_start == std::string::npos) {
    return {};
  }
  const std::string needle = key + "=";
  auto pos = url.find(needle, query_start + 1);
  if (pos == std::string::npos) {
    return {};
  }
  pos += needle.size();
  const auto end = url.find('&', pos);
  return url.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
}

std::string conformance_client_capabilities_json() {
  return "{"
         "\"sampling\":{\"includeContext\":true,\"tools\":{}},"
         "\"elicitation\":{\"form\":{},\"url\":{}},"
         "\"roots\":{\"listChanged\":true}"
         "}";
}

chio::NestedCallbackRouter conformance_nested_router() {
  chio::NestedCallbackRouter router;
  router
      .on_sampling([](const chio::JsonMessage& message) {
        return chio::Result<std::string>::success(
            chio::NestedCallbackRouter::sampling_text_result(
                message, "sampled by conformance peer", "chio-conformance-cpp-model"));
      })
      .on_elicitation([](const chio::JsonMessage& message) {
        if (contains(message.raw_json, "\"mode\":\"url\"")) {
          return chio::Result<std::string>::success(
              chio::NestedCallbackRouter::elicitation_accept_result(message));
        }
        return chio::Result<std::string>::success(
            chio::NestedCallbackRouter::elicitation_accept_result(
                message, "{\"answer\":\"elicited by conformance peer\"}"));
      })
      .on_roots([](const chio::JsonMessage& message) {
        return chio::Result<std::string>::success(
            chio::NestedCallbackRouter::roots_list_result(
                message,
                "[{\"uri\":\"file:///workspace/conformance-root\",\"name\":\"conformance-root\"}]"));
      });
  return router;
}

class ReceiveGuard {
 public:
  ReceiveGuard(chio::Session& session, chio::MessageHandler handler)
      : cancellation_(std::make_shared<chio::CancellationToken>()) {
    auto started = session.start_receive_loop(std::move(handler), cancellation_);
    if (!started) {
      throw std::runtime_error("failed to start receive loop: " + started.error().message);
    }
    thread_ = started.move_value();
  }

  ~ReceiveGuard() {
    cancellation_->cancel();
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  ReceiveGuard(const ReceiveGuard&) = delete;
  ReceiveGuard& operator=(const ReceiveGuard&) = delete;

 private:
  std::shared_ptr<chio::CancellationToken> cancellation_;
  std::thread thread_;
};

std::string form_encode(const std::map<std::string, std::string>& fields) {
  std::string out;
  bool first = true;
  for (const auto& field : fields) {
    if (!first) {
      out += "&";
    }
    first = false;
    out += url_encode(field.first);
    out += "=";
    out += url_encode(field.second);
  }
  return out;
}

chio::Result<chio::Session> initialize_with_token(const Args& args,
                                                  chio::HttpTransportPtr transport,
                                                  const std::string& token) {
  auto built_client = chio::ClientBuilder()
                          .base_url(args.base_url)
                          .bearer_token(token)
                          .transport(std::move(transport))
                          .timeout(std::chrono::milliseconds(10000))
                          .client_info("chio-conformance-cpp", "0.1.0")
                          .client_capabilities_json(conformance_client_capabilities_json())
                          .initialize_message_handler([](chio::Session& session,
                                                         const chio::JsonMessage& message) {
                            return conformance_nested_router().bind(session)(message);
                          })
                          .build();
  if (!built_client) {
    return chio::Result<chio::Session>::failure(built_client.error());
  }
  return built_client.value().initialize();
}

chio::Result<std::string> perform_authorization_code_flow(
    const Args& args,
    chio::HttpTransportPtr transport,
    const chio::OAuthMetadata& authorization_server_metadata) {
  const std::string verifier =
      "chio-conformance-cpp-verifier-abcdefghijklmnopqrstuvwxyz0123456789";
  auto pkce = chio::PkceChallenge::from_verifier(verifier);
  if (!pkce) {
    return chio::Result<std::string>::failure(pkce.error());
  }
  const std::string base =
      args.base_url.empty() || args.base_url.back() != '/'
          ? args.base_url
          : args.base_url.substr(0, args.base_url.size() - 1);
  const std::string resource = base + "/mcp";
  const std::string redirect_uri = "http://localhost:7777/callback";
  const std::string client_id = "https://client.example/app";
  const std::string state = "chio-cpp-state";
  const std::string authorization_endpoint =
      authorization_server_metadata.authorization_endpoint.empty()
          ? base + "/oauth/authorize"
          : authorization_server_metadata.authorization_endpoint;
  const std::string token_endpoint =
      authorization_server_metadata.token_endpoint.empty()
          ? base + "/oauth/token"
          : authorization_server_metadata.token_endpoint;

  const auto authorize_query = form_encode({
      {"client_id", client_id},
      {"code_challenge", pkce.value().challenge},
      {"code_challenge_method", "S256"},
      {"redirect_uri", redirect_uri},
      {"resource", resource},
      {"response_type", "code"},
      {"scope", args.auth_scope},
      {"state", state},
  });
  chio::HttpRequest authorize_request{
      "GET",
      authorization_endpoint + "?" + authorize_query,
      {{"Accept", "text/html, application/json"}},
      "",
  };
  auto authorize_response = transport->send(authorize_request);
  if (!authorize_response) {
    return chio::Result<std::string>::failure(authorize_response.error());
  }
  if (authorize_response.value().status != 200 ||
      !contains(authorize_response.value().body, "Approve")) {
    return chio::Result<std::string>::failure(
        chio::Error{chio::ErrorCode::Protocol,
                    "authorization endpoint did not return an approval page",
                    "cpp-peer::perform_authorization_code_flow"});
  }

  chio::HttpRequest approval_request{
      "POST",
      authorization_endpoint,
      {{"Content-Type", "application/x-www-form-urlencoded"}},
      form_encode({
          {"client_id", client_id},
          {"code_challenge", pkce.value().challenge},
          {"code_challenge_method", "S256"},
          {"decision", "approve"},
          {"redirect_uri", redirect_uri},
          {"resource", resource},
          {"response_type", "code"},
          {"scope", args.auth_scope},
          {"state", state},
      }),
  };
  auto approval_response = transport->send(approval_request);
  if (!approval_response) {
    return chio::Result<std::string>::failure(approval_response.error());
  }
  const auto location = header_value(approval_response.value().headers, "location");
  const auto code = url_decode(query_value(location, "code"));
  if (approval_response.value().status < 300 || approval_response.value().status >= 400 ||
      code.empty()) {
    return chio::Result<std::string>::failure(
        chio::Error{chio::ErrorCode::Protocol,
                    "authorization approval did not redirect with a code",
                    "cpp-peer::perform_authorization_code_flow"});
  }

  chio::TokenExchangeRequest token_request;
  token_request.token_endpoint = token_endpoint;
  token_request.grant_type = "authorization_code";
  token_request.code = code;
  token_request.redirect_uri = redirect_uri;
  token_request.client_id = client_id;
  token_request.code_verifier = verifier;
  token_request.resource = resource;
  chio::OAuthMetadataClient oauth(args.base_url, transport);
  auto token_response = oauth.exchange_token(token_request);
  if (!token_response) {
    return token_response;
  }
  const auto token = extract_string_field(token_response.value(), "access_token");
  if (token.empty()) {
    return chio::Result<std::string>::failure(
        chio::Error{chio::ErrorCode::Protocol,
                    "authorization code exchange did not return an access token",
                    "cpp-peer::perform_authorization_code_flow"});
  }
  return chio::Result<std::string>::success(token);
}

chio::Result<AuthContext> resolve_auth(const Args& args, chio::HttpTransportPtr transport) {
  if (args.auth_mode != "oauth-local") {
    return chio::Result<AuthContext>::success(
        AuthContext{"static-bearer", args.auth_token, {}, {}});
  }

  chio::OAuthMetadataClient oauth(args.base_url, transport);
  auto protected_resource = oauth.discover_protected_resource();
  if (!protected_resource) {
    return chio::Result<AuthContext>::failure(protected_resource.error());
  }
  if (protected_resource.value().authorization_servers.empty()) {
    return chio::Result<AuthContext>::failure(
        chio::Error{chio::ErrorCode::Protocol,
                    "protected resource metadata did not advertise an authorization server",
                    "cpp-peer::resolve_auth"});
  }
  auto authorization_server = oauth.discover_authorization_server(
      authorization_server_metadata_url(args.base_url,
                                        protected_resource.value().authorization_servers[0]));
  if (!authorization_server) {
    return chio::Result<AuthContext>::failure(authorization_server.error());
  }
  auto access_token =
      perform_authorization_code_flow(args, transport, authorization_server.value());
  if (!access_token) {
    return chio::Result<AuthContext>::failure(access_token.error());
  }
  return chio::Result<AuthContext>::success(
      AuthContext{"oauth-local", access_token.value(), protected_resource.value(),
                  authorization_server.value()});
}

std::uint64_t elapsed_ms(std::chrono::steady_clock::time_point started) {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - started)
          .count());
}

Result run_scenario(const Scenario& scenario,
                    const Args& args,
                    const AuthContext& auth_context,
                    chio::Session& session,
                    chio::HttpTransportPtr transport) {
  const auto started = std::chrono::steady_clock::now();

  if (scenario.id == "initialize") {
    return pass(scenario, elapsed_ms(started), "session_initialized");
  }

  if (scenario.id == "tools-list") {
    auto response = session.list_tools();
    if (response && contains(response.value(), "echo_text")) {
      return pass(scenario, elapsed_ms(started), "tools_list_contains_echo_text");
    }
    return fail(scenario,
                elapsed_ms(started),
                "tools_list_contains_echo_text",
                response ? response.value() : error_text(response.error()));
  }

  if (scenario.id == "tools-call-simple-text") {
    auto response = session.call_tool("echo_text", "{\"message\":\"hello from cpp peer\"}");
    if (response && contains(response.value(), "hello from cpp peer")) {
      return pass(scenario, elapsed_ms(started), "tool_result_matches_input_text");
    }
    return fail(scenario,
                elapsed_ms(started),
                "tool_result_matches_input_text",
                response ? response.value() : error_text(response.error()));
  }

  if (scenario.id == "resources-list") {
    auto response = session.list_resources();
    if (response && contains(response.value(), "fixture://docs/alpha")) {
      return pass(scenario, elapsed_ms(started), "resources_list_contains_fixture_uri");
    }
    return fail(scenario,
                elapsed_ms(started),
                "resources_list_contains_fixture_uri",
                response ? response.value() : error_text(response.error()));
  }

  if (scenario.id == "prompts-list") {
    auto response = session.list_prompts();
    if (response && contains(response.value(), "summarize_fixture")) {
      return pass(scenario, elapsed_ms(started), "prompts_list_contains_fixture_prompt");
    }
    return fail(scenario,
                elapsed_ms(started),
                "prompts_list_contains_fixture_prompt",
                response ? response.value() : error_text(response.error()));
  }

  if (scenario.id == "auth-unauthorized-challenge") {
    chio::HttpRequest request{
        "POST",
        args.base_url + "/mcp",
        {{"Accept", "application/json, text/event-stream"},
         {"Content-Type", "application/json"}},
        "{\"jsonrpc\":\"2.0\",\"id\":20,\"method\":\"initialize\",\"params\":{"
        "\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},"
        "\"clientInfo\":{\"name\":\"chio-conformance-cpp-unauthorized\","
        "\"version\":\"0.1.0\"}}}",
    };
    auto response = transport->send(request);
    if (response && response.value().status == 401 &&
        contains(header_value(response.value().headers, "www-authenticate"),
                 "resource_metadata=")) {
      return pass(scenario,
                  elapsed_ms(started),
                  "unauthorized_initialize_returns_resource_metadata_challenge");
    }
    return fail(scenario,
                elapsed_ms(started),
                "unauthorized_initialize_returns_resource_metadata_challenge",
                response ? response.value().body : error_text(response.error()));
  }

  if (scenario.id == "auth-protected-resource-metadata") {
    if (!auth_context.protected_resource_metadata.authorization_servers.empty() &&
        contains_value(auth_context.protected_resource_metadata.scopes_supported,
                       args.auth_scope)) {
      return pass(scenario,
                  elapsed_ms(started),
                  "protected_resource_metadata_advertises_auth_server_and_scope");
    }
    return fail(scenario,
                elapsed_ms(started),
                "protected_resource_metadata_advertises_auth_server_and_scope",
                "protected resource metadata did not advertise expected server and scope");
  }

  if (scenario.id == "auth-authorization-server-metadata") {
    if (contains_value(auth_context.authorization_server_metadata.grant_types_supported,
                       "authorization_code") &&
        contains_value(auth_context.authorization_server_metadata.grant_types_supported,
                       "urn:ietf:params:oauth:grant-type:token-exchange") &&
        !auth_context.authorization_server_metadata.authorization_endpoint.empty() &&
        !auth_context.authorization_server_metadata.token_endpoint.empty()) {
      return pass(scenario,
                  elapsed_ms(started),
                  "authorization_server_metadata_advertises_expected_grants");
    }
    return fail(scenario,
                elapsed_ms(started),
                "authorization_server_metadata_advertises_expected_grants",
                "authorization server metadata did not advertise expected grants");
  }

  if (scenario.id == "auth-code-initialize") {
    auto initialized = initialize_with_token(args, transport, auth_context.access_token);
    if (!initialized) {
      return fail(scenario,
                  elapsed_ms(started),
                  "authorization_code_access_token_initializes_session",
                  error_text(initialized.error()));
    }
    auto extra_session = initialized.move_value();
    (void)extra_session.close();
    return pass(scenario,
                elapsed_ms(started),
                "authorization_code_access_token_initializes_session");
  }

  if (scenario.id == "auth-token-exchange-initialize") {
    std::string base = args.base_url;
    while (!base.empty() && base.back() == '/') {
      base.pop_back();
    }
    chio::TokenExchangeRequest token_request;
    token_request.token_endpoint = auth_context.authorization_server_metadata.token_endpoint;
    token_request.grant_type = "urn:ietf:params:oauth:grant-type:token-exchange";
    token_request.subject_token = auth_context.access_token;
    token_request.subject_token_type =
        "urn:ietf:params:oauth:token-type:access_token";
    token_request.resource = base + "/mcp";
    token_request.scopes = {args.auth_scope};
    chio::OAuthMetadataClient oauth(args.base_url, transport);
    auto exchanged = oauth.exchange_token(token_request);
    if (!exchanged) {
      return fail(scenario,
                  elapsed_ms(started),
                  "token_exchange_access_token_initializes_session",
                  error_text(exchanged.error()));
    }
    const auto exchanged_token = extract_string_field(exchanged.value(), "access_token");
    auto initialized = initialize_with_token(args, transport, exchanged_token);
    if (!initialized) {
      return fail(scenario,
                  elapsed_ms(started),
                  "token_exchange_access_token_initializes_session",
                  error_text(initialized.error()));
    }
    auto extra_session = initialized.move_value();
    (void)extra_session.close();
    return pass(scenario,
                elapsed_ms(started),
                "token_exchange_access_token_initializes_session");
  }

  if (scenario.id == "tasks-call-get-result") {
    auto create = session.request(
        "tools/call",
        "{\"name\":\"echo_text\",\"arguments\":{\"message\":\"hello from cpp task peer\"},\"task\":{}}");
    if (!create || !contains(create.value(), "taskId")) {
      return fail(scenario,
                  elapsed_ms(started),
                  "task_created",
                  create ? create.value() : error_text(create.error()));
    }
    const auto task_id = extract_string_field(create.value(), "taskId");
    auto result = session.get_task_result(task_id);
    if (result && contains(result.value(), "hello from cpp task peer")) {
      return pass(scenario,
                  elapsed_ms(started),
                  "tasks_result_returns_related_terminal_payload");
    }
    return fail(scenario,
                elapsed_ms(started),
                "tasks_result_returns_related_terminal_payload",
                result ? result.value() : error_text(result.error()));
  }

  if (scenario.id == "tasks-cancel") {
    auto create = session.request(
        "tools/call",
        "{\"name\":\"slow_echo\",\"arguments\":{\"message\":\"hello from cpp cancel peer\"},\"task\":{}}");
    if (!create || !contains(create.value(), "taskId")) {
      return fail(scenario,
                  elapsed_ms(started),
                  "task_created",
                  create ? create.value() : error_text(create.error()));
    }
    const auto task_id = extract_string_field(create.value(), "taskId");
    auto cancel = session.cancel_task(task_id);
    if (cancel && contains(cancel.value(), "cancelled")) {
      return pass(scenario, elapsed_ms(started), "tasks_cancel_marks_cancelled");
    }
    return fail(scenario,
                elapsed_ms(started),
                "tasks_cancel_marks_cancelled",
                cancel ? cancel.value() : error_text(cancel.error()));
  }

  if (scenario.id == "catalog-list-changed-notifications") {
    bool saw_resource = false;
    bool saw_tool = false;
    bool saw_prompt = false;
    auto response = session.call_tool(
        "emit_fixture_notifications",
        "{\"count\":3,\"message\":\"hello from cpp notification peer\",\"uri\":\"fixture://docs/alpha\"}",
        [&](const chio::JsonMessage& message) {
          saw_resource = saw_resource || message.method == "notifications/resources/list_changed";
          saw_tool = saw_tool || message.method == "notifications/tools/list_changed";
          saw_prompt = saw_prompt || message.method == "notifications/prompts/list_changed";
          return chio::Result<void>::success();
        });
    if (response &&
        ((saw_resource && saw_tool && saw_prompt) ||
         (contains(response.value(), "notifications/resources/list_changed") &&
          contains(response.value(), "notifications/tools/list_changed")))) {
      return pass(scenario, elapsed_ms(started), "catalog_notifications_forwarded");
    }
    return fail(scenario,
                elapsed_ms(started),
                "catalog_notifications_forwarded",
                response ? response.value() : error_text(response.error()));
  }

  if (scenario.id == "resources-subscribe-updated-notification") {
    const std::string uri = "fixture://docs/alpha";
    bool saw_update = false;
    auto subscribed = session.subscribe_resource(uri);
    if (!subscribed) {
      return fail(scenario,
                  elapsed_ms(started),
                  "resources_subscribe_succeeds",
                  error_text(subscribed.error()));
    }
    auto response = session.call_tool(
        "emit_fixture_notifications",
        "{\"count\":2,\"uri\":\"fixture://docs/alpha\"}",
        [&](const chio::JsonMessage& message) {
          saw_update = saw_update ||
                       (message.method == "notifications/resources/updated" &&
                        contains(message.raw_json, uri));
          return chio::Result<void>::success();
        });
    if (response && (saw_update || contains(response.value(), "notifications/resources/updated"))) {
      return pass(scenario, elapsed_ms(started), "subscribed_resource_update_is_forwarded");
    }
    return fail(scenario,
                elapsed_ms(started),
                "subscribed_resource_update_is_forwarded",
                response ? response.value() : error_text(response.error()));
  }

  if (scenario.id == "nested-sampling-create-message") {
    auto router = conformance_nested_router();
    bool saw_sampling = false;
    auto response = session.call_tool(
        "sampled_echo",
        "{\"message\":\"nested callback sampling request\"}",
        [&](const chio::JsonMessage& message) {
          saw_sampling = saw_sampling || message.method == "sampling/createMessage";
          return router.bind(session)(message);
        });
    if (response && saw_sampling && contains(response.value(), "sampled by conformance peer")) {
      return pass(scenario, elapsed_ms(started), "nested_sampling_request_roundtrips");
    }
    return fail(scenario,
                elapsed_ms(started),
                "nested_sampling_request_roundtrips",
                response ? response.value() : error_text(response.error()));
  }

  if (scenario.id == "nested-elicitation-form-create") {
    auto router = conformance_nested_router();
    bool saw_elicitation = false;
    auto response = session.call_tool(
        "elicited_echo",
        "{\"message\":\"nested callback form elicitation request\"}",
        [&](const chio::JsonMessage& message) {
          saw_elicitation = saw_elicitation || message.method == "elicitation/create";
          return router.bind(session)(message);
        });
    if (response && saw_elicitation &&
        contains(response.value(), "elicited by conformance peer")) {
      return pass(scenario, elapsed_ms(started), "nested_form_elicitation_roundtrips");
    }
    return fail(scenario,
                elapsed_ms(started),
                "nested_form_elicitation_roundtrips",
                response ? response.value() : error_text(response.error()));
  }

  if (scenario.id == "nested-elicitation-url-create") {
    auto router = conformance_nested_router();
    bool saw_elicitation = false;
    auto response = session.call_tool(
        "url_elicited_echo",
        "{\"message\":\"nested callback url elicitation request\"}",
        [&](const chio::JsonMessage& message) {
          saw_elicitation = saw_elicitation || message.method == "elicitation/create";
          return router.bind(session)(message);
        });
    if (response && saw_elicitation && contains(response.value(), "elicitationId")) {
      return pass(scenario,
                  elapsed_ms(started),
                  "nested_url_elicitation_roundtrips_and_completes");
    }
    return fail(scenario,
                elapsed_ms(started),
                "nested_url_elicitation_roundtrips_and_completes",
                response ? response.value() : error_text(response.error()));
  }

  if (scenario.id == "nested-roots-list") {
    auto router = conformance_nested_router();
    bool saw_roots = false;
    auto response = session.call_tool(
        "roots_echo",
        "{\"message\":\"nested callback roots request\"}",
        [&](const chio::JsonMessage& message) {
          saw_roots = saw_roots || message.method == "roots/list";
          return router.bind(session)(message);
        });
    if (response && saw_roots &&
        contains(response.value(), "file:///workspace/conformance-root")) {
      return pass(scenario, elapsed_ms(started), "nested_roots_list_roundtrips");
    }
    return fail(scenario,
                elapsed_ms(started),
                "nested_roots_list_roundtrips",
                response ? response.value() : error_text(response.error()));
  }

  return unsupported(scenario,
                     elapsed_ms(started),
                     "unsupported scenario id " + scenario.id);
}

std::string result_to_json(const Result& result, const std::string& transcript_path) {
  std::string out = "{";
  out += "\"scenarioId\":" + quote(result.scenario.id);
  out += ",\"peer\":\"cpp\"";
  out += ",\"peerRole\":\"client_to_chio_server\"";
  out += ",\"deploymentMode\":\"remote_http\"";
  out += ",\"transport\":\"streamable-http\"";
  out += ",\"specVersion\":\"2025-11-25\"";
  out += ",\"category\":" + quote(result.scenario.category);
  out += ",\"status\":" + quote(result.status);
  out += ",\"durationMs\":" + std::to_string(result.duration_ms);
  out += ",\"assertions\":[{\"name\":" + quote(result.assertion_name) +
         ",\"status\":" + quote(result.assertion_status);
  if (!result.message.empty()) {
    out += ",\"message\":" + quote(result.message);
  }
  out += "}]";
  if (result.status != "pass") {
    out += ",\"failureKind\":" + quote(result.status == "unsupported" ? "unsupported"
                                                                       : "assertion-failed");
    out += ",\"failureMessage\":" + quote(result.message);
  }
  out += ",\"artifacts\":{\"transcript\":" + quote(transcript_path) + "}";
  out += "}";
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const Args args = parse_args(argc, argv);
    std::cerr << "cpp peer: loading scenarios from " << args.scenarios_dir << "\n";
    const auto scenarios = load_scenarios(args.scenarios_dir);
    std::cerr << "cpp peer: loaded " << scenarios.size() << " scenarios\n";
    std::filesystem::create_directories(args.artifacts_dir);
    const auto transcript_path = std::filesystem::path(args.artifacts_dir) / "transcript.jsonl";
    write_file(transcript_path, "{\"peer\":\"cpp\",\"event\":\"started\"}\n");

    std::vector<Result> results;
    auto transport = std::make_shared<chio::CurlHttpTransport>();
    auto auth_context = resolve_auth(args, transport);
    if (!auth_context) {
      for (const auto& scenario : scenarios) {
        results.push_back(fail(scenario, 0, "auth_resolved", error_text(auth_context.error())));
      }
    } else {
      auto built_client = chio::ClientBuilder()
                              .base_url(args.base_url)
                              .bearer_token(auth_context.value().access_token)
                              .transport(transport)
                              .timeout(std::chrono::milliseconds(10000))
                              .client_info("chio-conformance-cpp", "0.1.0")
                              .client_capabilities_json(conformance_client_capabilities_json())
                              .initialize_message_handler([](chio::Session& session,
                                                             const chio::JsonMessage& message) {
                                return conformance_nested_router().bind(session)(message);
                              })
                              .build();
      if (!built_client) {
        throw std::runtime_error(error_text(built_client.error()));
      }
      auto client = built_client.move_value();
      std::cerr << "cpp peer: initializing session\n";
      auto initialized = client.initialize();
      if (!initialized) {
        for (const auto& scenario : scenarios) {
          results.push_back(
              fail(scenario, 0, "session_initialized", error_text(initialized.error())));
        }
      } else {
        auto session = initialized.move_value();
        for (const auto& scenario : scenarios) {
          results.push_back(
              run_scenario(scenario, args, auth_context.value(), session, transport));
        }
        (void)session.close();
      }
    }

    std::string output = "[\n";
    for (std::size_t i = 0; i < results.size(); ++i) {
      if (i != 0) {
        output += ",\n";
      }
      output += "  " + result_to_json(results[i], transcript_path.string());
    }
    output += "\n]\n";
    write_file(args.results_output, output);
  } catch (const std::exception& error) {
    std::cerr << "C++ conformance peer failed: " << error.what() << "\n";
    return 1;
  }

  return 0;
}
