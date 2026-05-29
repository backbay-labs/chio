#include "chio/client.hpp"

#include <optional>
#include <utility>

#include "json.hpp"
#include "json_rpc.hpp"
#include "sse.hpp"
#include "transport_util.hpp"

namespace chio {
namespace {

Result<detail::JsonValue> parse_initialize_response_json(const std::string& body,
                                                         const std::string& expected_id_json,
                                                         int status) {
  auto parsed = detail::parse_json(body);
  if (parsed) {
    if (!detail::is_jsonrpc_terminal_response(*parsed, expected_id_json)) {
      return Result<detail::JsonValue>::failure(
          Error{ErrorCode::Protocol,
                "initialize response did not match JSON-RPC request id",
                "Client::initialize",
                status,
                detail::body_snippet(body)});
    }
    return Result<detail::JsonValue>::success(std::move(*parsed));
  }

  std::optional<detail::JsonValue> terminal_message;
  bool saw_mismatched_terminal = false;
  auto events = detail::for_each_sse_event(body, [&](const std::string& payload) {
    auto event_json = detail::parse_json(payload);
    if (!event_json) {
      return Result<void>::failure(
          Error{ErrorCode::Json,
                "failed to parse initialize SSE event",
                "Client::initialize",
                status,
                detail::body_snippet(payload)});
    }
    if (detail::is_jsonrpc_terminal_response(*event_json, expected_id_json)) {
      terminal_message = std::move(*event_json);
    } else if (event_json->get("result") != nullptr || event_json->get("error") != nullptr) {
      saw_mismatched_terminal = true;
    }
    return Result<void>::success();
  });
  if (!events) {
    return Result<detail::JsonValue>::failure(events.error());
  }
  if (terminal_message) {
    return Result<detail::JsonValue>::success(std::move(*terminal_message));
  }
  if (saw_mismatched_terminal) {
    return Result<detail::JsonValue>::failure(
        Error{ErrorCode::Protocol,
              "initialize response did not match JSON-RPC request id",
              "Client::initialize",
              status,
              detail::body_snippet(body)});
  }
  return Result<detail::JsonValue>::failure(
      Error{ErrorCode::Json,
            "failed to parse initialize response body",
            "Client::initialize",
            status,
            detail::body_snippet(body)});
}

}  // namespace

Client::Client(ClientOptions options, HttpTransportPtr transport, TraceSinkPtr trace_sink)
    : options_(std::move(options)),
      transport_(std::move(transport)),
      trace_sink_(std::move(trace_sink)) {
  options_.base_url = detail::trim_right_slash(options_.base_url);
}

Client Client::with_static_bearer(std::string base_url,
                                  std::string bearer_token,
                                  HttpTransportPtr transport) {
  return Client(ClientOptions{std::move(base_url), std::move(bearer_token)},
                std::move(transport));
}

Result<Session> Client::initialize() const {
  if (!transport_) {
    return Result<Session>::failure(Error{ErrorCode::Transport, "missing HTTP transport"});
  }
  std::string bearer_token = options_.bearer_token;
  if (options_.token_provider) {
    auto token = options_.token_provider->access_token();
    if (!token) {
      return Result<Session>::failure(token.error());
    }
    bearer_token = token.value();
  }
  if (bearer_token.empty()) {
    return Result<Session>::failure(
        Error{ErrorCode::Protocol, "bearer token is required", "Client::initialize"});
  }

  const std::string body =
      "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{"
      "\"protocolVersion\":" +
      detail::quote(options_.protocol_version) +
      ",\"capabilities\":" + options_.client_capabilities_json +
      ",\"clientInfo\":{\"name\":" + detail::quote(options_.client_name) +
      ",\"version\":" + detail::quote(options_.client_version) + "}}}";

  HttpRequest request{
      "POST",
      options_.base_url + "/mcp",
      {
          {"Authorization", "Bearer " + bearer_token},
          {"Accept", "application/json, text/event-stream"},
          {"Content-Type", "application/json"},
      },
      body,
      options_.timeout,
  };
  auto response = detail::send_with_policy(transport_, request, options_.retry_policy, trace_sink_,
                                           "Client::initialize");
  if (!response) {
    return Result<Session>::failure(response.error());
  }
  if (response.value().status != 200) {
    return Result<Session>::failure(
        Error{ErrorCode::Protocol, "initialize returned HTTP " +
                                      std::to_string(response.value().status),
              "Client::initialize", response.value().status,
              detail::body_snippet(response.value().body), {}, {},
              detail::retryable_status(response.value().status)});
  }

  const auto headers = detail::lower_headers(response.value().headers);
  auto session_header = headers.find("mcp-session-id");
  if (session_header == headers.end() || session_header->second.empty()) {
    return Result<Session>::failure(
        Error{ErrorCode::Protocol, "initialize response did not include MCP-Session-Id"});
  }
  std::string protocol;
  auto parsed = parse_initialize_response_json(
      response.value().body, detail::request_id_json(body), response.value().status);
  if (!parsed) {
    return Result<Session>::failure(parsed.error());
  }
  const auto* rpc_error = parsed.value().get("error");
  if (rpc_error != nullptr) {
    std::string message = "initialize returned JSON-RPC error";
    if (rpc_error->is_object()) {
      const auto error_message = rpc_error->string_field("message");
      if (!error_message.empty()) {
        message += ": " + error_message;
      }
    }
    return Result<Session>::failure(
        Error{ErrorCode::Protocol,
              std::move(message),
              "Client::initialize",
              response.value().status,
              detail::body_snippet(response.value().body)});
  }
  protocol = detail::json_string_at(parsed.value(), {"result", "protocolVersion"});
  if (protocol.empty()) {
    return Result<Session>::failure(
        Error{ErrorCode::Protocol,
              "initialize response missing result.protocolVersion",
              "Client::initialize",
              response.value().status,
              detail::body_snippet(response.value().body)});
  }

  Session session(options_.base_url, bearer_token, session_header->second, protocol,
                  transport_, options_.retry_policy, trace_sink_, options_.timeout,
                  options_.token_provider);
  if (options_.initialize_message_handler) {
    session.on_message([handler = options_.initialize_message_handler, &session](
                           const JsonMessage& message) {
      return handler(session, message);
    });
  }
  auto initialized = session.notification("notifications/initialized");
  if (options_.initialize_message_handler) {
    session.on_message({});
  }
  if (!initialized) {
    return Result<Session>::failure(initialized.error());
  }
  return Result<Session>::success(std::move(session));
}

ClientBuilder& ClientBuilder::base_url(std::string value) {
  options_.base_url = std::move(value);
  return *this;
}

ClientBuilder& ClientBuilder::bearer_token(std::string value) {
  options_.bearer_token = std::move(value);
  return *this;
}

ClientBuilder& ClientBuilder::token_provider(TokenProviderPtr value) {
  options_.token_provider = std::move(value);
  return *this;
}

ClientBuilder& ClientBuilder::transport(HttpTransportPtr value) {
  transport_ = std::move(value);
  return *this;
}

ClientBuilder& ClientBuilder::trace_sink(TraceSinkPtr value) {
  trace_sink_ = std::move(value);
  return *this;
}

ClientBuilder& ClientBuilder::timeout(std::chrono::milliseconds value) {
  options_.timeout = value;
  return *this;
}

ClientBuilder& ClientBuilder::retry_policy(RetryPolicy value) {
  options_.retry_policy = value;
  return *this;
}

ClientBuilder& ClientBuilder::client_info(std::string name, std::string version) {
  options_.client_name = std::move(name);
  options_.client_version = std::move(version);
  return *this;
}

ClientBuilder& ClientBuilder::protocol_version(std::string value) {
  options_.protocol_version = std::move(value);
  return *this;
}

ClientBuilder& ClientBuilder::client_capabilities_json(std::string value) {
  options_.client_capabilities_json = std::move(value);
  return *this;
}

ClientBuilder& ClientBuilder::initialize_message_handler(InitializeMessageHandler value) {
  options_.initialize_message_handler = std::move(value);
  return *this;
}

Result<Client> ClientBuilder::build() const {
  if (options_.base_url.empty()) {
    return Result<Client>::failure(
        Error{ErrorCode::Protocol, "base_url is required", "ClientBuilder::build"});
  }
  if (!transport_) {
    return Result<Client>::failure(
        Error{ErrorCode::Transport, "transport is required", "ClientBuilder::build"});
  }
  return Result<Client>::success(Client(options_, transport_, trace_sink_));
}

}  // namespace chio
