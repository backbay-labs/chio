#include "chio/session.hpp"

#include <memory>
#include <optional>
#include <utility>

#include "json_rpc.hpp"
#include "json.hpp"
#include "sse.hpp"
#include "transport_util.hpp"

namespace chio {
namespace {

JsonMessage to_message(const detail::JsonValue& value) {
  JsonMessage message;
  message.raw_json = value.dump();
  message.method = value.string_field("method");
  const auto* id = value.get("id");
  if (id != nullptr) {
    message.id_json = id->dump();
    message.id = id->is_string() ? id->as_string() : id->dump();
  }
  return message;
}

Result<void> deliver_message(const detail::JsonValue& value,
                             const MessageHandler& primary,
                             const MessageHandler& secondary) {
  const auto message = to_message(value);
  if (message.method.empty()) {
    return Result<void>::success();
  }
  if (primary) {
    auto handled = primary(message);
    if (!handled) {
      return handled;
    }
  }
  if (secondary) {
    auto handled = secondary(message);
    if (!handled) {
      return handled;
    }
  }
  return Result<void>::success();
}

const detail::JsonValue* result_array(const detail::JsonValue& root, std::string_view name) {
  const auto* direct = root.get(name);
  if (direct != nullptr && direct->kind() == detail::JsonValue::Kind::Array) {
    return direct;
  }
  const auto* result = root.get("result");
  if (result == nullptr) {
    return nullptr;
  }
  const auto* nested = result->get(name);
  if (nested != nullptr && nested->kind() == detail::JsonValue::Kind::Array) {
    return nested;
  }
  return nullptr;
}

std::vector<Tool> parse_tools(const detail::JsonValue& root) {
  std::vector<Tool> out;
  const auto* values = result_array(root, "tools");
  if (values == nullptr) {
    return out;
  }
  for (const auto& value : values->as_array()) {
    if (!value.is_object()) {
      continue;
    }
    Tool tool;
    tool.name = value.string_field("name");
    tool.title = value.string_field("title");
    tool.description = value.string_field("description");
    const auto* input_schema = value.get("inputSchema");
    if (input_schema == nullptr) {
      input_schema = value.get("input_schema");
    }
    if (input_schema != nullptr) {
      tool.input_schema_json = input_schema->dump();
    }
    const auto* annotations = value.get("annotations");
    if (annotations != nullptr && annotations->is_object()) {
      for (const auto& entry : annotations->as_object()) {
        if (entry.second.is_string()) {
          tool.annotations[entry.first] = entry.second.as_string();
        }
      }
    }
    out.push_back(std::move(tool));
  }
  return out;
}

std::vector<Resource> parse_resources(const detail::JsonValue& root) {
  std::vector<Resource> out;
  const auto* values = result_array(root, "resources");
  if (values == nullptr) {
    return out;
  }
  for (const auto& value : values->as_array()) {
    if (!value.is_object()) {
      continue;
    }
    Resource resource;
    resource.uri = value.string_field("uri");
    resource.name = value.string_field("name");
    resource.description = value.string_field("description");
    resource.mime_type = value.string_field("mimeType");
    if (resource.mime_type.empty()) {
      resource.mime_type = value.string_field("mime_type");
    }
    out.push_back(std::move(resource));
  }
  return out;
}

std::vector<Prompt> parse_prompts(const detail::JsonValue& root) {
  std::vector<Prompt> out;
  const auto* values = result_array(root, "prompts");
  if (values == nullptr) {
    return out;
  }
  for (const auto& value : values->as_array()) {
    if (!value.is_object()) {
      continue;
    }
    Prompt prompt;
    prompt.name = value.string_field("name");
    prompt.title = value.string_field("title");
    prompt.description = value.string_field("description");
    out.push_back(std::move(prompt));
  }
  return out;
}

std::vector<Task> parse_tasks(const detail::JsonValue& root) {
  std::vector<Task> out;
  const auto* values = result_array(root, "tasks");
  if (values == nullptr) {
    return out;
  }
  for (const auto& value : values->as_array()) {
    if (!value.is_object()) {
      continue;
    }
    Task task;
    task.task_id = value.string_field("taskId");
    if (task.task_id.empty()) {
      task.task_id = value.string_field("id");
    }
    task.status = value.string_field("status");
    const auto* status = value.get("status");
    if (task.status.empty() && status != nullptr) {
      task.status = status->dump();
    }
    task.raw_json = value.dump();
    out.push_back(std::move(task));
  }
  return out;
}

Error parse_error(std::string operation, const std::string& raw_json) {
  return Error{ErrorCode::Json,
               "failed to parse JSON response",
               std::move(operation),
               {},
               detail::body_snippet(raw_json)};
}

Result<void> reject_jsonrpc_error(const detail::JsonValue& root,
                                  std::string operation,
                                  const std::string& raw_json) {
  const auto* error = root.get("error");
  if (error == nullptr) {
    return Result<void>::success();
  }
  std::string message = "JSON-RPC error response";
  if (error->is_object()) {
    const auto error_message = error->string_field("message");
    if (!error_message.empty()) {
      message += ": " + error_message;
    }
  }
  return Result<void>::failure(
      Error{ErrorCode::Protocol, std::move(message), std::move(operation), {},
            detail::body_snippet(raw_json), {}, {}, false});
}

std::string request_terminal_id_json(const std::string& body_json) {
  auto parsed = detail::parse_json(body_json);
  if (!parsed || !parsed->is_object() || parsed->get("method") == nullptr) {
    return {};
  }
  const auto* id = parsed->get("id");
  return id == nullptr ? std::string() : id->dump();
}

Result<std::string> normalize_response_body(const std::string& body,
                                            const std::string& expected_id_json,
                                            std::string operation,
                                            bool require_terminal) {
  auto parsed = detail::parse_json(body);
  if (parsed) {
    if (expected_id_json.empty() && !require_terminal) {
      auto error = reject_jsonrpc_error(*parsed, operation, body);
      if (!error) {
        return Result<std::string>::failure(error.error());
      }
      return Result<std::string>::success(body);
    }
    if (!expected_id_json.empty() &&
        detail::is_jsonrpc_terminal_response(*parsed, expected_id_json)) {
      auto error = reject_jsonrpc_error(*parsed, operation, body);
      if (!error) {
        return Result<std::string>::failure(error.error());
      }
      return Result<std::string>::success(body);
    }
    return Result<std::string>::failure(
        Error{ErrorCode::Protocol,
              "MCP response did not include matching JSON-RPC terminal response",
              std::move(operation),
              {},
              detail::body_snippet(body)});
  }

  if (expected_id_json.empty()) {
    return Result<std::string>::success(body);
  }

  std::optional<std::string> terminal_response;
  auto events = detail::for_each_sse_event(body, [&](const std::string& payload) {
    auto event = detail::parse_json(payload);
    if (!event) {
      return Result<void>::failure(
          Error{ErrorCode::Json,
                "failed to parse JSON stream event",
                operation,
                {},
                detail::body_snippet(payload)});
    }
    if (detail::is_jsonrpc_terminal_response(*event, expected_id_json)) {
      auto error = reject_jsonrpc_error(*event, operation, payload);
      if (!error) {
        return Result<void>::failure(error.error());
      }
      terminal_response = payload;
    }
    return Result<void>::success();
  });
  if (!events) {
    return Result<std::string>::failure(events.error());
  }
  if (terminal_response) {
    return Result<std::string>::success(std::move(*terminal_response));
  }
  return Result<std::string>::failure(
      Error{ErrorCode::Protocol,
            "MCP response did not include matching JSON-RPC terminal response",
            std::move(operation),
            {},
            detail::body_snippet(body)});
}

}  // namespace

NestedCallbackRouter& NestedCallbackRouter::on_sampling(SamplingHandler handler) {
  sampling_handler_ = std::move(handler);
  return *this;
}

NestedCallbackRouter& NestedCallbackRouter::on_elicitation(ElicitationHandler handler) {
  elicitation_handler_ = std::move(handler);
  return *this;
}

NestedCallbackRouter& NestedCallbackRouter::on_roots(RootsHandler handler) {
  roots_handler_ = std::move(handler);
  return *this;
}

MessageHandler NestedCallbackRouter::bind(Session& session) const {
  auto sampling = sampling_handler_;
  auto elicitation = elicitation_handler_;
  auto roots = roots_handler_;
  auto send_envelope = session.envelope_sender();
  return [send_envelope, sampling, elicitation, roots](const JsonMessage& message) {
    Result<std::string> response = Result<std::string>::failure(
        Error{ErrorCode::Protocol, "no nested callback handler matched",
              "NestedCallbackRouter::bind"});
    if (message.method == "sampling/createMessage" && sampling) {
      response = sampling(message);
    } else if (message.method == "elicitation/create" && elicitation) {
      response = elicitation(message);
    } else if (message.method == "roots/list" && roots) {
      response = roots(message);
    } else {
      return Result<void>::success();
    }
    if (!response) {
      return Result<void>::failure(response.error());
    }
    auto sent = send_envelope(response.value());
    if (!sent) {
      return Result<void>::failure(sent.error());
    }
    return Result<void>::success();
  };
}

std::string NestedCallbackRouter::sampling_text_result(const JsonMessage& message,
                                                       std::string text,
                                                       std::string model,
                                                       std::string stop_reason) {
  const auto id = message.id_json.empty() ? "null" : message.id_json;
  return "{\"jsonrpc\":\"2.0\",\"id\":" + id +
         ",\"result\":{\"role\":\"assistant\",\"content\":{\"type\":\"text\",\"text\":" +
         detail::quote(text) + "},\"model\":" + detail::quote(model) +
         ",\"stopReason\":" + detail::quote(stop_reason) + "}}";
}

std::string NestedCallbackRouter::elicitation_accept_result(const JsonMessage& message,
                                                            std::string content_json) {
  const auto id = message.id_json.empty() ? "null" : message.id_json;
  std::string result = "{\"action\":\"accept\"";
  if (!content_json.empty() && content_json != "{}") {
    result += ",\"content\":" + content_json;
  }
  result += "}";
  return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":" + result + "}";
}

std::string NestedCallbackRouter::roots_list_result(const JsonMessage& message,
                                                    std::string roots_json) {
  const auto id = message.id_json.empty() ? "null" : message.id_json;
  return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"roots\":" +
         roots_json + "}}";
}

Session::Session(std::string base_url,
                 std::string bearer_token,
                 std::string session_id,
                 std::string protocol_version,
                 HttpTransportPtr transport,
                 RetryPolicy retry_policy,
                 TraceSinkPtr trace_sink,
                 std::chrono::milliseconds timeout,
                 TokenProviderPtr token_provider)
    : base_url_(detail::trim_right_slash(std::move(base_url))),
      bearer_token_(std::move(bearer_token)),
      token_provider_(std::move(token_provider)),
      session_id_(std::move(session_id)),
      protocol_version_(std::move(protocol_version)),
      transport_(std::move(transport)),
      retry_policy_(retry_policy),
      trace_sink_(std::move(trace_sink)),
      timeout_(timeout) {}

Session::Session(Session&& other) noexcept
    : base_url_(std::move(other.base_url_)),
      bearer_token_(std::move(other.bearer_token_)),
      token_provider_(std::move(other.token_provider_)),
      session_id_(std::move(other.session_id_)),
      protocol_version_(std::move(other.protocol_version_)),
      transport_(std::move(other.transport_)),
      retry_policy_(other.retry_policy_),
      trace_sink_(std::move(other.trace_sink_)),
      timeout_(other.timeout_),
      message_handler_(std::move(other.message_handler_)),
      next_request_id_(other.next_request_id_.load()) {}

Session& Session::operator=(Session&& other) noexcept {
  if (this == &other) {
    return *this;
  }
  base_url_ = std::move(other.base_url_);
  bearer_token_ = std::move(other.bearer_token_);
  token_provider_ = std::move(other.token_provider_);
  session_id_ = std::move(other.session_id_);
  protocol_version_ = std::move(other.protocol_version_);
  transport_ = std::move(other.transport_);
  retry_policy_ = other.retry_policy_;
  trace_sink_ = std::move(other.trace_sink_);
  timeout_ = other.timeout_;
  message_handler_ = std::move(other.message_handler_);
  next_request_id_.store(other.next_request_id_.load());
  return *this;
}

Result<std::string> Session::bearer_token_for_request(std::string operation) const {
  if (token_provider_) {
    auto token = token_provider_->access_token();
    if (!token) {
      return Result<std::string>::failure(token.error());
    }
    if (token.value().empty()) {
      return Result<std::string>::failure(
          Error{ErrorCode::Protocol, "bearer token is empty", std::move(operation)});
    }
    return Result<std::string>::success(token.value());
  }
  if (bearer_token_.empty()) {
    return Result<std::string>::failure(
        Error{ErrorCode::Protocol, "bearer token is empty", std::move(operation)});
  }
  return Result<std::string>::success(bearer_token_);
}

std::function<Result<std::string>(std::string)> Session::envelope_sender() const {
  auto base_url = base_url_;
  auto bearer_token = bearer_token_;
  auto token_provider = token_provider_;
  auto session_id = session_id_;
  auto protocol_version = protocol_version_;
  auto transport = transport_;
  auto retry_policy = retry_policy_;
  auto trace_sink = trace_sink_;
  auto timeout = timeout_;
  return [base_url = std::move(base_url),
          bearer_token = std::move(bearer_token),
          token_provider = std::move(token_provider),
          session_id = std::move(session_id),
          protocol_version = std::move(protocol_version),
          transport = std::move(transport),
          retry_policy,
          trace_sink = std::move(trace_sink),
          timeout](std::string body_json) -> Result<std::string> {
    if (!transport) {
      return Result<std::string>::failure(
          Error{ErrorCode::Transport, "missing HTTP transport", "NestedCallbackRouter::bind"});
    }
    std::string token;
    if (token_provider) {
      auto provider_token = token_provider->access_token();
      if (!provider_token) {
        return Result<std::string>::failure(provider_token.error());
      }
      token = provider_token.value();
    } else {
      token = bearer_token;
    }
    if (token.empty()) {
      return Result<std::string>::failure(
          Error{ErrorCode::Protocol, "bearer token is empty", "NestedCallbackRouter::bind"});
    }

    HttpRequest request{
        "POST",
        base_url + "/mcp",
        {
            {"Authorization", "Bearer " + token},
            {"Accept", "application/json, text/event-stream"},
            {"Content-Type", "application/json"},
            {"MCP-Session-Id", session_id},
            {"MCP-Protocol-Version", protocol_version},
        },
        std::move(body_json),
        timeout,
    };
    auto response = detail::send_with_policy(transport, std::move(request), retry_policy,
                                             trace_sink, "NestedCallbackRouter::bind");
    if (!response) {
      return Result<std::string>::failure(response.error());
    }
    auto http = response.move_value();
    if (http.status < 200 || http.status >= 300) {
      return Result<std::string>::failure(
          Error{ErrorCode::Protocol,
                "nested callback response returned HTTP " + std::to_string(http.status),
                "NestedCallbackRouter::bind",
                http.status,
                detail::body_snippet(http.body),
                {},
                {},
                detail::retryable_status(http.status)});
    }
    return Result<std::string>::success(std::move(http.body));
  };
}

Result<HttpRequest> Session::make_post(std::string body_json, bool stream_response) const {
  (void)stream_response;
  auto bearer_token = bearer_token_for_request("Session::make_post");
  if (!bearer_token) {
    return Result<HttpRequest>::failure(bearer_token.error());
  }
  return Result<HttpRequest>::success(HttpRequest{
      "POST",
      base_url_ + "/mcp",
      {
          {"Authorization", "Bearer " + bearer_token.value()},
          {"Accept", "application/json, text/event-stream"},
          {"Content-Type", "application/json"},
          {"MCP-Session-Id", session_id_},
          {"MCP-Protocol-Version", protocol_version_},
      },
      std::move(body_json),
      timeout_,
  });
}

Result<HttpRequest> Session::make_get_stream(
    std::shared_ptr<CancellationToken> cancellation) const {
  auto bearer_token = bearer_token_for_request("Session::make_get_stream");
  if (!bearer_token) {
    return Result<HttpRequest>::failure(bearer_token.error());
  }
  return Result<HttpRequest>::success(HttpRequest{
      "GET",
      base_url_ + "/mcp",
      {
          {"Authorization", "Bearer " + bearer_token.value()},
          {"Accept", "text/event-stream"},
          {"MCP-Session-Id", session_id_},
          {"MCP-Protocol-Version", protocol_version_},
      },
      "",
      std::chrono::milliseconds(0),
      1,
      std::move(cancellation),
  });
}

std::int64_t Session::next_id() const {
  return next_request_id_.fetch_add(1);
}

Result<std::string> Session::send_envelope(std::string body_json) const {
  auto response = send_envelope_response(std::move(body_json));
  if (!response) {
    return Result<std::string>::failure(response.error());
  }
  return Result<std::string>::success(std::move(response.value().value));
}

Result<TypedResponse<std::string>> Session::send_envelope_response(std::string body_json) const {
  if (!transport_) {
    return Result<TypedResponse<std::string>>::failure(
        Error{ErrorCode::Transport, "missing HTTP transport", "Session::send_envelope"});
  }
  const auto expected_id_json = request_terminal_id_json(body_json);
  auto request_result = make_post(std::move(body_json));
  if (!request_result) {
    return Result<TypedResponse<std::string>>::failure(request_result.error());
  }
  auto request = request_result.move_value();
  auto stream_dispatched = std::make_shared<bool>(false);
  if (message_handler_) {
    request.stream_message = [this, stream_dispatched](const std::string& raw_json) {
      auto parsed = detail::parse_json(raw_json);
      if (!parsed) {
        return Result<void>::failure(
            Error{ErrorCode::Json, "failed to parse streamed JSON message",
                  "Session::send_envelope", {}, detail::body_snippet(raw_json)});
      }
      *stream_dispatched = true;
      return deliver_message(*parsed, {}, message_handler_);
    };
  }
  auto response = detail::send_with_policy(
      transport_, std::move(request), retry_policy_, trace_sink_, "Session::send_envelope");
  if (!response) {
    return Result<TypedResponse<std::string>>::failure(response.error());
  }
  auto http = response.move_value();
  if (http.status < 200 || http.status >= 300) {
    return Result<TypedResponse<std::string>>::failure(
        Error{ErrorCode::Protocol,
              "MCP request returned HTTP " + std::to_string(http.status),
              "Session::send_envelope",
              http.status,
              detail::body_snippet(http.body),
              {},
              {},
              detail::retryable_status(http.status)});
  }
  auto normalized = normalize_response_body(http.body, expected_id_json,
                                            "Session::send_envelope", false);
  if (!normalized) {
    return Result<TypedResponse<std::string>>::failure(normalized.error());
  }
  auto raw = normalized.move_value();
  if (message_handler_ && !*stream_dispatched) {
    auto dispatched = dispatch_messages(http.body, {});
    if (!dispatched) {
      return Result<TypedResponse<std::string>>::failure(dispatched.error());
    }
  }
  return Result<TypedResponse<std::string>>::success(
      TypedResponse<std::string>{raw, raw, std::move(http)});
}

Result<std::string> Session::request(std::string method, std::string params_json) const {
  const auto id = next_id();
  std::string body = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
                     ",\"method\":" + detail::quote(method) + ",\"params\":" +
                     params_json + "}";
  return send_envelope(std::move(body));
}

Result<std::string> Session::request_streaming(std::string method,
                                               std::string params_json,
                                               MessageHandler handler) const {
  const auto id = next_id();
  const auto id_json = std::to_string(id);
  std::string body = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
                     ",\"method\":" + detail::quote(method) + ",\"params\":" +
                     params_json + "}";
  auto request_result = make_post(std::move(body), true);
  if (!request_result) {
    return Result<std::string>::failure(request_result.error());
  }
  auto request = request_result.move_value();
  auto saw_stream_message = std::make_shared<bool>(false);
  request.stream_message = [this, handler, saw_stream_message](const std::string& raw_json) {
    *saw_stream_message = true;
    auto parsed = detail::parse_json(raw_json);
    if (!parsed) {
      return Result<void>::failure(
          Error{ErrorCode::Json, "failed to parse streamed JSON message",
                "Session::request_streaming", {}, detail::body_snippet(raw_json)});
    }
    return deliver_message(*parsed, handler, message_handler_);
  };
  auto http_response = detail::send_with_policy(
      transport_, std::move(request), retry_policy_, trace_sink_,
      "Session::request_streaming");
  if (!http_response) {
    return Result<std::string>::failure(http_response.error());
  }
  auto http = http_response.move_value();
  if (http.status < 200 || http.status >= 300) {
    return Result<std::string>::failure(
        Error{ErrorCode::Protocol,
              "MCP streaming request returned HTTP " + std::to_string(http.status),
              "Session::request_streaming",
              http.status,
              detail::body_snippet(http.body),
              {},
              {},
              detail::retryable_status(http.status)});
  }
  auto response_body = std::move(http.body);
  if (!*saw_stream_message) {
    auto dispatched = dispatch_messages(response_body, std::move(handler));
    if (!dispatched) {
      return Result<std::string>::failure(dispatched.error());
    }
  }
  auto terminal_response = normalize_response_body(response_body, id_json,
                                                   "Session::request_streaming", true);
  if (!terminal_response) {
    return Result<std::string>::failure(terminal_response.error());
  }
  return Result<std::string>::success(terminal_response.move_value());
}

Result<std::string> Session::notification(std::string method, std::string params_json) const {
  std::string body = "{\"jsonrpc\":\"2.0\",\"method\":" + detail::quote(method) +
                     ",\"params\":" + params_json + "}";
  return send_envelope(std::move(body));
}

Result<std::string> Session::list_tools() const {
  return request("tools/list");
}

Result<TypedResponse<std::vector<Tool>>> Session::list_tools_typed() const {
  const auto id = next_id();
  auto raw = send_envelope_response("{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
                                    ",\"method\":\"tools/list\",\"params\":{}}");
  if (!raw) {
    return Result<TypedResponse<std::vector<Tool>>>::failure(raw.error());
  }
  auto parsed = detail::parse_json(raw.value().raw_json);
  if (!parsed) {
    return Result<TypedResponse<std::vector<Tool>>>::failure(
        parse_error("Session::list_tools_typed", raw.value().raw_json));
  }
  auto error = reject_jsonrpc_error(*parsed, "Session::list_tools_typed", raw.value().raw_json);
  if (!error) {
    return Result<TypedResponse<std::vector<Tool>>>::failure(error.error());
  }
  return Result<TypedResponse<std::vector<Tool>>>::success(
      TypedResponse<std::vector<Tool>>{parse_tools(*parsed), raw.value().raw_json,
                                       std::move(raw.value().response)});
}

Result<std::string> Session::call_tool(std::string name, std::string arguments_json) const {
  return request("tools/call", "{\"name\":" + detail::quote(name) +
                                  ",\"arguments\":" + arguments_json + "}");
}

Result<std::string> Session::call_tool(std::string name,
                                       std::string arguments_json,
                                       MessageHandler handler) const {
  return request_streaming("tools/call",
                           "{\"name\":" + detail::quote(name) +
                               ",\"arguments\":" + arguments_json + "}",
                           std::move(handler));
}

Result<std::string> Session::list_resources() const {
  return request("resources/list");
}

Result<TypedResponse<std::vector<Resource>>> Session::list_resources_typed() const {
  const auto id = next_id();
  auto raw = send_envelope_response("{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
                                    ",\"method\":\"resources/list\",\"params\":{}}");
  if (!raw) {
    return Result<TypedResponse<std::vector<Resource>>>::failure(raw.error());
  }
  auto parsed = detail::parse_json(raw.value().raw_json);
  if (!parsed) {
    return Result<TypedResponse<std::vector<Resource>>>::failure(
        parse_error("Session::list_resources_typed", raw.value().raw_json));
  }
  auto error =
      reject_jsonrpc_error(*parsed, "Session::list_resources_typed", raw.value().raw_json);
  if (!error) {
    return Result<TypedResponse<std::vector<Resource>>>::failure(error.error());
  }
  return Result<TypedResponse<std::vector<Resource>>>::success(
      TypedResponse<std::vector<Resource>>{parse_resources(*parsed), raw.value().raw_json,
                                           std::move(raw.value().response)});
}

Result<std::string> Session::read_resource(std::string uri) const {
  return request("resources/read", "{\"uri\":" + detail::quote(uri) + "}");
}

Result<std::string> Session::subscribe_resource(std::string uri) const {
  return request("resources/subscribe", "{\"uri\":" + detail::quote(uri) + "}");
}

Result<std::string> Session::unsubscribe_resource(std::string uri) const {
  return request("resources/unsubscribe", "{\"uri\":" + detail::quote(uri) + "}");
}

Result<std::string> Session::list_prompts() const {
  return request("prompts/list");
}

Result<TypedResponse<std::vector<Prompt>>> Session::list_prompts_typed() const {
  const auto id = next_id();
  auto raw = send_envelope_response("{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
                                    ",\"method\":\"prompts/list\",\"params\":{}}");
  if (!raw) {
    return Result<TypedResponse<std::vector<Prompt>>>::failure(raw.error());
  }
  auto parsed = detail::parse_json(raw.value().raw_json);
  if (!parsed) {
    return Result<TypedResponse<std::vector<Prompt>>>::failure(
        parse_error("Session::list_prompts_typed", raw.value().raw_json));
  }
  auto error = reject_jsonrpc_error(*parsed, "Session::list_prompts_typed", raw.value().raw_json);
  if (!error) {
    return Result<TypedResponse<std::vector<Prompt>>>::failure(error.error());
  }
  return Result<TypedResponse<std::vector<Prompt>>>::success(
      TypedResponse<std::vector<Prompt>>{parse_prompts(*parsed), raw.value().raw_json,
                                         std::move(raw.value().response)});
}

Result<std::string> Session::get_prompt(std::string name, std::string arguments_json) const {
  return request("prompts/get", "{\"name\":" + detail::quote(name) +
                                   ",\"arguments\":" + arguments_json + "}");
}

Result<std::string> Session::list_tasks() const {
  return request("tasks/list");
}

Result<TypedResponse<std::vector<Task>>> Session::list_tasks_typed() const {
  const auto id = next_id();
  auto raw = send_envelope_response("{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
                                    ",\"method\":\"tasks/list\",\"params\":{}}");
  if (!raw) {
    return Result<TypedResponse<std::vector<Task>>>::failure(raw.error());
  }
  auto parsed = detail::parse_json(raw.value().raw_json);
  if (!parsed) {
    return Result<TypedResponse<std::vector<Task>>>::failure(
        parse_error("Session::list_tasks_typed", raw.value().raw_json));
  }
  auto error = reject_jsonrpc_error(*parsed, "Session::list_tasks_typed", raw.value().raw_json);
  if (!error) {
    return Result<TypedResponse<std::vector<Task>>>::failure(error.error());
  }
  return Result<TypedResponse<std::vector<Task>>>::success(
      TypedResponse<std::vector<Task>>{parse_tasks(*parsed), raw.value().raw_json,
                                       std::move(raw.value().response)});
}

Result<std::string> Session::get_task(std::string task_id) const {
  return request("tasks/get", "{\"taskId\":" + detail::quote(task_id) + "}");
}

Result<std::string> Session::get_task_result(std::string task_id) const {
  return request("tasks/result", "{\"taskId\":" + detail::quote(task_id) + "}");
}

Result<std::string> Session::cancel_task(std::string task_id) const {
  return request("tasks/cancel", "{\"taskId\":" + detail::quote(task_id) + "}");
}

Result<HttpResponse> Session::close() const {
  if (!transport_) {
    return Result<HttpResponse>::failure(
        Error{ErrorCode::Transport, "missing HTTP transport", "Session::close"});
  }
  auto bearer_token = bearer_token_for_request("Session::close");
  if (!bearer_token) {
    return Result<HttpResponse>::failure(bearer_token.error());
  }
  HttpRequest request{
      "DELETE",
      base_url_ + "/mcp",
      {
          {"Authorization", "Bearer " + bearer_token.value()},
          {"MCP-Session-Id", session_id_},
      },
      "",
      timeout_,
  };
  return detail::send_with_policy(transport_, std::move(request), retry_policy_, trace_sink_,
                                  "Session::close");
}

void Session::on_message(MessageHandler handler) {
  message_handler_ = std::move(handler);
}

Result<std::thread> Session::start_receive_loop(
    MessageHandler handler,
    std::shared_ptr<CancellationToken> cancellation) const {
  auto transport = transport_;
  auto retry_policy = retry_policy_;
  auto trace_sink = trace_sink_;
  if (!transport) {
    return Result<std::thread>::failure(
        Error{ErrorCode::Transport, "missing HTTP transport", "Session::start_receive_loop"});
  }
  auto request_result = make_get_stream(std::move(cancellation));
  if (!request_result) {
    return Result<std::thread>::failure(request_result.error());
  }
  auto request = request_result.move_value();
  request.stream_message = [handler = std::move(handler)](const std::string& raw_json) {
    auto parsed = detail::parse_json(raw_json);
    if (!parsed) {
      return Result<void>::failure(
          Error{ErrorCode::Json, "failed to parse streamed JSON message",
                "Session::start_receive_loop", {}, detail::body_snippet(raw_json)});
    }
    return deliver_message(*parsed, handler, {});
  };
  return Result<std::thread>::success(
      std::thread([transport, retry_policy, trace_sink, request = std::move(request)]() mutable {
        (void)detail::send_with_policy(transport, std::move(request), retry_policy, trace_sink,
                                       "Session::start_receive_loop");
      }));
}

SessionInfo Session::info() const {
  return SessionInfo{session_id_, protocol_version_, {}, {}};
}

Result<void> Session::dispatch_messages(const std::string& body,
                                        MessageHandler handler) const {
  auto parsed = detail::parse_json(body);
  if (parsed) {
    auto delivered = deliver_message(*parsed, handler, message_handler_);
    if (!delivered) {
      return delivered;
    }
    const auto* messages = result_array(*parsed, "messages");
    if (messages != nullptr) {
      for (const auto& message : messages->as_array()) {
        delivered = deliver_message(message, handler, message_handler_);
        if (!delivered) {
          return delivered;
        }
      }
    }
    return Result<void>::success();
  }

  return detail::for_each_sse_event(body, [&](const std::string& payload) {
    auto event = detail::parse_json(payload);
    if (!event) {
      return Result<void>::failure(
          Error{ErrorCode::Json, "failed to parse JSON stream event",
                "Session::dispatch_messages", {}, detail::body_snippet(payload)});
    }
    auto delivered = deliver_message(*event, handler, message_handler_);
    if (!delivered) {
      return delivered;
    }
    return Result<void>::success();
  });
}

}  // namespace chio
