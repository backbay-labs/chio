#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "chio/auth.hpp"
#include "chio/models.hpp"
#include "chio/result.hpp"
#include "chio/transport.hpp"

namespace chio {

struct JsonMessage {
  std::string raw_json;
  std::string method;
  std::string id;
  std::string id_json;
};

using MessageHandler = std::function<Result<void>(const JsonMessage&)>;
using SamplingHandler = std::function<Result<std::string>(const JsonMessage&)>;
using ElicitationHandler = std::function<Result<std::string>(const JsonMessage&)>;
using RootsHandler = std::function<Result<std::string>(const JsonMessage&)>;

class Session;
class ToolClient;

class NestedCallbackRouter {
 public:
  NestedCallbackRouter& on_sampling(SamplingHandler handler);
  NestedCallbackRouter& on_elicitation(ElicitationHandler handler);
  NestedCallbackRouter& on_roots(RootsHandler handler);

  MessageHandler bind(Session& session) const;

  static std::string sampling_text_result(const JsonMessage& message,
                                          std::string text,
                                          std::string model = "chio-cpp-model",
                                          std::string stop_reason = "end_turn");
  static std::string elicitation_accept_result(const JsonMessage& message,
                                               std::string content_json = "{}");
  static std::string roots_list_result(const JsonMessage& message,
                                       std::string roots_json);

 private:
  SamplingHandler sampling_handler_;
  ElicitationHandler elicitation_handler_;
  RootsHandler roots_handler_;
};

class Session {
  friend class NestedCallbackRouter;
  friend class ToolClient;

 public:
  Session(std::string base_url,
          std::string bearer_token,
          std::string session_id,
          std::string protocol_version,
          HttpTransportPtr transport,
          RetryPolicy retry_policy = {},
          TraceSinkPtr trace_sink = {},
          std::chrono::milliseconds timeout = std::chrono::milliseconds(30000),
          TokenProviderPtr token_provider = {});

  Session(Session&& other) noexcept;
  Session& operator=(Session&& other) noexcept;

  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  Result<std::string> send_envelope(std::string body_json) const;
  Result<TypedResponse<std::string>> send_envelope_response(std::string body_json) const;
  Result<std::string> request(std::string method, std::string params_json = "{}") const;
  Result<std::string> request_streaming(std::string method,
                                        std::string params_json,
                                        MessageHandler handler) const;
  Result<std::string> notification(std::string method, std::string params_json = "{}") const;

  Result<std::string> list_tools() const;
  Result<TypedResponse<std::vector<Tool>>> list_tools_typed() const;
  Result<std::string> call_tool(std::string name, std::string arguments_json = "{}") const;
  Result<std::string> call_tool(std::string name,
                                std::string arguments_json,
                                MessageHandler handler) const;
  Result<std::string> list_resources() const;
  Result<TypedResponse<std::vector<Resource>>> list_resources_typed() const;
  Result<std::string> read_resource(std::string uri) const;
  Result<std::string> subscribe_resource(std::string uri) const;
  Result<std::string> unsubscribe_resource(std::string uri) const;
  Result<std::string> list_prompts() const;
  Result<TypedResponse<std::vector<Prompt>>> list_prompts_typed() const;
  Result<std::string> get_prompt(std::string name, std::string arguments_json = "{}") const;
  Result<std::string> list_tasks() const;
  Result<TypedResponse<std::vector<Task>>> list_tasks_typed() const;
  Result<std::string> get_task(std::string task_id) const;
  Result<std::string> get_task_result(std::string task_id) const;
  Result<std::string> cancel_task(std::string task_id) const;
  Result<HttpResponse> close() const;

  void on_message(MessageHandler handler);
  Result<std::thread> start_receive_loop(MessageHandler handler,
                                         std::shared_ptr<CancellationToken> cancellation) const;

  const std::string& session_id() const { return session_id_; }
  const std::string& protocol_version() const { return protocol_version_; }
  SessionInfo info() const;

 private:
  Result<HttpRequest> make_post(std::string body_json, bool stream_response = false) const;
  Result<HttpRequest> make_get_stream(std::shared_ptr<CancellationToken> cancellation) const;
  std::int64_t next_id() const;
  Result<void> dispatch_messages(const std::string& body, MessageHandler handler) const;
  Result<std::string> bearer_token_for_request(std::string operation) const;
  std::function<Result<std::string>(std::string)> envelope_sender() const;

  std::string base_url_;
  std::string bearer_token_;
  TokenProviderPtr token_provider_;
  std::string session_id_;
  std::string protocol_version_;
  HttpTransportPtr transport_;
  RetryPolicy retry_policy_;
  TraceSinkPtr trace_sink_;
  std::chrono::milliseconds timeout_;
  mutable MessageHandler message_handler_;
  mutable std::atomic<std::int64_t> next_request_id_{2};
};

}  // namespace chio
