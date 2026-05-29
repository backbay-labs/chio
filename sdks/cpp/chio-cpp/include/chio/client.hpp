#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <string>

#include "chio/auth.hpp"
#include "chio/result.hpp"
#include "chio/session.hpp"
#include "chio/transport.hpp"

namespace chio {

using InitializeMessageHandler = std::function<Result<void>(Session&, const JsonMessage&)>;

class SessionPool;

struct ClientOptions {
  std::string base_url;
  std::string bearer_token;
  std::string client_name = "chio-cpp";
  std::string client_version = "0.1.0";
  std::string protocol_version = "2025-11-25";
  std::string client_capabilities_json = "{}";
  std::chrono::milliseconds timeout{30000};
  RetryPolicy retry_policy;
  TokenProviderPtr token_provider;
  InitializeMessageHandler initialize_message_handler;
};

class Client {
 public:
  Client(ClientOptions options, HttpTransportPtr transport, TraceSinkPtr trace_sink = {});

  static Client with_static_bearer(std::string base_url,
                                   std::string bearer_token,
                                   HttpTransportPtr transport);

  Result<Session> initialize() const;
  const ClientOptions& options() const { return options_; }

 private:
  friend class SessionPool;

  ClientOptions options_;
  HttpTransportPtr transport_;
  TraceSinkPtr trace_sink_;
};

class ClientBuilder {
 public:
  ClientBuilder& base_url(std::string value);
  ClientBuilder& bearer_token(std::string value);
  ClientBuilder& token_provider(TokenProviderPtr value);
  ClientBuilder& transport(HttpTransportPtr value);
  ClientBuilder& trace_sink(TraceSinkPtr value);
  ClientBuilder& timeout(std::chrono::milliseconds value);
  ClientBuilder& retry_policy(RetryPolicy value);
  ClientBuilder& client_info(std::string name, std::string version);
  ClientBuilder& protocol_version(std::string value);
  ClientBuilder& client_capabilities_json(std::string value);
  ClientBuilder& initialize_message_handler(InitializeMessageHandler value);

  Result<Client> build() const;

 private:
  ClientOptions options_;
  HttpTransportPtr transport_;
  TraceSinkPtr trace_sink_;
};

}  // namespace chio
