#include "hello_app.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <functional>
#include <utility>

#include "chio/drogon.hpp"

namespace hello_drogon {
namespace {

bool is_blank(const std::string& value) {
  return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
    return std::isspace(ch) != 0;
  });
}

Json::Value base_body(const std::string& receipt_id) {
  Json::Value body(Json::objectValue);
  body["receipt_id"] = receipt_id;
  body["handled_by"] = "drogon";
  return body;
}

EchoContractResult invalid_echo_request(const std::string& message) {
  Json::Value body(Json::objectValue);
  body["error"] = "invalid_echo_request";
  body["message"] = message;
  return {drogon::k400BadRequest, std::move(body)};
}

}  // namespace

std::string env_or_default(const char* name, const char* fallback) {
  const char* value = std::getenv(name);
  if (value == nullptr || std::string(value).empty()) {
    return fallback;
  }
  return value;
}

Json::Value health_body() {
  Json::Value body(Json::objectValue);
  body["status"] = "ok";
  return body;
}

Json::Value hello_body(const std::string& receipt_id) {
  Json::Value body = base_body(receipt_id);
  body["message"] = "hello from drogon";
  return body;
}

EchoContractResult echo_body(const Json::Value* payload, const std::string& receipt_id) {
  if (payload == nullptr || !payload->isObject()) {
    return invalid_echo_request("expected JSON object body");
  }

  const auto& message = (*payload)["message"];
  if (!message.isString() || message.asString().empty() || is_blank(message.asString())) {
    return invalid_echo_request("message must contain at least one non-whitespace character");
  }

  int count = 1;
  if (payload->isMember("count")) {
    const auto& count_value = (*payload)["count"];
    if (!count_value.isInt() || count_value.asInt() < 1) {
      return invalid_echo_request("count must be greater than or equal to 1");
    }
    count = count_value.asInt();
  }

  Json::Value body = base_body(receipt_id);
  body["message"] = message.asString();
  body["count"] = count;
  return {drogon::k200OK, std::move(body)};
}

drogon::HttpResponsePtr json_response(const Json::Value& body,
                                      drogon::HttpStatusCode status) {
  auto response = drogon::HttpResponse::newHttpJsonResponse(body);
  response->setContentTypeCode(drogon::CT_APPLICATION_JSON);
  response->setStatusCode(status);
  return response;
}

void configure_chio_from_env() {
  chio::drogon::Options options;
  options.sidecar_url = env_or_default("CHIO_SIDECAR_URL", "http://127.0.0.1:9090");
  options.sidecar_failure_mode = chio::drogon::SidecarFailureMode::FailClosed;
  chio::drogon::configure(std::move(options));
}

void register_routes() {
  drogon::app().registerHandler(
      "/healthz",
      [](const drogon::HttpRequestPtr&,
         std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
        callback(json_response(health_body()));
      },
      {drogon::Get});

  drogon::app().registerHandler(
      "/hello",
      [](const drogon::HttpRequestPtr& request,
         std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
        callback(json_response(hello_body(chio::drogon::receipt_id(request))));
      },
      {drogon::Get, "chio::drogon::ChioMiddleware"});

  drogon::app().registerHandler(
      "/echo",
      [](const drogon::HttpRequestPtr& request,
         std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
        const auto payload = request->getJsonObject();
        const auto result = echo_body(payload.get(), chio::drogon::receipt_id(request));
        callback(json_response(result.body, result.status));
      },
      {drogon::Post, "chio::drogon::ChioMiddleware"});
}

unsigned short port_from_env() {
  return static_cast<unsigned short>(std::stoi(env_or_default("HELLO_DROGON_PORT", "8020")));
}

}  // namespace hello_drogon
