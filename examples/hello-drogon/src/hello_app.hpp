#pragma once

#include <string>

#include <drogon/drogon.h>
#include <json/json.h>

namespace hello_drogon {

struct EchoContractResult {
  drogon::HttpStatusCode status;
  Json::Value body;
};

std::string env_or_default(const char* name, const char* fallback);
Json::Value health_body();
Json::Value hello_body(const std::string& receipt_id);
EchoContractResult echo_body(const Json::Value* payload, const std::string& receipt_id);
drogon::HttpResponsePtr json_response(const Json::Value& body,
                                      drogon::HttpStatusCode status = drogon::k200OK);
void configure_chio_from_env();
void register_routes();
unsigned short port_from_env();

}  // namespace hello_drogon
