#include "hello_app.hpp"

#include <cassert>
#include <string>

namespace {

void assert_valid_echo() {
  Json::Value payload(Json::objectValue);
  payload["message"] = "hello";
  payload["count"] = 2;

  const auto result = hello_drogon::echo_body(&payload, "receipt-1");
  assert(result.status == drogon::k200OK);
  assert(result.body["message"].asString() == "hello");
  assert(result.body["count"].asInt() == 2);
  assert(result.body["receipt_id"].asString() == "receipt-1");
  assert(result.body["handled_by"].asString() == "drogon");
}

void assert_default_count() {
  Json::Value payload(Json::objectValue);
  payload["message"] = "hello";

  const auto result = hello_drogon::echo_body(&payload, "receipt-2");
  assert(result.status == drogon::k200OK);
  assert(result.body["count"].asInt() == 1);
}

void assert_invalid_echo(Json::Value payload, const std::string& expected_message) {
  const auto result = hello_drogon::echo_body(&payload, "receipt-3");
  assert(result.status == drogon::k400BadRequest);
  assert(result.body["error"].asString() == "invalid_echo_request");
  assert(result.body["message"].asString() == expected_message);
}

}  // namespace

int main() {
  assert(hello_drogon::health_body()["status"].asString() == "ok");
  assert(hello_drogon::hello_body("receipt-0")["message"].asString() == "hello from drogon");
  assert_valid_echo();
  assert_default_count();

  Json::Value blank_message(Json::objectValue);
  blank_message["message"] = "   ";
  assert_invalid_echo(blank_message,
                      "message must contain at least one non-whitespace character");

  Json::Value zero_count(Json::objectValue);
  zero_count["message"] = "hello";
  zero_count["count"] = 0;
  assert_invalid_echo(zero_count, "count must be greater than or equal to 1");

  Json::Value array_payload(Json::arrayValue);
  assert_invalid_echo(array_payload, "expected JSON object body");

  return 0;
}
