#include "chio/kernel.hpp"

#include <cassert>
#include <string>

#include "../src/json_field.hpp"
#include "../src/kernel_request_json.hpp"

int main() {
  chio::kernel::Kernel kernel;

  assert(std::string(chio::kernel::Kernel::version()) == "0.1.0");
  assert(kernel.options().kernel_id == "chio-cpp-kernel");
  assert(!kernel.options().default_now_secs.has_value());

  {
    chio::kernel::EvaluateRequest request;
    auto result = kernel.evaluate(request);
    assert(!result.ok);
    assert(result.verdict == "deny");
    assert(result.error_code == "invalid_argument");
    assert(result.result_json.find("\"ok\":false") != std::string::npos);
    assert(result.result_json.find("\"verdict\":\"deny\"") != std::string::npos);
  }

  {
    auto escaped = chio::kernel::detail::json_string_field(
        "{\"reason\":\"line\\nslash\\\\tab\\tunicode\\u0041\"}", "reason");
    assert(escaped.has_value());
    assert(*escaped == "line\nslash\\tab\tunicodeA");
    auto unicode_line = chio::kernel::detail::json_string_field(
        "{\"reason\":\"line\\u000Abreak\"}", "reason");
    assert(unicode_line.has_value());
    assert(*unicode_line == "line\nbreak");
    auto surrogate_pair = chio::kernel::detail::json_string_field(
        "{\"reason\":\"face \\uD83D\\uDE00\"}", "reason");
    assert(surrogate_pair.has_value());
    assert(*surrogate_pair == std::string("face \xF0\x9F\x98\x80"));
    assert(!chio::kernel::detail::json_string_field("{\"reason\":\"\\uZZZZ\"}", "reason"));
    assert(!chio::kernel::detail::json_string_field("{\"reason\":\"\\uD83D\"}", "reason"));
    assert(!chio::kernel::detail::json_string_field("{\"reason\":\"\\uDE00\"}", "reason"));
    assert(!chio::kernel::detail::json_string_field("{\"reason\":\"\\q\"}", "reason"));
    assert(!chio::kernel::detail::json_string_field(
        std::string("{\"reason\":\"line\nbreak\"}"), "reason"));
    auto real = chio::kernel::detail::json_string_field(
        "{\"message\":\"\\\"reason\\\":\\\"fake\\\"\",\"reason\":\"real\"}", "reason");
    assert(real.has_value());
    assert(*real == "real");
    assert(!chio::kernel::detail::json_string_field(
        "{\"message\":\"\\\"reason\\\":\\\"fake\\\"\"}", "reason"));
    assert(!chio::kernel::detail::json_string_field(
        "{\"ignored\":tru e,\"reason\":\"wrong\"}", "reason"));
    assert(!chio::kernel::detail::json_string_field(
        "{\"ignored\":@#$,\"reason\":\"wrong\"}", "reason"));
    assert(!chio::kernel::detail::json_string_field(
        "{\"ignored\":{\"bad\":tru e},\"reason\":\"wrong\"}", "reason"));
    assert(!chio::kernel::detail::json_string_field(
        "{\"ignored\":[true false],\"reason\":\"wrong\"}", "reason"));
    auto after_non_string_match = chio::kernel::detail::json_string_field(
        "{\"verdict\":123,\"reason\":\"kept\"}", "reason");
    assert(after_non_string_match.has_value());
    assert(*after_non_string_match == "kept");
    auto duplicate_string_match = chio::kernel::detail::json_string_field(
        "{\"verdict\":123,\"verdict\":\"allow\"}", "verdict");
    assert(duplicate_string_match.has_value());
    assert(*duplicate_string_match == "allow");
    assert(!chio::kernel::detail::json_string_field(
        "{\"verdict\":tru e,\"reason\":\"wrong\"}", "verdict"));

    auto matched_grant_index = chio::kernel::detail::json_uint_field(
        "{\"verdict\":\"allow\",\"matched_grant_index\":0}", "matched_grant_index");
    assert(matched_grant_index.has_value());
    assert(*matched_grant_index == 0);
    auto later_uint_match = chio::kernel::detail::json_uint_field(
        "{\"matched_grant_index\":\"bad\",\"matched_grant_index\":42}", "matched_grant_index");
    assert(later_uint_match.has_value());
    assert(*later_uint_match == 42);
    assert(!chio::kernel::detail::json_uint_field(
        "{\"matched_grant_index\":-1}", "matched_grant_index"));
    assert(!chio::kernel::detail::json_uint_field(
        "{\"matched_grant_index\":1.0}", "matched_grant_index"));
    assert(!chio::kernel::detail::json_uint_field(
        "{\"matched_grant_index\":01}", "matched_grant_index"));
    assert(!chio::kernel::detail::json_uint_field(
        "{\"matched_grant_index\":18446744073709551616}", "matched_grant_index"));

    std::size_t number_pos = 0;
    assert(!chio::kernel::detail::skip_json_number("-", number_pos));
    assert(number_pos == 0);
    assert(!chio::kernel::detail::skip_json_number("-x", number_pos));
    assert(number_pos == 0);
    assert(!chio::kernel::detail::skip_json_number("1.", number_pos));
    assert(number_pos == 0);
    assert(!chio::kernel::detail::skip_json_number("1e", number_pos));
    assert(number_pos == 0);
    assert(!chio::kernel::detail::skip_json_number("01", number_pos));
    assert(number_pos == 0);
    assert(chio::kernel::detail::skip_json_number("-12.34e+5", number_pos));
    assert(number_pos == 9);
  }

  {
    chio::kernel::KernelOptions options;
    options.default_now_secs = 77;
    chio::kernel::EvaluateRequest request;
    request.request_json = "{\"request_id\":\"req-epoch\",\"tool_name\":\"echo\"}";
    request.capability_json = "{\"id\":\"cap-epoch\"}";
    request.trusted_issuers_hex.push_back("00");

    request.now_secs = 0;
    auto explicit_epoch =
        chio::kernel::detail::build_kernel_request_json(options, request);
    assert(explicit_epoch.find("\"now_secs\":0") != std::string::npos);
    assert(explicit_epoch.find("\"now_secs\":77") == std::string::npos);

    request.now_secs.reset();
    auto default_time =
        chio::kernel::detail::build_kernel_request_json(options, request);
    assert(default_time.find("\"now_secs\":77") != std::string::npos);

    options.default_now_secs.reset();
    auto system_time =
        chio::kernel::detail::build_kernel_request_json(options, request);
    assert(system_time.find("\"now_secs\"") == std::string::npos);
  }

  {
    chio::kernel::EvaluateRequest request;
    request.request_json = "{\"request_id\":\"req-1\",\"tool_name\":\"echo\"}";
    request.capability_json = "{\"id\":\"cap-1\"}";
    request.trusted_issuers_hex.push_back("00");

    auto first = kernel.evaluate(request);
    auto second = kernel.evaluate(request);
    assert(!first.ok);
    assert(first.verdict == "deny");
    if (chio::kernel::Kernel::ffi_enabled()) {
      assert(first.error_code == "invalid_json");
    } else {
      assert(first.error_code == "unsupported");
    }
    assert(first.result_json == second.result_json);
  }

  {
    chio::kernel::KernelOptions options;
    options.policy_json = "{\"guards\":[]}";
    chio::kernel::Kernel policy_kernel(options);
    chio::kernel::EvaluateRequest request;
    request.request_json = "{\"request_id\":\"req-policy\",\"tool_name\":\"echo\"}";
    request.capability_json = "{\"id\":\"cap-policy\"}";
    request.trusted_issuers_hex.push_back("00");

    auto result = policy_kernel.evaluate(request);
    assert(!result.ok);
    assert(result.verdict == "deny");
    assert(result.error_code == "unsupported_policy");
    assert(result.error_message.find("policy_json") != std::string::npos);
  }

  return 0;
}
