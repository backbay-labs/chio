#include "chio/chio.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "../src/auth_encoding.hpp"
#include "../src/json.hpp"
#include "../src/curl_sse.hpp"
#include "../src/transport_util.hpp"

namespace {

class FakeTransport final : public chio::HttpTransport {
 public:
  explicit FakeTransport(std::vector<chio::HttpResponse> responses)
      : responses_(std::move(responses)) {}

  chio::Result<chio::HttpResponse> send(const chio::HttpRequest& request) override {
    requests.push_back(request);
    if (responses_.empty()) {
      return chio::Result<chio::HttpResponse>::failure(
          chio::Error{chio::ErrorCode::Transport, "no fake response queued"});
    }
    auto response = std::move(responses_.front());
    responses_.erase(responses_.begin());
    return chio::Result<chio::HttpResponse>::success(std::move(response));
  }

  std::vector<chio::HttpRequest> requests;

 private:
  std::vector<chio::HttpResponse> responses_;
};

class StreamingFakeTransport final : public chio::HttpTransport {
 public:
  chio::Result<chio::HttpResponse> send(const chio::HttpRequest& request) override {
    requests.push_back(request);
    const auto id_json = chio::detail::request_id_json(request.body);
    const std::string payload =
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}";
    const std::string terminal =
        "{\"jsonrpc\":\"2.0\",\"id\":" + id_json + ",\"result\":{\"ok\":true}}";
    if (request.stream_message) {
      auto delivered = request.stream_message(payload);
      if (!delivered) {
        return chio::Result<chio::HttpResponse>::failure(delivered.error());
      }
      delivered = request.stream_message(terminal);
      if (!delivered) {
        return chio::Result<chio::HttpResponse>::failure(delivered.error());
      }
    }
    return chio::Result<chio::HttpResponse>::success(
        chio::HttpResponse{200, {}, "data: " + payload + "\n\ndata: " + terminal + "\n\n"});
  }

  std::vector<chio::HttpRequest> requests;
};

class IncompleteStreamingFakeTransport final : public chio::HttpTransport {
 public:
  chio::Result<chio::HttpResponse> send(const chio::HttpRequest& request) override {
    requests.push_back(request);
    const std::string payload =
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}";
    if (request.stream_message) {
      auto delivered = request.stream_message(payload);
      if (!delivered) {
        return chio::Result<chio::HttpResponse>::failure(delivered.error());
      }
    }
    return chio::Result<chio::HttpResponse>::success(
        chio::HttpResponse{200, {}, "data: " + payload + "\n\n"});
  }

  std::vector<chio::HttpRequest> requests;
};

class FailingTransport final : public chio::HttpTransport {
 public:
  explicit FailingTransport(chio::Error error) : error_(std::move(error)) {}

  chio::Result<chio::HttpResponse> send(const chio::HttpRequest&) override {
    ++calls;
    return chio::Result<chio::HttpResponse>::failure(error_);
  }

  int calls = 0;

 private:
  chio::Error error_;
};

void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

void require_eq(const std::string& actual,
                const std::string& expected,
                const std::string& label) {
  if (actual != expected) {
    throw std::runtime_error(label + ": expected [" + expected + "], got [" + actual + "]");
  }
}

void require_contains(const std::string& haystack,
                      const std::string& needle,
                      const std::string& label) {
  if (haystack.find(needle) == std::string::npos) {
    throw std::runtime_error(label + ": missing [" + needle + "]");
  }
}

void require_no_header(const std::map<std::string, std::string>& headers,
                       const std::string& name,
                       const std::string& label) {
  if (headers.find(name) != headers.end()) {
    throw std::runtime_error(label + ": unexpected header [" + name + "]");
  }
}

std::string initialize_ok_response_json(const std::string& protocol = "2025-11-25",
                                        const std::string& id_json = "1") {
  return "{\"jsonrpc\":\"2.0\",\"id\":" + id_json +
         ",\"result\":{\"protocolVersion\":\"" + protocol + "\"}}";
}

std::string read_file(const std::string& relative_path) {
  const std::string path = std::string(CHIO_CPP_REPO_ROOT) + "/" + relative_path;
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("failed to open " + path);
  }
  return std::string((std::istreambuf_iterator<char>(input)),
                     std::istreambuf_iterator<char>());
}

std::pair<std::string, std::string> allow_receipt_fixture() {
  const auto receipt_vectors = read_file("tests/bindings/vectors/receipt/v1.json");
  auto parsed = chio::detail::parse_json(receipt_vectors);
  require(parsed.has_value(), "expected receipt vectors to parse");
  const auto* cases = parsed->get("cases");
  require(cases != nullptr && cases->is_array(), "expected receipt vector cases");
  for (const auto& test_case : cases->as_array()) {
    if (test_case.string_field("id") != "allow_receipt") {
      continue;
    }
    const auto* receipt = test_case.get("receipt");
    require(receipt != nullptr && receipt->is_object(), "expected allow receipt object");
    auto signer = receipt->string_field("kernel_key");
    require(!signer.empty(), "expected allow receipt kernel key");
    return {receipt->dump(), std::move(signer)};
  }
  throw std::runtime_error("missing allow_receipt fixture");
}

void test_invariants_from_shared_vectors() {
  require(chio::invariants::ffi_abi_version() == 1, "expected ABI version 1");
  const auto build_info = chio::invariants::ffi_build_info();
  require(build_info.ok(), build_info.error().message);
  require_contains(build_info.value(), "\"abi_version\":1", "ffi build info");

  const auto canonical_vectors = read_file("tests/bindings/vectors/canonical/v1.json");
  require_contains(canonical_vectors, "object_key_sorting", "canonical vectors");
  const auto canonical = chio::invariants::canonicalize_json("{\"z\":1,\"a\":2,\"m\":3}");
  require(canonical.ok(), canonical.error().message);
  require_eq(canonical.value(), "{\"a\":2,\"m\":3,\"z\":1}", "canonical json");

  const auto canonical_controls =
      chio::invariants::canonicalize_json("\"\\u007f\\u009f\"");
  require(canonical_controls.ok(), canonical_controls.error().message);
  const std::string controls = "\x7f\xc2\x9f";
  require_eq(canonical_controls.value(),
             "\"" + controls + "\"",
             "canonical control string");

  const auto canonical_control_key = chio::invariants::canonicalize_json(
      "{\"\\u007f\\u009f\":\"\\u007f\\u009f\"}");
  require(canonical_control_key.ok(), canonical_control_key.error().message);
  require_eq(canonical_control_key.value(),
             "{\"" + controls + "\":\"" + controls + "\"}",
             "canonical control object key");

  const auto hashing_vectors = read_file("tests/bindings/vectors/hashing/v1.json");
  require_contains(hashing_vectors, "hello_utf8", "hashing vectors");
  const auto hash = chio::invariants::sha256_hex_utf8("hello");
  require(hash.ok(), hash.error().message);
  require_eq(hash.value(),
             "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
             "sha256 hello");

  const auto signing_vectors = read_file("tests/bindings/vectors/signing/v1.json");
  require_contains(signing_vectors, "valid_utf8_message", "signing vectors");
  const auto verified = chio::invariants::verify_utf8_message_ed25519(
      "hello chio",
      "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
      "4b134ccad3c684ef462bf085ea2e87c416557980e01da869703d18016f3811a0f0310f38075e2019480f8c1abc06c7d823ef1776eb95687785e5eacdbe57250c");
  require(verified.ok(), verified.error().message);
  require(verified.value(), "expected vector signature to verify");

  const auto receipt_vectors = read_file("tests/bindings/vectors/receipt/v1.json");
  require_contains(receipt_vectors, "allow_receipt", "receipt vectors");
  const auto allow_receipt = allow_receipt_fixture();
  const auto trusted_receipt =
      chio::invariants::verify_receipt_json_with_trusted_signers(
          allow_receipt.first,
          std::vector<std::string>{allow_receipt.second});
  require(trusted_receipt.ok(), trusted_receipt.error().message);
  require_contains(trusted_receipt.value(),
                   "\"signer_trusted\":true",
                   "trusted receipt verification");
  require_contains(trusted_receipt.value(),
                   "\"authorized\":true",
                   "trusted receipt verification");
}

void test_private_json_helpers_are_strict() {
  const auto extracted = chio::detail::extract_json_string_field(
      "{\"value\":\"line\\nslash\\\\tab\\tquote\\\"\"}", "value");
  require_eq(extracted,
             std::string("line\nslash\\tab\tquote\""),
             "json string escape extraction");
  const auto unicode_extracted = chio::detail::extract_json_string_field(
      "{\"value\":\"\\u0041\\u000Aface \\uD83D\\uDE00\"}", "value");
  require_eq(unicode_extracted,
             std::string("A\nface \xF0\x9F\x98\x80"),
             "json unicode escape extraction");
  const auto escaped_key_extracted = chio::detail::extract_json_string_field(
      "{\"\\u0069d\":\"cap-1\"}", "id");
  require_eq(escaped_key_extracted, "cap-1", "json escaped key extraction");
  require_eq(chio::detail::extract_json_string_field(
                 "{\"a\":\"id\",\"b\":\"wrong\"}", "id"),
             "",
             "json field extractor ignores string values");
  auto unicode_parsed = chio::detail::parse_json("{\"id\":\"\\u0041\"}");
  require(unicode_parsed.has_value(), "expected unicode escaped json to parse");
  require_eq(unicode_parsed->string_field("id"), "A", "unicode parsed value");
  require_eq(unicode_parsed->dump(), "{\"id\":\"A\"}", "unicode json dump");

  require(!chio::detail::parse_json("{\"n\":-}"), "expected bare minus to fail");
  require(!chio::detail::parse_json("{\"n\":1.}"), "expected missing fraction to fail");
  require(!chio::detail::parse_json("{\"n\":1e}"), "expected missing exponent to fail");
  require(!chio::detail::parse_json("{\"n\":01}"), "expected leading zero to fail");
  require(!chio::detail::parse_json("{\"s\":\"\\uZZZZ\"}"),
          "expected non-hex unicode escape to fail");
  require(!chio::detail::parse_json("{\"s\":\"\\uD83D\"}"),
          "expected lone high surrogate to fail");
  require(!chio::detail::parse_json("{\"s\":\"\\uDE00\"}"),
          "expected lone low surrogate to fail");
  require(chio::detail::extract_json_string_field("{\"s\":\"\\uZZZZ\"}", "s").empty(),
          "expected non-hex unicode extraction to fail");
  require(!chio::detail::parse_json(std::string("{\"s\":\"line\nbreak\"}")),
          "expected raw control character to fail");
  require(chio::detail::extract_json_string_field(
              std::string("{\"s\":\"line\nbreak\"}"), "s").empty(),
          "expected raw control extraction to fail");

  std::string escaped_control;
  escaped_control.push_back('\x01');
  escaped_control += "42";
  require_eq(chio::detail::escape_json(escaped_control),
             "\\u000142",
             "control character json escaping");
}

void test_curl_sse_helpers_abort_after_terminal_message() {
  chio::detail::CurlBodyCapture capture;
  capture.id_json = "7";
  int delivered_count = 0;
  capture.stream_message = [&delivered_count](const std::string& payload) {
    ++delivered_count;
    require_contains(payload, "\"id\":7", "terminal payload");
    return chio::Result<void>::success();
  };

  std::string terminal =
      "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}\n\n";
  const auto returned =
      chio::detail::write_curl_body(&terminal[0], 1, terminal.size(), &capture);
  require(returned == 0, "expected curl write callback to abort after terminal SSE");
  require(capture.complete, "expected terminal SSE to mark capture complete");
  require(!capture.callback_failed, "expected terminal SSE not to be a callback failure");
  require(delivered_count == 1, "expected terminal SSE to be delivered once");

  chio::detail::CurlBodyCapture non_streaming;
  non_streaming.id_json = "7";
  std::string json = "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n";
  const auto json_returned =
      chio::detail::write_curl_body(&json[0], 1, json.size(), &non_streaming);
  require(json_returned == json.size(), "expected non-streaming body to keep reading");
  require(!non_streaming.complete, "expected non-streaming body to avoid repeated full parses");

  chio::detail::CurlBodyCapture anchored;
  int anchored_count = 0;
  anchored.stream_message = [&anchored_count](const std::string& payload) {
    ++anchored_count;
    require_contains(payload, "notifications/tools/list_changed", "anchored SSE payload");
    return chio::Result<void>::success();
  };
  std::string metadata = "event: metadata: not-a-data-field\n";
  const auto metadata_returned =
      chio::detail::write_curl_body(&metadata[0], 1, metadata.size(), &anchored);
  require(metadata_returned == metadata.size(), "expected metadata line to keep reading");
  require(anchored_count == 0, "expected non-data SSE field not to dispatch");
  std::string notification =
      "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n";
  const auto notification_returned =
      chio::detail::write_curl_body(&notification[0], 1, notification.size(), &anchored);
  require(notification_returned == notification.size(), "expected notification stream to continue");
  require(anchored_count == 1, "expected line-start data field to dispatch once");

  chio::detail::CurlBodyCapture multiline;
  int multiline_count = 0;
  multiline.stream_message = [&multiline_count](const std::string& payload) {
    ++multiline_count;
    require_contains(payload, "\"method\"", "multiline SSE payload");
    auto parsed = chio::detail::parse_json(payload);
    require(parsed.has_value(), "expected multiline SSE payload to parse");
    return chio::Result<void>::success();
  };
  std::string partial_multiline =
      "data: {\"jsonrpc\":\"2.0\",\n"
      "data: \"method\":\"notifications/tools/list_changed\"}\n";
  const auto partial_multiline_returned =
      chio::detail::write_curl_body(&partial_multiline[0], 1, partial_multiline.size(), &multiline);
  require(partial_multiline_returned == partial_multiline.size(),
          "expected incomplete multiline event to keep reading");
  require(multiline_count == 0, "expected multiline SSE to wait for event delimiter");
  std::string multiline_delimiter = "\n";
  const auto multiline_delimiter_returned =
      chio::detail::write_curl_body(&multiline_delimiter[0],
                                    1,
                                    multiline_delimiter.size(),
                                    &multiline);
  require(multiline_delimiter_returned == multiline_delimiter.size(),
          "expected multiline event delimiter to keep reading");
  require(multiline_count == 1, "expected multiline SSE event to dispatch once");

  chio::detail::CurlBodyCapture long_stream;
  int long_stream_count = 0;
  long_stream.stream_message = [&long_stream_count](const std::string&) {
    ++long_stream_count;
    return chio::Result<void>::success();
  };
  for (int i = 0; i < 300; ++i) {
    std::string event =
        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"i\":" +
        std::to_string(i) + "}}\n\n";
    const auto event_returned =
        chio::detail::write_curl_body(&event[0], 1, event.size(), &long_stream);
    require(event_returned == event.size(), "expected long stream to continue");
  }
  require(long_stream_count == 300, "expected every long stream event to dispatch");
  require(long_stream.scan_buffer.size() < chio::detail::kSseCompactThreshold + 1024,
          "expected processed SSE bytes to be compacted");
  require(long_stream.body.size() > chio::detail::kSseCompactThreshold,
          "expected compacted SSE response body to stay intact");

  chio::detail::CurlBodyCapture large_text;
  std::string full_text;
  for (int i = 0; i < 300; ++i) {
    full_text += "{\"line\":" + std::to_string(i) + "}\n";
  }
  const auto large_returned =
      chio::detail::write_curl_body(&full_text[0], 1, full_text.size(), &large_text);
  require(large_returned == full_text.size(), "expected large text response to keep reading");
  require_eq(large_text.body, full_text, "large text response body");
  require(large_text.scan_buffer.size() < chio::detail::kSseCompactThreshold + 1024,
          "expected large text scan buffer to compact independently");
}

void test_transport_policy_respects_retryable_flag() {
  chio::RetryPolicy policy;
  policy.max_attempts = 3;
  policy.initial_backoff = std::chrono::milliseconds(0);
  policy.max_backoff = std::chrono::milliseconds(0);

  chio::HttpRequest request{"POST", "http://127.0.0.1/mcp", {}, "{}"};
  auto hard = std::make_shared<FailingTransport>(
      chio::Error{chio::ErrorCode::Transport, "hard failure", "", {}, {}, {}, {}, false});
  auto hard_result = chio::detail::send_with_policy(
      hard, request, policy, {}, "test_transport_policy_respects_retryable_flag");
  require(!hard_result.ok(), "expected hard transport failure");
  require(hard->calls == 1, "expected non-retryable error to stop after one attempt");
  require(!hard_result.error().retryable, "expected non-retryable flag to be preserved");

  auto transient = std::make_shared<FailingTransport>(
      chio::Error{chio::ErrorCode::Transport, "transient failure", "", {}, {}, {}, {}, true});
  auto transient_result = chio::detail::send_with_policy(
      transient, request, policy, {}, "test_transport_policy_respects_retryable_flag");
  require(!transient_result.ok(), "expected retryable transport failure");
  require(transient->calls == 3, "expected retryable error to use all attempts");
  require(transient_result.error().retryable, "expected retryable flag to be preserved");
}

class FixedClock final : public chio::Clock {
 public:
  std::uint64_t now_unix_secs() const override { return 1700000000; }
};

class FixedNonceGenerator final : public chio::NonceGenerator {
 public:
  chio::Result<std::string> generate_nonce() override {
    return chio::Result<std::string>::success("fixed-nonce");
  }
};

class RotatingTokenProvider final : public chio::TokenProvider {
 public:
  explicit RotatingTokenProvider(std::vector<std::string> tokens)
      : tokens_(std::move(tokens)) {}

  chio::Result<std::string> access_token() override {
    if (next_ >= tokens_.size()) {
      return chio::Result<std::string>::failure(
          chio::Error{chio::ErrorCode::Protocol, "no token queued"});
    }
    return chio::Result<std::string>::success(tokens_[next_++]);
  }

  std::string cache_key() const override { return "rotating-test"; }

 private:
  std::vector<std::string> tokens_;
  std::size_t next_ = 0;
};

void test_dpop_proof() {
  chio::DpopSignParams params;
  params.capability_id = "cap-123";
  params.tool_server = "hosted-mcp";
  params.tool_name = "read_file";
  params.action_args_json = "{\"path\":\"/tmp/demo\"}";
  params.agent_seed_hex = "0909090909090909090909090909090909090909090909090909090909090909";
  params.nonce = "test-nonce";
  params.issued_at = 1700000000;

  const auto proof = chio::sign_dpop_proof(params);
  require(proof.ok(), proof.error().message);
  require_contains(proof.value().body_json, "\"schema\":\"chio.dpop_proof.v1\"", "dpop body");
  require_contains(proof.value().body_json, "\"nonce\":\"test-nonce\"", "dpop body");
  require(!proof.value().signature_hex.empty(), "expected DPoP signature");
  require_contains(proof.value().to_json(), "\"signature\":", "dpop json");

  const auto built = chio::DpopProofBuilder()
                         .capability_id("cap-123")
                         .tool_server("hosted-mcp")
                         .tool_name("read_file")
                         .action_args_json("{\"path\":\"/tmp/demo\"}")
                         .key_provider(std::make_shared<chio::StaticSeedKeyProvider>(
                             "0909090909090909090909090909090909090909090909090909090909090909"))
                         .clock(std::make_shared<FixedClock>())
                         .nonce_generator(std::make_shared<FixedNonceGenerator>())
                         .build();
  require(built.ok(), built.error().message);
  require_contains(built.value().body_json, "\"nonce\":\"fixed-nonce\"", "dpop builder");
}

void test_client_session_with_fake_transport() {
  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200, {{"MCP-Session-Id", "sess-1"}},
       "{\"jsonrpc\":\"2.0\",\"id\":1,\"metadata\":{\"protocolVersion\":\"wrong\"},"
       "\"result\":{\"protocolVersion\":\"2025-11-25\"}}"},
      {202, {}, "{}"},
      {200, {}, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}"},
      {200, {}, "{\"result\":\"closed\"}"},
  });

  auto client = chio::Client::with_static_bearer("http://127.0.0.1:8080/", "token", transport);
  auto initialized = client.initialize();
  require(initialized.ok(), initialized.error().message);
  auto session = initialized.move_value();
  require_eq(session.session_id(), "sess-1", "session id");
  require_eq(session.protocol_version(), "2025-11-25", "parsed initialize protocol");

  auto tools = session.list_tools();
  require(tools.ok(), tools.error().message);
  require_contains(tools.value(), "\"tools\":[]", "list tools body");

  auto closed = session.close();
  require(closed.ok(), closed.error().message);

  require(transport->requests.size() == 4, "expected initialize, initialized, tools, close");
  require_eq(transport->requests[0].method, "POST", "initialize method");
  require_eq(transport->requests[0].url, "http://127.0.0.1:8080/mcp", "initialize url");
  require_contains(transport->requests[0].body, "\"method\":\"initialize\"", "initialize body");
  require_contains(transport->requests[1].body,
                   "\"method\":\"notifications/initialized\"",
                   "initialized notification body");
  require_contains(transport->requests[2].body, "\"method\":\"tools/list\"", "tools body");
  require_eq(transport->requests[2].headers["MCP-Session-Id"], "sess-1", "session header");
  require_eq(transport->requests[2].headers["MCP-Protocol-Version"],
             "2025-11-25",
             "session protocol header");
}

void test_initialize_handles_sse_and_rejects_invalid_handshakes() {
  auto sse_transport = std::make_shared<FakeTransport>(
      std::vector<chio::HttpResponse>{
          {200,
           {{"MCP-Session-Id", "sess-sse"}},
           "id: event-2\nretry: 1000\n\nid: event-1\n"
           "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":"
           "\"2025-11-25\"}}\n\n"},
          {202, {}, "{}"},
      });
  auto sse_client = chio::Client::with_static_bearer(
      "http://127.0.0.1:8080/", "token", sse_transport);
  auto sse_initialized = sse_client.initialize();
  require(sse_initialized.ok(), sse_initialized.error().message);
  auto sse_session = sse_initialized.move_value();
  require_eq(sse_session.protocol_version(), "2025-11-25", "SSE initialize protocol");
  require(sse_transport->requests.size() == 2,
          "valid SSE initialize must send initialized notification");

  auto missing_protocol_transport = std::make_shared<FakeTransport>(
      std::vector<chio::HttpResponse>{
          {200, {{"MCP-Session-Id", "sess-missing"}},
           "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"},
      });
  auto missing_protocol_client = chio::Client::with_static_bearer(
      "http://127.0.0.1:8080/", "token", missing_protocol_transport);
  auto missing_protocol = missing_protocol_client.initialize();
  require(!missing_protocol.ok(), "expected missing protocolVersion to fail");
  require_contains(missing_protocol.error().message,
                   "result.protocolVersion",
                   "missing protocol error");
  require(missing_protocol_transport->requests.size() == 1,
          "missing protocol must not send initialized notification");

  auto missing_envelope_transport = std::make_shared<FakeTransport>(
      std::vector<chio::HttpResponse>{
          {200, {{"MCP-Session-Id", "sess-envelope"}},
           "{\"result\":{\"protocolVersion\":\"2025-11-25\"}}"},
      });
  auto missing_envelope_client = chio::Client::with_static_bearer(
      "http://127.0.0.1:8080/", "token", missing_envelope_transport);
  auto missing_envelope = missing_envelope_client.initialize();
  require(!missing_envelope.ok(), "expected missing JSON-RPC envelope to fail");
  require_contains(missing_envelope.error().message,
                   "JSON-RPC request id",
                   "missing JSON-RPC envelope error");
  require(missing_envelope_transport->requests.size() == 1,
          "missing envelope must not send initialized notification");

  auto wrong_id_transport = std::make_shared<FakeTransport>(
      std::vector<chio::HttpResponse>{
          {200, {{"MCP-Session-Id", "sess-wrong-id"}},
           initialize_ok_response_json("2025-11-25", "2")},
      });
  auto wrong_id_client = chio::Client::with_static_bearer(
      "http://127.0.0.1:8080/", "token", wrong_id_transport);
  auto wrong_id = wrong_id_client.initialize();
  require(!wrong_id.ok(), "expected mismatched JSON-RPC id to fail");
  require_contains(wrong_id.error().message, "JSON-RPC request id", "wrong id error");
  require(wrong_id_transport->requests.size() == 1,
          "wrong id must not send initialized notification");

  auto wrong_sse_id_transport = std::make_shared<FakeTransport>(
      std::vector<chio::HttpResponse>{
          {200,
           {{"MCP-Session-Id", "sess-wrong-sse-id"}},
           "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"protocolVersion\":"
           "\"2025-11-25\"}}\n\n"},
      });
  auto wrong_sse_id_client = chio::Client::with_static_bearer(
      "http://127.0.0.1:8080/", "token", wrong_sse_id_transport);
  auto wrong_sse_id = wrong_sse_id_client.initialize();
  require(!wrong_sse_id.ok(), "expected mismatched SSE JSON-RPC id to fail");
  require_contains(wrong_sse_id.error().message,
                   "JSON-RPC request id",
                   "wrong SSE id error");
  require(wrong_sse_id_transport->requests.size() == 1,
          "wrong SSE id must not send initialized notification");

  auto rpc_error_transport = std::make_shared<FakeTransport>(
      std::vector<chio::HttpResponse>{
          {200,
           {{"MCP-Session-Id", "sess-error"}},
           "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,"
           "\"message\":\"bad handshake\"}}"},
      });
  auto rpc_error_client = chio::Client::with_static_bearer(
      "http://127.0.0.1:8080/", "token", rpc_error_transport);
  auto rpc_error = rpc_error_client.initialize();
  require(!rpc_error.ok(), "expected JSON-RPC initialize error to fail");
  require_contains(rpc_error.error().message, "bad handshake", "initialize error");
  require(rpc_error_transport->requests.size() == 1,
          "JSON-RPC error must not send initialized notification");

  auto malformed_transport = std::make_shared<FakeTransport>(
      std::vector<chio::HttpResponse>{
          {200, {{"MCP-Session-Id", "sess-malformed"}}, "data: {not-json}\n\n"},
      });
  auto malformed_client = chio::Client::with_static_bearer(
      "http://127.0.0.1:8080/", "token", malformed_transport);
  auto malformed = malformed_client.initialize();
  require(!malformed.ok(), "expected malformed SSE initialize body to fail");
  require(malformed.error().code == chio::ErrorCode::Json,
          "expected malformed initialize body to be a JSON error");
  require(malformed_transport->requests.size() == 1,
          "malformed body must not send initialized notification");
}

void test_typed_list_helpers_reject_jsonrpc_errors() {
  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200,
       {},
       "{\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":-32603,"
       "\"message\":\"denied\"}}"},
      {200,
       {},
       "{\"jsonrpc\":\"2.0\",\"id\":3,\"error\":{\"code\":-32603,"
       "\"message\":\"denied\"}}"},
      {200,
       {},
       "{\"jsonrpc\":\"2.0\",\"id\":4,\"error\":{\"code\":-32603,"
       "\"message\":\"denied\"}}"},
      {200,
       {},
       "{\"jsonrpc\":\"2.0\",\"id\":5,\"error\":{\"code\":-32603,"
       "\"message\":\"denied\"}}"},
  });
  chio::Session session("http://127.0.0.1:8080",
                        "token",
                        "sess-errors",
                        "2025-11-25",
                        transport);

  auto tools = session.list_tools_typed();
  require(!tools.ok(), "expected tools/list JSON-RPC error to fail");
  require_contains(tools.error().message, "denied", "tools/list error");
  auto resources = session.list_resources_typed();
  require(!resources.ok(), "expected resources/list JSON-RPC error to fail");
  auto prompts = session.list_prompts_typed();
  require(!prompts.ok(), "expected prompts/list JSON-RPC error to fail");
  auto tasks = session.list_tasks_typed();
  require(!tasks.ok(), "expected tasks/list JSON-RPC error to fail");

  auto wrong_id_transport = std::make_shared<FakeTransport>(
      std::vector<chio::HttpResponse>{
          {200, {}, "{\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{\"tools\":[]}}"},
      });
  chio::Session wrong_id_session("http://127.0.0.1:8080",
                                 "token",
                                 "sess-wrong-response-id",
                                 "2025-11-25",
                                 wrong_id_transport);
  auto wrong_id_tools = wrong_id_session.list_tools_typed();
  require(!wrong_id_tools.ok(), "expected mismatched tools/list response id to fail");
  require_contains(wrong_id_tools.error().message,
                   "terminal response",
                   "mismatched tools/list response id error");
}

void test_untyped_session_helpers_reject_jsonrpc_errors() {
  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200,
       {},
       "{\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":-32603,"
       "\"message\":\"request denied\"}}"},
      {200,
       {},
       "{\"jsonrpc\":\"2.0\",\"id\":3,\"error\":{\"code\":-32603,"
       "\"message\":\"tool denied\"}}"},
      {202,
       {},
       "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,"
       "\"message\":\"notification denied\"}}"},
  });
  chio::Session session("http://127.0.0.1:8080",
                        "token",
                        "sess-untyped-errors",
                        "2025-11-25",
                        transport);

  auto request = session.request("tools/list", "{}");
  require(!request.ok(), "expected untyped request JSON-RPC error to fail");
  require_contains(request.error().message, "request denied", "untyped request error");

  auto tool = session.call_tool("slow", "{}");
  require(!tool.ok(), "expected untyped call_tool JSON-RPC error to fail");
  require_contains(tool.error().message, "tool denied", "untyped call_tool error");

  auto notification = session.notification("notifications/initialized", "{}");
  require(!notification.ok(), "expected notification JSON-RPC error to fail");
  require_contains(notification.error().message,
                   "notification denied",
                   "notification error");

  auto sse_transport = std::make_shared<FakeTransport>(
      std::vector<chio::HttpResponse>{
          {200,
           {},
           "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":-32603,"
           "\"message\":\"stream denied\"}}\n\n"},
      });
  chio::Session sse_session("http://127.0.0.1:8080",
                            "token",
                            "sess-sse-errors",
                            "2025-11-25",
                            sse_transport);
  auto streamed = sse_session.call_tool(
      "slow",
      "{}",
      [](const chio::JsonMessage&) { return chio::Result<void>::success(); });
  require(!streamed.ok(), "expected streaming JSON-RPC error to fail");
  require_contains(streamed.error().message, "stream denied", "streaming error");
}

void test_session_refreshes_token_provider_for_requests() {
  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200, {{"MCP-Session-Id", "sess-refresh"}},
       initialize_ok_response_json()},
      {202, {}, "{}"},
      {200, {}, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}"},
      {200, {}, "{\"result\":\"closed\"}"},
  });

  auto client = chio::ClientBuilder()
                    .base_url("http://127.0.0.1:8080/")
                    .token_provider(std::make_shared<RotatingTokenProvider>(
                        std::vector<std::string>{"init-token",
                                                 "notify-token",
                                                 "tools-token",
                                                 "close-token"}))
                    .transport(transport)
                    .build();
  require(client.ok(), client.error().message);
  auto initialized = client.value().initialize();
  require(initialized.ok(), initialized.error().message);
  auto session = initialized.move_value();
  auto tools = session.list_tools();
  require(tools.ok(), tools.error().message);
  auto closed = session.close();
  require(closed.ok(), closed.error().message);

  require(transport->requests.size() == 4, "expected refresh transport requests");
  require_eq(transport->requests[0].headers["Authorization"],
             "Bearer init-token",
             "initialize token");
  require_eq(transport->requests[1].headers["Authorization"],
             "Bearer notify-token",
             "initialized notification token");
  require_eq(transport->requests[2].headers["Authorization"],
             "Bearer tools-token",
             "session request token");
  require_eq(transport->requests[3].headers["Authorization"],
             "Bearer close-token",
             "close token");
}

void test_start_receive_loop_returns_setup_errors() {
  chio::Session missing_transport("http://127.0.0.1:8080",
                                  "token",
                                  "sess-receive",
                                  "2025-11-25",
                                  nullptr);
  auto missing_started = missing_transport.start_receive_loop([](const chio::JsonMessage&) {
    return chio::Result<void>::success();
  }, std::make_shared<chio::CancellationToken>());
  require(!missing_started.ok(), "expected receive loop transport setup failure");
  require_contains(missing_started.error().message,
                   "missing HTTP transport",
                   "receive loop transport setup error");
  require_eq(missing_started.error().operation,
             "Session::start_receive_loop",
             "receive loop transport operation");

  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{});
  chio::Session session("http://127.0.0.1:8080",
                        "",
                        "sess-receive",
                        "2025-11-25",
                        transport);
  auto started = session.start_receive_loop([](const chio::JsonMessage&) {
    return chio::Result<void>::success();
  }, std::make_shared<chio::CancellationToken>());
  require(!started.ok(), "expected receive loop setup failure");
  require_contains(started.error().message, "bearer token is empty", "receive loop setup error");
}

void test_nested_router_bind_captures_stable_sender() {
  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {202, {}, "{\"ok\":true}"},
  });

  chio::MessageHandler handler;
  {
    chio::Session session("http://127.0.0.1:8080",
                          "token",
                          "sess-bound-router",
                          "2025-11-25",
                          transport);
    chio::NestedCallbackRouter router;
    router.on_roots([](const chio::JsonMessage& message) {
      return chio::Result<std::string>::success(
          chio::NestedCallbackRouter::roots_list_result(
              message, "[{\"uri\":\"file:///tmp\",\"name\":\"tmp\"}]"));
    });
    handler = router.bind(session);
  }

  chio::JsonMessage message;
  message.method = "roots/list";
  message.id = "edge-client-2";
  message.id_json = "\"edge-client-2\"";
  const auto handled = handler(message);
  require(handled.ok(), handled.error().message);
  require(transport->requests.size() == 1, "expected bound router callback response");
  require_contains(transport->requests[0].body, "\"id\":\"edge-client-2\"", "bound callback id");
  require_contains(transport->requests[0].headers["MCP-Session-Id"],
                   "sess-bound-router",
                   "bound callback session id");
}

void test_initialize_nested_message_handler() {
  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200, {{"MCP-Session-Id", "sess-nested"}},
       initialize_ok_response_json()},
      {200, {}, "data: {\"jsonrpc\":\"2.0\",\"id\":\"edge-client-1\",\"method\":\"roots/list\",\"params\":{}}\n\n"},
      {202, {}, "{}"},
  });
  bool saw_roots = false;
  auto client = chio::ClientBuilder()
                    .base_url("http://127.0.0.1:8080/")
                    .bearer_token("token")
                    .transport(transport)
                    .client_capabilities_json("{\"roots\":{\"listChanged\":true}}")
                    .initialize_message_handler(
                        [&](chio::Session& session, const chio::JsonMessage& message) {
                          saw_roots = message.method == "roots/list";
                          const auto response = chio::NestedCallbackRouter::roots_list_result(
                              message, "[{\"uri\":\"file:///tmp\",\"name\":\"tmp\"}]");
                          auto sent = session.send_envelope(response);
                          if (!sent) {
                            return chio::Result<void>::failure(sent.error());
                          }
                          return chio::Result<void>::success();
                        })
                    .build();
  require(client.ok(), client.error().message);
  auto initialized = client.value().initialize();
  require(initialized.ok(), initialized.error().message);
  require(saw_roots, "expected initialize roots/list callback");
  require(transport->requests.size() == 3, "expected initialize callback response");
  require_contains(transport->requests[2].body, "\"id\":\"edge-client-1\"", "callback id");
  require_contains(transport->requests[2].body, "\"roots\"", "callback roots");
}

void test_builder_retry_trace_typed_models_and_streaming() {
  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {500, {}, "{\"error\":\"busy\"}"},
      {200, {{"MCP-Session-Id", "sess-2"}}, initialize_ok_response_json()},
      {202, {}, "{}"},
      {200, {}, "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"echo_text\",\"description\":\"Echo\",\"inputSchema\":{\"type\":\"object\"}}]}}\n\n"},
      {200, {}, "data: {\"jsonrpc\":\"2.0\",\ndata: \"method\":\"notifications/tools/list_changed\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"ok\":true}}\n\n"},
  });
  auto traces = std::make_shared<chio::test::RecordingTraceSink>();
  chio::RetryPolicy retry;
  retry.max_attempts = 2;
  retry.initial_backoff = std::chrono::milliseconds(0);
  retry.max_backoff = std::chrono::milliseconds(0);

  auto client = chio::ClientBuilder()
                    .base_url("http://127.0.0.1:8080/")
                    .token_provider(std::make_shared<chio::StaticBearerTokenProvider>("token"))
                    .transport(transport)
                    .trace_sink(traces)
                    .retry_policy(retry)
                    .build();
  require(client.ok(), client.error().message);

  auto initialized = client.value().initialize();
  require(initialized.ok(), initialized.error().message);
  auto session = initialized.move_value();
  require(transport->requests.size() >= 3, "expected initialize retry and notification");
  require(transport->requests[0].attempt == 1, "expected first initialize attempt");
  require(transport->requests[1].attempt == 2, "expected second initialize attempt");
  require_eq(transport->requests[1].headers["Authorization"],
             "Bearer token",
             "token provider header");
  require(traces->event_count() >= 2, "expected trace events for retry");

  auto tools = session.list_tools_typed();
  require(tools.ok(), tools.error().message);
  require(tools.value().value.size() == 1, "expected one typed tool");
  require_eq(tools.value().value[0].name, "echo_text", "typed tool name");
  require_contains(tools.value().raw_json, "\"tools\"", "typed raw json");

  bool saw_notification = false;
  auto streamed = session.request_streaming(
      "tools/list",
      "{}",
      [&](const chio::JsonMessage& message) {
        saw_notification = message.method == "notifications/tools/list_changed";
        return chio::Result<void>::success();
      });
  require(streamed.ok(), streamed.error().message);
  require(saw_notification, "expected streaming notification handler");

  auto streaming_transport = std::make_shared<StreamingFakeTransport>();
  chio::Session streaming_session("http://127.0.0.1:8080",
                                  "token",
                                  "sess-stream",
                                  "2025-11-25",
                                  streaming_transport);
  int delivered_count = 0;
  auto streamed_once = streaming_session.request_streaming(
      "tools/list",
      "{}",
      [&](const chio::JsonMessage& message) {
        if (message.method == "notifications/tools/list_changed") {
          ++delivered_count;
        }
        return chio::Result<void>::success();
      });
  require(streamed_once.ok(), streamed_once.error().message);
  require(delivered_count == 1, "streaming backend must not dispatch duplicate messages");

  auto incomplete_stream_transport = std::make_shared<IncompleteStreamingFakeTransport>();
  chio::Session incomplete_stream_session("http://127.0.0.1:8080",
                                          "token",
                                          "sess-incomplete-stream",
                                          "2025-11-25",
                                          incomplete_stream_transport);
  bool saw_incomplete_progress = false;
  auto incomplete_stream = incomplete_stream_session.request_streaming(
      "tools/list",
      "{}",
      [&](const chio::JsonMessage& message) {
        saw_incomplete_progress = message.method == "notifications/progress";
        return chio::Result<void>::success();
      });
  require(!incomplete_stream.ok(), "expected streaming response without terminal to fail");
  require(saw_incomplete_progress, "expected incomplete stream notification to be delivered");
  require_contains(incomplete_stream.error().message,
                   "terminal response",
                   "incomplete stream error");

  auto buffered_incomplete_transport = std::make_shared<FakeTransport>(
      std::vector<chio::HttpResponse>{
          {200,
           {},
           "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"},
      });
  chio::Session buffered_incomplete_session("http://127.0.0.1:8080",
                                            "token",
                                            "sess-buffered-incomplete-stream",
                                            "2025-11-25",
                                            buffered_incomplete_transport);
  bool saw_buffered_progress = false;
  auto buffered_incomplete = buffered_incomplete_session.request_streaming(
      "tools/list",
      "{}",
      [&](const chio::JsonMessage& message) {
        saw_buffered_progress = message.method == "notifications/progress";
        return chio::Result<void>::success();
      });
  require(!buffered_incomplete.ok(), "expected buffered stream without terminal to fail");
  require(saw_buffered_progress, "expected buffered stream notification to be delivered");
  require_contains(buffered_incomplete.error().message,
                   "terminal response",
                   "buffered incomplete stream error");

  auto tool_transport = std::make_shared<FakeTransport>(
      std::vector<chio::HttpResponse>{
          {200,
           {{"X-Test", "metadata"}},
           "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[]}}"},
      });
  chio::Session tool_session("http://127.0.0.1:8080",
                             "token",
                             "sess-tool-client",
                             "2025-11-25",
                             tool_transport);
  chio::ToolClient tool(tool_session, "echo");
  auto typed_call = tool.call_typed("{}");
  require(typed_call.ok(), typed_call.error().message);
  require(typed_call.value().response.status == 200,
          "expected ToolClient typed response status");
  require_eq(typed_call.value().response.headers["X-Test"],
             "metadata",
             "expected ToolClient typed response header");
  require_contains(typed_call.value().raw_json, "\"content\":[]", "typed tool call raw json");
  require_contains(tool_transport->requests[0].body,
                   "\"method\":\"tools/call\"",
                   "typed tool call request method");
  require_contains(tool_transport->requests[0].body, "\"name\":\"echo\"", "typed tool name");
}

void test_auth_metadata_and_pkce() {
  require_eq(chio::detail::base64url_encode({}), "", "base64url empty");
  require_eq(chio::detail::base64url_encode({'f'}), "Zg", "base64url one byte");
  require_eq(chio::detail::base64url_encode({'f', 'o'}), "Zm8", "base64url two bytes");
  require_eq(chio::detail::base64url_encode({'f', 'o', 'o'}), "Zm9v", "base64url three bytes");
  require_eq(chio::detail::base64url_encode({'f', 'o', 'o', 'b'}),
             "Zm9vYg",
             "base64url four bytes");
  require_eq(chio::detail::base64url_encode({'f', 'o', 'o', 'b', 'a'}),
             "Zm9vYmE",
             "base64url five bytes");
  require_eq(chio::detail::base64url_encode({'f', 'o', 'o', 'b', 'a', 'r'}),
             "Zm9vYmFy",
             "base64url six bytes");

  const std::string verifier =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abc";
  auto pkce = chio::PkceChallenge::from_verifier(verifier);
  require(pkce.ok(), pkce.error().message);
  require_eq(pkce.value().method, "S256", "pkce method");
  require(!pkce.value().challenge.empty(), "expected pkce challenge");

  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200, {}, "{\"issuer\":\"https://auth.example\",\"token_endpoint\":\"https://auth.example/token\",\"scopes_supported\":[\"tools.read\"]}"},
      {200, {}, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}"},
  });
  chio::OAuthMetadataClient oauth("https://server.example", transport);
  auto metadata = oauth.discover_protected_resource();
  require(metadata.ok(), metadata.error().message);
  require_eq(metadata.value().token_endpoint,
             "https://auth.example/token",
             "metadata token endpoint");

  chio::TokenExchangeRequest request;
  request.token_endpoint = metadata.value().token_endpoint;
  request.code = "code-1";
  request.redirect_uri = "https://client.example/callback";
  request.code_verifier = pkce.value().verifier;
  request.client_id = "client-1";
  request.scopes = {"tools.read", "tools.write"};
  auto token = oauth.exchange_token(request);
  require(token.ok(), token.error().message);
  require_contains(token.value(), "\"access_token\":\"tok\"", "token exchange response");
  require_contains(transport->requests[1].body, "code_verifier=", "token exchange form");
  require_contains(transport->requests[1].body,
                   "scope=tools.read+tools.write",
                   "token exchange scope");
  require(transport->requests[1].body.find("tools.read%20tools.write") ==
              std::string::npos,
          "token exchange form must encode spaces as plus");

  chio::StaticBearerTokenProvider provider("secret-token");
  const auto cache_key = provider.cache_key();
  require_contains(cache_key, "static-bearer:sha256:", "static bearer cache key");
  require(cache_key.find("secret-token") == std::string::npos,
          "static bearer cache key must not contain the raw token");
  require(cache_key != chio::StaticBearerTokenProvider("other-token").cache_key(),
          "static bearer cache key must distinguish token values");

  const std::string embedded_null_token("secret\0tail", 11);
  const auto embedded_null_key =
      chio::StaticBearerTokenProvider(embedded_null_token).cache_key();
  require_contains(embedded_null_key,
                   "static-bearer:sha256:",
                   "embedded null static bearer cache key");
  require(embedded_null_key != chio::StaticBearerTokenProvider("secret").cache_key(),
          "static bearer cache key must include bytes after embedded null");

  std::string invalid_utf8_token;
  invalid_utf8_token.push_back(static_cast<char>(0xff));
  invalid_utf8_token.push_back('a');
  const auto invalid_utf8_key =
      chio::StaticBearerTokenProvider(invalid_utf8_token).cache_key();
  require_contains(invalid_utf8_key,
                   "static-bearer:sha256:",
                   "invalid utf8 static bearer cache key");
}

void test_receipt_query_client() {
  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200, {}, "{\"receipts\":[]}"},
  });
  chio::ReceiptQueryClient client("http://127.0.0.1:8940/", "token", transport);
  const auto response = client.query({{"capability", "cap 1"}, {"limit", "10"}});
  require(response.ok(), response.error().message);
  require_eq(response.value(), "{\"receipts\":[]}", "receipt query body");
  require_eq(transport->requests[0].method, "GET", "receipt query method");
  require_contains(transport->requests[0].url, "capability=cap%201", "receipt query url");
  require_eq(transport->requests[0].headers["Authorization"],
             "Bearer token",
             "receipt query auth header");
}

void test_manifest_validation_error_code_names() {
  require(static_cast<int>(chio::ErrorCode::DuplicateServerTool) == 22,
          "duplicate server tool error code");
  require(static_cast<int>(chio::ErrorCode::InvalidToolName) == 23,
          "invalid tool name error code");
  require(static_cast<int>(chio::ErrorCode::InvalidInputSchema) == 24,
          "invalid input schema error code");
  require(static_cast<int>(chio::ErrorCode::InvalidOutputSchema) == 25,
          "invalid output schema error code");
  require(static_cast<int>(chio::ErrorCode::InvalidManifestField) == 26,
          "invalid manifest field error code");
  require(static_cast<int>(chio::ErrorCode::InvalidRequiredPermission) == 27,
          "invalid required permission error code");
  require(static_cast<int>(chio::ErrorCode::DuplicateRequiredPermission) == 28,
          "duplicate required permission error code");
}

void test_feature_helpers_and_middleware() {
  chio::CapabilityVerifier verifier(
      std::make_shared<FixedClock>(),
      UINT32_MAX,
      [](const std::string& capability_id) {
        return chio::Result<bool>::success(capability_id == "revoked-cap");
      });
  const auto revoked = verifier.verify("{\"id\":\"revoked-cap\"}");
  require(!revoked.ok(), "expected revoked capability to fail");
  require(revoked.error().code == chio::ErrorCode::CapabilityRevoked,
          "expected revocation error");

  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {503, {}, "{\"status\":\"down\"}"},
  });
  chio::http::Evaluator evaluator("http://127.0.0.1:9090/", transport);
  chio::http::Middleware middleware(evaluator);
  chio::http::ChioHttpRequest request;
  request.request_id = "req-closed";
  request.method = "GET";
  request.path = "/";
  const auto verdict = middleware.evaluate_fail_closed(request);
  require_eq(verdict.verdict, "deny", "fail closed verdict");

  auto pool_transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200, {{"MCP-Session-Id", "sess-a"}}, initialize_ok_response_json()},
      {202, {}, "{}"},
      {200, {{"MCP-Session-Id", "sess-b"}}, initialize_ok_response_json()},
      {202, {}, "{}"},
      {200, {{"MCP-Session-Id", "sess-c"}}, initialize_ok_response_json()},
      {202, {}, "{}"},
  });
  auto client_a = chio::ClientBuilder()
                      .base_url("http://127.0.0.1:8080/")
                      .bearer_token("token")
                      .transport(pool_transport)
                      .client_capabilities_json("{\"roots\":{\"listChanged\":true}}")
                      .build();
  auto client_b = chio::ClientBuilder()
                      .base_url("http://127.0.0.1:8080/")
                      .bearer_token("token")
                      .transport(pool_transport)
                      .client_capabilities_json("{\"sampling\":{}}")
                      .build();
  auto client_c = chio::ClientBuilder()
                      .base_url("http://127.0.0.1:8080/")
                      .token_provider(std::make_shared<chio::StaticBearerTokenProvider>("token-c"))
                      .transport(pool_transport)
                      .client_capabilities_json("{\"roots\":{\"listChanged\":true}}")
                      .build();
  require(client_a.ok(), client_a.error().message);
  require(client_b.ok(), client_b.error().message);
  require(client_c.ok(), client_c.error().message);
  chio::SessionPool pool;
  auto session_a = pool.get_or_initialize(client_a.value());
  auto session_b = pool.get_or_initialize(client_b.value());
  auto session_c = pool.get_or_initialize(client_c.value());
  require(session_a.ok(), session_a.error().message);
  require(session_b.ok(), session_b.error().message);
  require(session_c.ok(), session_c.error().message);
  require_eq(session_a.value()->session_id(), "sess-a", "pooled session a");
  require_eq(session_b.value()->session_id(), "sess-b", "pooled session b");
  require_eq(session_c.value()->session_id(), "sess-c", "pooled session c");
  require(pool_transport->requests.size() == 6, "expected separate session pool initializations");
  require_contains(pool_transport->requests[0].body, "\"roots\"", "pool capabilities a");
  require_contains(pool_transport->requests[2].body, "\"sampling\"", "pool capabilities b");
  require_eq(pool_transport->requests[4].headers["Authorization"],
             "Bearer token-c",
             "pool token provider auth");

  pool.clear();
  auto transport_a = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200, {{"MCP-Session-Id", "sess-transport-a"}},
       initialize_ok_response_json()},
      {202, {}, "{}"},
  });
  auto transport_b = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200, {{"MCP-Session-Id", "sess-transport-b"}},
       initialize_ok_response_json()},
      {202, {}, "{}"},
  });
  auto client_transport_a = chio::ClientBuilder()
                                .base_url("http://127.0.0.1:8080/")
                                .bearer_token("token")
                                .transport(transport_a)
                                .build();
  auto client_transport_b = chio::ClientBuilder()
                                .base_url("http://127.0.0.1:8080/")
                                .bearer_token("token")
                                .transport(transport_b)
                                .build();
  require(client_transport_a.ok(), client_transport_a.error().message);
  require(client_transport_b.ok(), client_transport_b.error().message);
  auto session_transport_a = pool.get_or_initialize(client_transport_a.value());
  auto session_transport_b = pool.get_or_initialize(client_transport_b.value());
  require(session_transport_a.ok(), session_transport_a.error().message);
  require(session_transport_b.ok(), session_transport_b.error().message);
  require_eq(session_transport_a.value()->session_id(),
             "sess-transport-a",
             "transport keyed session a");
  require_eq(session_transport_b.value()->session_id(),
             "sess-transport-b",
             "transport keyed session b");
  require(transport_a->requests.size() == 2, "expected transport a initialization");
  require(transport_b->requests.size() == 2, "expected transport b initialization");

  pool.clear();
  auto policy_transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200, {{"MCP-Session-Id", "sess-policy-a"}},
       initialize_ok_response_json()},
      {202, {}, "{}"},
      {200, {{"MCP-Session-Id", "sess-policy-b"}},
       initialize_ok_response_json()},
      {202, {}, "{}"},
      {200, {{"MCP-Session-Id", "sess-timeout-a"}},
       initialize_ok_response_json()},
      {202, {}, "{}"},
      {200, {{"MCP-Session-Id", "sess-timeout-b"}},
       initialize_ok_response_json()},
      {202, {}, "{}"},
  });
  chio::RetryPolicy one_attempt;
  one_attempt.max_attempts = 1;
  chio::RetryPolicy two_attempts;
  two_attempts.max_attempts = 2;
  auto client_policy_a = chio::ClientBuilder()
                             .base_url("http://127.0.0.1:8080/")
                             .bearer_token("token")
                             .transport(policy_transport)
                             .retry_policy(one_attempt)
                             .build();
  auto client_policy_b = chio::ClientBuilder()
                             .base_url("http://127.0.0.1:8080/")
                             .bearer_token("token")
                             .transport(policy_transport)
                             .retry_policy(two_attempts)
                             .build();
  auto client_timeout_a = chio::ClientBuilder()
                              .base_url("http://127.0.0.1:8080/")
                              .bearer_token("token")
                              .transport(policy_transport)
                              .timeout(std::chrono::milliseconds(1000))
                              .build();
  auto client_timeout_b = chio::ClientBuilder()
                              .base_url("http://127.0.0.1:8080/")
                              .bearer_token("token")
                              .transport(policy_transport)
                              .timeout(std::chrono::milliseconds(2000))
                              .build();
  require(client_policy_a.ok(), client_policy_a.error().message);
  require(client_policy_b.ok(), client_policy_b.error().message);
  require(client_timeout_a.ok(), client_timeout_a.error().message);
  require(client_timeout_b.ok(), client_timeout_b.error().message);
  auto session_policy_a = pool.get_or_initialize(client_policy_a.value());
  auto session_policy_b = pool.get_or_initialize(client_policy_b.value());
  auto session_timeout_a = pool.get_or_initialize(client_timeout_a.value());
  auto session_timeout_b = pool.get_or_initialize(client_timeout_b.value());
  require(session_policy_a.ok(), session_policy_a.error().message);
  require(session_policy_b.ok(), session_policy_b.error().message);
  require(session_timeout_a.ok(), session_timeout_a.error().message);
  require(session_timeout_b.ok(), session_timeout_b.error().message);
  require_eq(session_policy_a.value()->session_id(), "sess-policy-a", "policy session a");
  require_eq(session_policy_b.value()->session_id(), "sess-policy-b", "policy session b");
  require_eq(session_timeout_a.value()->session_id(), "sess-timeout-a", "timeout session a");
  require_eq(session_timeout_b.value()->session_id(), "sess-timeout-b", "timeout session b");
  require(policy_transport->requests.size() == 8,
          "expected retry policy and timeout keyed initializations");
}

void test_http_substrate_evaluator() {
  const std::string verified_authority =
      "{\"signature_valid\":true,\"signer_trusted\":true,"
      "\"receipt_id_valid\":true,\"parameter_hash_valid\":true,"
      "\"receipt_kind\":\"mediated_decision\",\"boundary_class\":\"prevent\","
      "\"trust_level\":\"mediated\",\"result\":\"allow\",\"authorized\":true,"
      "\"signer_key_hex\":\"dddd\",\"ok\":true}";
  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200, {}, "{\"verdict\":\"allow\",\"receipt\":{\"id\":\"r1\"}}"},
      {200, {}, "{\"verdict\":\"allow\",\"receipt\":{\"id\":\"r2\"}}"},
      {200, {}, "{\"metadata\":{\"legacy_valid\":true},\"ok\":false,\"authorized\":false}"},
      {200, {}, verified_authority},
      {503, {}, "{\"status\":\"degraded\"}"},
  });

  chio::http::ChioHttpRequest request;
  request.request_id = "req-1";
  request.method = "POST";
  request.route_pattern = "/v1/items";
  request.path = "/v1/items";
  request.headers = {
      {"authorization", "Bearer inbound-secret"},
      {"content-type", "application/json"},
      {"cookie", "session=inbound-secret"},
  };
  request.caller.subject = "agent-1";
  request.caller.verified = true;
  request.body_hash =
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
  request.body_length = 5;
  request.timestamp = 1700000000;

  chio::http::Evaluator evaluator("http://127.0.0.1:9090/", transport, 1234);
  const auto verdict = evaluator.evaluate(request, "cap-token-1");
  require(verdict.ok(), verdict.error().message);
  require_contains(verdict.value(), "\"verdict\":\"allow\"", "evaluate body");
  require_contains(transport->requests[0].body, "\"body_hash\":", "evaluate request");
  require_contains(transport->requests[0].body, "\"caller\":", "evaluate request");
  require_eq(transport->requests[0].headers["X-Chio-Capability"],
             "cap-token-1",
             "evaluate capability header");
  require(transport->requests[0].timeout == std::chrono::milliseconds(1234),
          "evaluate request should propagate configured timeout");
  require_no_header(transport->requests[0].headers, "Authorization", "evaluate headers");
  require_no_header(transport->requests[0].headers, "authorization", "evaluate headers");
  require_no_header(transport->requests[0].headers, "Cookie", "evaluate headers");
  require_no_header(transport->requests[0].headers, "cookie", "evaluate headers");
  require_no_header(transport->requests[0].headers, "X-Api-Key", "evaluate headers");

  const auto default_capability = evaluator.evaluate(request);
  require(default_capability.ok(), default_capability.error().message);
  require_no_header(transport->requests[1].headers,
                    "X-Chio-Capability",
                    "default evaluate headers");

  const auto false_verified = evaluator.verify_receipt("{\"receipt\":{\"id\":\"r1\"}}");
  require(false_verified.ok(), false_verified.error().message);
  require(!false_verified.value(), "expected ok=false to fail");

  const auto verified = evaluator.verify_receipt("{\"receipt\":{\"id\":\"r1\"}}");
  require(verified.ok(), verified.error().message);
  require(verified.value(), "expected receipt verification to succeed");
  require(transport->requests[3].timeout == std::chrono::milliseconds(1234),
          "verify request should propagate configured timeout");

  const auto health = evaluator.health();
  require(health.ok(), health.error().message);
  require_eq(health.value(), "{\"status\":\"degraded\"}", "health body");
  require(transport->requests[4].timeout == std::chrono::milliseconds(1234),
          "health request should propagate configured timeout");
}

void test_http_substrate_middleware_verdict_parsing() {
  const std::string verified_authority =
      "{\"signature_valid\":true,\"signer_trusted\":true,"
      "\"receipt_id_valid\":true,\"parameter_hash_valid\":true,"
      "\"receipt_kind\":\"mediated_decision\",\"boundary_class\":\"prevent\","
      "\"trust_level\":\"mediated\",\"result\":\"allow\",\"authorized\":true,"
      "\"signer_key_hex\":\"dddd\",\"ok\":true}";
  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200, {}, "{\"verdict\":\"allow\",\"reason\":\"ok\"}"},
      {200, {}, "{\"verdict\":\"allow\",\"reason\":\"ok\",\"receipt\":{\"id\":\"receipt-42\"},\"evidence\":[]}"},
      {200, {}, verified_authority},
      {200, {}, "{\"verdict\":{\"verdict\":\"allow\"},\"receipt\":{\"id\":\"nested-allow-receipt\"},\"evidence\":[]}"},
      {200, {}, verified_authority},
      {200, {}, "{\"verdict\":\"allow\",\"receipt\":{\"id\":\"non-authoritative-receipt\"},\"evidence\":[]}"},
      {200, {}, "{\"signature_valid\":true,\"signer_trusted\":true,"
                 "\"receipt_id_valid\":true,\"parameter_hash_valid\":true,"
                 "\"receipt_kind\":\"trace_observation\",\"boundary_class\":\"detect_only\","
                 "\"trust_level\":\"verified\",\"result\":\"allow\",\"authorized\":false,"
                 "\"signer_key_hex\":\"dddd\",\"ok\":true}"},
      {200, {}, "{\"verdict\":{\"verdict\":\"deny\",\"reason\":\"blocked by policy\",\"guard\":\"policy\"},\"receipt\":{\"id\":\"nested-deny-receipt\"},\"evidence\":[]}"},
      {200, {}, "{\"receipt\":{\"id\":\"missing-verdict-receipt\"},\"evidence\":[]}"},
      {200, {}, "{not-json"},
  });

  chio::http::ChioHttpRequest request;
  request.request_id = "req-verdict";
  request.method = "GET";
  request.path = "/guarded";

  chio::http::Middleware middleware(
      chio::http::Evaluator("http://127.0.0.1:9090/", transport));

  const auto raw_allow = middleware.evaluate_fail_closed(request);
  require_eq(raw_allow.verdict, "deny", "raw allow without receipt fails closed");
  require_eq(raw_allow.reason, "allow verdict missing receipt", "raw allow denial reason");

  const auto allow = middleware.evaluate_fail_closed(request);
  require_eq(allow.verdict, "allow", "allow verdict");
  require_eq(chio::http::receipt_id_from_verdict(allow),
             "receipt-42",
             "receipt id extraction");
  require_contains(allow.receipt_json, "\"id\":\"receipt-42\"", "receipt json");
  require_contains(transport->requests[2].url, "/chio/verify", "allow receipt verify request");
  require_contains(transport->requests[2].body, "\"id\":\"receipt-42\"", "allow verify body");

  const auto nested_allow = middleware.evaluate_fail_closed(request);
  require_eq(nested_allow.verdict, "allow", "nested allow verdict");
  require_eq(chio::http::receipt_id_from_verdict(nested_allow),
             "nested-allow-receipt",
             "nested allow receipt id extraction");

  const auto non_authoritative_allow = middleware.evaluate_fail_closed(request);
  require_eq(non_authoritative_allow.verdict, "deny", "non-authoritative allow fails closed");
  require_eq(non_authoritative_allow.reason,
             "allow receipt is not authoritative",
             "non-authoritative allow reason");

  const auto nested_deny = middleware.evaluate_fail_closed(request);
  require_eq(nested_deny.verdict, "deny", "nested deny verdict");
  require_eq(nested_deny.reason, "blocked by policy", "nested deny reason");
  require_eq(chio::http::receipt_id_from_verdict(nested_deny),
             "nested-deny-receipt",
             "nested deny receipt id extraction");

  const auto missing = middleware.evaluate_fail_closed(request);
  require_eq(missing.verdict, "deny", "missing verdict fail closed");
  require_eq(missing.reason, "missing verdict", "missing verdict reason");

  const auto malformed = middleware.evaluate_fail_closed(request);
  require_eq(malformed.verdict, "deny", "malformed verdict fail closed");
  require_eq(malformed.reason, "malformed evaluate response", "malformed verdict reason");
  require_eq(chio::http::receipt_id_from_verdict(malformed),
             "",
             "malformed receipt id extraction");
}

}  // namespace

int main() {
  try {
    test_invariants_from_shared_vectors();
    test_private_json_helpers_are_strict();
    test_curl_sse_helpers_abort_after_terminal_message();
    test_transport_policy_respects_retryable_flag();
    test_dpop_proof();
    test_client_session_with_fake_transport();
    test_initialize_handles_sse_and_rejects_invalid_handshakes();
    test_typed_list_helpers_reject_jsonrpc_errors();
    test_untyped_session_helpers_reject_jsonrpc_errors();
    test_session_refreshes_token_provider_for_requests();
    test_start_receive_loop_returns_setup_errors();
    test_nested_router_bind_captures_stable_sender();
    test_initialize_nested_message_handler();
    test_builder_retry_trace_typed_models_and_streaming();
    test_auth_metadata_and_pkce();
    test_receipt_query_client();
    test_manifest_validation_error_code_names();
    test_feature_helpers_and_middleware();
    test_http_substrate_evaluator();
    test_http_substrate_middleware_verdict_parsing();
  } catch (const std::exception& error) {
    std::cerr << "chio_cpp_tests failed: " << error.what() << "\n";
    return 1;
  }

  std::cout << "chio_cpp_tests passed\n";
  return 0;
}
