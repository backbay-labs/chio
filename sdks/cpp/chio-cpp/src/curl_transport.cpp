#include "chio/transport.hpp"

#ifdef CHIO_CPP_HAS_CURL

#include <curl/curl.h>

#include <chrono>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>

#include "curl_sse.hpp"

namespace chio {
namespace {

std::size_t write_header(char* buffer, std::size_t size, std::size_t nitems, void* userdata) {
  const std::size_t len = size * nitems;
  auto* headers = static_cast<std::map<std::string, std::string>*>(userdata);
  std::string line(buffer, len);
  const auto colon = line.find(':');
  if (colon != std::string::npos) {
    auto key = line.substr(0, colon);
    auto value = line.substr(colon + 1);
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
      value.erase(value.begin());
    }
    while (!value.empty() && (value.back() == '\r' || value.back() == '\n')) {
      value.pop_back();
    }
    (*headers)[key] = value;
  }
  return len;
}

struct ProgressContext {
  std::shared_ptr<CancellationToken> cancellation;
};

int progress_callback(void* userdata,
                      curl_off_t,
                      curl_off_t,
                      curl_off_t,
                      curl_off_t) {
  auto* context = static_cast<ProgressContext*>(userdata);
  if (context != nullptr && context->cancellation && context->cancellation->cancelled()) {
    return 1;
  }
  return 0;
}

}  // namespace

Result<HttpResponse> CurlHttpTransport::send(const HttpRequest& request) {
  if (request.cancellation && request.cancellation->cancelled()) {
    return Result<HttpResponse>::failure(
        Error{ErrorCode::Transport, "request cancelled before curl send",
              "CurlHttpTransport::send"});
  }

  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
  if (!curl) {
    return Result<HttpResponse>::failure(
        Error{ErrorCode::Transport, "curl_easy_init failed", "CurlHttpTransport::send"});
  }

  detail::CurlBodyCapture body_capture;
  body_capture.id_json = detail::request_id_json(request.body);
  body_capture.stream_message = request.stream_message;
  std::map<std::string, std::string> headers;
  curl_easy_setopt(curl.get(), CURLOPT_URL, request.url.c_str());
  curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, detail::write_curl_body);
  curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &body_capture);
  curl_easy_setopt(curl.get(), CURLOPT_HEADERFUNCTION, write_header);
  curl_easy_setopt(curl.get(), CURLOPT_HEADERDATA, &headers);
  curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
  if (request.timeout.count() > 0) {
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT_MS,
                     static_cast<long>(request.timeout.count()));
  }
  if (request.body.size() > static_cast<std::size_t>(std::numeric_limits<long>::max())) {
    return Result<HttpResponse>::failure(
        Error{ErrorCode::Transport, "request body is too large for curl POSTFIELDSIZE",
              "CurlHttpTransport::send"});
  }
  const auto body_size = static_cast<long>(request.body.size());

  ProgressContext progress{request.cancellation};
  if (request.cancellation) {
    curl_easy_setopt(curl.get(), CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl.get(), CURLOPT_XFERINFOFUNCTION, progress_callback);
    curl_easy_setopt(curl.get(), CURLOPT_XFERINFODATA, &progress);
  }

  if (request.method == "POST") {
    curl_easy_setopt(curl.get(), CURLOPT_POST, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, request.body.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, body_size);
  } else if (request.method != "GET") {
    curl_easy_setopt(curl.get(), CURLOPT_CUSTOMREQUEST, request.method.c_str());
    if (!request.body.empty()) {
      curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, request.body.c_str());
      curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, body_size);
    }
  }

  curl_slist* raw_headers = nullptr;
  for (const auto& header : request.headers) {
    const auto line = header.first + ": " + header.second;
    raw_headers = curl_slist_append(raw_headers, line.c_str());
  }
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> header_guard(raw_headers,
                                                                           curl_slist_free_all);
  if (raw_headers != nullptr) {
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, raw_headers);
  }

  const auto code = curl_easy_perform(curl.get());
  if (code != CURLE_OK) {
    if (body_capture.callback_failed) {
      return Result<HttpResponse>::failure(body_capture.callback_error);
    }
    if (body_capture.complete) {
      long status = 0;
      curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
      return Result<HttpResponse>::success(
          HttpResponse{static_cast<int>(status), std::move(headers), std::move(body_capture.body)});
    }
    long status = 0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
    const bool cancelled =
        request.cancellation && request.cancellation->cancelled() && code == CURLE_ABORTED_BY_CALLBACK;
    const auto snippet = body_capture.body.size() > 512
                             ? body_capture.body.substr(0, 512)
                             : body_capture.body;
    return Result<HttpResponse>::failure(
        Error{ErrorCode::Transport,
              cancelled ? "request cancelled" : curl_easy_strerror(code),
              "CurlHttpTransport::send",
              status > 0 ? std::optional<int>(static_cast<int>(status)) : std::nullopt,
              snippet,
              {},
              {},
              code == CURLE_OPERATION_TIMEDOUT || code == CURLE_COULDNT_CONNECT ||
                  code == CURLE_COULDNT_RESOLVE_HOST || code == CURLE_RECV_ERROR ||
                  code == CURLE_SEND_ERROR});
  }
  long status = 0;
  curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
  return Result<HttpResponse>::success(
      HttpResponse{static_cast<int>(status), std::move(headers), std::move(body_capture.body)});
}

}  // namespace chio

#endif
