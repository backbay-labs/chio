#include "chio/receipt_query.hpp"

#include <utility>

#include "json.hpp"

namespace chio {

ReceiptQueryClient::ReceiptQueryClient(std::string base_url,
                                       std::string bearer_token,
                                       HttpTransportPtr transport)
    : base_url_(detail::trim_right_slash(std::move(base_url))),
      bearer_token_(std::move(bearer_token)),
      transport_(std::move(transport)) {}

Result<std::string> ReceiptQueryClient::query(
    const std::map<std::string, std::string>& params) const {
  std::string query;
  bool first = true;
  for (const auto& entry : params) {
    if (!first) {
      query += "&";
    }
    first = false;
    query += detail::url_encode(entry.first);
    query += "=";
    query += detail::url_encode(entry.second);
  }
  return query_raw(query);
}

Result<std::string> ReceiptQueryClient::query_raw(std::string query_string) const {
  if (!transport_) {
    return Result<std::string>::failure(Error{ErrorCode::Transport, "missing HTTP transport"});
  }
  HttpRequest request{
      "GET",
      base_url_ + "/v1/receipts/query" + (query_string.empty() ? "" : "?" + query_string),
      {{"Authorization", "Bearer " + bearer_token_}, {"Accept", "application/json"}},
      "",
  };
  auto response = transport_->send(request);
  if (!response) {
    return Result<std::string>::failure(response.error());
  }
  if (response.value().status < 200 || response.value().status >= 300) {
    return Result<std::string>::failure(
        Error{ErrorCode::Protocol, "receipt query returned HTTP " +
                                      std::to_string(response.value().status)});
  }
  return Result<std::string>::success(response.value().body);
}

}  // namespace chio
