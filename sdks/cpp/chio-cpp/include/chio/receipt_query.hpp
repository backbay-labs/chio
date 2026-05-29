#pragma once

#include <map>
#include <memory>
#include <string>

#include "chio/result.hpp"
#include "chio/transport.hpp"

namespace chio {

class ReceiptQueryClient {
 public:
  ReceiptQueryClient(std::string base_url, std::string bearer_token, HttpTransportPtr transport);

  Result<std::string> query(const std::map<std::string, std::string>& params) const;
  Result<std::string> query_raw(std::string query_string) const;

 private:
  std::string base_url_;
  std::string bearer_token_;
  HttpTransportPtr transport_;
};

}  // namespace chio
