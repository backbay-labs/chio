#include "chio/drogon.hpp"

#include <type_traits>

int main() {
  static_assert(std::is_base_of<::drogon::HttpMiddlewareBase,
                                chio::drogon::ChioMiddleware>::value,
                "ChioMiddleware must be a Drogon middleware");
  static_assert(static_cast<int>(chio::drogon::SidecarFailureMode::FailClosed) !=
                static_cast<int>(chio::drogon::SidecarFailureMode::FailOpenWithoutReceipt),
                "SidecarFailureMode variants must be distinct");
  return 0;
}
