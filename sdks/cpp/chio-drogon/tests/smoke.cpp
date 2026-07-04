#include "chio/drogon.hpp"

#include <type_traits>

int main() {
  static_assert(std::is_base_of<::drogon::HttpMiddlewareBase,
                                chio::drogon::ChioMiddleware>::value,
                "ChioMiddleware must be a Drogon middleware");

  chio::drogon::Options options;
  chio::drogon::configure(options);

  return 0;
}
