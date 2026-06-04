#include <drogon/drogon.h>

#include "hello_app.hpp"

int main() {
  hello_drogon::configure_chio_from_env();
  hello_drogon::register_routes();
  drogon::app().addListener("127.0.0.1", hello_drogon::port_from_env());
  drogon::app().run();
}
