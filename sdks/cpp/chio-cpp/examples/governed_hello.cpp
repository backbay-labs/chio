#include "chio/chio.hpp"

#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

class DemoTransport final : public chio::HttpTransport {
 public:
  explicit DemoTransport(std::vector<chio::HttpResponse> responses)
      : responses_(std::move(responses)) {}

  chio::Result<chio::HttpResponse> send(const chio::HttpRequest& request) override {
    std::cout << request.method << " " << request.url << "\n";
    if (responses_.empty()) {
      return chio::Result<chio::HttpResponse>::failure(
          chio::Error{chio::ErrorCode::Transport, "demo transport exhausted"});
    }
    auto response = std::move(responses_.front());
    responses_.erase(responses_.begin());
    return chio::Result<chio::HttpResponse>::success(std::move(response));
  }

 private:
  std::vector<chio::HttpResponse> responses_;
};

int main() {
  auto transport = std::make_shared<DemoTransport>(std::vector<chio::HttpResponse>{
      {200, {{"MCP-Session-Id", "demo-session"}},
       "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-11-25\"}}"},
      {202, {}, "{}"},
      {200, {}, "{\"tools\":[{\"name\":\"hello\"}]}"},
  });

  auto client = chio::Client::with_static_bearer("http://127.0.0.1:8080", "demo-token", transport);
  auto initialized = client.initialize();
  if (!initialized) {
    std::cerr << initialized.error().message << "\n";
    return 1;
  }

  auto session = initialized.move_value();
  auto tools = session.list_tools();
  if (!tools) {
    std::cerr << tools.error().message << "\n";
    return 1;
  }

  std::cout << tools.value() << "\n";
  return 0;
}
