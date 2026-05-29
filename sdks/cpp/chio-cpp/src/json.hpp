#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace chio::detail {

inline std::string trim_right_slash(std::string value) {
  while (!value.empty() && value.back() == '/') {
    value.pop_back();
  }
  return value;
}

inline std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

inline std::string escape_json(std::string_view input) {
  std::ostringstream out;
  constexpr char kHexDigits[] = "0123456789abcdef";
  for (unsigned char c : input) {
    switch (c) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (c < 0x20) {
          out << "\\u00" << kHexDigits[(c >> 4U) & 0x0FU] << kHexDigits[c & 0x0FU];
        } else {
          out << static_cast<char>(c);
        }
    }
  }
  return out.str();
}

inline std::string quote(std::string_view input) {
  return "\"" + escape_json(input) + "\"";
}

inline bool is_hex_digit(char c) {
  const auto ch = static_cast<unsigned char>(c);
  return std::isdigit(ch) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline std::optional<std::uint32_t> hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<std::uint32_t>(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return static_cast<std::uint32_t>(10 + c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return static_cast<std::uint32_t>(10 + c - 'A');
  }
  return std::nullopt;
}

inline std::optional<std::uint32_t> parse_hex_code_unit(std::string_view input,
                                                        std::size_t pos) {
  if (pos + 4 > input.size()) {
    return std::nullopt;
  }
  std::uint32_t value = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    auto digit = hex_value(input[pos + i]);
    if (!digit.has_value()) {
      return std::nullopt;
    }
    value = (value << 4U) | *digit;
  }
  return value;
}

inline bool append_utf8(std::uint32_t code_point, std::string& out) {
  if (code_point <= 0x7FU) {
    out.push_back(static_cast<char>(code_point));
    return true;
  }
  if (code_point <= 0x7FFU) {
    out.push_back(static_cast<char>(0xC0U | (code_point >> 6U)));
    out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    return true;
  }
  if (code_point >= 0xD800U && code_point <= 0xDFFFU) {
    return false;
  }
  if (code_point <= 0xFFFFU) {
    out.push_back(static_cast<char>(0xE0U | (code_point >> 12U)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    return true;
  }
  if (code_point <= 0x10FFFFU) {
    out.push_back(static_cast<char>(0xF0U | (code_point >> 18U)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    return true;
  }
  return false;
}

inline std::string json_string_map(const std::map<std::string, std::string>& values) {
  std::string out = "{";
  bool first = true;
  for (const auto& entry : values) {
    if (!first) {
      out += ",";
    }
    first = false;
    out += quote(entry.first);
    out += ":";
    out += quote(entry.second);
  }
  out += "}";
  return out;
}

inline std::map<std::string, std::string> lower_headers(
    const std::map<std::string, std::string>& headers) {
  std::map<std::string, std::string> out;
  for (const auto& entry : headers) {
    out[lower(entry.first)] = entry.second;
  }
  return out;
}

inline std::string url_encode(std::string_view input) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;
  for (unsigned char c : input) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      escaped << c;
    } else {
      escaped << '%' << std::uppercase << std::setw(2) << int(c) << std::nouppercase;
    }
  }
  return escaped.str();
}

inline std::string form_url_encode(std::string_view input) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;
  for (unsigned char c : input) {
    if (c == ' ') {
      escaped << '+';
    } else if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      escaped << c;
    } else {
      escaped << '%' << std::uppercase << std::setw(2) << int(c) << std::nouppercase;
    }
  }
  return escaped.str();
}

class JsonValue {
 public:
  enum class Kind {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
  };

  static JsonValue null() { return JsonValue(); }
  static JsonValue boolean(bool value) {
    JsonValue out;
    out.kind_ = Kind::Bool;
    out.bool_ = value;
    return out;
  }
  static JsonValue number(std::string value) {
    JsonValue out;
    out.kind_ = Kind::Number;
    out.string_ = std::move(value);
    return out;
  }
  static JsonValue string(std::string value) {
    JsonValue out;
    out.kind_ = Kind::String;
    out.string_ = std::move(value);
    return out;
  }
  static JsonValue array(std::vector<JsonValue> value = {}) {
    JsonValue out;
    out.kind_ = Kind::Array;
    out.array_ = std::move(value);
    return out;
  }
  static JsonValue object(std::map<std::string, JsonValue> value = {}) {
    JsonValue out;
    out.kind_ = Kind::Object;
    out.object_ = std::move(value);
    return out;
  }

  Kind kind() const { return kind_; }
  bool is_object() const { return kind_ == Kind::Object; }
  bool is_array() const { return kind_ == Kind::Array; }
  bool is_string() const { return kind_ == Kind::String; }
  bool is_bool() const { return kind_ == Kind::Bool; }

  const std::string& as_string() const { return string_; }
  bool as_bool() const { return bool_; }
  const std::vector<JsonValue>& as_array() const { return array_; }
  const std::map<std::string, JsonValue>& as_object() const { return object_; }

  const JsonValue* get(std::string_view key) const {
    if (!is_object()) {
      return nullptr;
    }
    auto found = object_.find(std::string(key));
    return found == object_.end() ? nullptr : &found->second;
  }

  std::string string_field(std::string_view key) const {
    const auto* value = get(key);
    if (value == nullptr || !value->is_string()) {
      return {};
    }
    return value->as_string();
  }

  std::string dump() const {
    switch (kind_) {
      case Kind::Null:
        return "null";
      case Kind::Bool:
        return bool_ ? "true" : "false";
      case Kind::Number:
        return string_;
      case Kind::String:
        return quote(string_);
      case Kind::Array: {
        std::string out = "[";
        for (std::size_t i = 0; i < array_.size(); ++i) {
          if (i != 0) {
            out += ",";
          }
          out += array_[i].dump();
        }
        out += "]";
        return out;
      }
      case Kind::Object: {
        std::string out = "{";
        bool first = true;
        for (const auto& entry : object_) {
          if (!first) {
            out += ",";
          }
          first = false;
          out += quote(entry.first);
          out += ":";
          out += entry.second.dump();
        }
        out += "}";
        return out;
      }
    }
    return "null";
  }

 private:
  Kind kind_ = Kind::Null;
  bool bool_ = false;
  std::string string_;
  std::vector<JsonValue> array_;
  std::map<std::string, JsonValue> object_;
};

class JsonParser {
 public:
  explicit JsonParser(std::string_view input) : input_(input) {}

  std::optional<JsonValue> parse() {
    skip_ws();
    auto value = parse_value();
    skip_ws();
    if (!value || pos_ != input_.size()) {
      return std::nullopt;
    }
    return value;
  }

 private:
  void skip_ws() {
    while (pos_ < input_.size() &&
           std::isspace(static_cast<unsigned char>(input_[pos_]))) {
      ++pos_;
    }
  }

  bool consume(char c) {
    skip_ws();
    if (pos_ >= input_.size() || input_[pos_] != c) {
      return false;
    }
    ++pos_;
    return true;
  }

  bool consume_literal(std::string_view literal) {
    skip_ws();
    if (input_.substr(pos_, literal.size()) != literal) {
      return false;
    }
    pos_ += literal.size();
    return true;
  }

  std::optional<JsonValue> parse_value() {
    skip_ws();
    if (pos_ >= input_.size()) {
      return std::nullopt;
    }
    switch (input_[pos_]) {
      case 'n':
        return consume_literal("null") ? std::optional<JsonValue>(JsonValue::null())
                                       : std::nullopt;
      case 't':
        return consume_literal("true") ? std::optional<JsonValue>(JsonValue::boolean(true))
                                       : std::nullopt;
      case 'f':
        return consume_literal("false") ? std::optional<JsonValue>(JsonValue::boolean(false))
                                        : std::nullopt;
      case '"':
        return parse_string_value();
      case '[':
        return parse_array();
      case '{':
        return parse_object();
      default:
        if (input_[pos_] == '-' || std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
          return parse_number();
        }
        return std::nullopt;
    }
  }

  std::optional<std::string> parse_string_raw() {
    if (!consume('"')) {
      return std::nullopt;
    }
    std::string out;
    while (pos_ < input_.size()) {
      char c = input_[pos_++];
      if (c == '"') {
        return out;
      }
      if (c != '\\') {
        if (static_cast<unsigned char>(c) < 0x20) {
          return std::nullopt;
        }
        out.push_back(c);
        continue;
      }
      if (pos_ >= input_.size()) {
        return std::nullopt;
      }
      char esc = input_[pos_++];
      switch (esc) {
        case '"':
        case '\\':
        case '/':
          out.push_back(esc);
          break;
        case 'b':
          out.push_back('\b');
          break;
        case 'f':
          out.push_back('\f');
          break;
        case 'n':
          out.push_back('\n');
          break;
        case 'r':
          out.push_back('\r');
          break;
        case 't':
          out.push_back('\t');
          break;
        case 'u': {
          auto code_unit = parse_hex_code_unit(input_, pos_);
          if (!code_unit.has_value()) {
            return std::nullopt;
          }
          pos_ += 4;
          std::uint32_t code_point = *code_unit;
          if (code_point >= 0xD800U && code_point <= 0xDBFFU) {
            if (pos_ + 6 > input_.size() || input_[pos_] != '\\' ||
                input_[pos_ + 1] != 'u') {
              return std::nullopt;
            }
            pos_ += 2;
            auto low = parse_hex_code_unit(input_, pos_);
            if (!low.has_value() || *low < 0xDC00U || *low > 0xDFFFU) {
              return std::nullopt;
            }
            pos_ += 4;
            code_point = 0x10000U + ((code_point - 0xD800U) << 10U) +
                         (*low - 0xDC00U);
          } else if (code_point >= 0xDC00U && code_point <= 0xDFFFU) {
            return std::nullopt;
          }
          if (!append_utf8(code_point, out)) {
            return std::nullopt;
          }
          break;
        }
        default:
          return std::nullopt;
      }
    }
    return std::nullopt;
  }

  std::optional<JsonValue> parse_string_value() {
    auto value = parse_string_raw();
    if (!value) {
      return std::nullopt;
    }
    return JsonValue::string(std::move(*value));
  }

  std::optional<JsonValue> parse_number() {
    const auto start = pos_;
    if (input_[pos_] == '-') {
      ++pos_;
    }
    if (pos_ >= input_.size() || !std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
      return std::nullopt;
    }
    if (input_[pos_] == '0') {
      ++pos_;
      if (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
        return std::nullopt;
      }
    } else {
      while (pos_ < input_.size() &&
             std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
        ++pos_;
      }
    }
    if (pos_ < input_.size() && input_[pos_] == '.') {
      ++pos_;
      const auto fraction_start = pos_;
      while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
        ++pos_;
      }
      if (pos_ == fraction_start) {
        return std::nullopt;
      }
    }
    if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E')) {
      ++pos_;
      if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-')) {
        ++pos_;
      }
      const auto exponent_start = pos_;
      while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
        ++pos_;
      }
      if (pos_ == exponent_start) {
        return std::nullopt;
      }
    }
    return JsonValue::number(std::string(input_.substr(start, pos_ - start)));
  }

  std::optional<JsonValue> parse_array() {
    if (!consume('[')) {
      return std::nullopt;
    }
    std::vector<JsonValue> values;
    skip_ws();
    if (consume(']')) {
      return JsonValue::array(std::move(values));
    }
    while (true) {
      auto value = parse_value();
      if (!value) {
        return std::nullopt;
      }
      values.push_back(std::move(*value));
      if (consume(']')) {
        return JsonValue::array(std::move(values));
      }
      if (!consume(',')) {
        return std::nullopt;
      }
    }
  }

  std::optional<JsonValue> parse_object() {
    if (!consume('{')) {
      return std::nullopt;
    }
    std::map<std::string, JsonValue> values;
    skip_ws();
    if (consume('}')) {
      return JsonValue::object(std::move(values));
    }
    while (true) {
      auto key = parse_string_raw();
      if (!key || !consume(':')) {
        return std::nullopt;
      }
      auto value = parse_value();
      if (!value) {
        return std::nullopt;
      }
      values[*key] = std::move(*value);
      if (consume('}')) {
        return JsonValue::object(std::move(values));
      }
      if (!consume(',')) {
        return std::nullopt;
      }
    }
  }

  std::string_view input_;
  std::size_t pos_ = 0;
};

inline std::optional<JsonValue> parse_json(std::string_view input) {
  return JsonParser(input).parse();
}

inline std::string extract_json_string_field(const std::string& json, std::string_view field) {
  auto parsed = parse_json(json);
  if (!parsed || !parsed->is_object()) {
    return {};
  }
  return parsed->string_field(field);
}

inline const JsonValue* json_path(const JsonValue& root,
                                  std::initializer_list<std::string_view> path) {
  const JsonValue* current = &root;
  for (auto key : path) {
    current = current->get(key);
    if (current == nullptr) {
      return nullptr;
    }
  }
  return current;
}

inline std::string json_string_at(const JsonValue& root,
                                  std::initializer_list<std::string_view> path) {
  const auto* value = json_path(root, path);
  if (value == nullptr || !value->is_string()) {
    return {};
  }
  return value->as_string();
}

}  // namespace chio::detail
