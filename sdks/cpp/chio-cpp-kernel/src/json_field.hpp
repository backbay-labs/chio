#pragma once

#include <cctype>
#include <cstdint>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace chio {
namespace kernel {
namespace detail {

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

inline void skip_ws(std::string_view input, std::size_t& pos) {
  while (pos < input.size()) {
    const auto c = static_cast<unsigned char>(input[pos]);
    if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
      return;
    }
    ++pos;
  }
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

inline std::optional<std::string> parse_json_string(std::string_view input, std::size_t& pos) {
  if (pos >= input.size() || input[pos] != '"') {
    return std::nullopt;
  }
  ++pos;

  std::string out;
  while (pos < input.size()) {
    const char c = input[pos++];
    if (c == '"') {
      return out;
    }
    if (static_cast<unsigned char>(c) < 0x20) {
      return std::nullopt;
    }
    if (c != '\\') {
      out.push_back(c);
      continue;
    }
    if (pos >= input.size()) {
      return std::nullopt;
    }
    const char escaped = input[pos++];
    switch (escaped) {
      case '"':
      case '\\':
      case '/':
        out.push_back(escaped);
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
        auto code_unit = parse_hex_code_unit(input, pos);
        if (!code_unit.has_value()) {
          return std::nullopt;
        }
        pos += 4;
        std::uint32_t code_point = *code_unit;
        if (code_point >= 0xD800U && code_point <= 0xDBFFU) {
          if (pos + 6 > input.size() || input[pos] != '\\' || input[pos + 1] != 'u') {
            return std::nullopt;
          }
          pos += 2;
          auto low = parse_hex_code_unit(input, pos);
          if (!low.has_value() || *low < 0xDC00U || *low > 0xDFFFU) {
            return std::nullopt;
          }
          pos += 4;
          code_point = 0x10000U + ((code_point - 0xD800U) << 10U) + (*low - 0xDC00U);
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

inline bool skip_json_value(std::string_view input, std::size_t& pos);

inline bool skip_json_literal(std::string_view input, std::size_t& pos, std::string_view literal) {
  if (input.substr(pos, literal.size()) != literal) {
    return false;
  }
  pos += literal.size();
  return true;
}

inline bool skip_json_number(std::string_view input, std::size_t& pos) {
  const std::size_t start = pos;
  std::size_t cursor = pos;
  if (cursor < input.size() && input[cursor] == '-') {
    ++cursor;
  }
  if (cursor >= input.size() || !std::isdigit(static_cast<unsigned char>(input[cursor]))) {
    return false;
  }
  if (input[cursor] == '0') {
    ++cursor;
    if (cursor < input.size() && std::isdigit(static_cast<unsigned char>(input[cursor]))) {
      return false;
    }
  } else {
    while (cursor < input.size() &&
           std::isdigit(static_cast<unsigned char>(input[cursor]))) {
      ++cursor;
    }
  }
  if (cursor < input.size() && input[cursor] == '.') {
    ++cursor;
    if (cursor >= input.size() || !std::isdigit(static_cast<unsigned char>(input[cursor]))) {
      return false;
    }
    while (cursor < input.size() &&
           std::isdigit(static_cast<unsigned char>(input[cursor]))) {
      ++cursor;
    }
  }
  if (cursor < input.size() && (input[cursor] == 'e' || input[cursor] == 'E')) {
    ++cursor;
    if (cursor < input.size() && (input[cursor] == '+' || input[cursor] == '-')) {
      ++cursor;
    }
    if (cursor >= input.size() || !std::isdigit(static_cast<unsigned char>(input[cursor]))) {
      return false;
    }
    while (cursor < input.size() &&
           std::isdigit(static_cast<unsigned char>(input[cursor]))) {
      ++cursor;
    }
  }
  pos = cursor;
  return pos > start;
}

inline std::optional<std::uint64_t> parse_json_uint(std::string_view input,
                                                    std::size_t& pos) {
  std::size_t cursor = pos;
  if (cursor >= input.size() ||
      !std::isdigit(static_cast<unsigned char>(input[cursor]))) {
    return std::nullopt;
  }

  std::uint64_t value = 0;
  if (input[cursor] == '0') {
    ++cursor;
    if (cursor < input.size() && std::isdigit(static_cast<unsigned char>(input[cursor]))) {
      return std::nullopt;
    }
  } else {
    while (cursor < input.size() &&
           std::isdigit(static_cast<unsigned char>(input[cursor]))) {
      const auto digit = static_cast<std::uint64_t>(input[cursor] - '0');
      if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) {
        return std::nullopt;
      }
      value = value * 10U + digit;
      ++cursor;
    }
  }

  if (cursor < input.size() &&
      (input[cursor] == '.' || input[cursor] == 'e' || input[cursor] == 'E')) {
    return std::nullopt;
  }

  pos = cursor;
  return value;
}

inline bool skip_json_array(std::string_view input, std::size_t& pos) {
  if (pos >= input.size() || input[pos] != '[') {
    return false;
  }
  ++pos;
  skip_ws(input, pos);
  if (pos < input.size() && input[pos] == ']') {
    ++pos;
    return true;
  }
  while (pos < input.size()) {
    if (!skip_json_value(input, pos)) {
      return false;
    }
    skip_ws(input, pos);
    if (pos < input.size() && input[pos] == ']') {
      ++pos;
      return true;
    }
    if (pos >= input.size() || input[pos] != ',') {
      return false;
    }
    ++pos;
    skip_ws(input, pos);
  }
  return false;
}

inline bool skip_json_object(std::string_view input, std::size_t& pos) {
  if (pos >= input.size() || input[pos] != '{') {
    return false;
  }
  ++pos;
  skip_ws(input, pos);
  if (pos < input.size() && input[pos] == '}') {
    ++pos;
    return true;
  }
  while (pos < input.size()) {
    auto key = parse_json_string(input, pos);
    if (!key.has_value()) {
      return false;
    }
    skip_ws(input, pos);
    if (pos >= input.size() || input[pos] != ':') {
      return false;
    }
    ++pos;
    skip_ws(input, pos);
    if (!skip_json_value(input, pos)) {
      return false;
    }
    skip_ws(input, pos);
    if (pos < input.size() && input[pos] == '}') {
      ++pos;
      return true;
    }
    if (pos >= input.size() || input[pos] != ',') {
      return false;
    }
    ++pos;
    skip_ws(input, pos);
  }
  return false;
}

inline bool skip_json_value(std::string_view input, std::size_t& pos) {
  skip_ws(input, pos);
  if (pos >= input.size()) {
    return false;
  }
  switch (input[pos]) {
    case '"': {
      auto value = parse_json_string(input, pos);
      return value.has_value();
    }
    case '{':
      return skip_json_object(input, pos);
    case '[':
      return skip_json_array(input, pos);
    case 't':
      return skip_json_literal(input, pos, "true");
    case 'f':
      return skip_json_literal(input, pos, "false");
    case 'n':
      return skip_json_literal(input, pos, "null");
    default:
      return skip_json_number(input, pos);
  }
}

inline std::optional<std::string> json_string_field(const std::string& json,
                                                    std::string_view key) {
  std::string_view input(json);
  std::size_t pos = 0;
  std::optional<std::string> found;
  skip_ws(input, pos);
  if (pos >= input.size() || input[pos] != '{') {
    return std::nullopt;
  }
  ++pos;

  skip_ws(input, pos);
  if (pos < input.size() && input[pos] == '}') {
    ++pos;
    skip_ws(input, pos);
    return pos == input.size() ? found : std::nullopt;
  }

  while (pos < input.size()) {
    auto parsed_key = parse_json_string(input, pos);
    if (!parsed_key.has_value()) {
      return std::nullopt;
    }
    skip_ws(input, pos);
    if (pos >= input.size() || input[pos] != ':') {
      return std::nullopt;
    }
    ++pos;
    skip_ws(input, pos);

    if (*parsed_key == key) {
      if (pos < input.size() && input[pos] == '"') {
        auto value = parse_json_string(input, pos);
        if (!value.has_value()) {
          return std::nullopt;
        }
        found = std::move(value);
        skip_ws(input, pos);
        if (pos < input.size() && input[pos] != ',' && input[pos] != '}') {
          return std::nullopt;
        }
      } else if (!skip_json_value(input, pos)) {
        return std::nullopt;
      }
    } else if (!skip_json_value(input, pos)) {
      return std::nullopt;
    }
    skip_ws(input, pos);
    if (pos < input.size() && input[pos] == '}') {
      ++pos;
      skip_ws(input, pos);
      return pos == input.size() ? found : std::nullopt;
    }
    if (pos >= input.size() || input[pos] != ',') {
      return std::nullopt;
    }
    ++pos;
    skip_ws(input, pos);
  }

  return std::nullopt;
}

inline std::optional<std::uint64_t> json_uint_field(const std::string& json,
                                                   std::string_view key) {
  std::string_view input(json);
  std::size_t pos = 0;
  std::optional<std::uint64_t> found;
  skip_ws(input, pos);
  if (pos >= input.size() || input[pos] != '{') {
    return std::nullopt;
  }
  ++pos;

  skip_ws(input, pos);
  if (pos < input.size() && input[pos] == '}') {
    ++pos;
    skip_ws(input, pos);
    return pos == input.size() ? found : std::nullopt;
  }

  while (pos < input.size()) {
    auto parsed_key = parse_json_string(input, pos);
    if (!parsed_key.has_value()) {
      return std::nullopt;
    }
    skip_ws(input, pos);
    if (pos >= input.size() || input[pos] != ':') {
      return std::nullopt;
    }
    ++pos;
    skip_ws(input, pos);

    if (*parsed_key == key) {
      std::size_t value_pos = pos;
      auto value = parse_json_uint(input, value_pos);
      if (value.has_value()) {
        found = *value;
        pos = value_pos;
        skip_ws(input, pos);
        if (pos < input.size() && input[pos] != ',' && input[pos] != '}') {
          return std::nullopt;
        }
      } else if (!skip_json_value(input, pos)) {
        return std::nullopt;
      }
    } else if (!skip_json_value(input, pos)) {
      return std::nullopt;
    }
    skip_ws(input, pos);
    if (pos < input.size() && input[pos] == '}') {
      ++pos;
      skip_ws(input, pos);
      return pos == input.size() ? found : std::nullopt;
    }
    if (pos >= input.size() || input[pos] != ',') {
      return std::nullopt;
    }
    ++pos;
    skip_ws(input, pos);
  }

  return std::nullopt;
}

}  // namespace detail
}  // namespace kernel
}  // namespace chio
