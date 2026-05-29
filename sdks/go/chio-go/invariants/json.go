package invariants

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

func CanonicalizeJSONString(input string) (string, error) {
	value, err := ParseJSONText(input)
	if err != nil {
		return "", err
	}
	return CanonicalizeJSON(value)
}

func CanonicalizeJSON(value any) (string, error) {
	switch typed := value.(type) {
	case nil:
		return "null", nil
	case bool:
		if typed {
			return "true", nil
		}
		return "false", nil
	case string:
		return marshalJSONString(typed), nil
	case json.Number:
		return canonicalizeJSONNumber(typed)
	case float64:
		return canonicalizeFloat(typed)
	case float32:
		return canonicalizeFloat(float64(typed))
	case int:
		return strconv.Itoa(typed), nil
	case int8:
		return strconv.FormatInt(int64(typed), 10), nil
	case int16:
		return strconv.FormatInt(int64(typed), 10), nil
	case int32:
		return strconv.FormatInt(int64(typed), 10), nil
	case int64:
		return strconv.FormatInt(typed, 10), nil
	case uint:
		return strconv.FormatUint(uint64(typed), 10), nil
	case uint8:
		return strconv.FormatUint(uint64(typed), 10), nil
	case uint16:
		return strconv.FormatUint(uint64(typed), 10), nil
	case uint32:
		return strconv.FormatUint(uint64(typed), 10), nil
	case uint64:
		return strconv.FormatUint(typed, 10), nil
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			rendered, err := CanonicalizeJSON(item)
			if err != nil {
				return "", err
			}
			parts = append(parts, rendered)
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sortUTF16(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			rendered, err := CanonicalizeJSON(typed[key])
			if err != nil {
				return "", err
			}
			parts = append(parts, fmt.Sprintf("%s:%s", marshalJSONString(key), rendered))
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	default:
		return "", newInvariantError("canonical_json", fmt.Sprintf(
			"canonical JSON does not support values of type %T",
			value,
		))
	}
}

func canonicalizeJSONNumber(number json.Number) (string, error) {
	raw := number.String()
	if !strings.ContainsAny(raw, ".eE") {
		if raw == "-0" {
			return "0", nil
		}
		return raw, nil
	}
	parsed, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return "", newInvariantError("canonical_json", "canonical JSON does not support invalid numbers")
	}
	return canonicalizeFloat(parsed)
}

func canonicalizeFloat(value float64) (string, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "", newInvariantError("canonical_json", "canonical JSON does not support non-finite numbers")
	}
	if value == 0 {
		return "0", nil
	}
	if math.Trunc(value) == value && math.Abs(value) < 1e21 {
		return strconv.FormatFloat(value, 'f', 0, 64), nil
	}
	rendered := strings.ToLower(strconv.FormatFloat(value, 'g', -1, 64))
	return normalizeExponent(rendered), nil
}

func normalizeExponent(value string) string {
	index := strings.IndexByte(value, 'e')
	if index == -1 {
		return value
	}
	mantissa := value[:index]
	exponent := value[index+1:]
	if len(exponent) < 2 {
		return value
	}
	sign := exponent[:1]
	digits := strings.TrimLeft(exponent[1:], "0")
	if digits == "" {
		digits = "0"
	}
	return mantissa + "e" + sign + digits
}

func marshalJSONString(input string) string {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(input)
	return strings.TrimSuffix(buffer.String(), "\n")
}

func sortUTF16(values []string) {
	for left := 0; left < len(values); left += 1 {
		for right := left + 1; right < len(values); right += 1 {
			if compareUTF16(values[right], values[left]) < 0 {
				values[left], values[right] = values[right], values[left]
			}
		}
	}
}

func compareUTF16(left string, right string) int {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	for index := 0; index < len(leftUnits) && index < len(rightUnits); index += 1 {
		if leftUnits[index] < rightUnits[index] {
			return -1
		}
		if leftUnits[index] > rightUnits[index] {
			return 1
		}
	}
	if len(leftUnits) < len(rightUnits) {
		return -1
	}
	if len(leftUnits) > len(rightUnits) {
		return 1
	}
	return 0
}
