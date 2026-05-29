package invariants

import (
	"encoding/json"
	"fmt"
)

func copyWithoutKey(input map[string]any, excludedKey string) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		if key == excludedKey {
			continue
		}
		output[key] = value
	}
	return output
}

func mapField(input map[string]any, key string) (map[string]any, error) {
	value, ok := input[key]
	if !ok {
		return nil, fmt.Errorf("missing field %q", key)
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("field %q must be an object", key)
	}
	return result, nil
}

func stringField(input map[string]any, key string) (string, error) {
	value, ok := input[key]
	if !ok {
		return "", fmt.Errorf("missing field %q", key)
	}
	result, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("field %q must be a string", key)
	}
	return result, nil
}

func int64Field(input map[string]any, key string) (int64, error) {
	value, ok := input[key]
	if !ok {
		return 0, fmt.Errorf("missing field %q", key)
	}
	switch typed := value.(type) {
	case json.Number:
		return typed.Int64()
	case int64:
		return typed, nil
	case int:
		return int64(typed), nil
	case float64:
		return int64(typed), nil
	default:
		return 0, fmt.Errorf("field %q must be an integer", key)
	}
}
