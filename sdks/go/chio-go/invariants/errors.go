package invariants

import (
	"encoding/json"
	"strings"
)

type InvariantError struct {
	Code    string
	Message string
}

func (error *InvariantError) Error() string {
	return error.Message
}

func newInvariantError(code string, message string) error {
	return &InvariantError{
		Code:    code,
		Message: message,
	}
}

func ParseJSONText(input string) (any, error) {
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, newInvariantError("json", "input is not valid JSON")
	}
	return value, nil
}
