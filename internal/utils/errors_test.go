package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseJSONUnmarshalError(t *testing.T) {
	t.Parallel()

	t.Run("unmarshal type error", func(t *testing.T) {
		t.Parallel()
		var target struct {
			Port int `json:"port"`
		}
		rawErr := json.Unmarshal([]byte(`{"port":"not-an-int"}`), &target)
		require.Error(t, rawErr)

		parsed := ParseJSONUnmarshalError(fmt.Errorf("wrapped: %w", rawErr))
		require.Error(t, parsed)
		assert.Equal(t, `invalid value for field "port": expected "int" but got "string"`, parsed.Error())
	})

	t.Run("syntax error", func(t *testing.T) {
		t.Parallel()
		var target map[string]any
		rawErr := json.Unmarshal([]byte(`{"port":`), &target)
		require.Error(t, rawErr)

		parsed := ParseJSONUnmarshalError(fmt.Errorf("wrapped: %w", rawErr))
		require.Error(t, parsed)
		assert.Equal(t, "invalid input provided to the tool", parsed.Error())
	})

	t.Run("other error passes through", func(t *testing.T) {
		t.Parallel()
		sentinel := errors.New("unexpected failure")
		parsed := ParseJSONUnmarshalError(sentinel)
		assert.Same(t, sentinel, parsed)
	})

	t.Run("nil error returns nil", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, ParseJSONUnmarshalError(nil))
	})
}
