package response

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONSuccess(t *testing.T) {
	t.Parallel()

	payload := struct {
		Host string `json:"host"`
		OK   bool   `json:"ok"`
		Code int    `json:"code"`
	}{
		Host: "router.lan",
		OK:   true,
		Code: 200,
	}

	res, err := JSON(payload)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.False(t, res.IsError)
	require.Len(t, res.Content, 1)

	textContent, ok := res.Content[0].(mcp.TextContent)
	require.True(t, ok)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &decoded))
	assert.Equal(t, "router.lan", decoded["host"])
	assert.Equal(t, true, decoded["ok"])
	assert.Equal(t, float64(200), decoded["code"])

	nilRes, err := JSON(nil)
	require.NoError(t, err)
	require.Len(t, nilRes.Content, 1)
	nilText, ok := nilRes.Content[0].(mcp.TextContent)
	require.True(t, ok)
	assert.Equal(t, "null", nilText.Text)
}

func TestJSONMarshalError(t *testing.T) {
	t.Parallel()

	res, err := JSON(make(chan int))
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "error generating JSON")

	resNaN, errNaN := JSON(math.NaN())
	require.Error(t, errNaN)
	assert.Nil(t, resNaN)
	assert.Contains(t, errNaN.Error(), "error generating JSON")
}
