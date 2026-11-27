package mac_lookup

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecuteValidFormatsAndOUILookup(t *testing.T) {
	t.Parallel()

	initOUIMap()
	require.NotEmpty(t, ouiMap, "embedded oui.json.gz should populate ouiMap")
	require.NotEmpty(t, ouiMap["005056"], "expected VMware OUI 005056 in oui.json.gz")
	require.NotEmpty(t, ouiMap["00000C"], "expected Cisco OUI 00000C in oui.json.gz")

	tests := []struct {
		name       string
		input      string
		wantNorm   string
		wantOUI    string
		wantOUIKey string
	}{
		{
			name:       "colon lowercase",
			input:      "00:50:56:ab:cd:ef",
			wantNorm:   "00:50:56:AB:CD:EF",
			wantOUI:    "00:50:56",
			wantOUIKey: "005056",
		},
		{
			name:       "hyphen uppercase",
			input:      "00-50-56-AB-CD-EF",
			wantNorm:   "00:50:56:AB:CD:EF",
			wantOUI:    "00:50:56",
			wantOUIKey: "005056",
		},
		{
			name:       "cisco dot notation mixed case",
			input:      "0000.0c12.34aB",
			wantNorm:   "00:00:0C:12:34:AB",
			wantOUI:    "00:00:0C",
			wantOUIKey: "00000C",
		},
		{
			name:       "bare hex with surrounding spaces",
			input:      "  005056112233  ",
			wantNorm:   "00:50:56:11:22:33",
			wantOUI:    "00:50:56",
			wantOUIKey: "005056",
		},
		{
			name:       "6-hex OUI prefix only",
			input:      "00:50:56",
			wantNorm:   "00:50:56",
			wantOUI:    "00:50:56",
			wantOUIKey: "005056",
		},
		{
			name:       "partial 8-hex prefix formats as OUI",
			input:      "00-00-0c-99",
			wantNorm:   "00:00:0C",
			wantOUI:    "00:00:0C",
			wantOUIKey: "00000C",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := Execute(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.input, res.MAC)
			assert.Equal(t, tc.wantNorm, res.NormalizedMAC)
			assert.Equal(t, tc.wantOUI, res.OUI)
			assert.Equal(t, ouiMap[tc.wantOUIKey], res.Vendor)
			assert.False(t, res.IsLocallyAdministered)
			assert.Equal(t, "unicast_uaa", res.AddressType)
		})
	}
}

func TestExecuteInvalidMAC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		errPart string
	}{
		{name: "empty", input: "", errPart: "at least 6 hex characters"},
		{name: "whitespace only", input: "   ", errPart: "at least 6 hex characters"},
		{name: "separators only", input: "::--..", errPart: "at least 6 hex characters"},
		{name: "too short", input: "00:11:2", errPart: "at least 6 hex characters"},
		{name: "non-hex character", input: "00:50:5G:11:22:33", errPart: "non-hex character"},
		{name: "slash separator rejected", input: "00/50/56/11/22/33", errPart: "non-hex character"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := Execute(tc.input)
			require.Error(t, err)
			assert.Nil(t, res)
			assert.Contains(t, err.Error(), tc.errPart)
		})
	}
}

func TestExecuteLAAAndMulticastAndUnknownFallback(t *testing.T) {
	t.Parallel()

	initOUIMap()

	// Find a UAA prefix (bit 0 = 0, bit 1 = 0) not present in ouiMap for deterministic unknown UAA testing.
	var unknownUAA string
	for b1 := 0; b1 <= 0xFF && unknownUAA == ""; b1++ {
		if b1&0x03 != 0 {
			continue
		}
		candidate := "000000"
		if b1 != 0 {
			candidate = string([]byte{
				"0123456789ABCDEF"[b1>>4],
				"0123456789ABCDEF"[b1&0x0F],
				'F', 'F', 'F', 'F',
			})
		}
		if _, ok := ouiMap[candidate]; !ok {
			unknownUAA = candidate
		}
	}
	require.NotEmpty(t, unknownUAA)

	uaaUnknownRes, err := Execute(unknownUAA + "112233")
	require.NoError(t, err)
	assert.False(t, uaaUnknownRes.IsLocallyAdministered)
	assert.Equal(t, "unicast_uaa", uaaUnknownRes.AddressType)
	assert.Equal(t, "Unknown Vendor", uaaUnknownRes.Vendor)

	// Bit 1 of first octet set (0x02) -> Locally Administered Address.
	laaRes, err := Execute("02:42:ac:11:00:02")
	require.NoError(t, err)
	assert.True(t, laaRes.IsLocallyAdministered)
	assert.Equal(t, "locally_administered_laa", laaRes.AddressType)
	if _, ok := ouiMap["0242AC"]; !ok {
		assert.Equal(t, "Locally Administered / Virtual (Docker, VM, Random)", laaRes.Vendor)
	}

	// 0x06 also has bit 1 set and bit 0 clear.
	laaRes2, err := Execute("06-11-22-33-44-55")
	require.NoError(t, err)
	assert.True(t, laaRes2.IsLocallyAdministered)
	assert.Equal(t, "locally_administered_laa", laaRes2.AddressType)

	// Bit 0 set (0x01) -> multicast, not LAA.
	mcastRes, err := Execute("01:00:5e:00:00:01")
	require.NoError(t, err)
	assert.False(t, mcastRes.IsLocallyAdministered)
	assert.Equal(t, "multicast", mcastRes.AddressType)

	// Both bit 0 and bit 1 set (0x03) -> multicast addressType and IsLocallyAdministered true.
	mcastLAARes, err := Execute("03:11:22:33:44:55")
	require.NoError(t, err)
	assert.True(t, mcastLAARes.IsLocallyAdministered)
	assert.Equal(t, "multicast", mcastLAARes.AddressType)
}

func TestHandleMACLookup(t *testing.T) {
	t.Parallel()

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"mac": "00:50:56:01:02:03"}
	res, err := HandleMACLookup(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.Content, 1)

	textContent, ok := res.Content[0].(mcp.TextContent)
	require.True(t, ok)

	var decoded MACLookupResult
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &decoded))
	assert.Equal(t, "00:50:56:01:02:03", decoded.NormalizedMAC)
	assert.Equal(t, "00:50:56", decoded.OUI)
	assert.Equal(t, ouiMap["005056"], decoded.Vendor)

	badTypeReq := mcp.CallToolRequest{}
	badTypeReq.Params.Arguments = map[string]any{"mac": 12345}
	_, err = HandleMACLookup(context.Background(), badTypeReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse tool input")

	badMACReq := mcp.CallToolRequest{}
	badMACReq.Params.Arguments = map[string]any{"mac": "zz"}
	_, err = HandleMACLookup(context.Background(), badMACReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid MAC address")
}
