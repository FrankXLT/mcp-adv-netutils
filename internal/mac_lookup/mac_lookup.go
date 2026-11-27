package mac_lookup

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"

	resp "github.com/FrankXLT/mcp-adv-netutils/internal/response"
	"github.com/FrankXLT/mcp-adv-netutils/internal/utils"
)

// MACLookupParams represents the parameters for MAC vendor lookup.
type MACLookupParams struct {
	MAC string `json:"mac"`
}

// MACLookupResult represents the output of a MAC vendor lookup.
type MACLookupResult struct {
	MAC                   string `json:"mac"`
	NormalizedMAC         string `json:"normalized_mac"`
	OUI                   string `json:"oui"`
	Vendor                string `json:"vendor"`
	IsLocallyAdministered bool   `json:"is_locally_administered"`
	AddressType           string `json:"address_type"`
}

//go:embed oui.json.gz
var compressedOUIData []byte

var (
	ouiMap  map[string]string
	ouiOnce sync.Once
)

// Execute performs an IEEE OUI lookup and address-type analysis for a MAC address or prefix.
func Execute(mac string) (*MACLookupResult, error) {
	initOUIMap()

	clean := strings.ToUpper(
		strings.ReplaceAll(
			strings.ReplaceAll(
				strings.ReplaceAll(strings.TrimSpace(mac), ":", ""),
				"-", ""),
			".", ""),
	)
	if len(clean) < 6 {
		return nil, errors.New("invalid MAC address: must contain at least 6 hex characters")
	}

	for i := range len(clean) {
		if !isHexByte(clean[i]) {
			return nil, fmt.Errorf("invalid MAC address: non-hex character %q at position %d", clean[i], i)
		}
	}

	oui := clean[:6]
	formattedOUI := fmt.Sprintf("%s:%s:%s", oui[0:2], oui[2:4], oui[4:6])

	// Check LAA / Multicast bit on first byte.
	firstByte, err := strconv.ParseUint(clean[:2], 16, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address first byte %q: %w", clean[:2], err)
	}
	isLAA := (firstByte & 0x02) != 0
	isMulticast := (firstByte & 0x01) != 0

	addressType := "unicast_uaa"
	if isMulticast {
		addressType = "multicast"
	} else if isLAA {
		addressType = "locally_administered_laa"
	}

	vendor := ouiMap[oui]
	if vendor == "" {
		if isLAA {
			vendor = "Locally Administered / Virtual (Docker, VM, Random)"
		} else {
			vendor = "Unknown Vendor"
		}
	}

	formattedMAC := formattedOUI
	if len(clean) >= 12 {
		formattedMAC = fmt.Sprintf("%s:%s:%s:%s:%s:%s",
			clean[0:2], clean[2:4], clean[4:6], clean[6:8], clean[8:10], clean[10:12])
	}

	return &MACLookupResult{
		MAC:                   mac,
		NormalizedMAC:         formattedMAC,
		OUI:                   formattedOUI,
		Vendor:                vendor,
		IsLocallyAdministered: isLAA,
		AddressType:           addressType,
	}, nil
}

// HandleMACLookup performs an IEEE OUI lookup for a given MAC address.
//
//nolint:gocritic // Exported handler mirrors mcp-go ToolHandlerFunc value parameter.
func HandleMACLookup(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var params MACLookupParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	res, err := Execute(params.MAC)
	if err != nil {
		return nil, err
	}

	toolResult, err := resp.JSON(res)
	if err != nil {
		return nil, fmt.Errorf("encode MAC lookup response: %w", err)
	}
	return toolResult, nil
}

func initOUIMap() {
	ouiOnce.Do(func() {
		ouiMap = make(map[string]string)
		if len(compressedOUIData) == 0 {
			return
		}
		gr, err := gzip.NewReader(bytes.NewReader(compressedOUIData))
		if err != nil {
			return
		}

		var raw map[string]string
		decodeErr := json.NewDecoder(gr).Decode(&raw)
		closeErr := gr.Close()
		if decodeErr == nil && closeErr == nil && raw != nil {
			ouiMap = raw
		}
	})
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'F')
}
