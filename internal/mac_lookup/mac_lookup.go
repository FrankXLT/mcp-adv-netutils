package mac_lookup

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	resp "github.com/patrickdappollonio/mcp-netutils/internal/response"
	"github.com/patrickdappollonio/mcp-netutils/internal/utils"
)

//go:embed oui.json.gz
var compressedOUIData []byte

var (
	ouiMap  map[string]string
	ouiOnce sync.Once
)

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
		defer gr.Close()

		var raw map[string]string
		if err := json.NewDecoder(gr).Decode(&raw); err == nil {
			ouiMap = raw
		}
	})
}

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

// HandleMACLookup performs an IEEE OUI lookup for a given MAC address.
func HandleMACLookup(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	initOUIMap()

	var params MACLookupParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	clean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(params.MAC, ":", ""), "-", ""), ".", ""))
	if len(clean) < 6 {
		return nil, fmt.Errorf("invalid MAC address: must contain at least 6 hex characters")
	}

	oui := clean[:6]
	formattedOUI := fmt.Sprintf("%s:%s:%s", oui[0:2], oui[2:4], oui[4:6])

	// Check LAA / Multicast bit on first byte
	firstByte, err := strconv.ParseUint(clean[:2], 16, 8)
	isLAA := false
	isMulticast := false
	if err == nil {
		isLAA = (firstByte & 0x02) != 0
		isMulticast = (firstByte & 0x01) != 0
	}

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

	var formattedMAC string
	if len(clean) >= 12 {
		formattedMAC = fmt.Sprintf("%s:%s:%s:%s:%s:%s",
			clean[0:2], clean[2:4], clean[4:6], clean[6:8], clean[8:10], clean[10:12])
	} else {
		formattedMAC = formattedOUI
	}

	res := MACLookupResult{
		MAC:                   params.MAC,
		NormalizedMAC:         formattedMAC,
		OUI:                   formattedOUI,
		Vendor:                vendor,
		IsLocallyAdministered: isLAA,
		AddressType:           addressType,
	}

	return resp.JSON(res)
}
