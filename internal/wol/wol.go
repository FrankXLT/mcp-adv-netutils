package wol

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	resp "github.com/patrickdappollonio/mcp-netutils/internal/response"
	"github.com/patrickdappollonio/mcp-netutils/internal/utils"
)

type WOLParams struct {
	MAC         string `json:"mac"`
	BroadcastIP string `json:"broadcast_ip,omitempty"` // default: 255.255.255.255
	Port        *int   `json:"port,omitempty"`         // default: 9
}

type WOLResponse struct {
	MAC         string `json:"mac"`
	Normalized  string `json:"normalized_mac"`
	BroadcastIP string `json:"broadcast_ip"`
	Port        int    `json:"port"`
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	Timestamp   string `json:"timestamp"`
}

// HandleWakeOnLAN sends a Wake-on-LAN Magic Packet to wake a network device.
func HandleWakeOnLAN(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var params WOLParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	cleanMAC := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(params.MAC, ":", ""), "-", ""), ".", ""))
	if len(cleanMAC) != 12 {
		return nil, fmt.Errorf("invalid MAC address: must be exactly 12 hex characters")
	}

	macBytes, err := hex.DecodeString(cleanMAC)
	if err != nil {
		return nil, fmt.Errorf("error decoding MAC address hex: %w", err)
	}

	bcast := "255.255.255.255"
	if strings.TrimSpace(params.BroadcastIP) != "" {
		bcast = strings.TrimSpace(params.BroadcastIP)
	}

	port := 9
	if params.Port != nil && *params.Port > 0 && *params.Port <= 65535 {
		port = *params.Port
	}

	// Construct 102-byte Magic Packet: 6 bytes of 0xFF followed by 16 repetitions of 6-byte MAC
	packet := make([]byte, 102)
	for i := 0; i < 6; i++ {
		packet[i] = 0xFF
	}
	for i := 6; i < 102; i += 6 {
		copy(packet[i:i+6], macBytes)
	}

	targetAddr := fmt.Sprintf("%s:%d", bcast, port)
	conn, err := net.Dial("udp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to open UDP connection to %s: %w", targetAddr, err)
	}
	defer conn.Close()

	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("failed to send magic packet: %w", err)
	}

	formattedMAC := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		cleanMAC[0:2], cleanMAC[2:4], cleanMAC[4:6], cleanMAC[6:8], cleanMAC[8:10], cleanMAC[10:12])

	response := WOLResponse{
		MAC:         params.MAC,
		Normalized:  formattedMAC,
		BroadcastIP: bcast,
		Port:        port,
		Success:     true,
		Message:     fmt.Sprintf("Wake-on-LAN magic packet sent to %s via %s", formattedMAC, targetAddr),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	return resp.JSON(response)
}
