package wol

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	resp "github.com/FrankXLT/mcp-adv-netutils/internal/response"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/utils"
)

// WOLParams represents the parameters for sending a Wake-on-LAN magic packet.
type WOLParams struct {
	MAC         string `json:"mac"`
	BroadcastIP string `json:"broadcast_ip,omitempty"` // default: 255.255.255.255
	Port        *int   `json:"port,omitempty"`         // default: 9
}

// WOLResponse represents the result of sending a Wake-on-LAN magic packet.
type WOLResponse struct {
	MAC         string `json:"mac"`
	Normalized  string `json:"normalized_mac"`
	BroadcastIP string `json:"broadcast_ip"`
	Port        int    `json:"port"`
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	Timestamp   string `json:"timestamp"`
}

// Execute validates WOL parameters, builds a 102-byte magic packet, and sends it over UDP.
func Execute(ctx context.Context, params WOLParams, guard *security.TargetGuard) (*WOLResponse, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}

	cleanMAC := strings.ToUpper(
		strings.ReplaceAll(
			strings.ReplaceAll(
				strings.ReplaceAll(strings.TrimSpace(params.MAC), ":", ""),
				"-", ""),
			".", ""),
	)
	if len(cleanMAC) != 12 {
		return nil, errors.New("invalid MAC address: must be exactly 12 hex characters")
	}

	macBytes, err := hex.DecodeString(cleanMAC)
	if err != nil {
		return nil, fmt.Errorf("error decoding MAC address hex: %w", err)
	}
	if len(macBytes) != 6 {
		return nil, fmt.Errorf("invalid MAC address length: got %d bytes, want 6", len(macBytes))
	}

	bcast := "255.255.255.255"
	if trimmed := strings.TrimSpace(params.BroadcastIP); trimmed != "" {
		bcast = trimmed
	}

	ip := net.ParseIP(bcast)
	if ip == nil {
		return nil, fmt.Errorf("invalid broadcast IP address: %q", bcast)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	bcast = ip.String()

	if !ip.Equal(net.IPv4bcast) {
		if valErr := guard.ValidateIP(ip); valErr != nil {
			return nil, fmt.Errorf("broadcast IP validation failed: %w", valErr)
		}
	}

	port := 9
	if params.Port != nil {
		if *params.Port < 1 || *params.Port > 65535 {
			return nil, fmt.Errorf("invalid port %d: must be between 1 and 65535", *params.Port)
		}
		port = *params.Port
	}

	packet := buildMagicPacket(macBytes)

	targetAddr := net.JoinHostPort(bcast, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to open UDP connection to %s: %w", targetAddr, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("failed to send magic packet: %w", err)
	}

	formattedMAC := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		cleanMAC[0:2], cleanMAC[2:4], cleanMAC[4:6], cleanMAC[6:8], cleanMAC[8:10], cleanMAC[10:12])

	return &WOLResponse{
		MAC:         params.MAC,
		Normalized:  formattedMAC,
		BroadcastIP: bcast,
		Port:        port,
		Success:     true,
		Message:     fmt.Sprintf("Wake-on-LAN magic packet sent to %s via %s", formattedMAC, targetAddr),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// HandleWakeOnLAN sends a Wake-on-LAN Magic Packet to wake a network device.
//
//nolint:gocritic // Exported handler mirrors mcp-go ToolHandlerFunc value parameter.
func HandleWakeOnLAN(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var params WOLParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	response, err := Execute(ctx, params, nil)
	if err != nil {
		return nil, err
	}

	toolResult, err := resp.JSON(response)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Wake-on-LAN response: %w", err)
	}
	return toolResult, nil
}

func buildMagicPacket(macBytes []byte) []byte {
	// 102-byte Magic Packet: 6 bytes of 0xFF followed by 16 repetitions of 6-byte MAC.
	packet := make([]byte, 102)
	for i := range 6 {
		packet[i] = 0xFF
	}
	for i := 6; i < 102; i += 6 {
		copy(packet[i:i+6], macBytes)
	}
	return packet
}
