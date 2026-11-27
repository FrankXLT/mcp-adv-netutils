package wol_test

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/FrankXLT/mcp-adv-netutils/internal/mac_lookup"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/wol"
)

func TestWOLExecute_MagicPacketLoopback(t *testing.T) {
	t.Parallel()

	formats := []struct {
		name string
		mac  string
	}{
		{name: "colon_lowercase", mac: "aa:bb:cc:dd:ee:ff"},
		{name: "dash_uppercase", mac: "AA-BB-CC-DD-EE-FF"},
		{name: "cisco_dot_notation", mac: "aabb.ccdd.eeff"},
	}

	expectedMAC := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}

	for _, tc := range formats {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer func() { _ = pc.Close() }()

			udpAddr, ok := pc.LocalAddr().(*net.UDPAddr)
			require.True(t, ok)
			port := udpAddr.Port

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			res, err := wol.Execute(ctx, wol.WOLParams{
				MAC:         tc.mac,
				BroadcastIP: "127.0.0.1",
				Port:        &port,
			}, nil)
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.True(t, res.Success)
			assert.Equal(t, "AA:BB:CC:DD:EE:FF", res.Normalized)
			assert.Equal(t, "127.0.0.1", res.BroadcastIP)
			assert.Equal(t, port, res.Port)

			require.NoError(t, pc.SetReadDeadline(time.Now().Add(2*time.Second)))
			buf := make([]byte, 256)
			n, _, err := pc.ReadFrom(buf)
			require.NoError(t, err)
			require.Equal(t, 102, n, "magic packet must be exactly 102 bytes")

			for i := range 6 {
				assert.Equal(t, byte(0xFF), buf[i], "sync byte %d must be 0xFF", i)
			}
			for i := 6; i < 102; i += 6 {
				assert.Equal(t, expectedMAC, buf[i:i+6], "MAC repetition at offset %d", i)
			}
		})
	}
}

func TestWOLHandleWakeOnLAN_MCPTool(t *testing.T) {
	t.Parallel()

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()

	udpAddr, ok := pc.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{
		"mac":          "11:22:33:44:55:66",
		"broadcast_ip": "127.0.0.1",
		"port":         udpAddr.Port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := wol.HandleWakeOnLAN(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Content, 1)

	textContent, ok := mcp.AsTextContent(result.Content[0])
	require.True(t, ok)

	var parsed wol.WOLResponse
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &parsed))
	assert.True(t, parsed.Success)
	assert.Equal(t, "11:22:33:44:55:66", parsed.Normalized)
}

func TestWOLExecute_ValidationErrors(t *testing.T) {
	t.Parallel()

	validPort := 9
	zeroPort := 0
	negPort := -1
	highPort := 65536

	guardAllowLAN, err := security.NewTargetGuard([]string{"192.168.1.0/24"}, nil)
	require.NoError(t, err)

	guardBlockPriv, err := security.NewTargetGuardWithOptions(nil, nil, true)
	require.NoError(t, err)

	tests := []struct {
		name      string
		ctx       context.Context
		params    wol.WOLParams
		guard     *security.TargetGuard
		targetErr error
	}{
		{
			name:   "nil_context",
			ctx:    nil,
			params: wol.WOLParams{MAC: "AA:BB:CC:DD:EE:FF", BroadcastIP: "127.0.0.1", Port: &validPort},
		},
		{
			name:   "mac_too_short",
			ctx:    context.Background(),
			params: wol.WOLParams{MAC: "AA:BB:CC:DD:EE", BroadcastIP: "127.0.0.1", Port: &validPort},
		},
		{
			name:   "mac_too_long",
			ctx:    context.Background(),
			params: wol.WOLParams{MAC: "AA:BB:CC:DD:EE:FF:00", BroadcastIP: "127.0.0.1", Port: &validPort},
		},
		{
			name:   "mac_non_hex",
			ctx:    context.Background(),
			params: wol.WOLParams{MAC: "AA:BB:CC:DD:EE:ZZ", BroadcastIP: "127.0.0.1", Port: &validPort},
		},
		{
			name:   "mac_empty",
			ctx:    context.Background(),
			params: wol.WOLParams{MAC: "", BroadcastIP: "127.0.0.1", Port: &validPort},
		},
		{
			name:   "invalid_broadcast_ip_syntax",
			ctx:    context.Background(),
			params: wol.WOLParams{MAC: "AA:BB:CC:DD:EE:FF", BroadcastIP: "not-an-ip", Port: &validPort},
		},
		{
			name:   "invalid_broadcast_ip_cidr",
			ctx:    context.Background(),
			params: wol.WOLParams{MAC: "AA:BB:CC:DD:EE:FF", BroadcastIP: "192.168.1.255/24", Port: &validPort},
		},
		{
			name:      "metadata_ip_rejected_even_without_guard",
			ctx:       context.Background(),
			params:    wol.WOLParams{MAC: "AA:BB:CC:DD:EE:FF", BroadcastIP: "169.254.169.254", Port: &validPort},
			targetErr: security.ErrTargetDenied,
		},
		{
			name:      "guard_allowlist_rejects_disallowed_ip",
			ctx:       context.Background(),
			params:    wol.WOLParams{MAC: "AA:BB:CC:DD:EE:FF", BroadcastIP: "10.0.0.255", Port: &validPort},
			guard:     guardAllowLAN,
			targetErr: security.ErrTargetNotAllowed,
		},
		{
			name:      "guard_block_private_rejects_loopback",
			ctx:       context.Background(),
			params:    wol.WOLParams{MAC: "AA:BB:CC:DD:EE:FF", BroadcastIP: "127.0.0.1", Port: &validPort},
			guard:     guardBlockPriv,
			targetErr: security.ErrTargetDenied,
		},
		{
			name:   "port_zero_rejected",
			ctx:    context.Background(),
			params: wol.WOLParams{MAC: "AA:BB:CC:DD:EE:FF", BroadcastIP: "127.0.0.1", Port: &zeroPort},
		},
		{
			name:   "port_negative_rejected",
			ctx:    context.Background(),
			params: wol.WOLParams{MAC: "AA:BB:CC:DD:EE:FF", BroadcastIP: "127.0.0.1", Port: &negPort},
		},
		{
			name:   "port_over_65535_rejected",
			ctx:    context.Background(),
			params: wol.WOLParams{MAC: "AA:BB:CC:DD:EE:FF", BroadcastIP: "127.0.0.1", Port: &highPort},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res, err := wol.Execute(tc.ctx, tc.params, tc.guard)
			require.Error(t, err)
			assert.Nil(t, res)
			if tc.targetErr != nil {
				assert.ErrorIs(t, err, tc.targetErr)
			}
		})
	}
}

func TestWOLExecute_LimitedBroadcastBypassWithAllowGuard(t *testing.T) {
	t.Parallel()

	guardAllowLAN, err := security.NewTargetGuard([]string{"192.168.1.0/24"}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Default broadcast_ip ("255.255.255.255") may fail socket send (EACCES) in sandboxed
	// environments without SO_BROADCAST, but must never fail TargetGuard IP validation.
	_, execErr := wol.Execute(ctx, wol.WOLParams{MAC: "AA:BB:CC:DD:EE:FF"}, guardAllowLAN)
	if execErr != nil {
		assert.NotErrorIs(t, execErr, security.ErrTargetNotAllowed)
		assert.NotErrorIs(t, execErr, security.ErrTargetDenied)
	}
}

func TestMACLookupExecute_LAAAndUAA(t *testing.T) {
	t.Parallel()

	t.Run("docker_laa_mac", func(t *testing.T) {
		t.Parallel()

		res, err := mac_lookup.Execute("02:42:AC:11:00:02")
		require.NoError(t, err)
		require.NotNil(t, res)

		assert.Equal(t, "02:42:AC:11:00:02", res.NormalizedMAC)
		assert.Equal(t, "02:42:AC", res.OUI)
		assert.True(t, res.IsLocallyAdministered)
		assert.Equal(t, "locally_administered_laa", res.AddressType)
		assert.Equal(t, "Locally Administered / Virtual (Docker, VM, Random)", res.Vendor)
	})

	t.Run("real_uaa_vmware_oui", func(t *testing.T) {
		t.Parallel()

		res, err := mac_lookup.Execute("00-50-56-aa-bb-cc")
		require.NoError(t, err)
		require.NotNil(t, res)

		assert.Equal(t, "00:50:56:AA:BB:CC", res.NormalizedMAC)
		assert.Equal(t, "00:50:56", res.OUI)
		assert.False(t, res.IsLocallyAdministered)
		assert.Equal(t, "unicast_uaa", res.AddressType)
		assert.NotEmpty(t, res.Vendor)
		assert.NotEqual(t, "Unknown Vendor", res.Vendor)
		assert.Contains(t, res.Vendor, "VMware")
	})

	t.Run("real_uaa_raspberry_pi_prefix_only", func(t *testing.T) {
		t.Parallel()

		res, err := mac_lookup.Execute("b827.eb")
		require.NoError(t, err)
		require.NotNil(t, res)

		assert.Equal(t, "B8:27:EB", res.NormalizedMAC)
		assert.Equal(t, "B8:27:EB", res.OUI)
		assert.False(t, res.IsLocallyAdministered)
		assert.Equal(t, "unicast_uaa", res.AddressType)
		assert.Contains(t, res.Vendor, "Raspberry Pi")
	})

	t.Run("multicast_mac", func(t *testing.T) {
		t.Parallel()

		res, err := mac_lookup.Execute("01:00:5E:00:00:01")
		require.NoError(t, err)
		require.NotNil(t, res)

		assert.Equal(t, "multicast", res.AddressType)
		assert.False(t, res.IsLocallyAdministered)
	})
}

func TestMACLookupExecute_InvalidMACRejection(t *testing.T) {
	t.Parallel()

	invalidMACs := []string{
		"",
		"   ",
		"00:11",
		"00:11:2",
		"ZZ:11:22:33:44:55",
		"00:11:ZZ:33:44:55",
		"GG-HH-II",
		"00:50:56:ZZ:11:22",
		"00:50:56:11:22:ZZ",
		"00:50:56:11:22:3G",
	}

	for _, mac := range invalidMACs {
		t.Run(mac, func(t *testing.T) {
			t.Parallel()

			res, err := mac_lookup.Execute(mac)
			require.Error(t, err)
			assert.Nil(t, res)
		})
	}
}

func TestMACLookup_HandleAndConcurrency(t *testing.T) {
	t.Parallel()

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"mac": "02:42:AC:11:00:02"}
	result, err := mac_lookup.HandleMACLookup(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Content, 1)

	textContent, ok := mcp.AsTextContent(result.Content[0])
	require.True(t, ok)

	var parsed mac_lookup.MACLookupResult
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &parsed))
	assert.True(t, parsed.IsLocallyAdministered)
	assert.Equal(t, "02:42:AC", parsed.OUI)

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, lookupErr := mac_lookup.Execute("00:50:56:11:22:33")
			assert.NoError(t, lookupErr)
			assert.NotNil(t, res)
		}()
	}
	wg.Wait()
}
