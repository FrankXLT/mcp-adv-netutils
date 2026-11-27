package port_scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePortsPresetsAndDefault(t *testing.T) {
	defaultPorts, err := parsePorts("")
	require.NoError(t, err)
	assert.Equal(t, portPresets["common"], defaultPorts)
	assert.Len(t, defaultPorts, 25)

	whitespacePorts, err := parsePorts("   ")
	require.NoError(t, err)
	assert.Equal(t, portPresets["common"], whitespacePorts)

	for _, preset := range []string{"common", "homelab", "web", "iot"} {
		t.Run("preset_"+preset, func(t *testing.T) {
			got, parseErr := parsePorts(preset)
			require.NoError(t, parseErr)
			assert.Equal(t, portPresets[preset], got)

			upperGot, upperErr := parsePorts(strings.ToUpper(preset))
			require.NoError(t, upperErr)
			assert.Equal(t, portPresets[preset], upperGot)
		})
	}

	assert.Equal(t, []int{22, 53, 80, 443, 1883, 3000, 3306, 5000, 5001, 5432, 6379, 8000, 8080, 8123, 8443, 8883, 9000, 9090, 9443}, portPresets["homelab"])
	assert.Equal(t, []int{80, 443, 3000, 8000, 8080, 8443, 9000}, portPresets["web"])
	assert.Equal(t, []int{22, 23, 53, 80, 443, 554, 1883, 5000, 5353, 8000, 8080, 8123, 8883, 49152}, portPresets["iot"])

	combined, err := parsePorts("web,22,80")
	require.NoError(t, err)
	assert.Equal(t, []int{80, 443, 3000, 8000, 8080, 8443, 9000, 22}, combined)
}

func TestParsePortsCapAndValidation(t *testing.T) {
	exactCap, err := parsePorts("1-1024")
	require.NoError(t, err)
	assert.Len(t, exactCap, maxPorts)

	tests := []struct {
		name  string
		input string
	}{
		{name: "single_range_exceeds_1024", input: "1-1025"},
		{name: "multi_range_exceeds_1024", input: "1-600,601-1200"},
		{name: "range_plus_port_exceeds_1024", input: "1-1024,2000"},
		{name: "large_range_rejected", input: "1-65535"},
		{name: "port_zero", input: "0"},
		{name: "port_over_65535", input: "65536"},
		{name: "non_numeric", input: "http"},
		{name: "reversed_range", input: "100-50"},
		{name: "malformed_range", input: "80-90-100"},
		{name: "only_commas", input: ",,,"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, parseErr := parsePorts(tc.input)
			require.Error(t, parseErr)
		})
	}
}

func TestValidateTimeout(t *testing.T) {
	d, err := validateTimeout(nil)
	require.NoError(t, err)
	assert.Equal(t, time.Second, d)

	minVal := 50
	d, err = validateTimeout(&minVal)
	require.NoError(t, err)
	assert.Equal(t, 50*time.Millisecond, d)

	maxVal := 10000
	d, err = validateTimeout(&maxVal)
	require.NoError(t, err)
	assert.Equal(t, 10000*time.Millisecond, d)

	for _, invalid := range []int{-1, 0, 49, 10001} {
		v := invalid
		_, err := validateTimeout(&v)
		require.Error(t, err, "timeout %d should be rejected", invalid)
	}
}

func TestExecuteTargetValidationAndGuard(t *testing.T) {
	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	strictGuard, err := security.NewTargetGuardWithOptions(nil, nil, true)
	require.NoError(t, err)

	tests := []struct {
		name      string
		target    string
		guard     *security.TargetGuard
		targetErr error
	}{
		{name: "empty_target", target: "", guard: nil, targetErr: security.ErrTargetInvalid},
		{name: "leading_dash", target: "-p", guard: nil, targetErr: security.ErrTargetInvalid},
		{name: "leading_dash_with_spaces", target: " -sT", guard: guard, targetErr: security.ErrTargetInvalid},
		{name: "metadata_ipv4_blocked", target: "169.254.169.254", guard: guard, targetErr: security.ErrTargetDenied},
		{name: "metadata_ipv6_blocked", target: "fd00:ec2::254", guard: guard, targetErr: security.ErrTargetDenied},
		{name: "private_loopback_blocked", target: "127.0.0.1", guard: strictGuard, targetErr: security.ErrTargetDenied},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, execErr := Execute(context.Background(), PortScanParams{
				Target: tc.target,
				Ports:  "80",
			}, tc.guard)
			require.Error(t, execErr)
			assert.True(t, errors.Is(execErr, tc.targetErr), "expected %v, got %v", tc.targetErr, execErr)
		})
	}

	t.Run("nil_context", func(t *testing.T) {
		//nolint:staticcheck // intentionally testing nil context guard
		_, execErr := Execute(nil, PortScanParams{Target: "127.0.0.1", Ports: "80"}, guard)
		require.Error(t, execErr)
	})
}

func TestExecuteLocalTCPListeners(t *testing.T) {
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln1.Close() }()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln2.Close() }()

	// Accept connections cleanly so probes don't stall.
	for _, ln := range []net.Listener{ln1, ln2} {
		l := ln
		go func() {
			for {
				conn, acceptErr := l.Accept()
				if acceptErr != nil {
					return
				}
				_ = conn.Close()
			}
		}()
	}

	// Obtain a closed ephemeral port.
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	require.NoError(t, closedLn.Close())

	port1 := ln1.Addr().(*net.TCPAddr).Port
	port2 := ln2.Addr().(*net.TCPAddr).Port

	guard, err := security.NewTargetGuard([]string{"127.0.0.1/32"}, nil)
	require.NoError(t, err)

	timeoutMS := 500
	res, err := Execute(context.Background(), PortScanParams{
		Target:    "127.0.0.1",
		Ports:     fmt.Sprintf("%d,%d,%d", port1, closedPort, port2),
		TimeoutMS: &timeoutMS,
	}, guard)
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1", res.Target)
	assert.Equal(t, "127.0.0.1", res.IP)
	assert.Equal(t, 2, res.OpenCount)
	require.Len(t, res.Ports, 3)

	assert.Equal(t, port1, res.Ports[0].Port)
	assert.Equal(t, "open", res.Ports[0].State)

	assert.Equal(t, closedPort, res.Ports[1].Port)
	assert.Equal(t, "closed", res.Ports[1].State)

	assert.Equal(t, port2, res.Ports[2].Port)
	assert.Equal(t, "open", res.Ports[2].State)
}

func TestHandlePortScanWithLocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "tcp_port_scan",
			Arguments: map[string]any{
				"target":     "127.0.0.1",
				"ports":      fmt.Sprintf("%d", port),
				"timeout_ms": 500,
			},
		},
	}

	toolRes, err := HandlePortScan(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, toolRes)
	require.Len(t, toolRes.Content, 1)

	textContent, ok := toolRes.Content[0].(mcp.TextContent)
	require.True(t, ok)

	var decoded PortScanResponse
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &decoded))
	assert.Equal(t, 1, decoded.OpenCount)
	require.Len(t, decoded.Ports, 1)
	assert.Equal(t, "open", decoded.Ports[0].State)
}
